#!/usr/bin/env python3
import asyncio
import socket
import statistics
import time

async def _echo_handler(reader, writer, nodelay=False, bufsize=0):
    if nodelay:
        s = writer.get_extra_info("socket")
        if s:
            try: s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except: pass
    if bufsize > 0:
        s = writer.get_extra_info("socket")
        if s:
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, bufsize)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, bufsize)
            except: pass
    try:
        while True:
            d = await reader.read(131072)
            if not d:
                break
            writer.write(d)
            await writer.drain()
    except:
        pass
    try:
        writer.close()
        await writer.wait_closed()
    except:
        pass

async def bench_nodelay(iters=50):
    results = {}
    for mode, nodelay in [("nodelay_ON", True), ("nodelay_OFF", False)]:
        times = []
        srv = await asyncio.start_server(
            lambda r, w: _echo_handler(r, w, nodelay=nodelay),
            "127.0.0.1", 0,
        )
        port = srv.sockets[0].getsockname()[1]
        for _ in range(iters):
            r, w = await asyncio.open_connection("127.0.0.1", port)
            if nodelay:
                s = w.get_extra_info("socket")
                if s:
                    try: s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    except: pass
            t0 = time.perf_counter()
            for _ in range(10):
                w.write(b"x")
                await w.drain()
                await r.readexactly(1)
            times.append((time.perf_counter() - t0) * 100)
            w.close()
            await w.wait_closed()
        results[mode] = times
        srv.close()
        await srv.wait_closed()
    return results

async def bench_buf(mb=4):
    data = b"x" * (64 * 1024)
    total = mb * 1024 * 1024
    results = {}
    for mode, bufsize in [("default_buf", 0), ("large_buf_256KB", 256 * 1024)]:
        srv = await asyncio.start_server(
            lambda r, w: _echo_handler(r, w, bufsize=bufsize),
            "127.0.0.1", 0,
        )
        port = srv.sockets[0].getsockname()[1]
        r, w = await asyncio.open_connection("127.0.0.1", port)
        if bufsize > 0:
            s = w.get_extra_info("socket")
            if s:
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, bufsize)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, bufsize)
                except: pass
        sent = 0
        t0 = time.perf_counter()
        while sent < total:
            chunk = data if sent + len(data) <= total else data[: total - sent]
            w.write(chunk)
            await w.drain()
            sent += len(chunk)
        remaining = total
        while remaining > 0:
            d = await r.read(min(131072, remaining))
            if not d:
                break
            remaining -= len(d)
        elapsed = time.perf_counter() - t0
        mbps = total / (1024 * 1024) / elapsed
        results[mode] = {"mbps": round(mbps, 2), "sec": round(elapsed, 3)}
        w.close()
        await w.wait_closed()
        srv.close()
        await srv.wait_closed()
    return results

async def bench_tls_handshake(iters=20):
    import ssl
    import tempfile
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from scripts.benchmark import generate_cert

    results = {}
    with tempfile.TemporaryDirectory() as cert_dir:
        for algo in ["ecdsa", "rsa"]:
            generate_cert(cert_dir, algo)
            key_path = os.path.join(cert_dir, "server.key")
            crt_path = os.path.join(cert_dir, "server.crt")
            ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_ctx.load_cert_chain(certfile=crt_path, keyfile=key_path)
            ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            try:
                ssl_ctx.set_ciphers(
                    "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"
                )
            except ssl.SSLError:
                pass
            client_ctx = ssl.create_default_context()
            client_ctx.check_hostname = False
            client_ctx.verify_mode = ssl.CERT_NONE
            try:
                client_ctx.set_ciphers(
                    "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"
                )
            except ssl.SSLError:
                pass

            async def echo_h(r, w):
                try:
                    while True:
                        d = await r.read(65536)
                        if not d: break
                        w.write(d)
                        await w.drain()
                except: pass
                try: w.close(); await w.wait_closed()
                except: pass

            srv = await asyncio.start_server(echo_h, "127.0.0.1", 0, ssl=ssl_ctx)
            port = srv.sockets[0].getsockname()[1]
            times = []
            for _ in range(iters):
                t0 = time.perf_counter()
                r, w = await asyncio.open_connection("127.0.0.1", port, ssl=client_ctx, server_hostname="bench-server")
                t1 = time.perf_counter()
                w.write(b"p")
                await w.drain()
                await r.readexactly(1)
                times.append((t1 - t0) * 1000)
                w.close()
                await w.wait_closed()
            results[algo] = times
            srv.close()
            await srv.wait_closed()
    return results

async def fmt(name, times):
    return f"  {name}: mean={statistics.mean(times):.2f}ms median={statistics.median(times):.2f}ms min={min(times):.2f}ms p95={sorted(times)[int(len(times)*0.95)]:.2f}ms"

async def main():
    print("=" * 60)
    print("VPNProxy Performance Benchmark (Optimized)")
    print("=" * 60)

    print("\n[1/3] TCP_NODELAY RTT (10 ping-pongs x 50 iters)")
    nd = await bench_nodelay()
    for k, v in nd.items():
        print(await fmt(k, v))
    if nd.get("nodelay_ON") and nd.get("nodelay_OFF"):
        speedup = statistics.mean(nd["nodelay_OFF"]) / max(0.001, statistics.mean(nd["nodelay_ON"]))
        print(f"  >>> TCP_NODELAY speedup: {speedup:.2f}x")

    print(f"\n[2/3] Socket Buffer Throughput (4MB)")
    buf = await bench_buf()
    for k, v in buf.items():
        print(f"  {k}: {v['mbps']} MB/s ({v['sec']}s)")
    if buf["default_buf"]["mbps"] > 0:
        print(f"  >>> Large buffer speedup: {buf['large_buf_256KB']['mbps'] / buf['default_buf']['mbps']:.2f}x")

    print(f"\n[3/3] TLS Handshake (20 iters)")
    try:
        tls = await bench_tls_handshake()
        for algo in ["ecdsa", "rsa"]:
            if algo in tls:
                print(await fmt(algo, tls[algo]))
        if "ecdsa" in tls and "rsa" in tls:
            speedup = statistics.mean(tls["rsa"]) / max(0.001, statistics.mean(tls["ecdsa"]))
            print(f"  >>> ECDSA vs RSA speedup: {speedup:.2f}x")
    except Exception as e:
        print(f"  (skipped: {e})")

    print("\n" + "=" * 60)
    print("Benchmark complete.")

if __name__ == "__main__":
    asyncio.run(main())