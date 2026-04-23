import asyncio, socket, time

async def main():
    # Test 1: TCP_NODELAY RTT
    async def echo(r, w, nd):
        if nd:
            s = w.get_extra_info('socket')
            if s:
                try: s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except: pass
        try:
            while True:
                d = await r.read(65536)
                if not d: break
                w.write(d)
                await w.drain()
        except:
            pass
        try: w.close(); await w.wait_closed()
        except: pass

    times_on = []
    srv = await asyncio.start_server(lambda r, w: echo(r, w, True), '127.0.0.1', 0)
    port = srv.sockets[0].getsockname()[1]
    for i in range(20):
        r, w = await asyncio.open_connection('127.0.0.1', port)
        s = w.get_extra_info('socket')
        if s:
            try: s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except: pass
        t0 = time.perf_counter()
        for _ in range(5):
            w.write(b'x'); await w.drain(); await r.readexactly(1)
        times_on.append((time.perf_counter() - t0) * 1000 / 5)
        w.close(); await w.wait_closed()
    srv.close(); await srv.wait_closed()

    times_off = []
    srv = await asyncio.start_server(lambda r, w: echo(r, w, False), '127.0.0.1', 0)
    port = srv.sockets[0].getsockname()[1]
    for i in range(20):
        r, w = await asyncio.open_connection('127.0.0.1', port)
        t0 = time.perf_counter()
        for _ in range(5):
            w.write(b'x'); await w.drain(); await r.readexactly(1)
        times_off.append((time.perf_counter() - t0) * 1000 / 5)
        w.close(); await w.wait_closed()
    srv.close(); await srv.wait_closed()

    avg_on = sum(times_on) / len(times_on)
    avg_off = sum(times_off) / len(times_off)
    print(f'TCP_NODELAY RTT (5pp x 20iters):')
    print(f'  ON:  {avg_on:.3f}ms avg')
    print(f'  OFF: {avg_off:.3f}ms avg')
    print(f'  Speedup: {avg_off/avg_on:.2f}x')

    # Test 2: Throughput with 128KB buffer
    data = b'x' * (128 * 1024)
    total = 8 * 1024 * 1024

    async def echo_big(r, w):
        try:
            while True:
                d = await r.read(131072)
                if not d: break
                w.write(d)
                await w.drain()
        except:
            pass
        try: w.close(); await w.wait_closed()
        except: pass

    srv = await asyncio.start_server(echo_big, '127.0.0.1', 0)
    port = srv.sockets[0].getsockname()[1]
    r, w = await asyncio.open_connection('127.0.0.1', port)
    sent = 0
    t0 = time.perf_counter()
    while sent < total:
        c = data if sent + len(data) <= total else data[:total - sent]
        w.write(c)
        await w.drain()
        sent += len(c)
    rem = total
    while rem > 0:
        d = await r.read(min(131072, rem))
        if not d: break
        rem -= len(d)
    t1 = time.perf_counter()
    mbps = total / (1024*1024) / (t1 - t0)
    print(f'\nThroughput (128KB buf, 8MB): {mbps:.1f} MB/s ({t1-t0:.3f}s)')
    w.close(); await w.wait_closed()
    srv.close(); await srv.wait_closed()
    print('\nDone.')

asyncio.run(main())