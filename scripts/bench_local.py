import asyncio, socket, time, statistics

async def bench():
    print('=== TCP_NODELAY RTT (10 pp x 30 iters) ===')
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
                w.write(d); await w.drain()
        except: pass
        try: w.close(); await w.wait_closed()
        except: pass

    results_nd = {}
    for label, nd in [('NODELAY_ON', True), ('NODELAY_OFF', False)]:
        srv = await asyncio.start_server(lambda r, w: echo(r, w, nd), '127.0.0.1', 0)
        port = srv.sockets[0].getsockname()[1]
        times = []
        for _ in range(30):
            r, w = await asyncio.open_connection('127.0.0.1', port)
            if nd:
                s = w.get_extra_info('socket')
                if s:
                    try: s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    except: pass
            t0 = time.perf_counter()
            for _ in range(10):
                w.write(b'x'); await w.drain(); await r.readexactly(1)
            times.append((time.perf_counter() - t0) * 100)
            w.close(); await w.wait_closed()
        results_nd[label] = times
        srv.close(); await srv.wait_closed()
        m = statistics.mean(times)
        med = statistics.median(times)
        print(f'  {label}: mean={m:.2f}ms median={med:.2f}ms min={min(times):.2f}ms p95={sorted(times)[int(len(times)*0.95)]:.2f}ms')
    if results_nd.get('NODELAY_ON') and results_nd.get('NODELAY_OFF'):
        s = statistics.mean(results_nd['NODELAY_OFF']) / max(0.001, statistics.mean(results_nd['NODELAY_ON']))
        print(f'  >>> TCP_NODELAY speedup: {s:.2f}x')

    print()
    print('=== Socket Buffer Throughput (4MB) ===')
    for label, bs in [('default', 0), ('256KB', 256*1024)]:
        async def te(r, w):
            if bs > 0:
                s = w.get_extra_info('socket')
                if s:
                    try:
                        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, bs)
                        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, bs)
                    except: pass
            try:
                while True:
                    d = await r.read(131072)
                    if not d: break
                    w.write(d); await w.drain()
            except: pass
            try: w.close(); await w.wait_closed()
            except: pass
        srv = await asyncio.start_server(lambda r, w: te(r, w), '127.0.0.1', 0)
        port = srv.sockets[0].getsockname()[1]
        r, w = await asyncio.open_connection('127.0.0.1', port)
        if bs > 0:
            s = w.get_extra_info('socket')
            if s:
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, bs)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, bs)
                except: pass
        data = b'x' * (64 * 1024)
        total = 4 * 1024 * 1024
        sent = 0
        t0 = time.perf_counter()
        while sent < total:
            c = data if sent + len(data) <= total else data[:total - sent]
            w.write(c); await w.drain(); sent += len(c)
        rem = total
        while rem > 0:
            d = await r.read(min(131072, rem))
            if not d: break
            rem -= len(d)
        t1 = time.perf_counter()
        mbps = total / (1024*1024) / (t1-t0)
        print(f'  {label}: {mbps:.1f} MB/s ({t1-t0:.3f}s)')
        w.close(); await w.wait_closed()
        srv.close(); await srv.wait_closed()

    print()
    print('Done.')

asyncio.run(bench())