import argparse
import asyncio
import unittest
from unittest import mock

import client
import server


class IntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self._servers = []

    async def asyncTearDown(self):
        for s in self._servers:
            s.close()
            await s.wait_closed()

    async def _start_server(self, cb):
        srv = await asyncio.start_server(cb, host="127.0.0.1", port=0)
        self._servers.append(srv)
        return srv

    async def test_end_to_end_socks_to_proxy_chain(self):
        async def echo_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            data = await reader.read(4096)
            writer.write(b"echo:" + data)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        target_server = await self._start_server(echo_handler)
        target_port = target_server.sockets[0].getsockname()[1]

        proxy_server = await self._start_server(
            lambda r, w: server.handle_client(r, w, {"tkn"}, [], 3.0)
        )
        proxy_port = proxy_server.sockets[0].getsockname()[1]

        args = argparse.Namespace(
            server="127.0.0.1",
            server_port=proxy_port,
            token="tkn",
            ca_cert=None,
            insecure=True,
            sni=None,
            connect_retries=0,
            retry_delay=0.01,
        )

        socks_server = await self._start_server(
            lambda r, w: client.handle_socks_client(r, w, args)
        )
        socks_port = socks_server.sockets[0].getsockname()[1]

        # Integration uses plaintext transport to simplify test runtime:
        # replace TLS context builder with None so asyncio uses plain TCP.
        with mock.patch("client.build_tls_context", return_value=None):
            r, w = await asyncio.open_connection("127.0.0.1", socks_port)

            w.write(b"\x05\x01\x00")
            await w.drain()
            greet_resp = await r.readexactly(2)
            self.assertEqual(greet_resp, b"\x05\x00")

            request = (
                b"\x05\x01\x00\x01"
                + b"\x7f\x00\x00\x01"
                + target_port.to_bytes(2, "big")
            )
            w.write(request)
            await w.drain()
            connect_resp = await r.readexactly(10)
            self.assertEqual(connect_resp[:2], b"\x05\x00")

            payload = b"hello-through-proxy"
            w.write(payload)
            await w.drain()
            echoed = await r.read(len(b"echo:") + len(payload))
            self.assertEqual(echoed, b"echo:" + payload)

            w.close()
            await w.wait_closed()
