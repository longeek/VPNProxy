import argparse
import asyncio
import ssl
import unittest
from unittest import mock

import client


class MemoryWriter:
    def __init__(self):
        self.buf = bytearray()
        self.closed = False
        self.drain_calls = 0

    def write(self, data: bytes) -> None:
        self.buf.extend(data)

    async def drain(self) -> None:
        self.drain_calls += 1
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


class DummyReader:
    def __init__(self, lines):
        self._lines = list(lines)

    async def readline(self):
        if self._lines:
            return self._lines.pop(0)
        return b""


class ClientHelpersTests(unittest.IsolatedAsyncioTestCase):
    async def test_socks5_handshake_domain(self):
        reader = asyncio.StreamReader()
        writer = MemoryWriter()

        payload = (
            b"\x05\x01\x00"  # greeting
            b"\x05\x01\x00\x03"  # connect + domain
            b"\x0bexample.com"  # domain len + name
            b"\x01\xbb"  # 443
        )
        reader.feed_data(payload)
        reader.feed_eof()

        host, port, cmd = await client.socks5_handshake(reader, writer)
        self.assertEqual(host, "example.com")
        self.assertEqual(port, 443)
        self.assertEqual(cmd, 0x01)
        self.assertEqual(writer.buf, b"\x05\x00")

    async def test_socks5_handshake_unsupported_command(self):
        reader = asyncio.StreamReader()
        writer = MemoryWriter()
        payload = b"\x05\x01\x00" + b"\x05\x02\x00\x01" + b"\x7f\x00\x00\x01" + b"\x00\x50"
        reader.feed_data(payload)
        reader.feed_eof()
        with self.assertRaises(client.SocksProtocolError):
            await client.socks5_handshake(reader, writer)

    async def test_send_socks_reply(self):
        writer = MemoryWriter()
        await client.send_socks_reply(writer, 0x00)
        self.assertEqual(
            bytes(writer.buf),
            b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00",
        )


class ClientOpenTunnelTests(unittest.IsolatedAsyncioTestCase):
    async def test_open_tunnel_retries_then_success(self):
        args = argparse.Namespace(
            server="127.0.0.1",
            server_port=8443,
            token="tok",
            ca_cert=None,
            insecure=True,
            sni=None,
            connect_retries=2,
            retry_delay=0.01,
        )

        writer = MemoryWriter()
        reader = DummyReader([b"OK\n"])

        attempts = {"n": 0}

        async def fake_open_connection(**kwargs):
            attempts["n"] += 1
            if attempts["n"] < 2:
                raise ConnectionError("boom")
            return reader, writer

        with mock.patch("client.asyncio.open_connection", side_effect=fake_open_connection):
            with mock.patch("client.asyncio.sleep", new=mock.AsyncMock()):
                got_reader, got_writer = await client.open_tunnel(
                    "example.com", 443, args, "sid-1"
                )
                self.assertIs(got_reader, reader)
                self.assertIs(got_writer, writer)
                self.assertGreaterEqual(attempts["n"], 2)

    async def test_open_tunnel_fails_after_retries(self):
        args = argparse.Namespace(
            server="127.0.0.1",
            server_port=8443,
            token="tok",
            ca_cert=None,
            insecure=True,
            sni=None,
            connect_retries=1,
            retry_delay=0.01,
        )
        with mock.patch(
            "client.asyncio.open_connection",
            side_effect=ConnectionError("always down"),
        ):
            with mock.patch("client.asyncio.sleep", new=mock.AsyncMock()):
                with self.assertRaises(ConnectionError):
                    await client.open_tunnel("example.com", 443, args, "sid-2")


class ClientTlsContextTests(unittest.TestCase):
    def test_build_tls_context_insecure(self):
        ctx = client.build_tls_context(None, True)
        self.assertIsInstance(ctx, ssl.SSLContext)
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)


class ClientPipeDrainTests(unittest.IsolatedAsyncioTestCase):
    async def test_pipe_does_not_drain_for_small_transfer(self):
        reader = asyncio.StreamReader()
        writer = MemoryWriter()

        reader.feed_data(b"a" * 65536)
        reader.feed_data(b"b" * 65536)
        reader.feed_data(b"c" * 65536)  # 3 * 64KiB = 192KiB < 256KiB threshold
        reader.feed_eof()

        await client.pipe(reader, writer)
        self.assertEqual(writer.drain_calls, 0)

    async def test_pipe_drains_periodically_for_large_transfer(self):
        reader = asyncio.StreamReader()
        writer = MemoryWriter()

        for _ in range(5):  # 5 * 64KiB = 320KiB => should trigger at least one drain
            reader.feed_data(b"x" * 65536)
        reader.feed_eof()

        await client.pipe(reader, writer)
        self.assertGreaterEqual(writer.drain_calls, 1)
