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

    def is_closing(self) -> bool:
        return self.closed

    def write_eof(self) -> None:
        pass

    async def wait_closed(self) -> None:
        return None

    def get_extra_info(self, name: str, default=None):
        return default


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


class Socks5AuthTests(unittest.IsolatedAsyncioTestCase):
    async def test_socks5_auth_success(self):
        reader = asyncio.StreamReader()
        writer = MemoryWriter()
        user, pwd = "longeek", "Mengql123"
        ulen = len(user)
        plen = len(pwd)
        auth_payload = bytes([0x01, ulen]) + user.encode() + bytes([plen]) + pwd.encode()
        connect_payload = (
            b"\x05\x01\x00\x01"
            + b"\x7f\x00\x00\x01"
            + b"\x00\x50"
        )
        reader.feed_data(b"\x05\x02\x00\x02" + auth_payload + connect_payload)
        reader.feed_eof()
        host, port, cmd = await client.socks5_handshake(reader, writer, proxy_user=user, proxy_pass=pwd)
        self.assertEqual(host, "127.0.0.1")
        self.assertEqual(port, 80)
        self.assertEqual(cmd, 0x01)
        self.assertIn(b"\x05\x02", bytes(writer.buf))
        self.assertIn(b"\x01\x00", bytes(writer.buf))

    async def test_socks5_auth_wrong_password(self):
        reader = asyncio.StreamReader()
        writer = MemoryWriter()
        user, pwd = "longeek", "wrong"
        ulen = len(user)
        plen = len(pwd)
        auth_payload = bytes([0x01, ulen]) + user.encode() + bytes([plen]) + pwd.encode()
        reader.feed_data(b"\x05\x02\x00\x02" + auth_payload)
        reader.feed_eof()
        with self.assertRaises(client.SocksProtocolError):
            await client.socks5_handshake(reader, writer, proxy_user="longeek", proxy_pass="Mengql123")

    async def test_socks5_auth_no_method_offered(self):
        reader = asyncio.StreamReader()
        writer = MemoryWriter()
        reader.feed_data(b"\x05\x01\x00")
        reader.feed_eof()
        with self.assertRaises(client.SocksProtocolError):
            await client.socks5_handshake(reader, writer, proxy_user="longeek", proxy_pass="Mengql123")

    async def test_socks5_no_auth_when_no_credentials(self):
        reader = asyncio.StreamReader()
        writer = MemoryWriter()
        payload = b"\x05\x01\x00" + b"\x05\x01\x00\x01" + b"\x7f\x00\x00\x01" + b"\x01\xbb"
        reader.feed_data(payload)
        reader.feed_eof()
        host, port, cmd = await client.socks5_handshake(reader, writer)
        self.assertEqual(host, "127.0.0.1")
        self.assertEqual(port, 443)
        self.assertEqual(cmd, 0x01)


class HttpProxyAuthTests(unittest.IsolatedAsyncioTestCase):
    async def test_http_proxy_auth_required_response(self):
        reader = asyncio.StreamReader()
        writer = MemoryWriter()
        args = argparse.Namespace(
            server="127.0.0.1", server_port=8443, token="tok",
            ca_cert=None, insecure=True, sni=None,
            connect_retries=0, retry_delay=0.01,
            pool_size=0, pool_ttl=8.0,
            proxy_user="longeek", proxy_pass="Mengql123",
        )
        request = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
        reader.feed_data(request)
        reader.feed_eof()
        with mock.patch("client.open_tunnel", side_effect=Exception("should not call")):
            await client.handle_http_client(reader, writer, args)
        response = bytes(writer.buf)
        self.assertIn(b"407", response)
        self.assertIn(b"Proxy-Authenticate", response)


class ClientPipeDrainTests(unittest.IsolatedAsyncioTestCase):
    async def test_pipe_does_not_drain_for_small_transfer(self):
        reader = asyncio.StreamReader()
        writer = MemoryWriter()

        reader.feed_data(b"a" * 32768)
        reader.feed_data(b"b" * 32768)
        reader.feed_data(b"c" * 32768)  # 3 * 32KiB = 96KiB < 128KiB threshold
        reader.feed_eof()

        await client.pipe(reader, writer)
        self.assertEqual(writer.drain_calls, 0)

    async def test_pipe_drains_periodically_for_large_transfer(self):
        reader = asyncio.StreamReader()
        writer = MemoryWriter()

        for _ in range(8):  # 8 * 64KiB = 512KiB => should trigger drain
            reader.feed_data(b"x" * 65536)
        reader.feed_eof()

        await client.pipe(reader, writer)
        self.assertGreaterEqual(writer.drain_calls, 1)
