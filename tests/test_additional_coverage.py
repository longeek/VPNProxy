import argparse
import asyncio
import ssl
import unittest
from unittest import mock

import client
import server


class FakeWriter:
    def __init__(self, peer=("127.0.0.1", 12345)):
        self.buf = bytearray()
        self.closed = False
        self.peer = peer

    def write(self, data: bytes):
        self.buf.extend(data)

    async def drain(self):
        return None

    def close(self):
        self.closed = True

    def is_closing(self):
        return self.closed

    def write_eof(self):
        pass

    async def wait_closed(self):
        return None

    def get_extra_info(self, name: str):
        if name == "peername":
            return self.peer
        return None


class FakeReader:
    def __init__(self, lines=None, chunks=None):
        self._lines = list(lines or [])
        self._chunks = list(chunks or [])

    async def readline(self):
        if self._lines:
            return self._lines.pop(0)
        return b""

    async def read(self, _size: int):
        if self._chunks:
            return self._chunks.pop(0)
        return b""

    async def readexactly(self, size: int):
        if not self._chunks:
            raise asyncio.IncompleteReadError(partial=b"", expected=size)
        data = self._chunks.pop(0)
        if len(data) < size:
            raise asyncio.IncompleteReadError(partial=data, expected=size)
        return data[:size]


class FakeSocket:
    def __init__(self, host="127.0.0.1", port=9999):
        self._host = host
        self._port = port

    def getsockname(self):
        return (self._host, self._port)


class FakeServer:
    def __init__(self):
        self.sockets = [FakeSocket()]

    def close(self) -> None:
        pass

    async def wait_closed(self) -> None:
        return None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def serve_forever(self):
        raise RuntimeError("stop loop")


class ServerFlowCoverageTests(unittest.IsolatedAsyncioTestCase):
    async def test_server_pipe_counts_upload_and_closes(self):
        stats = server.SessionStats()
        reader = FakeReader(chunks=[b"abc", b"de", b""])
        writer = FakeWriter()
        await server.pipe(reader, writer, stats, True)
        self.assertEqual(stats.upload_bytes, 5)
        self.assertEqual(stats.download_bytes, 0)
        self.assertTrue(writer.closed)

    async def test_handle_client_auth_fail(self):
        reader = FakeReader(lines=[b'{"auth":"bad","host":"x.com","port":443}\n'])
        writer = FakeWriter()
        await server.handle_client(reader, writer, {"good"}, [], 1.0)
        self.assertIn(b"ERR auth\n", bytes(writer.buf))

    async def test_handle_client_connect_fail(self):
        reader = FakeReader(lines=[b'{"auth":"good","host":"x.com","port":443}\n'])
        writer = FakeWriter()
        with mock.patch(
            "server.asyncio.open_connection",
            side_effect=ConnectionError("down"),
        ):
            await server.handle_client(reader, writer, {"good"}, [], 1.0)
        self.assertIn(b"ERR connect\n", bytes(writer.buf))

    async def test_handle_client_cidr_reject(self):
        reader = FakeReader(lines=[b'{"auth":"good","host":"x.com","port":443}\n'])
        writer = FakeWriter(peer=("10.1.2.3", 4567))
        allow = [server.ipaddress.ip_network("127.0.0.1/32")]
        await server.handle_client(reader, writer, {"good"}, allow, 1.0)
        self.assertIn(b"ERR connect\n", bytes(writer.buf))

    async def test_handle_client_success_path(self):
        reader = FakeReader(lines=[b'{"auth":"good","host":"x.com","port":443}\n'])
        writer = FakeWriter()
        target_reader = FakeReader()
        target_writer = FakeWriter()

        with mock.patch(
            "server.asyncio.open_connection",
            new=mock.AsyncMock(return_value=(target_reader, target_writer)),
        ):
            with mock.patch("server.pipe", new=mock.AsyncMock()):
                await server.handle_client(reader, writer, {"good"}, [], 1.0)
        self.assertIn(b"OK\n", bytes(writer.buf))


class ServerMainCoverageTests(unittest.IsolatedAsyncioTestCase):
    async def test_main_async_requires_token(self):
        args = argparse.Namespace(
            token=None,
            tokens_file=None,
            allow_cidrs="",
            cert="cert.pem",
            key="key.pem",
            listen="0.0.0.0",
            port=8443,
            connect_timeout=1.0,
            log_level="INFO",
        )
        with self.assertRaises(SystemExit):
            await server.main_async(args)

    async def test_main_async_starts_server(self):
        args = argparse.Namespace(
            token="tok",
            tokens_file=None,
            allow_cidrs="127.0.0.1/32",
            cert="cert.pem",
            key="key.pem",
            listen="0.0.0.0",
            port=8443,
            connect_timeout=1.0,
            bootstrap_timeout=30.0,
            backlog=512,
            log_level="INFO",
        )
        ssl_ctx = mock.Mock(spec=ssl.SSLContext)
        fake_server = FakeServer()
        with mock.patch("server.ssl.create_default_context", return_value=ssl_ctx):
            with mock.patch.object(ssl_ctx, "load_cert_chain") as load_cert_chain:
                with mock.patch(
                    "server.asyncio.start_server",
                    new=mock.AsyncMock(return_value=fake_server),
                ):
                    with self.assertRaises(RuntimeError):
                        await server.main_async(args)
        load_cert_chain.assert_called_once_with(certfile="cert.pem", keyfile="key.pem")

    def test_server_build_arg_parser_defaults(self):
        parser = server.build_arg_parser()
        args = parser.parse_args([])
        self.assertEqual(args.listen, "0.0.0.0")
        self.assertEqual(args.port, 8443)

    def test_server_main_invokes_asyncio_run(self):
        parser = server.build_arg_parser()

        def fake_run(coro):
            coro.close()

        with mock.patch("server.build_arg_parser", return_value=parser):
            with mock.patch("sys.argv", ["server.py", "--token", "tok"]):
                with mock.patch("server.asyncio.run", side_effect=fake_run) as run_mock:
                    server.main()
        run_mock.assert_called_once()

    def test_parse_allow_cidrs_empty(self):
        self.assertEqual(server.parse_allow_cidrs(""), [])

    def test_peer_allowed_invalid_peer(self):
        allow = [server.ipaddress.ip_network("127.0.0.1/32")]
        self.assertFalse(server.peer_allowed("bad", allow))


class ClientFlowCoverageTests(unittest.IsolatedAsyncioTestCase):
    async def test_client_pipe_download_branch(self):
        writer = FakeWriter()
        reader = FakeReader(chunks=[b"1", b"2", b""])
        await client.pipe(reader, writer)
        self.assertEqual(bytes(writer.buf), b"12")
        self.assertTrue(writer.closed)

    async def test_read_exact(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b"abcd")
        out = await client.read_exact(reader, 4)
        self.assertEqual(out, b"abcd")

    async def test_socks5_handshake_ipv4(self):
        reader = asyncio.StreamReader()
        writer = FakeWriter()
        payload = b"\x05\x01\x00" + b"\x05\x01\x00\x01" + b"\x7f\x00\x00\x01" + b"\x1f\x90"
        reader.feed_data(payload)
        reader.feed_eof()
        host, port, cmd = await client.socks5_handshake(reader, writer)
        self.assertEqual(host, "127.0.0.1")
        self.assertEqual(port, 8080)
        self.assertEqual(cmd, 0x01)

    async def test_socks5_handshake_bad_version(self):
        reader = asyncio.StreamReader()
        writer = FakeWriter()
        reader.feed_data(b"\x04\x01\x00")
        reader.feed_eof()
        with self.assertRaises(ValueError):
            await client.socks5_handshake(reader, writer)

    async def test_socks5_handshake_bad_atyp(self):
        reader = asyncio.StreamReader()
        writer = FakeWriter()
        reader.feed_data(b"\x05\x01\x00" + b"\x05\x01\x00\x09")
        reader.feed_eof()
        with self.assertRaises(ValueError):
            await client.socks5_handshake(reader, writer)

    async def test_open_tunnel_refused_status(self):
        args = argparse.Namespace(
            server="127.0.0.1",
            server_port=8443,
            token="tok",
            ca_cert=None,
            insecure=True,
            sni=None,
            connect_retries=0,
            retry_delay=0.01,
            pool_size=0,
            pool_ttl=8.0,
        )
        reader = FakeReader(lines=[b"ERR auth\n"])
        writer = FakeWriter()
        with mock.patch(
            "client.asyncio.open_connection",
            new=mock.AsyncMock(return_value=(reader, writer)),
        ):
            with self.assertRaises(ConnectionError):
                await client.open_tunnel("example.com", 443, args, "sid-3")

    async def test_handle_socks_client_failure_reply(self):
        args = argparse.Namespace(
            server="127.0.0.1",
            server_port=8443,
            token="tok",
            ca_cert=None,
            insecure=True,
            sni=None,
            connect_retries=0,
            retry_delay=0.01,
            pool_size=0,
            pool_ttl=8.0,
        )
        reader = FakeReader()
        writer = FakeWriter()
        with mock.patch(
            "client.socks5_handshake",
            side_effect=client.SocksProtocolError("bad req", 0x08),
        ):
            await client.handle_socks_client(reader, writer, args)
        self.assertIn(b"\x05\x08", bytes(writer.buf))
        self.assertTrue(writer.closed)

    async def test_handle_socks_client_success_path(self):
        args = argparse.Namespace(
            server="127.0.0.1",
            server_port=8443,
            token="tok",
            ca_cert=None,
            insecure=True,
            sni=None,
            connect_retries=0,
            retry_delay=0.01,
            pool_size=0,
            pool_ttl=8.0,
        )
        reader = FakeReader()
        writer = FakeWriter()
        t_reader = FakeReader()
        t_writer = FakeWriter()
        with mock.patch(
            "client.socks5_handshake",
            new=mock.AsyncMock(return_value=("x.com", 443, 0x01)),
        ):
            with mock.patch("client.open_tunnel", new=mock.AsyncMock(return_value=(t_reader, t_writer))):
                with mock.patch("client.send_socks_reply", new=mock.AsyncMock()) as reply_mock:
                    with mock.patch("client.pipe", new=mock.AsyncMock()):
                        await client.handle_socks_client(reader, writer, args)
        reply_mock.assert_awaited_once_with(writer, 0x00)


class ClientMainCoverageTests(unittest.IsolatedAsyncioTestCase):
    async def test_client_main_async_requires_server(self):
        args = argparse.Namespace(
            listen="127.0.0.1",
            listen_port=1080,
            server=None,
            token="tok",
            log_level="INFO",
        )
        with self.assertRaises(SystemExit):
            await client.main_async(args)

    async def test_client_main_async_requires_token(self):
        args = argparse.Namespace(
            listen="127.0.0.1",
            listen_port=1080,
            server="127.0.0.1",
            token=None,
            log_level="INFO",
        )
        with self.assertRaises(SystemExit):
            await client.main_async(args)

    async def test_client_main_async_starts_server(self):
        args = argparse.Namespace(
            listen="127.0.0.1",
            listen_port=1080,
            server="127.0.0.1",
            server_port=8443,
            token="tok",
            ca_cert=None,
            insecure=True,
            sni=None,
            connect_retries=0,
            retry_delay=0.01,
            pool_size=0,
            pool_ttl=8.0,
            proxy_user=None,
            proxy_pass=None,
            log_level="INFO",
        )
        fake_server = FakeServer()
        with mock.patch(
            "client.asyncio.start_server",
            new=mock.AsyncMock(return_value=fake_server),
        ):
            with self.assertRaises(RuntimeError):
                await client.main_async(args)

    def test_client_build_arg_parser_defaults(self):
        parser = client.build_arg_parser()
        args = parser.parse_args([])
        self.assertEqual(args.listen, "127.0.0.1")
        self.assertEqual(args.listen_port, 1080)

    def test_client_main_invokes_asyncio_run(self):
        parser = client.build_arg_parser()

        def fake_run(coro):
            coro.close()

        with mock.patch("client.build_arg_parser", return_value=parser):
            with mock.patch(
                "sys.argv",
                ["client.py", "--server", "127.0.0.1", "--token", "tok"],
            ):
                with mock.patch("client.asyncio.run", side_effect=fake_run) as run_mock:
                    client.main()
        run_mock.assert_called_once()

    def test_build_tls_context_default(self):
        ctx = client.build_tls_context(None, False)
        self.assertIsInstance(ctx, ssl.SSLContext)

    def test_build_tls_context_with_cafile(self):
        with mock.patch("client.ssl.create_default_context") as ctx_builder:
            ctx_builder.return_value = mock.Mock(spec=ssl.SSLContext)
            _ctx = client.build_tls_context("ca.pem", False)
        ctx_builder.assert_called_once_with(cafile="ca.pem")
