import argparse
import asyncio
import ipaddress
import tempfile
import unittest
from pathlib import Path

import server


class ServerParsingTests(unittest.TestCase):
    def test_parse_bootstrap_valid(self):
        host, port, proto = server.parse_bootstrap_line(
            b'{"auth":"t1","host":"example.com","port":443}\n',
            {"t1"},
        )
        self.assertEqual(host, "example.com")
        self.assertEqual(port, 443)
        self.assertEqual(proto, "tcp")

    def test_parse_bootstrap_udp_wildcard(self):
        host, port, proto = server.parse_bootstrap_line(
            b'{"auth":"t1","host":"0.0.0.0","port":0,"proto":"udp"}\n',
            {"t1"},
        )
        self.assertEqual((host, port, proto), ("0.0.0.0", 0, "udp"))

    def test_parse_bootstrap_bad_proto(self):
        with self.assertRaises(ValueError):
            server.parse_bootstrap_line(
                b'{"auth":"t1","host":"example.com","port":443,"proto":"quic"}\n',
                {"t1"},
            )

    def test_parse_bootstrap_bad_auth(self):
        with self.assertRaises(server.AuthError):
            server.parse_bootstrap_line(
                b'{"auth":"bad","host":"example.com","port":443}\n',
                {"t1"},
            )

    def test_parse_bootstrap_invalid_payload(self):
        with self.assertRaises(ValueError):
            server.parse_bootstrap_line(b'{"auth":"t1","host":"","port":0}\n', {"t1"})

    def test_parse_bootstrap_invalid_json(self):
        with self.assertRaises(ValueError):
            server.parse_bootstrap_line(b"not-json\n", {"t1"})


class ServerConfigTests(unittest.TestCase):
    def test_load_allowed_tokens_from_file_and_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            token_file = Path(tmp) / "tokens.txt"
            token_file.write_text("# comment\nalpha\n\nbeta\n", encoding="utf-8")
            args = argparse.Namespace(token="admin", tokens_file=str(token_file))
            tokens = server.load_allowed_tokens(args)
            self.assertSetEqual(tokens, {"admin", "alpha", "beta"})

    def test_parse_allow_cidrs(self):
        networks = server.parse_allow_cidrs("127.0.0.1/32,10.0.0.0/8")
        self.assertEqual(len(networks), 2)
        self.assertIn(ipaddress.ip_address("127.0.0.1"), networks[0])

    def test_peer_allowed(self):
        networks = [ipaddress.ip_network("127.0.0.1/32")]
        self.assertTrue(server.peer_allowed(("127.0.0.1", 10000), networks))
        self.assertFalse(server.peer_allowed(("10.10.10.10", 10000), networks))
        self.assertTrue(server.peer_allowed(("10.10.10.10", 10000), []))


class ServerPipeDrainTests(unittest.IsolatedAsyncioTestCase):
    async def test_pipe_does_not_drain_for_small_transfer(self):
        reader = asyncio.StreamReader()

        class CountingWriter:
            def __init__(self):
                self.drain_calls = 0
                self.closed = False

            def write(self, _data: bytes) -> None:
                return None

            async def drain(self) -> None:
                self.drain_calls += 1

            def close(self) -> None:
                self.closed = True

            def is_closing(self) -> bool:
                return self.closed

            def write_eof(self) -> None:
                pass

        writer = CountingWriter()
        stats = server.SessionStats()

        reader.feed_data(b"a" * 32768)
        reader.feed_data(b"b" * 32768)
        reader.feed_data(b"c" * 32768)
        reader.feed_eof()

        await server.pipe(reader, writer, stats, True)
        self.assertEqual(writer.drain_calls, 0)
        self.assertEqual(stats.upload_bytes, 3 * 32768)

    async def test_pipe_drains_periodically_for_large_transfer(self):
        reader = asyncio.StreamReader()

        class CountingWriter:
            def __init__(self):
                self.drain_calls = 0

            def write(self, _data: bytes) -> None:
                return None

            async def drain(self) -> None:
                self.drain_calls += 1

            def close(self) -> None:
                return None

            def is_closing(self) -> bool:
                return False

            def write_eof(self) -> None:
                pass

        writer = CountingWriter()
        stats = server.SessionStats()

        for _ in range(8):
            reader.feed_data(b"x" * 65536)
        reader.feed_eof()

        await server.pipe(reader, writer, stats, False)
        self.assertGreaterEqual(writer.drain_calls, 1)
        self.assertEqual(stats.download_bytes, 8 * 65536)
