#!/usr/bin/env python3
"""Server-side TCP connection pool for backend connection reuse.

Provides a FIFO pool of asyncio TCP connections to a target (host, port).
Designed for reusing backend connections across multiple client requests
in an async proxy server, reducing TCP handshake overhead.

Architecture:
  - FIFO semantics: get() pops from the front, put() appends to the back
  - Connections idle longer than idle_timeout are discarded on get()
  - Thread-safe via asyncio.Lock for use from concurrent async tasks
  - Configurable max_size and idle_timeout
"""

import asyncio
import logging
import ssl
import time
from dataclasses import dataclass, field
from typing import Optional, Tuple

_LOG = logging.getLogger(__name__)


@dataclass
class _PoolEntry:
    """Internal pool entry wrapping a TCP connection with its creation time."""

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    created: float = field(default_factory=time.monotonic)


class ServerConnPool:
    """FIFO connection pool for reusing backend TCP connections.

    Manages a pool of ``asyncio.open_connection()`` streams to a fixed
    target (host, port). Connections are reused across multiple calls to
    :meth:`get` / :meth:`put`, reducing TCP handshake overhead.

    Thread-safe via :class:`asyncio.Lock` for concurrent async usage.
    """

    def __init__(
        self,
        host: str,
        port: int,
        max_size: int = 10,
        idle_timeout: float = 30.0,
        ssl_context: Optional[ssl.SSLContext] = None,
    ) -> None:
        self._host = host
        self._port = port
        self._max_size = max_size
        self._idle_timeout = idle_timeout
        self._ssl_context = ssl_context

        self._lock = asyncio.Lock()
        self._entries: list[_PoolEntry] = []
        self._closed = False

    @property
    def max_size(self) -> int:
        """Return the maximum number of connections the pool can hold."""
        return self._max_size

    @property
    def size(self) -> int:
        """Return the current number of idle connections in the pool."""
        return len(self._entries)

    async def get(self) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Obtain a connection from the pool or create a new one.

        Returns a (reader, writer) tuple from an existing idle connection
        if one is available and not expired. Otherwise creates a fresh
        connection via :func:`asyncio.open_connection`.

        Expired connections (idle longer than *idle_timeout*) are silently
        closed and skipped.
        """
        async with self._lock:
            if self._closed:
                raise RuntimeError("pool is closed")

            now = time.monotonic()
            # Scan from front (FIFO) until we find a live, non-expired entry
            while self._entries:
                entry = self._entries.pop(0)
                age = now - entry.created
                if age >= self._idle_timeout or entry.writer.is_closing():
                    _LOG.debug("discarding stale connection (age=%.2fs)", age)
                    await self._close_writer(entry.writer)
                    continue
                _LOG.debug("reused pooled connection (age=%.2fs)", age)
                return entry.reader, entry.writer

        # Pool empty or all entries expired: create a fresh connection
        reader, writer = await asyncio.open_connection(
            self._host, self._port, ssl=self._ssl_context,
        )
        return reader, writer

    async def put(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Return a connection to the pool for future reuse.

        If the pool is not full and the connection is still alive, it is
        appended to the back of the FIFO queue. Otherwise the connection
        is closed immediately.

        It is safe to call this method after :meth:`close`; the connection
        will simply be closed.
        """
        async with self._lock:
            if self._closed:
                await self._close_writer(writer)
                return

            if writer.is_closing():
                _LOG.debug("returned connection is closing, discarding")
                await self._close_writer(writer)
                return

            if len(self._entries) >= self._max_size:
                _LOG.debug("pool full (%d/%d), closing returned connection",
                           len(self._entries), self._max_size)
                await self._close_writer(writer)
                return

            # Append to back (FIFO)
            self._entries.append(_PoolEntry(reader=reader, writer=writer))
            _LOG.debug("returned connection to pool (%d/%d)",
                       len(self._entries), self._max_size)

    async def close(self) -> None:
        """Close all pooled connections and mark the pool as shut down.

        Safe to call multiple times. Once closed, :meth:`get` will raise
        :exc:`RuntimeError` and :meth:`put` will close returned connections.
        """
        async with self._lock:
            if self._closed:
                return
            self._closed = True
            entries = self._entries
            self._entries = []

        for entry in entries:
            await self._close_writer(entry.writer)

    async def _close_writer(self, writer: asyncio.StreamWriter) -> None:
        """Safely close a stream writer, ignoring errors."""
        try:
            if not writer.is_closing():
                writer.close()
                await writer.wait_closed()
        except (ConnectionError, OSError, RuntimeError):
            pass


def create_backend_pool(host: str, port: int, **kwargs) -> ServerConnPool:
    """Create a :class:`ServerConnPool` for the given backend target.

    Parameters
    ----------
    host : str
        Backend server hostname or IP.
    port : int
        Backend server port.
    **kwargs
        Additional arguments forwarded to :class:`ServerConnPool`
        (e.g. *max_size*, *idle_timeout*, *ssl_context*).

    Returns
    -------
    ServerConnPool
        A new connection pool instance.
    """
    return ServerConnPool(host, port, **kwargs)
