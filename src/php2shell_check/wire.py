"""Minimal raw HTTP transport for the lab chain."""
from __future__ import annotations

import socket
import time
from dataclasses import dataclass


@dataclass
class HttpResponse:
    raw: bytes
    status: int | None
    reason: str
    headers: list[tuple[str, str]]
    body: bytes
    elapsed: float

    def header(self, name: str) -> str | None:
        lname = name.lower()
        for key, value in self.headers:
            if key.lower() == lname:
                return value
        return None


def _parse(raw: bytes, elapsed: float) -> HttpResponse:
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = None
    reason = ""
    if lines and lines[0].startswith(b"HTTP/"):
        parts = lines[0].split(b" ", 2)
        if len(parts) >= 2:
            try:
                status = int(parts[1])
            except ValueError:
                pass
        if len(parts) >= 3:
            reason = parts[2].decode("latin1", "replace")
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        key, sep, value = line.partition(b":")
        if sep:
            headers.append((key.decode("latin1"), value.strip().decode("latin1")))
    return HttpResponse(raw=raw, status=status, reason=reason, headers=headers,
                        body=body, elapsed=elapsed)


def _recv(sock: socket.socket, limit: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < limit:
        try:
            piece = sock.recv(min(65536, limit - len(chunks)))
        except (socket.timeout, OSError):
            break
        if not piece:
            break
        chunks += piece
    return bytes(chunks)


def post_chunked(host: str, port: int, path: str, body: bytes,
                 boundary: bytes = b"C" * 10, timeout: float = 300.0,
                 chunk_size: int = 65536, limit: int = 4 << 20) -> HttpResponse:
    header = (
        "POST %s HTTP/1.1\r\nHost: %s:%d\r\n"
        "Content-Type: multipart/form-data; boundary=%s\r\n"
        "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        % (path, host, port, boundary.decode("latin1"))
    ).encode()
    wire = bytearray(header)
    for i in range(0, len(body), chunk_size):
        piece = body[i:i + chunk_size]
        wire += ("%x\r\n" % len(piece)).encode() + piece + b"\r\n"
    wire += b"0\r\n\r\n"

    started = time.monotonic()
    sock = socket.create_connection((host, port), timeout=15)
    sock.settimeout(timeout)
    try:
        sock.sendall(wire)
        raw = _recv(sock, limit)
    finally:
        sock.close()
    return _parse(raw, time.monotonic() - started)


def post_plain(host: str, port: int, path: str, body: bytes,
               boundary: bytes = b"C" * 10, timeout: float = 300.0,
               limit: int = 2 << 20) -> HttpResponse:
    header = (
        "POST %s HTTP/1.1\r\nHost: %s:%d\r\n"
        "Content-Type: multipart/form-data; boundary=%s\r\n"
        "Content-Length: %d\r\nConnection: close\r\n\r\n"
        % (path, host, port, boundary.decode("latin1"), len(body))
    ).encode()
    started = time.monotonic()
    sock = socket.create_connection((host, port), timeout=15)
    sock.settimeout(timeout)
    try:
        sock.sendall(header + body)
        raw = _recv(sock, limit)
    finally:
        sock.close()
    return _parse(raw, time.monotonic() - started)


def get(host: str, port: int, path: str, timeout: float = 15.0,
        limit: int = 1 << 20) -> HttpResponse:
    request = ("GET %s HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n"
               % (path, host, port)).encode()
    started = time.monotonic()
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        sock.sendall(request)
        raw = _recv(sock, limit)
    finally:
        sock.close()
    return _parse(raw, time.monotonic() - started)
