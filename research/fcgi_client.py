"""Minimal FastCGI client (lab only).

Sends one responder request with explicit params and an optional body, then
collects STDOUT/STDERR until END_REQUEST. No third-party dependencies.
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

FCGI_BEGIN_REQUEST = 1
FCGI_ABORT_REQUEST = 2
FCGI_END_REQUEST = 3
FCGI_PARAMS = 4
FCGI_STDIN = 5
FCGI_STDOUT = 6
FCGI_STDERR = 7
FCGI_RESPONDER = 1

VERSION = 1


def _record(kind: int, request_id: int, content: bytes) -> bytes:
    padding = (8 - (len(content) % 8)) % 8
    return (struct.pack("!BBHHBB", VERSION, kind, request_id, len(content), padding, 0)
            + content + b"\x00" * padding)


def _length(n: int) -> bytes:
    if n < 128:
        return struct.pack("!B", n)
    return struct.pack("!I", n | 0x80000000)


def _nv(name: bytes, value: bytes) -> bytes:
    return _length(len(name)) + _length(len(value)) + name + value


@dataclass
class FastCgiResponse:
    stdout: bytes
    stderr: bytes
    app_status: int
    protocol_status: int

    @property
    def status(self) -> int | None:
        head = self.stdout.split(b"\r\n\r\n", 1)[0].splitlines()
        for line in head:
            if line.lower().startswith(b"status:"):
                try:
                    return int(line.split(b":", 1)[1].strip().split()[0])
                except (IndexError, ValueError):
                    return None
        if head and head[0].startswith(b"HTTP/"):
            try:
                return int(head[0].split()[1])
            except (IndexError, ValueError):
                return None
        return None

    @property
    def body(self) -> bytes:
        return self.stdout.split(b"\r\n\r\n", 1)[-1] if b"\r\n\r\n" in self.stdout else self.stdout


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise OSError("FastCGI connection closed after %d/%d bytes" % (len(data), n))
        data += chunk
    return bytes(data)


def request(host: str, port: int, params: dict[bytes, bytes],
            body: bytes = b"", timeout: float = 60.0) -> FastCgiResponse:
    payload = b"".join(_nv(k, v) for k, v in params.items())
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(_record(FCGI_BEGIN_REQUEST, 1,
                             struct.pack("!HB5x", FCGI_RESPONDER, 0)))
        # FastCGI params are legal in multiple records; a single record caps at
        # 65535 bytes, which is too small for the large-auth groom.
        for offset in range(0, len(payload), 0xFFFF):
            sock.sendall(_record(FCGI_PARAMS, 1, payload[offset:offset + 0xFFFF]))
        sock.sendall(_record(FCGI_PARAMS, 1, b""))
        if body:
            sock.sendall(_record(FCGI_STDIN, 1, body))
        sock.sendall(_record(FCGI_STDIN, 1, b""))

        stdout = bytearray()
        stderr = bytearray()
        app_status = 0
        protocol_status = 0
        while True:
            header = _recv_exact(sock, 8)
            version, kind, _req, clen, plen, _res = struct.unpack("!BBHHBB", header)
            if version != VERSION:
                raise OSError("bad FastCGI version %d" % version)
            content = _recv_exact(sock, clen)
            if plen:
                _recv_exact(sock, plen)
            if kind == FCGI_STDOUT:
                stdout += content
            elif kind == FCGI_STDERR:
                stderr += content
            elif kind == FCGI_END_REQUEST:
                app_status, protocol_status = struct.unpack("!IB3x", content)
                break
        return FastCgiResponse(bytes(stdout), bytes(stderr),
                               app_status, protocol_status)


def base_params(script: bytes, uri: bytes, query: bytes = b"") -> dict[bytes, bytes]:
    return {
        b"GATEWAY_INTERFACE": b"CGI/1.1",
        b"SERVER_SOFTWARE": b"php2shell-lab",
        b"SERVER_NAME": b"localhost",
        b"SERVER_PORT": b"9000",
        b"SERVER_PROTOCOL": b"HTTP/1.1",
        b"REMOTE_ADDR": b"127.0.0.1",
        b"REMOTE_PORT": b"50000",
        b"REQUEST_METHOD": b"GET",
        b"REQUEST_URI": uri,
        b"DOCUMENT_URI": uri.split(b"?", 1)[0],
        b"SCRIPT_NAME": uri.split(b"?", 1)[0],
        b"SCRIPT_FILENAME": script,
        b"DOCUMENT_ROOT": b"/var/www/html",
        b"QUERY_STRING": query,
    }
