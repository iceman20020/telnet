"""Minimal asyncio telnet client."""

import asyncio
import re
import time
from typing import Optional

IAC  = 0xFF
DONT = 0xFE
DO   = 0xFD
WONT = 0xFC
WILL = 0xFB
SB   = 0xFA
SE   = 0xF0

PROMPT_RE   = re.compile(rb"(?:login|username|user)\s*[:\s]", re.I)
PASSWORD_RE = re.compile(rb"password\s*[:\s]", re.I)
SHELL_RE    = re.compile(rb"[$#>]\s*$", re.M)
FAIL_RE     = re.compile(rb"(?:incorrect|invalid|failed|denied|wrong|bad)", re.I)


def strip_iac(data: bytes) -> bytes:
    out = bytearray()
    i, n = 0, len(data)
    while i < n:
        b = data[i]
        if b == IAC and i + 1 < n:
            cmd = data[i + 1]
            if cmd in (DO, DONT, WILL, WONT) and i + 2 < n:
                i += 3
                continue
            if cmd == SB:
                j = i + 2
                while j + 1 < n and not (data[j] == IAC and data[j + 1] == SE):
                    j += 1
                i = j + 2
                continue
            i += 2
            continue
        out.append(b)
        i += 1
    return bytes(out)


class TelnetSession:
    def __init__(self, ip: str, port: int = 23, timeout: float = 6.0):
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None

    async def connect(self) -> bool:
        try:
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(self.ip, self.port),
                timeout=self.timeout,
            )
            return True
        except (OSError, asyncio.TimeoutError):
            return False

    async def drain(self, wait: float) -> bytes:
        chunk = b""
        deadline = time.monotonic() + wait
        while True:
            remain = deadline - time.monotonic()
            if remain <= 0:
                break
            try:
                data = await asyncio.wait_for(self.reader.read(4096), timeout=remain)
                if not data:
                    break
                chunk += data
            except (asyncio.TimeoutError, OSError):
                break
        return chunk

    async def send(self, data: bytes):
        if self.writer:
            self.writer.write(data)
            await self.writer.drain()

    async def read_until(self, regex: re.Pattern, wait: float = 5.0) -> bytes:
        deadline = time.monotonic() + wait
        acc = b""
        while time.monotonic() < deadline:
            remain = deadline - time.monotonic()
            try:
                data = await asyncio.wait_for(self.reader.read(1024), timeout=remain)
                if not data:
                    break
                acc += data
                if regex.search(strip_iac(acc)):
                    break
            except (asyncio.TimeoutError, OSError):
                break
        return acc

    async def close(self):
        try:
            if self.writer:
                self.writer.close()
                await self.writer.wait_closed()
        except Exception:
            pass
