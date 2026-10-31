#!/usr/bin/env python3
"""telnet.py — entrypoint. Prints banner, prompts, launches scanner."""

import asyncio
import os
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


def prompt(text: str) -> str:
    return input(f"root@telnet~: ").strip()


def main():
    os.system("cls" if os.name == "nt" else "clear")
    print(BANNER)
    print()

    print("1. webhook?")
    webhook = prompt("")

    print("2. threads?")
    try:
        threads = int(prompt("") or "200")
    except ValueError:
        threads = 200

    print()
    if not webhook.startswith("https://discord.com/api/webhooks/"):
        print("[!] that doesn't look like a discord webhook — proceeding anyway")
        if input("root@telnet~: continue? [y/N] ").strip().lower() != "y":
            sys.exit(0)

    print(f"[*] webhook set. threads={threads}. launching.\n")

    from core.scanner import run
    try:
        asyncio.run(run(webhook, threads))
    except KeyboardInterrupt:
        print("\n[*] interrupted")


if __name__ == "__main__":
    main()
