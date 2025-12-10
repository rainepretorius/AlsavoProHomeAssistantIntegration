"""Standalone Alsavo Pro probe to verify UDP connectivity and payloads.

Run directly on a machine with network access to the heat pump. This script
performs the handshake and a single `query_all`, then prints a concise summary
of the returned payloads.
"""

import argparse
import asyncio
import logging
import sys
from pathlib import Path


# Ensure repository root is on sys.path when run from tools/ directory.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


async def _probe(host: str, port: int, serial: int, password: str, debug: bool) -> int:
    """Connect to the pump, perform query_all, and print the result."""

    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    # Avoid import-time side effects when running as a standalone script.
    from custom_components.alsavopro.AlsavoPyCtrl import AlsavoSocketCom

    client = AlsavoSocketCom()
    try:
        await client.connect(host, port, serial, password)
        response = await client.query_all()
    except Exception:  # pragma: no cover - requires networked device
        logging.exception("Probe failed")
        return 1

    summary = response.debug_summary()
    logging.info("Handshake and query succeeded")
    logging.info("Payload summary: %s", summary)

    # Display a few representative readings for quick validation.
    status = summary.get("status") or {}
    config = summary.get("config") or {}
    print("\n=== Alsavo Pro probe results ===")
    print(f"Server: {host}:{port}  Serial: {serial}")
    if status:
        print(f"Status payload: count={status.get('count')} indices={status.get('indices')} sample={status.get('sample')}")
    if config:
        print(f"Config payload: count={config.get('count')} indices={config.get('indices')} sample={config.get('sample')}")
    if not status and not config:
        print("No payload data returned (status and config are empty)")

    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Probe an Alsavo Pro heat pump over UDP")
    parser.add_argument("--host", required=True, help="Heat pump IP or cloud endpoint")
    parser.add_argument("--port", type=int, default=1194, help="UDP port (1194 local, 51192 cloud)")
    parser.add_argument("--serial", type=int, required=True, help="Heat pump serial number")
    parser.add_argument("--password", required=True, help="Alsavo Pro app password")
    parser.add_argument("--debug", action="store_true", help="Enable verbose logging")

    args = parser.parse_args(argv)

    return asyncio.run(_probe(args.host, args.port, args.serial, args.password, args.debug))


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    sys.exit(main(sys.argv[1:]))
