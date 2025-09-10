#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HylexCrypt CLI wrapper (no PIN feature)

Place this file next to your core implementation (core.py) and run:
  python cli.py --help

This wrapper:
 - Uses core.encode_to_carriers, core.decode_from_parts, core.wipe_message_bits,
   core.wipe_later_action, core.selftest and core.MANUAL_TEXT.
 - Adds a top-level --debug that sets HYLEXCRYPT_DEBUG=1 and raises logging to DEBUG.
 - Prompts for a password if not provided on the command line (safer).
"""
from __future__ import annotations
import os
import sys
import argparse
import getpass
from pathlib import Path
from typing import Optional

# Import your core module (must be in same folder or installed)
import core

# expose core logger locally (optional)
logger = core.logger

def create_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hylexcrypt", description="HylexCrypt CLI wrapper (uses core module)")
    p.add_argument("--debug", action="store_true", help="Enable debug mode (sets HYLEXCRYPT_DEBUG=1 and shows tracebacks)")
    sp = p.add_subparsers(dest="cmd", required=True)

    enc = sp.add_parser("encode", help="Embed and encrypt message into carriers")
    enc.add_argument("carriers", nargs="+", help="Carrier files (images, wav). Can be multiple.")
    enc.add_argument("-o", "--outdir", required=True, help="Output directory")
    enc.add_argument("-m", "--message", required=True, help="Message to embed")
    enc.add_argument("-p", "--password", required=False, help="Password (will prompt if not provided)")
    enc.add_argument("-s", "--profile", choices=list(core.SECURITY_PROFILES.keys()), default="nexus", help="Security profile")
    enc.add_argument("--decoys", type=int, default=0, help="Number of decoy files to create")
    enc.add_argument("--expire", type=int, default=0, help="Expire payload after N seconds (logical self-destruct)")
    enc.add_argument("--fec", action="store_true", help="Enable Reed-Solomon FEC (optional)")
    enc.add_argument("--compress", action="store_true", help="Compress payload (zlib)")
    enc.add_argument("--pepper", default=None, help="Optional pepper string (adds extra secret)")
    enc.add_argument("--device-lock", action="store_true", help="Bind key to this device (device-lock)")
    enc.add_argument("--autowipe", type=int, default=0, help="Schedule background wipe of the embedded message after N seconds (detached).")

    dec = sp.add_parser("decode", help="Extract and decrypt message from stego files")
    dec.add_argument("parts", nargs="+", help="Stego part files (order matters)")
    dec.add_argument("-p", "--password", required=False, help="Password (will prompt if not provided)")
    dec.add_argument("-s", "--profile", choices=list(core.SECURITY_PROFILES.keys()), default="nexus", help="Security profile")
    dec.add_argument("--fec", action="store_true", help="Decode with FEC")
    dec.add_argument("--compress", action="store_true", help="Decompress payload (zlib)")
    dec.add_argument("--pepper", default=None, help="Optional pepper string if used during encode")
    dec.add_argument("--device-lock", action="store_true", help="Set if encoded with device-lock")

    sp.add_parser("selftest", help="Run a built-in self-test (encode->decode->expire->wipe)")

    wipe = sp.add_parser("wipe-message", help="Wipe embedded message bits from files (keeps file)")
    wipe.add_argument("files", nargs="+", help="Files to wipe")
    wipe.add_argument("-p", "--password", required=False, help="Password (optional). If provided, wipe-later may attempt body wipe when used in detached mode.")

    wl = sp.add_parser("wipe-later", help="(Internal / debug) sleep then wipe payload bits (foreground).")
    wl.add_argument("delay", type=int, help="Delay seconds")
    wl.add_argument("files", nargs="+", help="Files to wipe")
    wl.add_argument("--password", required=False, help="If provided, attempts to wipe payload body (not only header)")
    wl.add_argument("--profile", default="nexus", choices=list(core.SECURITY_PROFILES.keys()))
    wl.add_argument("--pepper", default=None)
    wl.add_argument("--device-lock", action="store_true")

    man = sp.add_parser("manual", help="Display full manual")
    return p

def prompt_password_if_needed(cli_pw: Optional[str]) -> str:
    if cli_pw:
        return cli_pw
    try:
        return getpass.getpass("Password: ")
    except Exception:
        raise RuntimeError("Unable to read password from input; provide --password on command line")

def main() -> int:
    parser = create_parser()
    if len(sys.argv) == 1:
        print("No arguments given — running selftest (safe default). Use --help for usage.")
        return core.selftest(verbose=False)

    args = parser.parse_args()

    # enable debug mode if requested
    if getattr(args, "debug", False):
        os.environ["HYLEXCRYPT_DEBUG"] = "1"
        core.logger.setLevel(core.logging.DEBUG)
        logger.debug("Debug mode enabled (HYLEXCRYPT_DEBUG=1)")

    try:
        if args.cmd == "manual":
            print(core.MANUAL_TEXT)
            return 0

        if args.cmd == "selftest":
            return core.selftest(verbose=True)

        if args.cmd == "encode":
            password = prompt_password_if_needed(args.password)
            pepper = args.pepper.encode() if args.pepper else None
            try:
                res = core.encode_to_carriers(
                    args.carriers,
                    args.outdir,
                    args.message,
                    password,
                    profile_name=args.profile,
                    create_decoys=args.decoys,
                    expire_seconds=args.expire,
                    use_fec=args.fec,
                    compress=args.compress,
                    pepper=pepper,
                    bind_device=args.device_lock,
                    autowipe=args.autowipe
                )
            except Exception as e:
                core.friendly_log_exception("Encode failed", e)
                return 1
            # show results
            print(core.GREEN + "Encode complete. Files written:" + core.RESET if hasattr(core, "GREEN") else "Encode complete. Files written:")
            for w in res.get("written", []):
                print("  ", w)
            if res.get("decoys"):
                print("Decoys:")
                for d in res.get("decoys", []):
                    print("  ", d)
            # show autowipe note if requested
            if args.autowipe and args.autowipe > 0:
                logger.info("Autowipe scheduled in %ds (if supported by core).", args.autowipe)
            return 0

        if args.cmd == "decode":
            password = prompt_password_if_needed(args.password)
            pepper = args.pepper.encode() if args.pepper else None
            try:
                msg = core.decode_from_parts(
                    args.parts,
                    password,
                    profile_name=args.profile,
                    use_fec=args.fec,
                    compress=args.compress,
                    pepper=pepper,
                    bind_device=args.device_lock
                )
                print(core.GREEN + "DECODE OK" + core.RESET if hasattr(core, "GREEN") else "DECODE OK")
                print(msg)
                return 0
            except Exception as e:
                core.friendly_log_exception("Decode failed", e)
                return 1

        if args.cmd == "wipe-message":
            # password optional for header-only wipe; provided if you want body wipe attempt
            password = args.password
            try:
                core.wipe_message_bits(args.files)
                print(core.GREEN + "Wipe complete (embedded message bits removed; files intact)." + core.RESET if hasattr(core, "GREEN") else "Wipe complete (embedded message bits removed; files intact).")
                return 0
            except Exception as e:
                core.friendly_log_exception("Wipe failed", e)
                return 1

        if args.cmd == "wipe-later":
            password = args.password
            pepper = args.pepper.encode() if args.pepper else None
            try:
                # runs in foreground here (useful for testing/debugging)
                core.wipe_later_action(int(args.delay), args.files, password=password, profile_name=args.profile, pepper=pepper, bind_device=args.device_lock)
                return 0
            except Exception as e:
                core.friendly_log_exception("wipe-later failed", e)
                return 1

        logger.error("Unknown command")
        return 2

    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        return 130
    except Exception as exc:
        core.friendly_log_exception("Fatal error", exc)
        return 1

if __name__ == "__main__":
    sys.exit(main())
