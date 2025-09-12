from __future__ import annotations
import sys
from pathlib import Path
import argparse
import subprocess
import os
import logging
from hylexcrypt import core
# Import core functions & constants from your main implementation file (core.py)
# Make sure core.py is in the same directory or available on PYTHONPATH.
try:
    from hylexcrypt.core import (
        encode_to_carriers,
        decode_from_parts,
        wipe_message_bits,
        wipe_later_action,
        selftest,
        MANUAL_TEXT,
        SECURITY_PROFILES,
        GREEN,
        RESET,
    )
    # Optional/diagnostic imports
    try:
        from hylexcrypt.core import REEDSOLO_AVAILABLE, ReedSolomonError
    except Exception:
        REEDSOLO_AVAILABLE = False
        ReedSolomonError = Exception
except Exception as imp_ex:
    print("ERROR: Failed to import core module (core.py). Make sure core.py is in the same folder and importable.")
    print("Import error:", imp_ex)
    sys.exit(2)

logger = logging.getLogger("hylexcrypt-cli")
logger.setLevel(logging.INFO)
_ch = logging.StreamHandler(sys.stdout)
_ch.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
logger.handlers = [_ch]


def create_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hylexcrypt", description="HylexCrypt Ultimate 2050 - stego + crypto (CLI wrapper)")
    sp = p.add_subparsers(dest="cmd", required=True)

    enc = sp.add_parser("encode", help="Embed and encrypt message into carriers")
    enc.add_argument("carriers", nargs="+", help="Carrier files (images, wav). Can be multiple.")
    enc.add_argument("-o", "--outdir", required=True, help="Output directory")
    enc.add_argument("-m", "--message", required=True, help="Message to embed")
    enc.add_argument("-p", "--password", required=True, help="Password")
    enc.add_argument("-s", "--profile", choices=list(SECURITY_PROFILES.keys()), default="nexus", help="Security profile")
    enc.add_argument("--decoys", type=int, default=0, help="Number of decoy files to create")
    enc.add_argument("--expire", type=int, default=0, help="Expire payload after N seconds (logical self-destruct)")
    enc.add_argument("--fec", action="store_true", help="Enable Reed-Solomon FEC (optional)")
    enc.add_argument("--compress", action="store_true", help="Compress payload (zlib)")
    enc.add_argument("--pepper", default=None, help="Optional pepper string (adds extra secret)")
    enc.add_argument("--device-lock", action="store_true", help="Bind key to this device (device-lock)")
    enc.add_argument("--autowipe", type=int, default=0, help="Schedule background wipe of the embedded message after N seconds (detached).")

    dec = sp.add_parser("decode", help="Extract and decrypt message from stego files")
    dec.add_argument("parts", nargs="+", help="Stego part files (order matters)")
    dec.add_argument("-p", "--password", required=True, help="Password")
    dec.add_argument("-s", "--profile", choices=list(SECURITY_PROFILES.keys()), default="nexus", help="Security profile")
    dec.add_argument("--fec", action="store_true", help="Decode with FEC")
    dec.add_argument("--compress", action="store_true", help="Decompress payload (zlib)")
    dec.add_argument("--pepper", default=None, help="Optional pepper string if used during encode")
    dec.add_argument("--device-lock", action="store_true", help="Set if encoded with device-lock")

    sp.add_parser("selftest", help="Run a built-in self-test (encode->decode->expire->wipe)")

    wipe = sp.add_parser("wipe-message", help="Wipe embedded message bits from files (keeps file)")
    wipe.add_argument("files", nargs="+", help="Files to wipe")

    wl = sp.add_parser("wipe-later", help="(Internal) detached wipe helper; sleeps then wipes payload")
    wl.add_argument("delay", type=int, help="Delay seconds")
    wl.add_argument("files", nargs="+", help="Files to wipe")
    wl.add_argument("--password", default=None, help="If provided, attempts to wipe payload body (not only header)")
    wl.add_argument("--profile", default="nexus", choices=list(SECURITY_PROFILES.keys()))
    wl.add_argument("--pepper", default=None)
    wl.add_argument("--device-lock", action="store_true")

    sp.add_parser("manual", help="Display full manual")
    return p


def main() -> int:
    parser = create_parser()
    if len(sys.argv) == 1:
        print("No arguments given — running selftest (safe default). Use --help for usage.")
        return selftest(verbose=False)
    args = parser.parse_args()
    try:
        if args.cmd == "manual":
            print(MANUAL_TEXT)
            return 0

        if args.cmd == "selftest":
            return selftest(verbose=True)

        if args.cmd == "encode":
            pepper = args.pepper.encode() if args.pepper else None
            res = encode_to_carriers(
                args.carriers, args.outdir, args.message, args.password,
                profile_name=args.profile, create_decoys=args.decoys, expire_seconds=args.expire,
                use_fec=args.fec, compress=args.compress, pepper=pepper,
                bind_device=args.device_lock, autowipe=args.autowipe
            )
            print(GREEN + "Encode complete. Files written:" + RESET)
            for w in res.get("written", []):
                print("  ", w)
            if res.get("decoys"):
                print("Decoys:")
                for d in res.get("decoys", []):
                    print("  ", d)
            return 0

        if args.cmd == "decode":
            pepper = args.pepper.encode() if args.pepper else None
            msg = decode_from_parts(args.parts, args.password, profile_name=args.profile, use_fec=args.fec, compress=args.compress, pepper=pepper, bind_device=args.device_lock)
            print(GREEN + "DECODE OK" + RESET)
            print(msg)
            return 0

        if args.cmd == "wipe-message":
            wipe_message_bits(args.files)
            print(GREEN + "Wipe complete (embedded message bits removed; files intact)." + RESET)
            return 0

        if args.cmd == "wipe-later":
            pepper = args.pepper.encode() if args.pepper else None
            # Call core's wipe_later_action directly (this will block until completion in-process).
            # The core's encode_to_carriers may spawn core.py as a detached process for autowipe,
            # so this handler allows the detached process to invoke wipe-later behaviour.
            wipe_later_action(int(args.delay), args.files, password=args.password, profile_name=args.profile, pepper=pepper, bind_device=args.device_lock)
            return 0

        logger.error("Unknown command")
        return 2

    except Exception as e:
        msg = str(e) if str(e) else type(e).__name__
        print("ERROR:", msg)
        # Provide tailored suggestions for common error types
        if isinstance(e, FileNotFoundError):
            print("Suggestion: One or more input files were not found. Check the file paths you provided.")
        elif isinstance(e, ValueError):
            if "payload too large" in msg.lower() or "capacity" in msg.lower():
                print("Suggestion: Carrier does not have enough capacity for the payload. Try smaller message or larger carrier, or use multiple carriers.")
            elif "expired" in msg.lower():
                print("Suggestion: The message has expired (self-destructed). Encoding used an expiry time.")
            else:
                print("Suggestion: A value error occurred. Check the command flags and inputs.")
        elif REEDSOLO_AVAILABLE and isinstance(e, RuntimeError) and "FEC decode failed" in msg:
            print("FEC troubleshooting:")
            print(" - If you encoded without --fec, decode without --fec.")
            print(" - If you encoded with --fec, ensure you decode with --fec and that the file is not corrupted.")
            print(" - Verify password / device-lock / pepper match the original encode operation.")
        elif REEDSOLO_AVAILABLE and isinstance(e, ReedSolomonError):
            print("ReedSolomonError: Too many errors to correct. Likely payload corruption or mismatched FEC usage.")
            print("Suggestion: Try decoding without --fec if you didn't encode with --fec.")
        else:
            print("General troubleshooting:")
            print(" - Ensure you used the same password, pepper and device-lock flags at decode as you did at encode.")
            print(" - Try running 'selftest' to validate your installation: python cli.py selftest")
            print(" - If this error persists, capture the short error message above and contact the developer with that message.")
        return 1


if __name__ == "__main__":
    sys.exit(main())


# Copyright 2025 TwinCiphers
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cli.py - Command line wrapper for HylexCrypt core functionality

This file is intended to be used alongside the single-file core implementation
you provided (for example `core.py`). It imports the core functions and exposes
an identical CLI surface so behaviour matches the original single-file CLI.

Place this file next to your `core.py` (or rename the core file to `core.py`) and
run `python cli.py --help` to see the same usage.
"""