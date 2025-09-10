#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HylexCrypt - The Ultimate CLI
------------------------
Command-line interface for the core crypto/stego system.
"""

import argparse
import logging
import sys

from core import (
    encode_to_carriers,
    decode_from_parts,
    wipe_message_bits,
    wipe_later_action,
    selftest,
    SECURITY_PROFILES,
    MANUAL_TEXT,
)

# Configure logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cli")


# -------------------------------------------------------------------
# ENCODE COMMAND
# -------------------------------------------------------------------
def cmd_encode(args):
    try:
        written, decoys = encode_to_carriers(
            carriers=args.carriers,
            outdir=args.outdir,
            message=args.message,
            password=args.password,
            profile=args.profile,
            pepper=args.pepper,
            decoys=args.decoys,
            expire=args.expire,
            fec=args.fec,
            compress=args.compress,
            autowipe=args.autowipe,
            device_lock=args.device_lock,
        )
        logger.info("Encode complete.")
        for f in written:
            print(f"[+] Written: {f}")
        if decoys:
            for f in decoys:
                print(f"[+] Decoy written: {f}")
    except Exception as e:
        logger.error(f"Encode failed: {e}")
        sys.exit(1)


# -------------------------------------------------------------------
# DECODE COMMAND
# -------------------------------------------------------------------
def cmd_decode(args):
    try:
        message = decode_from_parts(
            parts=args.parts,
            password=args.password,
            profile=args.profile,
            pepper=args.pepper,
            autowipe=args.autowipe,
            device_lock=args.device_lock,
        )
        print("[+] DECODE OK")
        if message:
            print(message.decode("utf-8", errors="replace"))
    except Exception as e:
        logger.error(f"Decode failed: {e}")
        sys.exit(1)


# -------------------------------------------------------------------
# WIPE COMMANDS
# -------------------------------------------------------------------
def cmd_wipe_message(args):
    try:
        wipe_message_bits(args.parts, password=args.password)
        logger.info("Message bits wiped successfully.")
    except Exception as e:
        logger.error(f"Wipe-message failed: {e}")
        sys.exit(1)


def cmd_wipe_later(args):
    try:
        wipe_later_action()
        logger.info("Autowipe executed successfully.")
    except Exception as e:
        logger.error(f"Wipe-later failed: {e}")
        sys.exit(1)


# -------------------------------------------------------------------
# SELFTEST COMMAND
# -------------------------------------------------------------------
def cmd_selftest(args):
    try:
        selftest()
    except Exception as e:
        logger.error(f"Selftest failed: {e}")
        sys.exit(1)


# -------------------------------------------------------------------
# MANUAL COMMAND
# -------------------------------------------------------------------
def cmd_manual(args):
    print(MANUAL_TEXT)


# -------------------------------------------------------------------
# MAIN PARSER
# -------------------------------------------------------------------
def build_parser():
    parser = argparse.ArgumentParser(
        prog="hylexcrypt",
        description="HylexCrypt Ultimate 2050 - Stego + Crypto tool",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # encode
    enc = subparsers.add_parser("encode", help="Encrypt & embed message")
    enc.add_argument("carriers", nargs="+", help="Carrier files to embed into")
    enc.add_argument("-o", "--outdir", required=True, help="Output directory")
    enc.add_argument("-m", "--message", required=True, help="Message to embed")
    enc.add_argument("-p", "--password", required=True, help="Password")
    enc.add_argument("-s", "--profile", choices=SECURITY_PROFILES.keys(), default="basic")
    enc.add_argument("--pepper", default="", help="Optional pepper")
    enc.add_argument("--decoys", type=int, default=0, help="Number of decoy outputs")
    enc.add_argument("--expire", type=int, default=0, help="Expiration in seconds")
    enc.add_argument("--fec", action="store_true", help="Enable Forward Error Correction")
    enc.add_argument("--compress", action="store_true", help="Enable compression")
    enc.add_argument("--autowipe", type=int, default=0, help="Autowipe delay (seconds)")
    enc.add_argument("--device-lock", action="store_true", help="Bind encryption to device fingerprint")
    enc.set_defaults(func=cmd_encode)

    # decode
    dec = subparsers.add_parser("decode", help="Extract & decrypt message")
    dec.add_argument("parts", nargs="+", help="Stego files (or parts) to decode from")
    dec.add_argument("-p", "--password", required=True, help="Password")
    dec.add_argument("-s", "--profile", choices=SECURITY_PROFILES.keys(), default="basic")
    dec.add_argument("--pepper", default="", help="Optional pepper")
    dec.add_argument("--autowipe", type=int, default=0, help="Autowipe delay (seconds)")
    dec.add_argument("--device-lock", action="store_true", help="Require device fingerprint")
    dec.set_defaults(func=cmd_decode)

    # wipe-message
    wm = subparsers.add_parser("wipe-message", help="Wipe message bits in carriers")
    wm.add_argument("parts", nargs="+", help="Files to wipe")
    wm.add_argument("-p", "--password", required=True, help="Password")
    wm.set_defaults(func=cmd_wipe_message)

    # wipe-later
    wl = subparsers.add_parser("wipe-later", help="Execute pending autowipe action")
    wl.set_defaults(func=cmd_wipe_later)

    # selftest
    st = subparsers.add_parser("selftest", help="Run self-test")
    st.set_defaults(func=cmd_selftest)

    # manual
    man = subparsers.add_parser("manual", help="Show manual text")
    man.set_defaults(func=cmd_manual)

    return parser


# -------------------------------------------------------------------
# ENTRY POINT
# -------------------------------------------------------------------
def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()