# HylexCrypt-TU2050 — Usage Guide

Table of contents
-----------------
- Prerequisites and installation
- Running self-test
- Basic encode/decode examples
- Advanced encoding options
- Device-lock and Pepper
- Wipe & Autowipe
- Decoys and Recovery
- Troubleshooting & error messages
- Operational security guidance
- Packaging, CI & builds
- Examples and workflows

Prerequisites and installation
------------------------------
- Python 3.9+
- Core deps:
  pip install pillow numpy cryptography argon2-cffi
- Optional:
  pip install scipy reedsolo soundfile colorama psutil

**you can use** : hylexC or hylexcrypt

Running self-test
-----------------
hylexcrypt selftest

Basic encode/decode
-------------------
Encode:
hylexcrypt encode cover.png -o out -m "Top Secret" -p "Pass"

Decode:
hylexcrypt decode out/cover_stego.png -p "Pass"

Advanced encoding
-----------------
Profiles: --profile basic|nexus|transcendent
--compress (zlib)
--fec (Reed–Solomon)
--decoys N
--autowipe

Device-lock and Pepper
----------------------
--pepper "text" adds extra secret to KDF
--device-lock binds to device fingerprint

Wipe & Autowipe
---------------
wipe-message:
hylexcrypt wipe-message file.png

autowipe:
hylexcrypt encode cover.png -o out -m "Msg" -p "Pass" --autowipe 120

Decoys and Recovery
-------------------
--decoys N generates decoys. Recovery files planned.

Troubleshooting
---------------
Missing required packages → install deps
Declared ciphertext length too large → wrong password or corruption
Carrier too small → use bigger carrier
Message expired → expiry triggered

Operational security
--------------------
- Avoid showing passwords on CLI
- Prefer pepper files
- Device-lock reduces portability
- Beware autowipe background password processes

Packaging, CI & builds
----------------------
- pyproject.toml + setuptools_scm
- MkDocs + Material recommended
- Sphinx + myst-parser for ReadTheDocs

Examples
--------
Multi-carrier:
encode:
hylexcrypt encode c1.png c2.png -o out -m "Large" -p "Str0ng!" --fec --compress

decode:
hylexcrypt decode out/file.png -p "Pass"

Wipe after decode:
hylexcrypt wipe-message out/file.png

Manual:
hylexcrypt manual

help:
hylexcrypt --help [-h]
