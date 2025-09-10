# HylexCrypt-TU2050 - API Reference

High-level functions
--------------------
encode_to_carriers(carriers, out_dir, message, password, profile_name="nexus", create_decoys=0, expire_seconds=0, use_fec=False, compress=False, pepper=None, bind_device=False, autowipe=None) -> dict
- Encode message into carrier files.
- Returns dict with written, decoys, salt.

decode_from_parts(parts, password, profile_name="nexus", use_fec=False, compress=False, pepper=None, bind_device=False) -> str
- Decode and return plaintext message.

Core cryptographic primitives
-----------------------------
derive_key(password, salt, length, profile, pepper=None, bind_device=False)
- Argon2id KDF wrapper.

aead_encrypt(key, plaintext) -> bytes
- AEAD (ChaCha20-Poly1305 preferred, AES-GCM fallback).

aead_decrypt(key, blob) -> bytes
- Decrypt AEAD blob.

Stego helpers
-------------
lsb_embed_image / lsb_extract_image
- Embed/extract payload into numpy array image.

lsb_embed_wav / lsb_extract_wav
- Embed/extract payload into WAV PCM16.

Packaging
---------
package_payload(message, password, profile, expire_seconds=0, use_fec=False, compress=False, pepper=None, bind_device=False) -> (bytes, bytes)
- Build encrypted payload, returns payload and salt.

unpackage_payload(blob, password, profile, use_fec=False, compress=False, pepper=None, bind_device=False) -> str
- Reverse decode, returns plaintext.

Wipe & secure delete
--------------------
wipe_message_bits(files)
- Zero header bits.

wipe_later_action(delay, files, password=None, profile_name="nexus", pepper=None, bind_device=False)
- Schedule wipe.

secure_delete(path, passes=3)
- Overwrite and unlink file.

Types & exceptions
------------------
- ValueError on malformed payloads or capacity issues.
- FileNotFoundError for missing files.
- Cryptographic failures bubble up.

Examples
--------
Programmatic encode:

from hylexcrypt import encode_to_carriers
encode_to_carriers(["cover.png"], "out", "Secret", "Pass", "nexus")

Programmatic decode:

from hylexcrypt import decode_from_parts
decode_from_parts(["out/cover_stego.png"], "Pass", "nexus")
