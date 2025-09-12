# HylexCrypt-TU2050

HylexCrypt is an advanced hybrid steganography + cryptography toolkit (CLI + library) designed for robust, future-ready secret messaging inside image and audio carriers. It combines modern KDFs, AEAD ciphers, optional error-correction, and adaptive embedding strategies to maximize stealth, integrity and recoverability.

Tagline: Quantum-resistant steganography and encryption - practicality and plausibility for the next generation of secure content hiding.

Quick facts
-----------
- Languages: Python 3.9+
- Primary features: Argon2id KDF, ChaCha20-Poly1305 / AES-GCM AEAD, Reed–Solomon FEC (optional), adaptive LSB embedding with deterministic position selection, WAV/PNG/JPEG support, device-lock binding, logical expiry (self-destruct), in-place embedded-message wipe (keeps carrier), scheduled wipe (background process).
- Author(s): Deepak P S, Nithin S
- Project / Maintainers: TwinCiphers
- Recommended installation: see Usage for local install and dev setup.
- Documentation: this set - Home, Usage Guide, API Reference, Research.

Table of contents
-----------------
- Quick start
- Primary design goals
- Security & design notes
- Authors, TwinCiphers formation & acknowledgements
- Research & future insight (roadmap)
- Where to go next

Quick start
-----------
1. Ensure Python 3.9+ and core dependencies are installed:
   pip install -r requirements.txt
   # or minimal
   pip install pillow numpy cryptography argon2-cffi

2. Run a self-test:
   hylexcrypt selftest

3. Encode:
   hylexcrypt encode carrier.png -o out -m "Top Secret" -p "StrongPass!2025"

4. Decode:
   hylexcrypt decode out/carrier_stego.png -p "StrongPass!2025"

Primary design goals
--------------------
1. Cryptographic robustness — Argon2id KDF, ChaCha20-Poly1305 preferred AEAD with AES-GCM fallback.
2. Stealth & anti-detection — adaptive position selection.
3. Recoverability — optional Reed–Solomon FEC.
4. Operational safety — logical expiry and wipe functions.
5. Usability — single-file CLI/demo module.

Security & design notes
-----------------------
- Key derivation: profile-driven Argon2id.
- AEAD: authenticated encryption.
- Device-lock: non-portable payloads.
- Self-destruct / expiry: logical expiry encoded.
- Autowipe: scheduled background wipe.
- Wipe vs delete: carrier preserved vs full file removal.
- Decoys: alternate plausible payloads.

Authors, TwinCiphers formation & acknowledgements, Assitance
------------------------------------------------------------
Authors: Deepak P S (cryptography, algorithms, systems integration) & Nithin S (System integration,Cryptography, tooling)

TwinCiphers (maintainers): security research & tooling collective focusing on steganography and privacy-preserving workflows.

Formation story: HylexCrypt grew from collaboration exploring practical steganography + crypto fusions.

Acknowledgements: Pillow, NumPy, cryptography, argon2-cffi, reedsolo, SciPy, soundfile, colorama, psutil.

Research & future insight (roadmap)
-----------------------------------
Short-term: robust metadata headers, DCT embedding, adaptive FEC.
Mid-term: post-quantum KEM integration, ML-aided embedding adaptors.
Long-term: formal steganalysis testing, GUI, enterprise features.

Where to go next
----------------
- Usage Guide
- API Reference
- Research
