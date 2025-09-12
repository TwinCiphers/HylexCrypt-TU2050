# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),  
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]
### Planned
- Post-quatuam security algorithms and encryption
- Adding more Formats (like pdf,gif,etc.,)
- Integration with cloud-based secure storage  
- Extended plugin system for custom cryptography modules  

---

## [2050.1.0] - 2025-09-12
### Added
- Initial stable release of **HylexCrypt TU2050**
- Argon2id KDF with configurable security profiles  
- AEAD ChaCha20-Poly1305 (preferred) and AES-GCM (fallback)  
- Multi-layer encryption (configurable 1–255 layers)  
- Device-lock binding option (`--device-lock`)  
- Expiry timestamp for logical self-destruct  
- Auto-wipe feature for sensitive data  
- Steganography module (embed/extract messages)  
- Compression and error correction support  
- CLI tool with easy entry point: `hylexcrypt` & `hylexC` 
- Full documentation  

---