from __future__ import annotations
import os
import sys
import time
import json
import struct
import secrets
import hashlib
import logging
import argparse
import tempfile
import math
import shutil
import subprocess
import platform
import uuid
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional

# --- Dependency checks ---
_missing = []
try:
    import numpy as np
except Exception:
    _missing.append("numpy")
try:
    from PIL import Image
except Exception:
    _missing.append("Pillow")
try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
except Exception:
    _missing.append("cryptography")
try:
    from argon2.low_level import hash_secret_raw, Type as Argon2Type
except Exception:
    _missing.append("argon2-cffi")
# optional
try:
    from scipy.fft import dct, idct
    SCIPY_AVAILABLE = True
except Exception:
    SCIPY_AVAILABLE = False
try:
    import reedsolo
    REEDSOLO_AVAILABLE = True
except Exception:
    REEDSOLO_AVAILABLE = False
try:
    import soundfile as sf
    AUDIO_AVAILABLE = True
except Exception:
    AUDIO_AVAILABLE = False
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    GREEN, RED, YELLOW, RESET = Fore.GREEN, Fore.RED, Fore.YELLOW, Style.RESET_ALL
except Exception:
    GREEN = RED = YELLOW = RESET = ""
try:
    import psutil
    MONITORING_AVAILABLE = True
except Exception:
    MONITORING_AVAILABLE = False

if _missing:
    print("Missing required packages:", ", ".join(sorted(set(_missing))))
    print("Install example:")
    print("  pip install pillow numpy cryptography argon2-cffi scipy reedsolo colorama soundfile psutil")
    sys.exit(2)

# --- Try import RSCodec in guarded way (some environments vary) ---
if REEDSOLO_AVAILABLE:
    try:
        from reedsolo import RSCodec, ReedSolomonError
    except Exception:
        RSCodec = None
        ReedSolomonError = Exception
        REEDSOLO_AVAILABLE = False
else:
    RSCodec = None
    ReedSolomonError = Exception

# --- Constants / Profiles ---
FIXED_HEADER_BYTES = 24      # header region: 16 bytes salt | 8 bytes ciphertext length
HEADER_BIT_COUNT = FIXED_HEADER_BYTES * 8
CHUNK_SALT_LEN = 16
RS_PARITY = 32
MIN_PW_ENTROPY = 60.0
SECURITY_PROFILES = {
    "basic": {"kdf_time": 2, "kdf_mem_kib": 64 * 1024, "kdf_par": 2},
    "nexus": {"kdf_time": 3, "kdf_mem_kib": 128 * 1024, "kdf_par": 4},
    "transcendent": {"kdf_time": 5, "kdf_mem_kib": 256 * 1024, "kdf_par": 8},
}

# --- Logging ---
logger = logging.getLogger("Hylex2050")
logger.setLevel(logging.INFO)
_ch = logging.StreamHandler(sys.stdout)
_ch.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
logger.handlers = [_ch]

# --- Utilities ---
def sha3_256(b: bytes) -> bytes:
    return hashlib.sha3_256(b).digest()

def device_fingerprint() -> bytes:
    """Stable device fingerprint used for optional device-lock."""
    sysinfo = f"{platform.system()}|{platform.machine()}|{uuid.getnode()}"
    return hashlib.sha256(sysinfo.encode()).digest()[:16]

def estimate_entropy(pw: str) -> float:
    pools = 0
    if any(c.islower() for c in pw): pools += 26
    if any(c.isupper() for c in pw): pools += 26
    if any(c.isdigit() for c in pw): pools += 10
    if any(not c.isalnum() for c in pw): pools += 32
    if pools == 0: return 0.0
    return len(pw) * math.log2(pools)

COMMON_PASSWORDS = {"password", "123456", "qwerty", "letmein", "admin", "welcome", "111111"}

def check_password_strength(pw: str) -> Tuple[bool, str]:
    if not pw: return False, "Empty password"
    if pw.lower() in COMMON_PASSWORDS: return False, "Common password"
    if len(pw) < 12: return False, "Password must be >= 12 characters"
    classes = sum([
        any(c.islower() for c in pw),
        any(c.isupper() for c in pw),
        any(c.isdigit() for c in pw),
        any(not c.isalnum() for c in pw)
    ])
    if classes < 3:
        return False, "Use at least 3 character classes (upper/lower/digit/symbol)"
    ent = estimate_entropy(pw)
    if ent < MIN_PW_ENTROPY:
        return False, f"Entropy {ent:.1f} bits < {MIN_PW_ENTROPY}"
    return True, f"Entropy {ent:.1f} bits"

# --- KDF (Argon2id) ---
def derive_key(password: str, salt: bytes, length: int, profile: Dict[str, Any], pepper: Optional[bytes] = None, bind_device: bool = False) -> bytes:
    secret = password.encode()
    if pepper:
        secret += pepper
    if bind_device:
        secret += device_fingerprint()
    return hash_secret_raw(secret, salt, int(profile["kdf_time"]), int(profile["kdf_mem_kib"]), int(profile["kdf_par"]), length, Argon2Type.ID)

# --- AEAD ---
def aead_encrypt(key: bytes, plaintext: bytes) -> bytes:
    k = key[:32]
    nonce = secrets.token_bytes(12)
    try:
        ct = ChaCha20Poly1305(k).encrypt(nonce, plaintext, None)
        return b"CC20" + nonce + ct
    except Exception:
        ct = AESGCM(k).encrypt(nonce, plaintext, None)
        return b"AGCM" + nonce + ct

def aead_decrypt(key: bytes, blob: bytes) -> bytes:
    if len(blob) < 4:
        raise ValueError("AEAD blob too short")
    tag = blob[:4]; body = blob[4:]
    if tag == b"CC20":
        return ChaCha20Poly1305(key[:32]).decrypt(body[:12], body[12:], None)
    if tag == b"AGCM":
        return AESGCM(key[:32]).decrypt(body[:12], body[12:], None)
    raise ValueError("Unknown AEAD tag")

# --- Reed-Solomon FEC helpers ---
def fec_encode(data: bytes, nsym: int = RS_PARITY) -> bytes:
    if not REEDSOLO_AVAILABLE or RSCodec is None:
        return data
    r = RSCodec(nsym)
    return r.encode(data)

def fec_decode(data: bytes, nsym: int = RS_PARITY) -> bytes:
    if not REEDSOLO_AVAILABLE or RSCodec is None:
        return data
    try:
        r = RSCodec(nsym)
        result = r.decode(data)
        # result can be bytes or a tuple (decoded, corrections, ...)
        if isinstance(result, tuple):
            return result[0]
        return result
    except ReedSolomonError as exc:
        # Raise a clearer error for upstream handling
        raise RuntimeError(
            "FEC decode failed: probably not FEC-encoded data, or too many errors to correct. "
            "If you are decoding, try omitting --fec; if you encoded, ensure you encoded with --fec."
        ) from exc

# --- Deterministic PRNG from key + salt ---
def prng_from_key_and_salt(key: bytes, salt: bytes) -> np.random.Generator:
    seed_bytes = sha3_256(key + salt)[:8]
    seed = int.from_bytes(seed_bytes, 'big')
    return np.random.default_rng(seed)

# --- Evolutionary/adaptive position selector ---
def evolve_positions(rng: np.random.Generator, data_size: int, bits_needed: int, trials: int = 8, gens: int = 4) -> np.ndarray:
    data_size = int(data_size)
    bits_needed = int(bits_needed)
    if bits_needed <= 0:
        return np.array([], dtype=np.int64)
    if bits_needed * 3 > data_size:
        pos = np.linspace(0, data_size - 1, num=bits_needed, dtype=np.int64)
        return np.sort(pos)
    best_pos = None
    best_score = float('inf')
    for g in range(gens):
        for t in range(trials):
            try:
                pos = np.sort(rng.choice(data_size, size=bits_needed, replace=False))
            except Exception:
                perm = rng.permutation(data_size)
                pos = np.sort(perm[:bits_needed])
            diffs = np.diff(pos)
            score = float(np.var(diffs)) + 0.0005 * (pos[0] + (data_size - 1 - pos[-1]))
            if score < best_score:
                best_score = score
                best_pos = pos
    return best_pos.astype(np.int64)

# --- Two-phase LSB embed/extract for images ---
def lsb_embed_image(cover_arr: np.ndarray, payload: bytes, password: str, profile: Dict[str, Any], pepper: Optional[bytes], bind_device: bool) -> np.ndarray:
    flat = cover_arr.flatten().astype(np.uint8)
    total_vals = flat.size
    header = payload[:FIXED_HEADER_BYTES]
    header_bits = np.unpackbits(np.frombuffer(header, dtype=np.uint8))
    header_bit_count = header_bits.size
    if header_bit_count >= total_vals:
        raise ValueError("Carrier too small for header")
    out = flat.copy()
    out[:header_bit_count] = (out[:header_bit_count] & 0xFE) | header_bits
    body = payload[FIXED_HEADER_BYTES:]
    if len(body) > 0:
        body_bits = np.unpackbits(np.frombuffer(body, dtype=np.uint8))
        free_slots = total_vals - header_bit_count
        if body_bits.size > free_slots:
            raise ValueError("Payload too large for carrier capacity")
        salt = header[:CHUNK_SALT_LEN]
        key_seed = derive_key(password, salt, 64, profile, pepper, bind_device)
        rng = prng_from_key_and_salt(key_seed, salt)
        pos = evolve_positions(rng, free_slots, body_bits.size)
        pos = (pos + header_bit_count).astype(np.int64)
        out[pos] = (out[pos] & 0xFE) | body_bits
    return out.reshape(cover_arr.shape)

def lsb_extract_image(stego_arr: np.ndarray, password: str, profile: Dict[str, Any], pepper: Optional[bytes], bind_device: bool, expected_max_bytes: int = 50 * 1024 * 1024) -> bytes:
    flat = stego_arr.flatten().astype(np.uint8)
    total_vals = flat.size
    header_bit_count = HEADER_BIT_COUNT
    if header_bit_count >= total_vals:
        raise ValueError("Carrier too small for header")
    header_bits = (flat[:header_bit_count] & 1).astype(np.uint8)
    header = np.packbits(header_bits).tobytes()[:FIXED_HEADER_BYTES]
    salt = header[:CHUNK_SALT_LEN]
    clen = struct.unpack('<Q', header[CHUNK_SALT_LEN:FIXED_HEADER_BYTES])[0]
    if clen > expected_max_bytes:
        raise ValueError("Declared ciphertext length too large (corruption or wrong password)")
    body_len = clen
    body = b''
    if body_len > 0:
        bits_needed = body_len * 8
        free_slots = total_vals - header_bit_count
        if bits_needed > free_slots:
            raise ValueError("Carrier does not contain enough capacity for claimed payload length")
        key_seed = derive_key(password, salt, 64, profile, pepper, bind_device)
        rng = prng_from_key_and_salt(key_seed, salt)
        pos = evolve_positions(rng, free_slots, bits_needed)
        pos = (pos + header_bit_count).astype(np.int64)
        bits = (flat[pos] & 1).astype(np.uint8)
        body = np.packbits(bits).tobytes()[:body_len]
    return header + body

# --- WAV LSB embed/extract ---
def lsb_embed_wav(file_in: str, file_out: str, payload: bytes, password: str, profile: Dict[str, Any], pepper: Optional[bytes], bind_device: bool) -> None:
    data, sr = sf.read(file_in, dtype='int16')
    flat = data.flatten()
    header = payload[:FIXED_HEADER_BYTES]
    header_bits = np.unpackbits(np.frombuffer(header, dtype=np.uint8))
    if header_bits.size > flat.size:
        raise ValueError("Audio carrier too small for header")
    out = flat.copy()
    out[:header_bits.size] = (out[:header_bits.size] & ~1) | header_bits
    body = payload[FIXED_HEADER_BYTES:]
    if body:
        bits = np.unpackbits(np.frombuffer(body, dtype=np.uint8))
        region = flat.size - header_bits.size
        if bits.size > region:
            raise ValueError("Payload too large for audio carrier")
        salt = header[:CHUNK_SALT_LEN]
        key_seed = derive_key(password, salt, 64, profile, pepper, bind_device)
        rng = prng_from_key_and_salt(key_seed, salt)
        pos = evolve_positions(rng, region, bits.size)
        pos = (pos + header_bits.size).astype(np.int64)
        out[pos] = (out[pos] & ~1) | bits
    out = out.reshape(data.shape)
    sf.write(file_out, out, sr, subtype='PCM_16')

def lsb_extract_wav(file_in: str, password: str, profile: Dict[str, Any], pepper: Optional[bytes], bind_device: bool, expected_guess: int = 50 * 1024 * 1024) -> bytes:
    data, sr = sf.read(file_in, dtype='int16')
    flat = data.flatten()
    header_bits = (flat[:HEADER_BIT_COUNT] & 1).astype(np.uint8)
    header = np.packbits(header_bits).tobytes()[:FIXED_HEADER_BYTES]
    salt = header[:CHUNK_SALT_LEN]
    clen = struct.unpack('<Q', header[CHUNK_SALT_LEN:FIXED_HEADER_BYTES])[0]
    total_len = FIXED_HEADER_BYTES + clen
    body = b''
    if clen > 0:
        bits_needed = clen * 8
        region = flat.size - HEADER_BIT_COUNT
        if bits_needed > region:
            raise ValueError("Declared payload too big for audio carrier")
        key_seed = derive_key(password, salt, 64, profile, pepper, bind_device)
        rng = prng_from_key_and_salt(key_seed, salt)
        pos = evolve_positions(rng, region, bits_needed)
        pos = (pos + HEADER_BIT_COUNT).astype(np.int64)
        bits = (flat[pos] & 1).astype(np.uint8)
        body = np.packbits(bits).tobytes()[:clen]
    return header + body

# --- Packaging / encryption pipeline ---
def package_payload(message: str, password: str, profile: Dict[str, Any], expire_seconds: int = 0, use_fec: bool = False, compress: bool = False, pepper: Optional[bytes] = None, bind_device: bool = False) -> Tuple[bytes, bytes]:
    ts = int(time.time())
    pkg = {"hdr": "HYLEXV1", "timestamp": ts, "expire_seconds": int(expire_seconds), "message": message}
    serialized = json.dumps(pkg, separators=(',', ':')).encode('utf-8')
    if compress:
        import zlib
        serialized = zlib.compress(serialized, level=9)
    processed = serialized
    if use_fec and REEDSOLO_AVAILABLE:
        processed = fec_encode(processed)
    salt = secrets.token_bytes(CHUNK_SALT_LEN)
    key = derive_key(password, salt, 64, profile, pepper, bind_device)
    cipher_blob = aead_encrypt(key, processed)
    final = salt + struct.pack('<Q', len(cipher_blob)) + cipher_blob
    return final, salt

def unpackage_payload(blob: bytes, password: str, profile: Dict[str, Any], use_fec: bool = False, compress: bool = False, pepper: Optional[bytes] = None, bind_device: bool = False) -> str:
    if len(blob) < FIXED_HEADER_BYTES:
        raise ValueError("Payload too small")
    salt = blob[:CHUNK_SALT_LEN]
    clen = struct.unpack('<Q', blob[CHUNK_SALT_LEN:FIXED_HEADER_BYTES])[0]
    cipher = blob[FIXED_HEADER_BYTES:FIXED_HEADER_BYTES + clen]
    key = derive_key(password, salt, 64, profile, pepper, bind_device)
    processed = aead_decrypt(key, cipher)
    if use_fec and REEDSOLO_AVAILABLE:
        processed = fec_decode(processed)
    if compress:
        import zlib
        processed = zlib.decompress(processed)
    pkg = json.loads(processed.decode('utf-8'))
    expire_seconds = int(pkg.get("expire_seconds", 0))
    ts = int(pkg.get("timestamp", 0))
    if expire_seconds and (time.time() > ts + expire_seconds):
        raise ValueError("Message has logically expired (self-destructed)")
    return pkg.get("message", "")

# --- Capacity helpers ---
def image_capacity(arr: np.ndarray) -> int:
    return int(np.prod(arr.shape)) // 8

def wav_capacity(file_in: str) -> int:
    data, sr = sf.read(file_in, dtype='int16')
    return data.size // 8

# --- Splitting - simple single-carrier demo approach ---
def encode_to_carriers(carriers: List[str], out_dir: str, message: str, password: str, profile_name: str = "nexus", create_decoys: int = 0, expire_seconds: int = 0, use_fec: bool = False, compress: bool = False, pepper: Optional[bytes] = None, bind_device: bool = False, autowipe: Optional[int] = None) -> Dict[str, Any]:
    profile = SECURITY_PROFILES.get(profile_name)
    if profile is None:
        raise ValueError("Unknown profile")
    ok, reason = check_password_strength(password)
    if not ok:
        logger.warning("Password strength check: %s", reason)
    os.makedirs(out_dir, exist_ok=True)
    payload, salt = package_payload(message, password, profile, expire_seconds, use_fec, compress, pepper, bind_device)
    written = []
    for idx, c in enumerate(carriers):
        p = Path(c)
        if not p.exists():
            logger.warning("Carrier missing, skipping: %s", c)
            continue
        outname = Path(out_dir) / (p.stem + f"_stego{p.suffix}")
        if p.suffix.lower() in ('.wav',) and AUDIO_AVAILABLE:
            lsb_embed_wav(str(p), str(outname), payload, password, profile, pepper, bind_device)
        else:
            arr = np.array(Image.open(p).convert("RGB"))
            out_arr = lsb_embed_image(arr, payload, password, profile, pepper, bind_device)
            Image.fromarray(out_arr).save(str(outname), quality=95 if p.suffix.lower() in ('.jpg', '.jpeg') else None)
        written.append(str(outname))
    # create decoys if requested
    decoys = []
    for i in range(create_decoys):
        if carriers:
            c = carriers[i % len(carriers)]
            p = Path(c)
            outname = Path(out_dir) / (p.stem + f"_decoy_{i}{p.suffix}")
            decoy_payload, _ = package_payload(f"decoy-{secrets.token_hex(6)}", password, profile, 0, use_fec, compress, pepper, bind_device)
            if p.suffix.lower() in ('.wav',) and AUDIO_AVAILABLE:
                lsb_embed_wav(str(p), str(outname), decoy_payload, password, profile, pepper, bind_device)
            else:
                arr = np.array(Image.open(p).convert("RGB"))
                out_arr = lsb_embed_image(arr, decoy_payload, password, profile, pepper, bind_device)
                Image.fromarray(out_arr).save(str(outname))
            decoys.append(str(outname))
    # schedule autowipe (detached) if requested
    if autowipe and autowipe > 0:
        files_to_wipe = written + decoys
        cmd = [sys.executable, str(Path(__file__).resolve()), "wipe-later", str(autowipe)] + files_to_wipe + ["--password", password]
        kwargs = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL, "close_fds": True}
        if os.name == "nt":
            kwargs["creationflags"] = subprocess.DETACHED_PROCESS
        try:
            subprocess.Popen(cmd, **kwargs)
            logger.info("Scheduled autowipe in %ds for %d files (background).", autowipe, len(files_to_wipe))
        except Exception:
            logger.warning("Unable to schedule detached autowipe on this platform; autowipe skipped.")
    return {"written": written, "decoys": decoys, "salt": salt.hex()}

def decode_from_parts(parts: List[str], password: str, profile_name: str = "nexus", use_fec: bool = False, compress: bool = False, pepper: Optional[bytes] = None, bind_device: bool = False) -> str:
    profile = SECURITY_PROFILES.get(profile_name)
    if profile is None:
        raise ValueError("Unknown profile")
    blob = b''
    for p in parts:
        pth = Path(p)
        if not pth.exists():
            raise FileNotFoundError(p)
        if pth.suffix.lower() in ('.wav',) and AUDIO_AVAILABLE:
            chunk = lsb_extract_wav(str(pth), password, profile, pepper, bind_device)
        else:
            arr = np.array(Image.open(pth).convert("RGB"))
            chunk = lsb_extract_image(arr, password, profile, pepper, bind_device)
        blob += chunk
    return unpackage_payload(blob, password, profile, use_fec, compress, pepper, bind_device)

# --- Secure delete (file removal) ---
def secure_delete(path: str, passes: int = 3) -> bool:
    try:
        p = Path(path)
        if not p.exists():
            return True
        size = p.stat().st_size
        with p.open('r+b') as f:
            for _ in range(passes):
                f.seek(0)
                remaining = size
                while remaining > 0:
                    chunk = min(65536, remaining)
                    f.write(secrets.token_bytes(chunk))
                    remaining -= chunk
                f.flush()
                os.fsync(f.fileno())
        try:
            p.unlink()
        except Exception:
            pass
        if os.name == "posix" and shutil.which("shred"):
            try:
                os.system(f'shred -u -n {passes} "{str(p)}" 2>/dev/null || true')
            except Exception:
                pass
        return True
    except Exception as e:
        logger.error("secure_delete error: %s", e)
        return False

# --- Wipe embedded message bits (keep file intact) ---
def wipe_message_bits(files: List[str]) -> None:
    for f in files:
        p = Path(f)
        if not p.exists():
            logger.warning("File not found for wipe: %s", f)
            continue
        try:
            if p.suffix.lower() in ('.wav',) and AUDIO_AVAILABLE:
                data, sr = sf.read(str(p), dtype='int16')
                flat = data.flatten().astype(np.int16)
                flat[:HEADER_BIT_COUNT] &= ~1
                sf.write(str(p), flat.reshape(data.shape), sr, subtype='PCM_16')
            else:
                img = Image.open(str(p)).convert("RGB")
                arr = np.array(img)
                flat = arr.flatten().astype(np.uint8)
                flat[:HEADER_BIT_COUNT] &= 0xFE
                out = flat.reshape(arr.shape)
                Image.fromarray(out).save(str(p))
            logger.info("Wiped embedded message bits in: %s", f)
        except Exception as e:
            logger.error("Wipe failed for %s: %s", f, e)

# --- Detached wipe-later helper (internal) ---
def wipe_later_action(delay: int, files: List[str], password: Optional[str] = None, profile_name: str = "nexus", pepper: Optional[bytes] = None, bind_device: bool = False):
    logger.info("wipe-later sleeping %ds before wiping message bits on %d files", delay, len(files))
    try:
        time.sleep(delay)
        if password:
            profile = SECURITY_PROFILES.get(profile_name, SECURITY_PROFILES["nexus"])
            for f in files:
                p = Path(f)
                if not p.exists(): continue
                try:
                    if p.suffix.lower() in ('.wav',) and AUDIO_AVAILABLE:
                        data, sr = sf.read(str(p), dtype='int16')
                        flat = data.flatten().astype(np.int16)
                        header_bits = (flat[:HEADER_BIT_COUNT] & 1).astype(np.uint8)
                        header = np.packbits(header_bits).tobytes()[:FIXED_HEADER_BYTES]
                        salt = header[:CHUNK_SALT_LEN]
                        clen = struct.unpack('<Q', header[CHUNK_SALT_LEN:FIXED_HEADER_BYTES])[0]
                        bits_needed = clen * 8
                        region = flat.size - HEADER_BIT_COUNT
                        key_seed = derive_key(password, salt, 64, profile, pepper, bind_device)
                        rng = prng_from_key_and_salt(key_seed, salt)
                        pos = evolve_positions(rng, region, bits_needed)
                        pos = (pos + HEADER_BIT_COUNT).astype(np.int64)
                        flat[pos] &= ~1
                        flat[:HEADER_BIT_COUNT] &= ~1
                        sf.write(str(p), flat.reshape(data.shape), sr, subtype='PCM_16')
                    else:
                        img = Image.open(str(p)).convert("RGB")
                        arr = np.array(img)
                        flat = arr.flatten().astype(np.uint8)
                        header_bits = (flat[:HEADER_BIT_COUNT] & 1).astype(np.uint8)
                        header = np.packbits(header_bits).tobytes()[:FIXED_HEADER_BYTES]
                        salt = header[:CHUNK_SALT_LEN]
                        clen = struct.unpack('<Q', header[CHUNK_SALT_LEN:FIXED_HEADER_BYTES])[0]
                        bits_needed = clen * 8
                        region = flat.size - HEADER_BIT_COUNT
                        key_seed = derive_key(password, salt, 64, profile, pepper, bind_device)
                        rng = prng_from_key_and_salt(key_seed, salt)
                        pos = evolve_positions(rng, region, bits_needed)
                        pos = (pos + HEADER_BIT_COUNT).astype(np.int64)
                        flat[pos] &= 0xFE
                        flat[:HEADER_BIT_COUNT] &= 0xFE
                        out = flat.reshape(arr.shape)
                        Image.fromarray(out).save(str(p))
                    logger.info("Wiped payload bits in %s", p)
                except Exception as e:
                    logger.error("Failed to wipe payload bits for %s: %s", p, e)
        else:
            wipe_message_bits(files)
    except Exception as e:
        logger.error("wipe-later exception: %s", e)

# --- Selftest / Demo helper ---
def selftest(verbose: bool = False) -> int:
    logger.info("Running self-test (encode->decode->expiry->wipe demo)...")
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        c = tmpdir / "carrier.png"
        arr = np.zeros((128, 128, 3), dtype=np.uint8)
        for i in range(128):
            arr[i, :, 0] = i
            arr[i, :, 1] = (i * 2) % 256
            arr[i, :, 2] = (i * 3) % 256
        Image.fromarray(arr).save(str(c))
        pwd = "Str0ngSelfT3st!2050"
        msg = "SELFTEST: " + secrets.token_hex(8)
        outdir = tmpdir / "out"
        outdir.mkdir()
        res = encode_to_carriers([str(c)], str(outdir), msg, pwd, profile_name="nexus", create_decoys=0, expire_seconds=15, use_fec=False, compress=False, pepper=None, bind_device=False, autowipe=None)
        if verbose:
            logger.info("Wrote files: %s", res["written"])
        try:
            decoded = decode_from_parts([res["written"][0]], pwd, "nexus", use_fec=False, compress=False, pepper=None, bind_device=False)
            if decoded != msg:
                logger.error("Selftest decode mismatch")
                return 2
        except Exception as e:
            logger.error("Selftest decode error: %s", e)
            return 3
        logger.info("Selftest decode OK (before expiry)")
        time.sleep(30)
        try:
            _ = decode_from_parts([res["written"][0]], pwd, "nexus", use_fec=False, compress=False, pepper=None, bind_device=False)
            logger.error("Selftest: expected expiry but decode succeeded")
            return 4
        except Exception:
            logger.info("Selftest expiry behaviour OK")
        wipe_message_bits(res["written"])
        try:
            _ = decode_from_parts([res["written"][0]], pwd, "nexus", use_fec=False, compress=False, pepper=None, bind_device=False)
            logger.error("Selftest: expected decode failure after wipe but succeeded")
            return 5
        except Exception:
            logger.info("Selftest wipe behaviour OK")
        logger.info("SELFTEST PASSED")
        return 0

# --- CLI Manual text ---
MANUAL_TEXT = r"""
HylexCrypt - The Ultimate 2050 - Full Manual
=====================================

Overview
--------
HylexCrypt is a steganography + cryptography tool. It embeds
an encrypted payload into image or audio carriers using an LSB
based scheme with an adaptive (evolutionary) selection of embedding positions.

Major features:
 - Argon2id KDF with configurable security profiles.
 - AEAD encryption (ChaCha20-Poly1305 preferred; AES-GCM fallback).
 - Optional device-lock binding (binds the key to the current machine).
 - Expiry (logical self-destruct) inside the encrypted payload.
 - Wipe of embedded message bits (keeps carrier file intact).
 - Schedule background wipe (wipe-later / autowipe).
 - Reed-Solomon FEC optional (requires 'reedsolo' package).
 - WAV (LSB) and PNG/JPG (LSB) support. JPEG DCT mode is a placeholder if SciPy present.
 - Selftest and demo commands.

Quick examples
--------------
1) Encode a message into one PNG carrier:
   hylexcrypt encode carrier.png -o outdir -m "Top Secret" -p "StrongPass!2025"

2) Decode:
   hylexcrypt decode outdir/carrier_stego.png -p "StrongPass!2025"

3) Encode with expiry (message expires logically after 60s):
   hylexcrypt encode carrier.png -o outdir -m "Ephemeral" -p "Pass!" --expire 60

4) Wipe embedded message bits in place (keeps file):
   hylexcrypt wipe-message outdir/carrier_stego.png

5) Schedule a background wipe (autowipe) that runs detached:
   hylexcrypt encode carrier.png -o outdir -m "AutoWipe" -p "Pass!" --autowipe 120

 Avail Flags: 
  --fec
  --autowipe
  --decoys
  --compress
  --device-lock
  --expire
  --pepper
  --profile
    
Security notes
--------------
 - Never share passwords on the command line in multi-user environments.
 - Device-locking binds decryption to the local device fingerprint; use only if you need device-bound protection.
 - Autowipe/wipe-later passes password to a background process; this is a convenience feature but has security implications.

Requirements
------------
 - Python 3.9+
 - Required: pillow, numpy, cryptography, argon2-cffi
 - Optional (recommended): scipy, reedsolo, soundfile, colorama, psutil

 For Full Documentation visit:
 -----------------------------
 https://hackmd.io/@hylexcrypt-tu2050/SkRnM51ogl
"""

# --- CLI Parser ---
def create_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hylexcrypt", description="HylexCrypt Ultimate 2050 - stego + crypto")
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

    man = sp.add_parser("manual", help="Display full manual")
    return p

# --- main with user-friendly error messages (no stack traces) ---
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
            for w in res["written"]:
                print("  ", w)
            if res["decoys"]:
                print("Decoys:")
                for d in res["decoys"]:
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
            wipe_later_action(int(args.delay), args.files, password=args.password, profile_name=args.profile, pepper=pepper, bind_device=args.device_lock)
            return 0

        logger.error("Unknown command")
        return 2

    except Exception as e:
        # Hide stack trace; present a clear friendly message and actionable hints
        msg = str(e) if str(e) else type(e).__name__
        print(RED + "ERROR:" + RESET, msg)
        # Provide tailored suggestions for common error types
        if isinstance(e, FileNotFoundError):
            print("Suggestion: One or more input files were not found. Check the file paths you provided.")
        elif isinstance(e, ValueError):
            # generic value errors often are capacity, payload length or expired
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
        # Do NOT print traceback / source code
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
HylexCrypt - The Ultimate 2050 - Unified Advanced Stego + Crypto Tool (single file)

"""