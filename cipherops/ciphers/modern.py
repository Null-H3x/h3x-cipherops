"""Modern symmetric, asymmetric, and hash-based cryptographic primitives."""

from __future__ import annotations

import base64
import hashlib
import json
from functools import lru_cache

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ed25519, padding as asym_padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding as sym_padding

MASTER = b"llm-cryptography-v1-dataset-seed"


def _hkdf(info: str, length: int) -> bytes:
    return HKDF(hashes.SHA256(), length, salt=b"llm-crypto-dataset", info=info.encode()).derive(MASTER)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def _pack(payload: dict[str, str]) -> str:
    return json.dumps(payload, separators=(",", ":"))


def _unpack(text: str) -> dict[str, str]:
    return json.loads(text)


def _aes_gcm(key_info: str, key_len: int, plaintext: str) -> str:
    key = _hkdf(key_info, key_len)
    nonce = _hkdf(f"{key_info}-nonce", 12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return _pack({"n": _b64(nonce), "c": _b64(ct)})


def _aes_gcm_decrypt(key_info: str, key_len: int, payload: str) -> str:
    data = _unpack(payload)
    key = _hkdf(key_info, key_len)
    pt = AESGCM(key).decrypt(_b64d(data["n"]), _b64d(data["c"]), None)
    return pt.decode("utf-8")


def aes_128_gcm_encrypt(plaintext: str) -> str:
    return _aes_gcm("aes-128-gcm", 16, plaintext)


def aes_128_gcm_decrypt(payload: str) -> str:
    return _aes_gcm_decrypt("aes-128-gcm", 16, payload)


def aes_256_gcm_encrypt(plaintext: str) -> str:
    return _aes_gcm("aes-256-gcm", 32, plaintext)


def aes_256_gcm_decrypt(payload: str) -> str:
    return _aes_gcm_decrypt("aes-256-gcm", 32, payload)


def _aes_cbc(key_info: str, key_len: int, plaintext: str) -> str:
    key = _hkdf(key_info, key_len)
    iv = _hkdf(f"{key_info}-iv", 16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    return _pack({"i": _b64(iv), "c": _b64(ct)})


def _aes_cbc_decrypt(key_info: str, key_len: int, payload: str) -> str:
    data = _unpack(payload)
    key = _hkdf(key_info, key_len)
    iv = _b64d(data["i"])
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(_b64d(data["c"])) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    pt = unpadder.update(padded) + unpadder.finalize()
    return pt.decode("utf-8")


def aes_128_cbc_encrypt(plaintext: str) -> str:
    return _aes_cbc("aes-128-cbc", 16, plaintext)


def aes_128_cbc_decrypt(payload: str) -> str:
    return _aes_cbc_decrypt("aes-128-cbc", 16, payload)


def aes_256_cbc_encrypt(plaintext: str) -> str:
    return _aes_cbc("aes-256-cbc", 32, plaintext)


def aes_256_cbc_decrypt(payload: str) -> str:
    return _aes_cbc_decrypt("aes-256-cbc", 32, payload)


def aes_128_ctr_encrypt(plaintext: str) -> str:
    key = _hkdf("aes-128-ctr", 16)
    nonce = _hkdf("aes-128-ctr-nonce", 16)
    encryptor = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
    ct = encryptor.update(plaintext.encode("utf-8")) + encryptor.finalize()
    return _pack({"n": _b64(nonce), "c": _b64(ct)})


def aes_128_ctr_decrypt(payload: str) -> str:
    data = _unpack(payload)
    key = _hkdf("aes-128-ctr", 16)
    decryptor = Cipher(algorithms.AES(key), modes.CTR(_b64d(data["n"]))).decryptor()
    pt = decryptor.update(_b64d(data["c"])) + decryptor.finalize()
    return pt.decode("utf-8")


def chacha20_poly1305_encrypt(plaintext: str) -> str:
    key = _hkdf("chacha20-poly1305", 32)
    nonce = _hkdf("chacha20-poly1305-nonce", 12)
    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return _pack({"n": _b64(nonce), "c": _b64(ct)})


def chacha20_poly1305_decrypt(payload: str) -> str:
    data = _unpack(payload)
    key = _hkdf("chacha20-poly1305", 32)
    pt = ChaCha20Poly1305(key).decrypt(_b64d(data["n"]), _b64d(data["c"]), None)
    return pt.decode("utf-8")


def triple_des_cbc_encrypt(plaintext: str) -> str:
    key = _hkdf("3des-cbc", 24)
    iv = _hkdf("3des-cbc-iv", 8)
    padder = sym_padding.PKCS7(64).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    encryptor = Cipher(algorithms.TripleDES(key), modes.CBC(iv)).encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    return _pack({"i": _b64(iv), "c": _b64(ct)})


def triple_des_cbc_decrypt(payload: str) -> str:
    data = _unpack(payload)
    key = _hkdf("3des-cbc", 24)
    iv = _b64d(data["i"])
    decryptor = Cipher(algorithms.TripleDES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(_b64d(data["c"])) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(64).unpadder()
    pt = unpadder.update(padded) + unpadder.finalize()
    return pt.decode("utf-8")


@lru_cache(maxsize=1)
def _fernet() -> Fernet:
    key = base64.urlsafe_b64encode(_hkdf("fernet-key", 32))
    return Fernet(key)


def fernet_encrypt(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def fernet_decrypt(token: str) -> str:
    return _fernet().decrypt(token.encode("ascii")).decode("utf-8")


def xor_sha256_stream_encrypt(plaintext: str) -> str:
    key = _hkdf("xor-sha256-stream", 32)
    data = plaintext.encode("utf-8")
    stream = b""
    counter = 0
    while len(stream) < len(data):
        stream += hashlib.sha256(key + counter.to_bytes(4, "big")).digest()
        counter += 1
    out = bytearray(byte ^ stream[i] for i, byte in enumerate(data))
    return _b64(bytes(out))


def xor_sha256_stream_decrypt(payload: str) -> str:
    key = _hkdf("xor-sha256-stream", 32)
    data = _b64d(payload)
    stream = b""
    counter = 0
    while len(stream) < len(data):
        stream += hashlib.sha256(key + counter.to_bytes(4, "big")).digest()
        counter += 1
    out = bytearray(byte ^ stream[i] for i, byte in enumerate(data))
    return bytes(out).decode("utf-8")


@lru_cache(maxsize=1)
def _rsa_keypair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    # Deterministic 1024-bit RSA parameters for dataset reproducibility (not for production).
    p = 8933081181530059413174384160823081721500087146552475442629592922963026799464676457604947806324923840578333696355633880255656283011736596603331878116859461
    q = 10937034156325506597647999777995396743784513657579938348353721947757552571363824495947116193545287150142166389980129538623905734818261364241055238700962211
    e = 65537
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    dmp1 = d % (p - 1)
    dmq1 = d % (q - 1)
    iqmp = pow(q, -1, p)
    pub_numbers = rsa.RSAPublicNumbers(e, n)
    priv_numbers = rsa.RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp, pub_numbers)
    private_key = priv_numbers.private_key()
    return private_key, private_key.public_key()


def rsa_oaep_hybrid_encrypt(plaintext: str) -> str:
    _, public_key = _rsa_keypair()
    aes_key = _hkdf("rsa-hybrid-aes", 32)
    nonce = _hkdf("rsa-hybrid-nonce", 12)
    ct = AESGCM(aes_key).encrypt(nonce, plaintext.encode("utf-8"), None)
    enc_key = public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return _pack({"ek": _b64(enc_key), "n": _b64(nonce), "c": _b64(ct)})


def rsa_oaep_hybrid_decrypt(payload: str) -> str:
    private_key, _ = _rsa_keypair()
    data = _unpack(payload)
    aes_key = private_key.decrypt(
        _b64d(data["ek"]),
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    pt = AESGCM(aes_key).decrypt(_b64d(data["n"]), _b64d(data["c"]), None)
    return pt.decode("utf-8")


@lru_cache(maxsize=1)
def _ed25519_keypair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    seed = _hkdf("ed25519-seed", 32)
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    return private_key, private_key.public_key()


def ed25519_sign_encrypt(plaintext: str) -> str:
    private_key, _ = _ed25519_keypair()
    signature = private_key.sign(plaintext.encode("utf-8"))
    return _pack({"m": _b64(plaintext.encode("utf-8")), "s": _b64(signature)})


def ed25519_sign_decrypt(payload: str) -> str:
    _, public_key = _ed25519_keypair()
    data = _unpack(payload)
    pt_bytes = _b64d(data["m"])
    public_key.verify(_b64d(data["s"]), pt_bytes)
    return pt_bytes.decode("utf-8")


@lru_cache(maxsize=2)
def _x25519_private(label: str) -> x25519.X25519PrivateKey:
    return x25519.X25519PrivateKey.from_private_bytes(_hkdf(f"x25519-{label}", 32))


def x25519_shared_secret_encrypt(plaintext: str) -> str:
    alice = _x25519_private("alice")
    bob = _x25519_private("bob")
    shared = alice.exchange(bob.public_key())
    digest = hashlib.sha256(shared + plaintext.encode("utf-8")).hexdigest()
    return _pack({"ss": shared.hex(), "h": digest, "m": _b64(plaintext.encode("utf-8"))})


def x25519_shared_secret_decrypt(payload: str) -> str:
    data = _unpack(payload)
    alice = _x25519_private("alice")
    bob = _x25519_private("bob")
    shared = alice.exchange(bob.public_key())
    if data["ss"] != shared.hex():
        raise ValueError("X25519 shared secret mismatch")
    pt_bytes = _b64d(data["m"])
    digest = hashlib.sha256(shared + pt_bytes).hexdigest()
    if data["h"] != digest:
        raise ValueError("X25519 payload digest mismatch")
    return pt_bytes.decode("utf-8")


def pbkdf2_aes_gcm_encrypt(plaintext: str) -> str:
    password = b"correct-horse-battery-staple"
    salt = _hkdf("pbkdf2-salt", 16)
    kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 100_000)
    key = kdf.derive(password)
    nonce = _hkdf("pbkdf2-aes-nonce", 12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return _pack({"salt": _b64(salt), "n": _b64(nonce), "c": _b64(ct)})


def pbkdf2_aes_gcm_decrypt(payload: str) -> str:
    password = b"correct-horse-battery-staple"
    data = _unpack(payload)
    salt = _b64d(data["salt"])
    kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 100_000)
    key = kdf.derive(password)
    pt = AESGCM(key).decrypt(_b64d(data["n"]), _b64d(data["c"]), None)
    return pt.decode("utf-8")


def hkdf_aes_gcm_encrypt(plaintext: str) -> str:
    ikm = _hkdf("hkdf-ikm", 32)
    salt = _hkdf("hkdf-salt", 16)
    info = b"llm-crypto-aes-gcm-v1"
    key = HKDF(hashes.SHA256(), 32, salt, info).derive(ikm)
    nonce = _hkdf("hkdf-aes-nonce", 12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return _pack({"n": _b64(nonce), "c": _b64(ct)})


def hkdf_aes_gcm_decrypt(payload: str) -> str:
    ikm = _hkdf("hkdf-ikm", 32)
    salt = _hkdf("hkdf-salt", 16)
    info = b"llm-crypto-aes-gcm-v1"
    key = HKDF(hashes.SHA256(), 32, salt, info).derive(ikm)
    data = _unpack(payload)
    pt = AESGCM(key).decrypt(_b64d(data["n"]), _b64d(data["c"]), None)
    return pt.decode("utf-8")


def sha256_digest(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def sha256_decrypt(_: str) -> str:
    raise ValueError("SHA-256 is one-way; decryption is undefined")


def sha512_digest(plaintext: str) -> str:
    return hashlib.sha512(plaintext.encode("utf-8")).hexdigest()


def sha512_decrypt(_: str) -> str:
    raise ValueError("SHA-512 is one-way; decryption is undefined")


def sha3_256_digest(plaintext: str) -> str:
    return hashlib.sha3_256(plaintext.encode("utf-8")).hexdigest()


def sha3_256_decrypt(_: str) -> str:
    raise ValueError("SHA3-256 is one-way; decryption is undefined")


def blake2b_digest(plaintext: str) -> str:
    return hashlib.blake2b(plaintext.encode("utf-8")).hexdigest()


def blake2b_decrypt(_: str) -> str:
    raise ValueError("BLAKE2b is one-way; decryption is undefined")


def hmac_sha256_digest(plaintext: str) -> str:
    key = _hkdf("hmac-sha256-key", 32)
    mac = hmac.HMAC(key, hashes.SHA256())
    mac.update(plaintext.encode("utf-8"))
    return mac.finalize().hex()


def hmac_sha256_decrypt(_: str) -> str:
    raise ValueError("HMAC-SHA256 is one-way; decryption is undefined")
