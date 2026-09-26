"""Cipher and checksum primitives for the Lockly frame protocol.

No Home Assistant imports, no I/O, no logging. Everything here is a pure
function over bytes so it can be tested standalone and reasoned about.

`cryptography` is the only dependency and it is already a hard Home Assistant
core requirement, which is why this integration ships `requirements: []`.

AES mode is **ECB**, confirmed by disassembly of `libkey.so` (2026-09-19): a
table-driven AES-128 round looped over independent 16-byte blocks, no IV and no
chaining. The dispatcher is never handed a model id, firmware version or
opcode, so every lock model runs byte-identical AES-128. ECB is a weak mode in
general; it is what the lock implements, and the anti-replay story here rests
on a plain timestamp rather than on the cipher (see the README's disclosure).
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK = 16

# poly 0x31, init 0x00, non-reflected, no final XOR. Not a named standard --
# closest relatives are CRC-8/NRSC-5 (same poly, init 0xFF) and CRC-8/MAXIM
# (same poly but reflected), and both give different answers. Do not
# "correct" this to a named variant.
CRC8_POLY = 0x31
CRC8_INIT = 0x00


def crc8(data: bytes) -> int:
    """CRC-8 over `data`, MSB-first.

    Covers every byte of a frame except the final CRC byte itself.
    """
    crc = CRC8_INIT
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = ((crc << 1) ^ CRC8_POLY) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc


def crc8_ok(frame: bytes) -> bool:
    """True when a whole frame's trailing CRC byte matches its contents."""
    return len(frame) >= 2 and crc8(frame[:-1]) == frame[-1]


def aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    """AES-128-ECB. `data` must already be block-aligned -- padding is the
    caller's job and is part of the frame format, not of the cipher.

    The native library rejects non-block-aligned input outright, so this
    raises rather than padding silently on the caller's behalf.
    """
    _check(key, data)
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()  # noqa: S305
    return enc.update(data) + enc.finalize()


def aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    """AES-128-ECB. Returns plaintext with frame padding still attached; use
    the reply parser's strip, which has to handle two padding conventions."""
    _check(key, data)
    dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()  # noqa: S305
    return dec.update(data) + dec.finalize()


def _check(key: bytes, data: bytes) -> None:
    if len(key) != BLOCK:
        raise ValueError(f"AES key must be {BLOCK} bytes, got {len(key)}")
    if not data or len(data) % BLOCK:
        raise ValueError(
            f"AES input must be a non-zero multiple of {BLOCK} bytes, got {len(data)}"
        )


# --- key material ---------------------------------------------------------
#
# Two functions below XOR the master code against the lock uuid, and they use
# **different modulo conventions**: `derive_key` wraps on the uuid's hex-string
# length, `encrypt_master_code` on its byte length. That is not a transcription
# error, it is what the application does in two separate helpers. Do not
# refactor them into one.

MIN_MC_DIGITS = 4
MAX_MC_DIGITS = 9


def _digits(master_code: str) -> bytes:
    """One byte per decimal digit: "1234" -> b"\\x01\\x02\\x03\\x04".

    The app reaches this by prefixing each character with '0' and hex-decoding,
    so a non-digit character would decode to something else entirely. Reject
    rather than reproduce that.
    """
    if not master_code.isdigit():
        raise ValueError("master code must be decimal digits")
    return bytes(int(c) for c in master_code)


def check_master_code(master_code: str) -> None:
    """Reject the lengths the app cannot encode correctly.

    Below 4 digits the app throws: the second key region needs `digit[0..3]`.
    Above 16 it throws too, writing past a 16-byte key array.

    We stop at **9**, well before either, because of a separate ambiguity in
    the frame's `mcLen` field: the app renders the digit count with Java's
    decimal `toString` and then hex-decodes it, so 10 digits emits `0x10` (16),
    not 10. Whether the lock reads that byte as binary or as BCD is not
    decidable from the application, and a lock is the wrong place to find out.
    Real Lockly master codes are 6-8 digits.
    """
    n = len(master_code)
    if n < MIN_MC_DIGITS:
        raise ValueError(f"master code must be at least {MIN_MC_DIGITS} digits")
    if n > MAX_MC_DIGITS:
        raise ValueError(
            f"master code is {n} digits; refusing above {MAX_MC_DIGITS} because "
            "the mcLen field's encoding is ambiguous past 9 and untestable"
        )


def derive_key(master_code: str, uuid: bytes, uuid_hex_len: int | None = None) -> bytes:
    """The AES-128 key, reproducing the application byte for byte.

    `libkey.so` performs no derivation of its own -- it is handed these 16
    bytes and runs only the standard AES key schedule -- so this function is
    the entire derivation, quirks included.

    Two quirks are deliberate and must not be "fixed":

    **A 6-digit master code leaves `key[6]` and `key[7]` zero.** The first
    region's loop runs only as many times as there are digits, and the second
    region starts at index 8, so nothing ever writes 6 and 7. Two key bytes
    carry no entropy.

    **The wrap is on the uuid's hex-string length, not its byte length.** This
    lock's uuid is 12 bytes -- 24 hex characters -- so the wrap is `% 24`, while
    the loop above indexes at most 8 bytes in. It therefore never wraps and
    never protects anything: it is unreachable on any input that does not
    already fail the length check. Kept visible because the sibling function
    below wraps on the **byte** length, where the same expression wraps at 12
    and produces a different key. Conflating the two is silent.
    """
    check_master_code(master_code)
    mc = _digits(master_code)
    if len(uuid) < 12:
        raise ValueError(f"lock uuid must be at least 12 bytes, got {len(uuid)}")
    wrap = uuid_hex_len if uuid_hex_len is not None else len(uuid) * 2
    if wrap < 1:
        # `i % 0` is a ZeroDivisionError, which reads like an arithmetic bug
        # rather than a bad argument.
        raise ValueError(f"uuid_hex_len must be at least 1, got {wrap}")

    key = bytearray(BLOCK)
    for i in range(len(mc)):                      # region A
        key[i] = uuid[i % wrap] ^ mc[i]
    for i in range(8, 12):                        # region B, overwrites A
        key[i] = uuid[i] ^ mc[i - 8]
    key[12:16] = uuid[0:4]                        # region C, no XOR at all
    return bytes(key)


def encrypt_master_code(master_code: str, uuid: bytes) -> bytes:
    """The obfuscated master code carried *inside* the frame payload.

    Same two inputs as `derive_key` and a similar XOR, but this one wraps on
    the uuid's **byte** length. One byte out per digit in.
    """
    check_master_code(master_code)
    mc = _digits(master_code)
    if not uuid:
        raise ValueError("lock uuid must not be empty")
    return bytes(mc[i] ^ uuid[i % len(uuid)] for i in range(len(mc)))
