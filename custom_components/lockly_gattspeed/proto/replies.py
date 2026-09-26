"""Reply classification, decryption and padding strip.

Reply layout, which is **not** the request layout:

    [0..3]    A1 B2 C3 D4
    [4..5]    total frame length, LE16
    [6..8)    reply cmd code, PLAINTEXT -- 0x0A + the echoed opcode
              (3 bytes on 500-group-password models)
    [8..n-1)  payload -- ciphertext on success, one plaintext byte on an error
    [n-1]     CRC-8

**There is no metadata byte on a reply.** So inbound padding has to describe
itself, and does, by two different conventions -- see `strip_padding`.

**Classify on the reply code, never on length.** `0x1E` and `0x34` both return
121-byte frames with completely different layouts past byte 62, so length
cannot tell them apart. The code can. There is also no correlation id anywhere
in this protocol, which is why only one command may ever be in flight: a reply
is assumed to belong to the outstanding request, and the code is the only
check on that assumption.
"""

from __future__ import annotations

from .errors import ProtoError

from dataclasses import dataclass, field
from enum import Enum

from .crypto import aes_ecb_decrypt, crc8_ok

MAGIC = bytes((0xA1, 0xB2, 0xC3, 0xD4))
ACK_PREFIX = 0x0A
"""First byte of a normal reply code."""

NAK_PREFIX = 0x0C
"""First byte of a negative acknowledgement.

Seen in only one place in the whole application -- a hard-coded frame literal
and one string comparison -- so the prefix is confirmed for two opcodes and
generalised. The *offset* of the error byte is certain; this prefix is not.
Treat a non-0x0A prefix as an error regardless of its value.
"""

ERROR_CODE_OFFSET = 8
MIN_FRAME = 10

ERRORS: dict[int, str] = {
    0xE7: "duplicate HomeKit password",
    0xF0: "access-code length rule violated",
    0xF1: "battery too low for OTA",
    0xF3: "master code error",
    0xF5: "a Bluetooth connection hiccup -- the frame did not arrive cleanly",
    0xF8: "cannot change password",
    0xF9: "validity window has not started",
    0xFA: "unknown command",
    0xFB: "maximum reached",
    0xFC: "master code not enabled -- the lock reports it has been reset or was never provisioned",
    0xFD: "code already used",
    0xFE: "generic system error",
    0xFF: "wrong password",
}

CREDENTIAL_ERRORS = frozenset({0xF3, 0xFA, 0xFF})
"""Codes that mean "your cached credentials are stale", so reauth, not retry.

Matching only 0xFF -- the obvious one -- misses two of the three, and the lock
then looks broken rather than re-authable.

**0xFC is deliberately not here, and was briefly added by mistake.** It reads
as a credential code -- "master code not enabled" -- and a session-03 note
called `{F3, FA, FC, FF}` the safe union. It is not. Six call sites in the
application treat `getErrorCode() == 252` as *the lock has been factory reset
or was never provisioned* and route to a reset flow
(`error-and-result-code-taxonomy-reharvest.md` §3.3-3.4). Prompting for
credentials answers it with the same master code and the same 0xFC, forever.
It has its own set below.

The original grouping here was copied from `Cmd.isMasterCodeError()`, which
switches a 4-character command type against 2-character error codes
(`Cmd.java:358`) and so can never match -- right in intent, taken from dead
code. That is why it is worth being explicit about each member.
"""

UNPROVISIONED_ERRORS = frozenset({0xFC})
"""The lock says it has no master code to check ours against.

Not a wrong credential and not a transport fault: the lock has been reset, or
this is not the lock that was enrolled. Neither reauth nor retry changes it.
`LocklyLink._classify` logs it as `lock_unprovisioned` and raises a plain
`LocklyError`, so it surfaces as a setup failure with a message that says what
happened rather than as a reauth prompt that cannot be satisfied.
"""

TRANSPORT_ERRORS = frozenset({0xF5})
"""The frame did not reach the lock intact -- a link fault, not a refusal.

Read by `LocklyLink._classify`, which logs it as `transport_error` rather than
`lock_error` so the two are distinguishable in a logs file. It deliberately
does **not** drive a retry: a read is safe to repeat and a motor command never
is, and no caller currently needs the distinction at runtime.

The constant name in the application disagrees with its own string --
`..._CRC_VERIFICATION` against "a hiccup with the Bluetooth connection". The
string is the one to trust; `windows` confirmed it from the resource table.
"""


class ReplyKind(Enum):
    SUCCESS = "success"
    ERROR = "error"
    MISMATCH = "mismatch"
    """A well-formed reply for a *different* command. Not an error from the
    lock -- a desynchronised stream, which only a reply-code check catches."""


class ReplyError(ProtoError, ValueError):
    """The frame is malformed: bad magic, bad CRC, or truncated."""


@dataclass(frozen=True)
class Reply:
    kind: ReplyKind
    opcode: int
    code: int | None = None
    """The error byte, when `kind` is ERROR."""

    plain: bytes = field(repr=False, default=b"")
    """Decrypted, padding-stripped payload. Excluded from `repr` and never in
    `to_log()` -- it is plaintext frame content."""

    @property
    def credential_failure(self) -> bool:
        return self.code in CREDENTIAL_ERRORS

    @property
    def transport_failure(self) -> bool:
        return self.code in TRANSPORT_ERRORS

    @property
    def unprovisioned(self) -> bool:
        return self.code in UNPROVISIONED_ERRORS

    @property
    def message(self) -> str:
        if self.code is None:
            return ""
        return ERRORS.get(self.code, f"undocumented error 0x{self.code:02X}")

    def to_log(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "opcode": f"0x{self.opcode:02X}",
            "code": None if self.code is None else f"0x{self.code:02X}",
            "message": self.message,
            "plain_len": len(self.plain),
        }

    def __str__(self) -> str:
        return f"Reply({self.to_log()})"


def strip_padding(plain: bytes, aes_f0: bool) -> bytes:
    """Remove inbound padding, reproducing the application exactly.

    Two conventions, and **0xF0 is checked first**:

    1. A single trailing `0xF0` terminator, on models in
       `isSupportAesEncryptF0()`. Strips exactly one byte.
    2. Otherwise a marker byte whose **low nibble** is N, followed by exactly
       N zero bytes. Strips N+1 bytes. The marker does not count itself.

    The app does this on the hex string rather than on bytes, and this
    function mirrors that arithmetic rather than reimplementing it, because
    the two are not equivalent at the edges. In particular the marker's *high*
    nibble is never examined -- `0x13` followed by three zeros strips exactly
    as `0x03` would. A byte-oriented rewrite that checked `marker == n_zeros`
    would diverge there.

    **This is content sniffing with no length field, and it is ambiguous.**
    Real data ending in `0x02 0x00 0x00` is indistinguishable from padding and
    will be stripped. Callers must validate the expected payload length for
    the opcode afterwards and treat a mismatch as a decode failure rather than
    trusting the strip.
    """
    text = plain.hex()
    if aes_f0 and text.lower().endswith("f0"):
        return plain[:-1]

    rev = text[::-1]
    idx = next((i for i, ch in enumerate(rev) if ch != "0"), None)
    if idx is None or idx <= 1:
        # All zeros, or fewer than two trailing zero characters: the app
        # leaves a lone trailing 0x00 alone.
        return plain
    marker = int(rev[idx], 16)
    if marker >= 1 and idx == marker * 2:
        return plain[: len(plain) - (idx + 2) // 2]
    return plain


def classify(frame: bytes, expect_opcode: int, key: bytes, aes_f0: bool,
             code_len: int = 2) -> Reply:
    """Validate, classify and decrypt one complete reply frame."""
    if len(frame) < MIN_FRAME:
        raise ReplyError(f"reply is {len(frame)} bytes, minimum is {MIN_FRAME}")
    if frame[:4] != MAGIC:
        raise ReplyError("reply does not start with the frame magic")
    declared = int.from_bytes(frame[4:6], "little")
    if declared != len(frame):
        raise ReplyError(
            f"length field says {declared} bytes, received {len(frame)}"
        )
    if not crc8_ok(frame):
        raise ReplyError("reply CRC-8 does not match")

    prefix = frame[6]
    echoed = frame[7]

    if prefix != ACK_PREFIX:
        # Negative acknowledgement. Plaintext, and short -- do not decrypt.
        # NOTE: this offset assumes a 2-byte reply code. On a 3-byte
        # (500-group-password) model the error byte would sit one later. No
        # such model is in the capability table, so the branch is unreachable
        # today; widen this with `code_len` before adding one.
        return Reply(
            kind=ReplyKind.ERROR,
            opcode=echoed,
            code=frame[ERROR_CODE_OFFSET],
        )

    if echoed != expect_opcode:
        # A valid ack for something else. With no correlation id in the
        # protocol, this is the only way to notice a desynchronised stream.
        return Reply(kind=ReplyKind.MISMATCH, opcode=echoed)

    body = frame[6 + code_len : -1]
    if not body or len(body) % 16:
        raise ReplyError(
            f"reply body is {len(body)} bytes, not a whole number of AES blocks"
        )
    plain = strip_padding(aes_ecb_decrypt(key, body), aes_f0)
    return Reply(kind=ReplyKind.SUCCESS, opcode=echoed, plain=plain)
