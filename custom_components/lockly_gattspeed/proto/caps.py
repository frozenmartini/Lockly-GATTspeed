"""Per-model capability table.

The lock's own behaviour varies by model, and the app expresses that as a pile
of boolean predicates (`isSupport82Cmd()`, `isVision()`, ...) over a lock-type
number. That number arrives in **byte 18 of the decrypted status reply**, not
from the cloud record -- so the flow is always: read status once, learn the
type, then build commands for it.

Two rules govern this file, and both exist because only one lock model can
ever be tested in this house.

**Every row is labelled `VERIFIED` or `DERIVED`, and the second never reads as
the first.** `VERIFIED` means observed on real hardware. `DERIVED` means read
out of the decompiled application and believed, but never sent to a lock.

**An unknown lock type is refused, not defaulted.** A missing predicate must
never silently evaluate false: "not in the 82-command list" and "we have never
heard of this model" would then build different frames while looking
identical, and the difference is which opcode operates the motor. Refusing is
the only safe reading of absent evidence.
"""

from __future__ import annotations

from .errors import ProtoError

from dataclasses import dataclass
from typing import ClassVar
from enum import Enum


class Provenance(Enum):
    """How much a row is worth."""

    VERIFIED = "verified on hardware"
    DERIVED = "derived from the application"


@dataclass(frozen=True)
class Capabilities:
    """What a lock model needs from the frame builders.

    Field names mirror the app's predicates so a claim here can be checked
    against the decompiled source without a translation step.
    """

    lock_type: int
    model: str
    provenance: Provenance

    supports_aes: bool
    """AES status command 0x1E rather than the legacy plaintext 0x09."""

    supports_82_cmd: bool
    """Motor command is 0x52 rather than 0x22. Also widens the slot field."""

    supports_timestamp: bool
    """Trailing 8-byte field is a little-endian millisecond timestamp rather
    than the nonce cached from the last status reply."""

    lithium_battery: bool
    """Battery is a plain percent at byte 7 rather than two LE u16 voltages."""

    aes_encrypt_f0: bool
    """Decrypted replies may use a single trailing 0xF0 terminator, which must
    be checked before the 0x0N-marker rule."""

    wide_slot_field: bool
    """The 0x52 slot field is 2-byte LE where 0x22 carries 1 byte."""

    supports_500_group_password: bool
    """Motor reply code is 3 bytes (0A2202) rather than 2 (0A52 / 0A22).
    Changes where the payload starts, so it changes every parse."""

    supports_148_cmd: bool
    """Access log is 0x94 with a split pwdId/relationUserId, rather than 0x7C
    with a 4-byte pwdId. v2 only, recorded so the table is complete."""

    def encrypt_type(self, opcode: int) -> int:
        """Low nibble of the frame's metadata byte.

        Not a constant per model: the 0x52 family carries **11 (0x0B)** for a
        host, while everything else carries 5. Confirmed twice in source
        (`NewUnlockCmd`, `LockStatusAndReportCmd`) and twice on hardware.

        The app's own enumeration of `{1,2,3,4,5,7}` is documentation of six
        constants that nothing references; `7` is never emitted by any
        builder. Do not "restore" it.
        """
        if opcode == 0x52 and self.supports_82_cmd:
            return ENCRYPT_TYPE_HOST_82
        return ENCRYPT_TYPE_HOST_AES

    def motor_opcode(self) -> int:
        """Which opcode operates the bolt on this model."""
        return 0x52 if self.supports_82_cmd else 0x22

    SUB_INDEXED_REPLIES: ClassVar[frozenset[int]] = frozenset({0x1A})
    """Opcodes whose reply code is 3 bytes **by opcode, not by model**.

    `OtherQueryCmd` does not override `getCmdType`, so it inherits `Cmd`'s
    3-byte default and its reply code is `0A1A01` -- the sub-index is echoed
    back. Reading it as 2 shifts the entire field map by one byte and every
    counter comes out wrong without anything failing.
    """

    def reply_code_len(self, opcode: int | None = None) -> int:
        """Reply cmd-type width in bytes, which sets where the payload starts.

        The frame header is `6 + len(reply_code)`. Most commands use a 2-byte
        code (0A || opcode); the sub-indexed ones use 3, and that is a
        property of the *command class*, not of the model -- which is why this
        takes an opcode. Passing none keeps the model-only answer, where for
        the v1 set only 0x22 can widen and only on 500-group-password models.
        """
        if opcode is not None and opcode in self.SUB_INDEXED_REPLIES:
            return 3
        return 3 if self.supports_500_group_password else 2


ENCRYPT_TYPE_HOST_AES = 5
"""`Cmd.getEncryptType()` for a host with AES -- 0x1E and ~120 other builders."""

ENCRYPT_TYPE_HOST_82 = 11
"""`NewUnlockCmd`: host on the 0x52 family. Guest is 12, long-term guest 13."""


PGK728WRHK = Capabilities(
    lock_type=105,
    model="PGK728WRHK",
    provenance=Provenance.VERIFIED,
    supports_aes=True,
    supports_82_cmd=True,
    supports_timestamp=True,
    lithium_battery=True,
    aes_encrypt_f0=True,
    wide_slot_field=True,
    supports_500_group_password=False,
    supports_148_cmd=True,
    )
"""The only model anyone here can test.

`supports_timestamp` is true via `isSupport82Cmd() && !isPGI301()`, **not**
via `isHost() && isVision()` -- 105 is not in the `isVision()` list, despite
what `status-block-and-ack-field-maps.md` says. Same answer, different
dependency, and the difference matters the moment this table grows.

Because the timestamp branch applies, v1 needs no nonce at all: 0x1E has no
nonce field, and the motor commands take the timestamp.
"""


class BootstrapOnly(Exception):
    """Something asked the bootstrap row for a model-specific answer."""


@dataclass(frozen=True)
class _BootstrapCapabilities(Capabilities):
    """The framing facts every row shares -- for the **first status read only**.

    There is a chicken and egg here: the lock type arrives in byte 18 of a
    status reply, and a status reply has to be asked for before it can be
    read. This row is the smallest honest answer to that, and it is not a
    default -- `capabilities_for` still refuses an unknown type.

    It is safe for exactly one command because **0x1E is model-independent in
    every respect that reaches the wire**: `encrypt_type()` returns 5 for it on
    every row in the table, and `build_status` consults nothing else.

    Two fields do affect the *reply* parse, and neither can change the answer
    this read exists to get:

    * `aes_encrypt_f0` is the padding convention. Wrong in either direction it
      strips or leaves one byte at the **tail**, and every field v1 reads --
      lock type included, at byte 18 -- sits below byte 91.
    * `reply_code_len()` is 2 here, which is correct for 0x1E on every model:
      only 0x22 widens, and only on 500-group-password models.

    The motor is the exact opposite -- which opcode moves the bolt is the
    model-specific fact -- so `motor_opcode()` refuses rather than guessing.
    """

    def motor_opcode(self) -> int:
        raise BootstrapOnly(
            "the bootstrap capabilities may only build a status read; the "
            "lock model is unknown until byte 18 of the reply has been parsed"
        )


BOOTSTRAP = _BootstrapCapabilities(
    lock_type=-1,
    model="<unidentified>",
    provenance=Provenance.DERIVED,
    supports_aes=True,
    supports_82_cmd=False,
    supports_timestamp=False,
    lithium_battery=False,
    aes_encrypt_f0=True,
    wide_slot_field=False,
    supports_500_group_password=False,
    supports_148_cmd=False,
)
"""Use once, to ask an unidentified lock what it is. Never for anything else.

`lock_type=-1` is deliberately not a real type, so a row that leaked into a
comparison or a log is obvious rather than plausible.
"""


_TABLE: dict[int, Capabilities] = {PGK728WRHK.lock_type: PGK728WRHK}


KNOWN_INCOMPLETE = True
"""This table covers one model out of a space of dozens.

The app's predicate membership lists are known by **model predicate name**
(`isPGK7SWH()`, `isPGD899G()`, ...) but most of those names have not been
mapped to the lock-type integer the status reply actually carries. Until that
mapping is traced, adding a guessed row would be inventing hardware
behaviour, so the table stays short and `capabilities_for` refuses instead.
"""


class UnknownLockType(ProtoError):
    """Raised for a lock type with no entry.

    Deliberately not a soft failure. The caller must surface this to the user
    as "this model is not supported yet" rather than proceeding on defaults --
    guessing `supports_82_cmd` wrong means sending 0x22 to a lock expecting
    0x52, or vice versa, which is a motor command built from the wrong table.
    """

    def __init__(self, lock_type: int) -> None:
        super().__init__(
            f"lock type {lock_type} is not in the capability table. "
            "Supported: " + ", ".join(
                f"{c.lock_type} ({c.model})" for c in _TABLE.values()
            )
        )
        self.lock_type = lock_type


def capabilities_for(lock_type: int) -> Capabilities:
    """Look up a model, or refuse. Never returns a default."""
    try:
        return _TABLE[lock_type]
    except KeyError:
        raise UnknownLockType(lock_type) from None


def supported_lock_types() -> tuple[int, ...]:
    return tuple(sorted(_TABLE))
