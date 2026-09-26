"""The one base class everything in this package raises.

**Why this exists.** Before it, the package raised three unrelated bases
across six exceptions: `UnknownLockType` and `OpcodeNotAllowed` from bare
`Exception`, and `FieldError`, `ReplyError`, `MotorAckParseError` and
`StatusParseError` from `ValueError`. Nothing tied them together, so a caller
had to enumerate all six to handle "the protocol layer refused this" -- and
the integration's setup path enumerated three of them and let the rest escape.
That left a connected, keepalive-holding link running behind a config entry
that had reported failure, holding the lock's only BLE slot.

A caller that wants to handle every protocol refusal catches `ProtoError`. One
that wants to distinguish them catches the specific class, as before.

The `ValueError` in the bases of the parse errors is kept deliberately: this
package is usable without Home Assistant, and an existing `except ValueError`
around a decode call must keep working.
"""

from __future__ import annotations


class ProtoError(Exception):
    """Base for every error raised by this package.

    Catching this means "the protocol layer refused, or could not parse,
    something". It never means an I/O failure -- this package performs no I/O
    and has no transport. A timeout or a disconnection is the caller's to
    raise and the caller's to catch.
    """
