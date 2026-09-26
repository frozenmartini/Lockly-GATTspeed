"""Lockly frame protocol — pure, standalone, no Home Assistant, no I/O.

This package is the piece that survives every other decision in the
integration. It knows how to turn credentials and an intent into bytes, and
bytes back into decoded fields, and nothing else: no transport, no entity
model, no config entry, no logging. That is what makes it testable without a
lock and reusable if the Home Assistant layer is ever rewritten.

Written fresh from the decompiled Lockly application, not ported. The fork's
upstream is **not** used here, not even as a test oracle -- it has at least
four field-level errors that were app-derived and never checked against a
capture, and porting the code would inherit the readings.

Safety properties that live in this package and must not be relaxed:

- `frames.ALLOW` is the only gate between this integration and a factory
  reset. The transport carries opaque ciphertext and can enforce nothing.
- Credentials and plaintext never reach a `repr`, a `str` or a `to_log()`.
- Every payload field is mandatory. The application silently drops empty
  fields, shortening the frame; here that raises.
"""

from .access_log import (
    OPEN_TYPES,
    AccessLogError,
    AccessLogPage,
    AccessLogRecord,
    event_name,
    parse_access_log_page,
)
from .caps import (
    BOOTSTRAP,
    BootstrapOnly,
    Capabilities,
    UnknownLockType,
    capabilities_for,
)
from .crypto import crc8, derive_key, encrypt_master_code
from .errors import ProtoError
from .frames import (
    ALLOW,
    NEVER_SEND,
    Creds,
    FieldError,
    OpcodeNotAllowed,
    build,
)
from .motor_ack import MotorAck, MotorAckParseError, MotorResult, parse_motor_ack
from .replies import ERRORS, Reply, ReplyError, ReplyKind, classify
from .status import Status, StatusParseError, parse_status
from .telemetry import Telemetry, TelemetryParseError, parse_telemetry

__all__ = [
    "ALLOW",
    "AccessLogError",
    "AccessLogPage",
    "AccessLogRecord",
    "BOOTSTRAP",
    "BootstrapOnly",
    "Capabilities",
    "Creds",
    "ERRORS",
    "FieldError",
    "MotorAck",
    "MotorAckParseError",
    "MotorResult",
    "NEVER_SEND",
    "OPEN_TYPES",
    "OpcodeNotAllowed",
    "ProtoError",
    "Reply",
    "ReplyError",
    "ReplyKind",
    "Status",
    "StatusParseError",
    "Telemetry",
    "TelemetryParseError",
    "UnknownLockType",
    "build",
    "capabilities_for",
    "classify",
    "crc8",
    "derive_key",
    "encrypt_master_code",
    "event_name",
    "parse_access_log_page",
    "parse_motor_ack",
    "parse_status",
    "parse_telemetry",
]
