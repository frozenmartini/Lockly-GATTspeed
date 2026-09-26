"""Cloud enrolment -- sign in once, read this lock's codes.

This is the one place the integration talks to a vendor server, and it runs
**only in the config flow**. Nothing here is on the command path: the three
values it fetches never expire, so once an entry exists this module is idle.
That is why `iot_class` is `local_polling`.

Nothing from the sign-in is kept: not the email, not the password, not its
hash and not the token. The entry keeps the chosen lock's codes only.

## Where every line of this came from

Written from this project's own sources and nothing else. None of them ship
with the component; they are the project's private research notes:

* the cloud-enrolment API note (`lockly-cloud-enrolment-api.md`) -- the
  endpoints, the request envelope, the password transform, the token, the
  response layout and the `cod` taxonomy, each with a `file:line` citation
  into the decompiled application.
* the `libkey.so` disassembly note (`native-libkey-cloud-enrolment-crypto.md`),
  written on the decompiling machine for backstage `lockly#009`, which supplied
  the algorithm, mode, padding and encoding of all four crypto natives.
* the decompiled application itself, re-read directly for the constants below
  rather than copied from anywhere.

**No code from `dev/lockly`, from its upstream `Forcky/LocklyHA`, or from any
other Lockly integration was read into this file or used as a test oracle.**
That is the owner's standing rule for this project and it holds here too.

## The two traps that would fail silently

**RSA is `NONE/NoPadding`, not PKCS#1 v1.5.** The app builds its cipher with an
explicit `BouncyCastleProvider` and the bare transform string `"RSA"`, and in
the bundled BouncyCastle bare `Cipher.RSA` maps to `CipherSpi$NoPadding`
(`RSA.java:93`; PKCS#1 is the separate `"RSA/PKCS1"` at `:95`, OAEP only
`"RSA/OAEP"` at `:102`). Python's own habits go the other way, so this is
implemented as a raw modular exponentiation -- `cryptography` deliberately
offers no NoPadding mode. Get this wrong and the request is well-formed
ciphertext the server rejects, which reads as a request-shape bug for hours.

**⚠️ CORRECTED 2026-09-22 — outbound `para` needs PKCS#7, not zero-padding.**
`native-libkey-cloud-enrolment-crypto.md`'s disassembly of native `l`
(`DES3Utils.c`) reads zero-padding, and that is what shipped here. Live
against the real server it produced `cod=909` ("system error") on every
DES3-encrypted post-login endpoint tried (`acu/list`, `acu/crdntl/list`,
`getEkeyList`) -- see backstage `lockly#014`. Switching the *encrypt* side to
PKCS#7 took all three to `cod=200` on the first try, with nothing else
changed; the RSA-encrypted `login`/device-list calls were never affected
either way. **Decrypt is unaffected by this correction** -- the records the
server sends back are PKCS#5-padded regardless (see `strip_des3_padding`),
so decrypt already had to and still does tolerate both schemes. The
disassembly and the live server disagree on the encrypt side; `lockly#014`
has the open ask back to re-check `l` at the byte boundary. Until that's
resolved, trust the live result: it is what the server actually accepts.

## The keys

The two RSA keys are in `cloud_keys.py`. They are the vendor app's own
constants, shipped inside every copy of the app, and not secrets.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.serialization import (
    load_der_private_key,
    load_der_public_key,
)

try:  # cryptography >= 43 moved it, and >= 48 removes the old path entirely
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:  # pragma: no cover -- only on cryptography < 43
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

from .cloud_keys import CLIENT_PRIVATE_KEY_DER_B64, SERVER_PUBLIC_KEY_DER_B64

_LOGGER = logging.getLogger(__name__)

# ── Endpoints ──────────────────────────────────────────────────────────────

API_BASE = "https://apiserv03c.lockly.com/pgsmtlkv2/api/"
"""`PgConfig.a()`, read from the decompiled tree.

`PgConfig` returns six other hosts. `b()`/`c()` are the common-API host,
`d()`/`e()` feedback, `f()` a short-link domain -- none are on this path.
"""

ENDPOINT_LOGIN = "login"
ENDPOINT_DEVICE_LIST = "qrylknew"
"""`@POST("qrylknew")`, method `queryAccount`, `PGNetManager.java:950-951`.

**This was `getUserInfoAndDvList` until 2026-09-20, and that was wrong.** It
returned `cod` 200, a valid session key and a `dl` array, and not one record
in it carried a master code -- so setup told the owner their account held no
usable lock, on an account that holds one.

The mistake was reasoning from the *parser* to the *payload*.
`AccountInfoBean` (A's type) extends `AccountQueryBean` (B's) declaring no
fields of its own (`AccountInfoBean.java:12`), and both decode each `dl`
element into the same `BackupLockBean`, which does carry `mc`/`hc`/`ID`
(`:141-142`, `:128-129`, `:115-116`). Identical types, so "it carries the same
`key` + `dl` pair" was true -- and told us nothing about what the server
chooses to put there.

What settles it is the consumer side. `AccountInfoBean.getLockList()` -- the
A-only decoder -- has exactly one caller in the whole tree
(`LockManager.java:78`), and the writers it feeds set uuid, name, lockType,
version, houseId, roomId and bleName, **and no master code or house code**.
The only writer of those onto a host's lock is `UserManager.O0()`
(`:803`, `:806-807`), reached solely through `D0()` (`:267-269`), and every
caller of `D0` is fed by a **`qrylknew`** response. A's decoder also skips the
second DES3 decrypt of `aesKey`/`guestKey` that B's does
(`AccountQueryBean.java:68-69`), which is consistent with those sub-fields not
being there to decrypt.

The `lockList.size() <= 5` condition that argued against B reads the *local
database* after A has already populated it (`LockerManager.java:723-738`,
written by `LockManager.P()`), so it means "this account owns five or fewer
locks" -- a small-account fast path, trivially true for one lock, not a reason
B is unavailable. Above five the app fetches per-lock, `qrylknew` again with
`dv` set (`LockInfoDataSource.java:85`). Credentials arrive over B either way.

Not provable from the APK: whether the server *could* populate A's `dl` with
credentials. The app never asks it to. One place reads `hc` off a possibly-A
payload (`WrongPassword.java:158-186`), which is why this says "the app never
relies on it" rather than "the server never sends it".
"""

ENDPOINT_DEVICE_LIST_LEGACY = "getUserInfoAndDvList"
"""`PGNetManager.java:848-849`. Not called. Kept named so the endpoint this
integration shipped by mistake is greppable from the docstring above."""

# ── Request envelope ───────────────────────────────────────────────────────

APP_VER = "334"
APP_VERSION_NAME = "3.3.4"
"""`AppUtils.k()`/`l()` return the int 334; `n()` returns `"3.3.4"`.

Read from the decompiled tree, which is APK 3.3.4. Both are hardcoded returns,
not build config, so they are constants in the app too.
"""

APP_TYPE = "LOCKLY"
"""`PostBody`'s constructor. The `LOCKLY_PRO` branch is behind `AppUtils.z()`,
a hardcoded `return false` in this build."""

DEFAULT_LOCALE = "EN"
"""`LanguageManager.a()` returns the device language, **uppercased**."""

REQUEST_TIMEOUT_S = 30.0

PARA_CHUNK_BYTES = 64
"""Plaintext bytes per RSA block on the `para` path -- native `c`'s `0x40`.

Not a property of the key. `c` loops `chunk = min(remaining, 0x40)` at
`libkey.so` `0x27c84`, so the chunk size is fixed in the application and does
not widen if the modulus does. See `rsa_encrypt_para`.
"""


# ── Errors ─────────────────────────────────────────────────────────────────


class CloudError(Exception):
    """Anything that stopped the enrolment fetch.

    `cod` is the server's response code when one caused it, else None, and
    `step` names the call that answered it (`"login"` or `"device list"`).
    """

    def __init__(self, message: str = "", cod: str | None = None,
                 step: str | None = None) -> None:
        super().__init__(message)
        self.cod = cod
        self.step = step


class CloudKeysUnavailable(CloudError):
    """The RSA key material is not present. See `cloud_keys.py`."""


class CloudAuthError(CloudError):
    """The account or password was rejected -- retrying identically will not help.

    Wrong password (`906`), account disabled (`409`, `410`, `9010`) or account
    gone (`903`, `904`). A stored login that gets one of these is dead until the
    person signs in again; it is never retried.
    """


class CloudTokenExpired(CloudError):
    """The session token was refused (`403`, `407`, `408`) -- sign in again.

    Not an account problem: the token lasts 24 hours and renewing it means a
    fresh login (`TokenRenewInterceptor.isTokenExpired`). It must never drop a
    stored login. Nothing retries on it today: Options → Names reports it as
    unreachable and the person presses Submit again.
    """


class CloudProtocolError(CloudError):
    """The server answered, but not in a shape this code can use."""


COD_MEANINGS: dict[str, str] = {
    "200": "ok",
    "904": "no such account",
    "906": "wrong password",
    "9010": "account disabled",
    "403": "token expired",
    "407": "token expired",
    "408": "token expired",
    "409": "account disabled",
    "410": "account disabled",
    "903": "no such account",
    "909": "request could not be parsed",
    "910": "para was not encrypted",
}
"""`BaseResponseBean.java:16` makes `cod` a **string**, so compare it as one.

Labels are the app's own strings (`BaseResponseBean.getErrorInfo()`, read by
`windows` on backstage `lockly#016`, 2026-09-22): `409`/`410` "Your account is
disabled", `903`/`904` "Account not exist". Until 2026-09-23 this table called
`409`/`410`/`903` "signed out elsewhere" and grouped them with the token codes;
`isRejectLogin()` means *account gone or disabled*, and nothing in the app
enforces one session per account.
"""

_AUTH_CODES = frozenset({"409", "410", "903", "904", "906", "9010"})
_TOKEN_CODES = frozenset({"403", "407", "408"})


# ── The lock record ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class CloudLock:
    """One lock from the account, decrypted.

    `__repr__` is overridden and that is not cosmetic: two of these fields are
    the credentials this project is forbidden from printing anywhere, and a
    dataclass's generated repr would put all three into any log line, any
    `assert` failure and every traceback frame that happens to hold one.
    """

    name: str
    ble_name: str
    model: str
    master_code: str
    uuid_hex: str
    house_code: str

    def __repr__(self) -> str:
        return (
            f"CloudLock(name={self.name!r}, ble_name={self.ble_name!r}, "
            f"model={self.model!r}, master_code=<{len(self.master_code)} digits>, "
            f"uuid_hex=<{len(self.uuid_hex)} hex chars>, "
            f"house_code=<{len(self.house_code)} digits>)"
        )

    __str__ = __repr__


# ── Primitives ─────────────────────────────────────────────────────────────


def sha256_hex(password: str) -> str:
    """`LoginActivity.java:538` -> `SHA256Util.java:10-34`.

    SHA-256 over the UTF-8 bytes of the **trimmed** field text, lowercase hex,
    zero-padded per byte. No salt and no nonce, so the digest is a
    password-equivalent secret -- the cached copy is what the silent re-login
    replays (`TokenRenewInterceptor.java:63`). Never log it.
    """
    return hashlib.sha256(password.strip().encode("utf-8")).hexdigest()


def _b64d(value: str) -> bytes:
    """Base64 decode, tolerating missing `=` padding.

    The native encoder's line-wrapping is flag-gated and called in its
    non-wrapping branch, so values arrive unwrapped; whether it emits padding
    was not decidable from the disassembly. Accept either rather than depend
    on it.

    **`validate=True` is the important argument here.** Python's default is to
    *silently discard* characters outside the base64 alphabet, so a corrupted
    field decodes to plausible-looking wrong bytes instead of failing -- which
    downstream becomes a 3DES block that decrypts to noise, or an RSA integer
    that is simply not the one the server sent. Whitespace is stripped first,
    deliberately, so that wrapping stays acceptable while corruption does not.
    """
    if not isinstance(value, str):
        raise CloudProtocolError(f"expected a base64 string, got {type(value).__name__}")
    stripped = "".join(value.split())
    try:
        return base64.b64decode(stripped + "=" * (-len(stripped) % 4), validate=True)
    except (ValueError, TypeError) as err:
        # `binascii.Error` is a ValueError, and one escaping from here would
        # leave the config flow -- which catches `CloudError` -- to fail with
        # a traceback instead of a message.
        raise CloudProtocolError("value was not valid base64") from err


def cloud_available() -> bool:
    """Whether the cloud route can run at all in this build.

    The config flow asks this once, at the top, and skips straight to the
    manual form when it is false. Keeping the question here rather than
    reaching into `cloud_keys` from the flow means supplying the keys needs
    no change anywhere else.
    """
    return SERVER_PUBLIC_KEY_DER_B64 is not None and CLIENT_PRIVATE_KEY_DER_B64 is not None


def _require_keys() -> None:
    if not cloud_available():
        raise CloudKeysUnavailable(
            "The Lockly cloud RSA keys are not available in this build, so "
            "credentials cannot be fetched from the account. Enter the lock's "
            "master code, lock ID and access code by hand instead."
        )


def _public_key() -> Any:
    _require_keys()
    assert SERVER_PUBLIC_KEY_DER_B64 is not None
    return load_der_public_key(_b64d(SERVER_PUBLIC_KEY_DER_B64))


def _private_key() -> Any:
    _require_keys()
    assert CLIENT_PRIVATE_KEY_DER_B64 is not None
    return load_der_private_key(_b64d(CLIENT_PRIVATE_KEY_DER_B64), password=None)


def rsa_encrypt_para(plaintext: str, public_key: Any | None = None) -> str:
    """RSA/NONE/NoPadding encrypt, base64 out. Native `c`.

    Raw textbook RSA: each block is left-padded with zero bytes to exactly the
    modulus width and exponentiated. `cryptography` offers no NoPadding mode --
    correctly, since it is unsafe in general -- so this is `pow()` over the
    public numbers, which is what raw RSA is.

    **The plaintext is chunked at 64 bytes, not sent as one block.** `c` loops
    `chunk = min(remaining, 0x40)` / `offset += 0x40` (`libkey.so`
    `0x27c68-0x27cdc`), producing one `k`-byte cipher block per chunk, all
    concatenated before a single base64. The earlier reading of `c` as a single
    `doFinal` came from the Java wrapper's one call and was a wrapper artefact;
    `windows` corrected it on backstage `lockly#009`.

    That removes the payload ceiling this function used to enforce. A 1024-bit
    modulus leaves 126 usable bytes in one block, and a login `para` runs ~112
    bytes before the account name -- so a long enough address used to be
    refused outright. Chunked, length is not a limit at all.

    The chunk size also makes `m < n` structural rather than checked: 64 bytes
    into a `k`-byte block leaves `k - 64` leading zero bytes, so for any modulus
    wider than the chunk the integer cannot reach the modulus. A key narrow
    enough to break that is refused rather than silently wrapping.

    **Both forms are accepted by the live server** (verified 2026-09-20; the
    bench note `cloud-live-test.md` in the project's private docs records the
    run). Chunking is what the application does and what removes the ceiling,
    so it is what ships.
    """
    pub = public_key if public_key is not None else _public_key()
    numbers = pub.public_numbers()
    k = (numbers.n.bit_length() + 7) // 8
    if k <= PARA_CHUNK_BYTES:
        raise CloudProtocolError(
            f"modulus is {k * 8} bits; a {PARA_CHUNK_BYTES}-byte chunk needs a "
            f"wider key to guarantee the plaintext stays below it"
        )
    msg = plaintext.encode("utf-8")
    if not msg:
        raise CloudProtocolError("para is empty; there is nothing to encrypt")

    out = bytearray()
    for start in range(0, len(msg), PARA_CHUNK_BYTES):
        block = msg[start : start + PARA_CHUNK_BYTES]
        padded = b"\x00" * (k - len(block)) + block
        out += pow(int.from_bytes(padded, "big"), numbers.e, numbers.n).to_bytes(k, "big")
    return base64.b64encode(bytes(out)).decode("ascii")


def rsa_decrypt_session_key(value: str, private_key: Any | None = None) -> str:
    """RSA/NONE/NoPadding decrypt of the response `key` field. Native `d`.

    `d` accumulates through a `ByteArrayOutputStream`, so the field may be
    several concatenated blocks; each is exponentiated and the leading zeros
    that raw RSA reintroduces are stripped before the pieces are joined.
    """
    priv = private_key if private_key is not None else _private_key()
    numbers = priv.private_numbers()
    n = numbers.public_numbers.n
    d = numbers.d
    k = (n.bit_length() + 7) // 8

    raw = _b64d(value)
    if not raw or len(raw) % k:
        raise CloudProtocolError(
            f"session key field is {len(raw)} bytes, not a multiple of the "
            f"{k}-byte RSA block"
        )

    out = bytearray()
    for start in range(0, len(raw), k):
        block = int.from_bytes(raw[start : start + k], "big")
        if block >= n:
            raise CloudProtocolError("session key block is not below the modulus")
        out += pow(block, d, n).to_bytes(k, "big").lstrip(b"\x00")
    try:
        return out.decode("ascii")
    except UnicodeDecodeError as err:
        raise CloudProtocolError("session key did not decrypt to text") from err


def des3_key_from_session(session_key: str) -> bytes:
    """The session key string is base64 of exactly 24 key bytes -- K1|K2|K3.

    Three independent DES schedules, not two-key and not K1==K3. `windows`
    found the native length-checks the string at >= 32 characters, which is
    what 24 bytes of base64 comes to.
    """
    key = _b64d(session_key)
    if len(key) < 24:
        raise CloudProtocolError(
            f"session key decoded to {len(key)} bytes, need at least 24"
        )
    return key[:24]


def des3_encrypt(key: bytes, plaintext: str) -> str:
    """DESede-ECB, **PKCS#7 padding**, base64 out.

    Native `l` (`DES3Utils.c`) disassembles as zero-padding
    (`native-libkey-cloud-enrolment-crypto.md`), but the live server rejects
    a zero-padded `para` with `cod=909` and accepts a PKCS#7-padded one --
    proven 2026-09-22 against `acu/list`, `acu/crdntl/list` and `getEkeyList`
    on a real account. See the module docstring and backstage `lockly#014`.
    """
    data = plaintext.encode("utf-8")
    pad_len = 8 - (len(data) % 8)
    data += bytes([pad_len]) * pad_len
    encryptor = Cipher(TripleDES(key), modes.ECB()).encryptor()
    return base64.b64encode(encryptor.update(data) + encryptor.finalize()).decode(
        "ascii"
    )


def strip_des3_padding(data: bytes) -> bytes:
    """Remove whichever trailing pad is actually present.

    **We pad one way and the server pads another, and only the live server
    could say so.** `des3_encrypt` zero-pads, which is what the native library
    does on the way out and what the server accepted from us at login. The
    records it sends *back* are PKCS#5-padded, so stripping zeros left the pad
    bytes on the JSON and every record failed to parse -- reported to the owner
    as "that account has no locks with usable codes on it", on an account with
    a lock. Found 2026-09-20, against the real server, after the endpoint fix
    finally got a record back to decrypt.

    Unambiguous for these payloads: a PKCS#5 tail is 1-8 bytes each equal to
    the count, and a JSON object ends with `}` (0x7D), so the two can never be
    confused. Anything that is not a valid PKCS#5 tail falls through to the
    zero strip, which is what our own fixtures and `getHostMasterCode` use.

    Whether the native library pads records with PKCS#5 in the encrypt
    direction too is **not decidable from the Java tree** -- `DES3Utils` is a
    five-line delegate into `libkey.so` -- and is a question for `windows`.
    Handling both is cheaper than being certain.
    """
    if data:
        pad = data[-1]
        if 1 <= pad <= 8 and data[-pad:] == bytes([pad]) * pad:
            return data[:-pad]
    return data.rstrip(b"\x00")


def des3_decrypt(key: bytes, value: str) -> bytes:
    """DESede-ECB decrypt, trailing pad removed. Native `m`."""
    raw = _b64d(value)
    if not raw or len(raw) % 8:
        raise CloudProtocolError(
            f"ciphertext is {len(raw)} bytes, not a multiple of the 8-byte block"
        )
    decryptor = Cipher(TripleDES(key), modes.ECB()).decryptor()
    return strip_des3_padding(decryptor.update(raw) + decryptor.finalize())


# ── Envelope and responses ─────────────────────────────────────────────────


def device_id_for(email: str) -> str:
    """A stable per-account `dvid`: 32 lowercase hex characters.

    The app persists a random UUID with its hyphens stripped
    (`DeviceUtils.java:31-33`, `LockerConfig.java:1105-1113`). Reading the app
    cannot say whether the server registers that value, or challenges an
    unfamiliar one -- the `smstoken` endpoint exists and the login screen has a
    two-factor branch (`PGNetManager.java:3840-3850`).

    So it is derived from the account name rather than drawn fresh: the same
    account presents the same device on every attempt, which is the benign
    reading whichever way the server treats it, and it needs nothing stored.
    """
    digest = hashlib.sha256(f"lockly_gattspeed:{email.strip().lower()}".encode())
    return digest.hexdigest()[:32]


def build_post_body(para: str, email: str, locale: str = DEFAULT_LOCALE) -> dict[str, str]:
    """`PostBody.java:12-39`, Gson field names as wire keys, nulls dropped.

    Corroborated field-for-field by the Kotlin twin `bean/RequestBody.java`,
    which carries explicit `@SerializedName` -- a worthwhile cross-check, since
    an obfuscator could have renamed `PostBody`'s fields without the wire
    format changing.

    `did`, `md`, `mod`, `pmcId`, `ref` and `turnstileToken` are left null by
    the constructor on this path and Gson omits them, so they are absent here
    rather than empty. `turnstileToken` in particular belongs to three other
    endpoints (`chkac`, `renewpwreq`, `smstoken`) and sending it would be wrong.
    """
    return {
        "os": "android",
        "ver": APP_VER,
        "versionName": APP_VERSION_NAME,
        "appType": APP_TYPE,
        "para": para,
        "tk": "",
        "dvid": device_id_for(email),
        "rid1": "",
        "rid2": "",
        "ctry": "",
        "locale": locale,
    }


def check_cod(body: Any, what: str) -> None:
    """Raise the right error class for a non-200 `cod`."""
    if not isinstance(body, dict):
        raise CloudProtocolError(f"{what}: response was not a JSON object")
    cod = str(body.get("cod", ""))
    if cod == "200":
        return
    meaning = COD_MEANINGS.get(cod, "unrecognised response code")
    if cod in _AUTH_CODES:
        raise CloudAuthError(f"{what}: {meaning} (cod {cod})", cod=cod, step=what)
    if cod in _TOKEN_CODES:
        raise CloudTokenExpired(f"{what}: {meaning} (cod {cod})", cod=cod, step=what)
    raise CloudProtocolError(f"{what}: {meaning} (cod {cod})", cod=cod, step=what)


def parse_lock_records(body: Any, session_key: bytes) -> list[CloudLock]:
    """Decrypt `dl` and map each record onto the three values the BLE path needs.

    Field names from `BackupLockBean.java`: `mc` master code `:141-142`, `ID`
    lock uuid `:115-116` -- capital I, capital D -- `hc` house code `:128-129`,
    `mod` model `:134-135`, `blename` `:47-48`, `na` display name `:125-126`.
    Corroborated at `UserManager.java:800-806`, which maps exactly those into
    the app's own record.

    **`mc` is plaintext inside a record that is encrypted as a whole.** It is
    individually encrypted on `getHostMasterCode`, and conflating the two is a
    documented trap -- decrypting it twice yields nothing.

    **Two arrays, not one.** `dl` holds the locks the account owns; `sludl`
    (`AccountQueryBean.java:47-48`) holds the ones it is sub-admin on. The app
    always concatenates them before persisting (`LockManager.java:93-94`,
    `LockInfoDataSource.java:99-100`), so reading only `dl` silently drops a
    shared lock. A third array, `familyDeviceList`, is annotated
    `@SerializedName("")` and has no callers in 3.3.4; it is not read here.

    A record that will not decrypt or parse is skipped rather than fatal: one
    unreadable lock on a multi-lock account should not stop the others being
    offered, and the caller reports an empty list as its own failure.
    """
    records: list[Any] = []
    for key in ("dl", "sludl"):
        part = body.get(key) or []
        if not isinstance(part, list):
            raise CloudProtocolError(f"device list: {key!r} was not a list")
        records.extend(part)

    unreadable = 0
    incomplete = 0
    reasons: list[str] = []
    locks: list[CloudLock] = []
    for index, record in enumerate(records):
        try:
            plaintext = des3_decrypt(session_key, record)
        except (CloudProtocolError, ValueError, TypeError) as err:
            unreadable += 1
            reasons.append(f"record {index}: {type(err).__name__} decrypting")
            _LOGGER.debug("device list: record %d did not decrypt (%s)", index, err)
            continue
        try:
            fields = json.loads(plaintext)
            if not isinstance(fields, dict):
                raise CloudProtocolError("record did not decrypt to a JSON object")
            lock = CloudLock(
                name=str(fields.get("na") or "").strip(),
                ble_name=str(fields.get("blename") or "").strip(),
                model=str(fields.get("mod") or "").strip(),
                master_code=str(fields.get("mc") or "").strip(),
                uuid_hex=str(fields.get("ID") or "").strip().lower(),
                house_code=str(fields.get("hc") or "").strip(),
            )
        except (CloudProtocolError, ValueError, TypeError) as err:
            unreadable += 1
            # Shape, never content. Whether the plaintext even begins with `{`
            # separates the two hypotheses that look identical from outside: a
            # wrong session key gives random bytes, while a right key with the
            # wrong padding gives readable JSON with rubbish on the end.
            reasons.append(
                f"record {index}: {type(err).__name__} parsing {len(plaintext)} B"
                f", {'JSON-shaped' if plaintext[:1] == b'{' else 'not JSON-shaped'}"
            )
            _LOGGER.debug("device list: record %d did not parse (%s)", index, err)
            continue
        if not (lock.master_code and lock.uuid_hex and lock.house_code):
            incomplete += 1
            _LOGGER.debug("device list: record %d is missing a credential", index)
            continue
        locks.append(lock)

    if records and not locks:
        # WARNING, not DEBUG. This is the exact state that reaches the owner as
        # "that account has no locks with usable codes on it", and the two
        # DEBUG lines above explaining which of the three things happened are
        # invisible on any installation running `logger.default: warning` --
        # which is how shipping the wrong endpoint cost a session to diagnose.
        # Counts only; never a field value.
        _LOGGER.warning(
            "device list carried %d record(s) but none are usable: "
            "%d would not decrypt or parse, %d lack a master code, lock id or "
            "house code%s",
            len(records), unreadable, incomplete,
            f" [{'; '.join(reasons)}]" if reasons else "",
        )
    return locks


# ── The two calls ──────────────────────────────────────────────────────────


def _timeout() -> Any:
    """A `ClientTimeout` when aiohttp is present, a plain float otherwise.

    aiohttp deprecated bare numbers for this argument and removes them in 4.0,
    so passing `REQUEST_TIMEOUT_S` straight through would work today and stop
    working on an upgrade. The import is local because nothing else in this
    module needs aiohttp, which is what keeps it unit-testable against a
    scripted session object.
    """
    try:
        from aiohttp import ClientTimeout
    except ImportError:  # pragma: no cover -- only outside Home Assistant
        return REQUEST_TIMEOUT_S
    return ClientTimeout(total=REQUEST_TIMEOUT_S)


def _client_errors() -> tuple[type[BaseException], ...]:
    """aiohttp's `ClientError`, when aiohttp is present.

    Local for the same reason `_timeout` is: nothing else here needs aiohttp,
    and keeping the import out of module scope is what lets the unit tests
    drive this with a scripted session object.
    """
    try:
        from aiohttp import ClientError
    except ImportError:  # pragma: no cover -- only outside Home Assistant
        return ()
    return (ClientError,)


async def _post(session: Any, endpoint: str, body: dict[str, str], token: str | None) -> Any:
    """POST and return the parsed JSON body plus the response headers.

    Every way the transport can fail comes out as a `CloudError`, so the
    config flow catches one class and says "could not reach the service".
    aiohttp's own hierarchy is only partly `OSError`: a server that hangs up
    mid-body raises a plain `ClientError`, and a body that is not JSON -- a
    maintenance page in front of the API -- raises `json.JSONDecodeError`,
    which is a `ValueError`. Both once escaped the flow as a traceback.
    """
    headers = {"Content-Type": "application/json; charset=UTF-8"}
    if token:
        # Stored and replayed **verbatim**. No `Bearer ` prefix is added or
        # stripped anywhere in the app (`TokenRenewInterceptor.java:144-153`,
        # `AuthorizationInterceptor.java:90-95`), so the value is opaque and
        # manipulating it here would be inventing a format.
        headers["Authorization"] = token
    try:
        async with session.post(
            API_BASE + endpoint, json=body, headers=headers, timeout=_timeout()
        ) as response:
            # `content_type=None` because the server's declared type is not
            # guaranteed to be application/json and aiohttp is strict by
            # default.
            return await response.json(content_type=None), response.headers
    except _client_errors() as err:
        raise CloudError(f"{endpoint}: {type(err).__name__}: {err}") from err
    except ValueError as err:
        raise CloudProtocolError(f"{endpoint}: response body was not JSON") from err


async def async_login_hashed(session: Any, email: str, password_hash: str) -> str:
    """Sign in with the password's SHA-256 hex and return the session token.

    The hash is exactly what the app stores (`account_pwd_ciphertext`, plain
    lowercase SHA-256 hex on every write path) and re-sends to `login` when its
    token expires -- confirmed by `windows` on `lockly#016`. So a stored hash
    renews the token the way the app does. It is password-equivalent for
    Lockly: never log it.

    The token is an **HTTP response header**, not a body field -- the app
    captures it with an interceptor that inspects every response rather than
    from the login call's own payload.
    """
    _require_keys()
    para = rsa_encrypt_para(
        json.dumps(
            {"acct": email, "cloudId": "", "pw": password_hash},
            separators=(",", ":"),
        )
    )
    body, headers = await _post(
        session, ENDPOINT_LOGIN, build_post_body(para, email), token=None
    )
    check_cod(body, "login")
    token = headers.get("Authorization") or ""
    if not token:
        raise CloudProtocolError("login succeeded but carried no Authorization header")
    _LOGGER.debug("cloud login accepted, token of %d characters", len(token))
    return token


async def async_fetch_locks(session: Any, token: str, email: str) -> list[CloudLock]:
    """Fetch the account's locks with their credentials."""
    locks, _ = await _async_fetch_locks_and_key(session, token, email)
    return locks


async def _async_fetch_locks_and_key(
    session: Any, token: str, email: str
) -> tuple[list[CloudLock], bytes]:
    """The device list, and the session key later calls encrypt `para` with."""
    _require_keys()
    para = rsa_encrypt_para(json.dumps({"acct": email}, separators=(",", ":")))
    body, _ = await _post(
        session, ENDPOINT_DEVICE_LIST, build_post_body(para, email), token=token
    )
    check_cod(body, "device list")

    wrapped = body.get("key")
    if not wrapped:
        raise CloudProtocolError("device list carried no session key")
    session_key = des3_key_from_session(rsa_decrypt_session_key(wrapped))

    locks = parse_lock_records(body, session_key)
    _LOGGER.debug("device list returned %d usable lock record(s)", len(locks))
    return locks, session_key


async def async_fetch_account(
    session: Any, email: str, password_hash: str
) -> list[CloudLock]:
    """Sign in with the password hash and fetch the account's locks.

    One sign-in, once, in the config flow. Nothing from it is kept but the
    chosen lock's three codes.
    """
    token = await async_login_hashed(session, email, password_hash)
    return await async_fetch_locks(session, token, email)
