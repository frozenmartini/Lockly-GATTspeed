"""The two RSA keys the cloud enrolment path needs.

**To a reviewer or a secret scanner: these are not credentials, and there is
nothing to rotate, vault or move to an environment variable.** They are
constants compiled into the vendor's Android application, byte-identical in
every installation of it worldwide -- anyone who downloads the APK has them.
They are protocol constants in the same class as an opcode table or a CRC
polynomial. The private half decrypts a session key the server sends *to the
application in general*; it is not an identity, it authenticates nothing, and it
grants no access to any account. Any implementation that talks to this API must
use exactly these bytes, because different bytes are rejected by the server.

Measured rather than asserted: a third-party integration extracted the same keys
from an *older* build of the app, and the public key is byte-identical to ours
from the newer one (the project's `compare_keys.py` tool, kept outside this
repository).

The owner's actual secrets -- master code, house code, lock uuid, nonce, derived
AES key -- are covered by a strict redaction rule, never appear in this
repository, and are a different thing entirely.

They live in a module of their own so that the question "where did these come
from?" has exactly one place to look.

**They are two different keypairs, not a public/private pair.** That is the
protocol, not an artefact of extraction:

* `SERVER_PUBLIC_KEY_DER_B64` encrypts the `para` request payload, so that only
  the server, holding its private half, can read it. Native `c` in `libkey.so`.
* `CLIENT_PRIVATE_KEY_DER_B64` decrypts the `key` field the server returns,
  which the server encrypted to the application's embedded public half.
  Native `d`.

## Provenance

Reconstructed on the decompiling machine for backstage `lockly#009` from
`lib/arm64-v8a/libkey.so`, **381,280 bytes, SHA-256 `8685b94e...f7ce6fe6`**,
out of `LOCKLY 3.3.4` -- the same build our decompiled tree is from. The
write-up is the research note `native-libkey-cloud-enrolment-keys.md`, kept
with the project's private docs.

Each key's base64 is stored as **two 32-char header fragments plus one long
body**, scattered in `.rodata` among decoys. `sub_28004` rebuilds the header at
runtime as `strA[1::2] + strB[0::2]` -- odd-index characters of one string
followed by even-index characters of another -- then appends the body and
base64-decodes once. That de-interleave is why a plain `MIIB...` grep never
produced a usable key.

**Verified independently on this box, 2026-09-20** (27 checks, all passing,
recorded in the project's key-verification logs files): both DERs parse at
the stated sizes, both
moduli match the reported hex, both are 1024-bit with `e = 65537`,
`n == p*q`, `e*d = 1 mod lcm(p-1, q-1)`, `dP`/`dQ`/`qInv` correct, `p` and `q`
512-bit and Miller-Rabin prime at 40 rounds, and RSA round-trips through both
the plain and the CRT paths. `pub.n != priv.n`, confirming two keypairs.
Applying the de-interleave rule to the `.rodata` fragments reproduces both
canonical ASN.1 headers byte-identically.

**Cross-checked against APK 3.2.9, 2026-09-20** (recorded in the key-comparison
logs files):
a third-party integration built from that older library carries the *same*
public key byte-for-byte and the same private modulus (stored PKCS#1 where ours
is PKCS#8). **Neither key rotated between 3.2.9 and 3.3.4.**

## Two corrections this file used to carry

1. **The `2048-bit` inference was wrong.** This module previously reasoned that
   the SPKI fragments at `0x17e99` / `0x163ed` / `0x16b5a` were 2048-bit shaped
   and therefore the live key. They are **decoys** -- a scan of `.text` finds
   no instruction referencing them at all. Both real keys are 1024-bit.
2. **The payload-size argument that supported it was also wrong.** It assumed
   `c` is a single `doFinal`, so a `para` over ~127 bytes could not fit. The
   native `c` **chunks the plaintext in 64-byte input blocks**, each producing
   one 128-byte cipher block, concatenated before base64. A long payload is
   chunked, not rejected -- see `rsa_encrypt_para` in `cloud.py`.
"""

from __future__ import annotations

SERVER_PUBLIC_KEY_DER_B64: str | None = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCZtiijnvRo5EEI0n2I7shxljMX"
    "b7mZ/FpjuS98MHGWuYYUrsiJQVgfPn29lmI/MDkhVc7oVTsg5BIyC0TUpZKTgxyF"
    "DZw08AdWKe9JZvzyGB00AGkRxcem2J64xJJ04o9FW6PDLF0gSvblZAvUdHU1YyfB"
    "7DgJhikP7lPrFNdGwwIDAQAB"
)
"""X.509 SubjectPublicKeyInfo DER, base64. Encrypts `para`. Native `c`."""

CLIENT_PRIVATE_KEY_DER_B64: str | None = (
    "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAMBZug0p9CRIsZI+"
    "o3rMj1dlKt7AE52Ql44dSgVvaTVZ3ZWB2vRpvA80cF/QQXVbODgaU3xD0ZTkeGY6"
    "EP3lQaxLwGbQC1xrfLl4rVJPBt2qk0EtSQt729rOYBzMJSp0r5fPMmVDPogp3neM"
    "lFhP2xFlkp+yy+hsbkvXmsT9kpZjAgMBAAECgYAy0cIBJlt1lqsrq1b/47nfakA4"
    "V+EW2RPhnUVoSDYwvUx46rURrDnefolOFzSkL/SbhgEWrMhboT1aLO8+VWrTCF3B"
    "L2BPK0+G0QGYh8l56qk0dyoJiAz6Qus4OSlypNO01VIZGhNfayYlPjVlrZtDRTZF"
    "1kPbnUjcUwEKsrHXcQJBAOZbj4zopmYTfB7xFsbyP/K7nMOREjANLilie1Fkl8RZ"
    "8xSRwdz6s7r1Vx3JuUZbwyyNMG27NO+tZgdvF0u3pskCQQDVwxYUyuF+iIH9Ia2q"
    "Q1c1Al5fIBBUY8o7BT4tviLpQEjL2lZeJBvlRRzCyiZZISR+KXq8Id4+OKVpix6F"
    "oC3LAkB9z0niannezAuBFqka9NmKJ38hrEyjo78vaRLyzB67ZWkGNekMWHvqwu3W"
    "XgLrc1hwL5hghdsOf8R2kOzHNMFJAkA7xh+olMrVbSqcNAyx7b63DgCBrR+j2Xu1"
    "YVPvyplMjDNO/bDlBkfepqLSPWDXz5K6zLKLZRUWZRSsHMDeMNpdAkB1CAvpgzVt"
    "/OYbGvUDDK9VFbKtprN0hyFxuaX/pYaQL8hz7l+wkSvAd6lQgNlW5qLfYog06XUe"
    "xrOFRvMjIhMm"
)
"""PKCS#8 PrivateKeyInfo DER, base64. Decrypts the session `key`. Native `d`."""
