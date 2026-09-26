"""Constants for Lockly GATTspeed."""

from __future__ import annotations

from typing import Final

DOMAIN: Final = "lockly_gattspeed"

# Config entry data. The keys match the full integration's, so an entry made
# here keeps working when the full integration replaces this one.
CONF_MASTER_CODE: Final = "master_code"
CONF_LOCK_UUID: Final = "lock_uuid"
CONF_HOUSE_CODE: Final = "house_code"
CONF_LOCK_NAME: Final = "lock_name"

# The lock's GATT service: commands are written to fff1, replies arrive as
# notifications on fff4, 20 bytes at a time.
WRITE_UUID: Final = "0000fff1-0000-1000-8000-00805f9b34fb"
NOTIFY_UUID: Final = "0000fff4-0000-1000-8000-00805f9b34fb"
CHUNK: Final = 20

# How a Lockly lock names itself when it advertises. A prefix only: the name
# is shortened differently by different Bluetooth radios.
LOCAL_NAME_PREFIXES: Final = ("PGK", "PGD")

REPLY_TIMEOUT_S: Final = 8.0
"""The longest wait for any reply, a lock/unlock acknowledgement included."""

READ_TIMEOUT_S: Final = 2.5
"""The wait for one reply to a log read after a command. A read is safe to
repeat, so a short wait and another try beats one long wait."""

CONFIRM_FIRST_READ_DELAY_S: Final = 0.5
"""The pause between the lock's acknowledgement and the first log read. A read
sent while the motor is still stopping is often dropped."""

CONFIRM_READ_TRIES: Final = 5
CONFIRM_READ_GAP_S: Final = 1.0

# `open_type`s in the lock's own log. After one of these the bolt is thrown,
# or withdrawn; a record of any other type does not move the bolt.
LOCKS_BOLT: Final = frozenset({41, 42, 43, 44, 47, 48, 49, 58, 64, 80, 81, 94})
UNLOCKS_BOLT: Final = frozenset({
    1, 2, 3, 4, 5, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 20, 21, 22, 23, 24,
    25, 26, 27, 28, 29, 30, 31, 32, 33, 36, 50, 54, 55, 56, 57, 60, 61, 63,
    67, 68, 69, 70, 83, 92, 93,
})
JAMMED: Final = frozenset({37, 38})
"""The bolt jammed, or the lock refused to throw it because the door is open."""
