# Lockly GATTspeed

A Home Assistant integration that locks and unlocks a Lockly smart lock **directly over
Bluetooth**: no Lockly hub, and no cloud when you lock or unlock.

> **One model only.** This release supports the **Lockly Visage Zeno Series, model
> `PGK728WRHK`** (lock type 105), the only model tested on a real lock. Setup stops on any
> other model with *"This lock model is not supported yet"*.

This is a first, deliberately small release: one lock entity. A fuller release will follow.

Not affiliated with or endorsed by Lockly.

## What you need

- Home Assistant 2026.9 or later, with its **Bluetooth** integration working, and a Bluetooth
  radio in range of the lock. That can be the Home Assistant machine's own adapter, a USB dongle,
  or an [ESPHome Bluetooth proxy](https://esphome.io/components/bluetooth_proxy.html) near the
  door. Signal strength matters more than anything else here; a proxy near the door is the
  reliable choice.
- The **Lockly account** the lock is registered to, for one sign-in at setup.

## Install

**HACS:** add this repository as a custom repository (type *Integration*), install
**Lockly GATTspeed**, and restart Home Assistant.

**By hand:** copy `custom_components/lockly_gattspeed/` into your Home Assistant
`custom_components/` folder and restart.

## Set up

1. Home Assistant discovers the lock over Bluetooth. Open **Settings → Devices & services** and
   add it. You can also add *Lockly GATTspeed* yourself and pick the lock.
2. Sign in with your Lockly account. This fetches the lock's codes. If the account has more than
   one lock, pick this one.
3. The integration connects to the lock once, checks the codes and the model, and lets go. Only
   then is the lock added.

## How it works

You get one entity: the **lock**.

Each lock or unlock connects to the lock, reads its status, sends the command **once**, reads the
lock's own log to see where the bolt went, and disconnects. Expect a few seconds per command,
longer on a weak signal. Between commands the integration is not connected, so the lock stays free
for the Lockly app, Apple Home and anything else.

The lock entity shows:

- **Locking / Unlocking** while the command is sent,
- **Locked / Unlocked** from the lock's answer and its log,
- **Jammed** if the lock logs a jam for the command,
- **Unknown** if the lock did not answer. The command is never repeated automatically.

Between commands nothing is read. A change made at the lock (keypad, fingerprint, key, the Lockly
app, or the lock's own auto-lock) shows at the next command, or when Home Assistant restarts.

## What is stored

Only what a Bluetooth command needs: the lock's Bluetooth address, its name, and three codes from
your Lockly account (the master code, the lock's uuid and its house code). Your email, your
password, its hash and the Lockly sign-in are **not** stored. The Lockly cloud is contacted only
during setup.

If the lock's master code is changed later, remove the lock from Home Assistant and add it again.

## Security

- **A captured command could be replayed.** The lock's protection against replay is a plain
  timestamp in each command, so someone recording Bluetooth traffic within radio range could
  plausibly resend a captured lock or unlock command. This is a property of the lock's protocol,
  and nothing in this integration can change it.
- Anyone who can use your Home Assistant can unlock your door. Protect it accordingly.
- A lock or unlock command is sent **once** and never retried, whatever happens.

## How it was made

Independently implemented from a study of the Lockly Android app. The integration carries the
Lockly app's own cloud sign-in constants (`cloud_keys.py`), which the app ships to every phone.

## License

[MIT](LICENSE)
