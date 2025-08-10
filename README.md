# sigsurgeon — normalize, convert, and sanity-check Ethereum signatures (offline)

**sigsurgeon** makes signatures safe to store and easy to interoperate with:
it accepts both 65-byte **standard** (`r||s||v`) and **EIP-2098 compact** (64-byte)
signatures, normalizes them to **low-s** (EIP-2) with `v ∈ {27,28}`, and can
recover the signer from a message (EIP-191 personal_sign) or a raw digest.

No RPC. No internet. Just clean crypto hygiene for wallets, relayers, and backends.

## Why this is useful

- Prevents signature malleability by enforcing **low-s**.
- Unifies messy `v` variants (`0/1`, `27/28`, **EIP-155** tx-style `>=35`) into `27/28`.
- Converts to/from **EIP-2098 compact** and standard encodings.
- Quick **address recovery** for logs, audits, and CI.

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
