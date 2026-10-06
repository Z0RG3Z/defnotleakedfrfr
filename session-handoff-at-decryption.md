# Handoff: AT decryption → room id → drop the recflare lookup

Written 2026-09-18 to move this work to a session running **on the voice server itself** (the build
here is `devin`'s tree; the live server runs as `photon` / on the remote host, so a locally-built
binary was never the one under test — that's why the new `AT ->` log line kept not appearing).

## The goal

We patched the client's embedded RSA modulus to **our own keypair**, so the server can now decrypt
the handshake blobs with the matching private key (`--private-key <RSAKeyValue.xml>`). The client
knows which room it's joining, so it almost certainly ships the room/instance id inside the
encrypted handshake. If we can read it, we **delete the recflare `AI → roomInstanceId` HTTP lookup**
(`src/room_lookup.cpp`) and gain: no external dependency, no network I/O on the handshake path
(kills the synchronous up-to-`room_timeout_ms` stall), and room scoping that can't go stale.

## What the blobs are (proven live, 2048-bit key, dev AccountId "2")

The `ConnectionData` JSON carries `AI` (AccountId, plaintext) + RSA-encrypted `AT/VB/CKA/CIA/CPK`.
Decrypted (each `VB/CKA/CIA` is a single 256-byte RSA block → small plaintext):

| blob | decrypts to | notes |
|------|-------------|-------|
| `CKA` | **32 bytes** | AES-256 **key**; random per connection |
| `CIA` | **16 bytes** | AES **IV**; random per connection |
| `VB`  | **16 bytes** | **constant across connections** (`1932c56880289e22caa8710914885c1b` for AccountId 2) → a stable identity/verifier, **not** the AT IV |
| `AT`  | 880 bytes ciphertext | `880 = 55 × 16` → **AES-CBC** payload (the auth token) |
| `CPK` | 160 bytes | the client's own public key; we don't decrypt it |

Conclusion: `AT` is a hybrid envelope — the token AES-256-CBC'd under the RSA-wrapped `CKA`(key)/
`CIA`(iv). This is implemented but **not yet observed decrypted** (the running server was a stale
binary without the AES code).

## Code in this change (uncommitted — please commit + deploy)

- `src/crypto.{h,cpp}`: `aes_cbc_decrypt(key, key_len, iv, data, len, strip_padding=true)` —
  OpenSSL EVP, picks AES-128/192/256 by key length, PKCS#7 strip with a raw-blocks fallback.
- `src/tachyon_server.cpp` (`handle_connection_request`): after RSA-decrypting the blobs, captures
  `CKA`/`CIA`/`AT` and decrypts `AT` as AES-256-CBC(key=CKA, iv=CIA), logging the plaintext at
  debug: `[hand]  AT -> N bytes (AES-256-CBC key=CKA iv=CIA): <hex> | "<ascii>"`. Tries PKCS#7 then
  raw blocks.

Not included / unrelated: `traffic.txt` (test captures, commit or discard as you like),
`vendor/LiteNetLibPP` dirty flag (the build-time patch — expected, don't commit),
`docs/client-agent-request-6.md`/`-7.md` (client-agent Q&A from the RR-join effort).

## Next step on the server

Build and run the **freshly built** binary with the private key against a live join:

```
cmake --build build -j
./build/tachyon --config tachyon.conf --private-key <your-key.xml> -v
```
Confirm it's the right binary: `grep -a -c AES-256-CBC ./build/tachyon` prints `1`.

Look at the new `AT ->` line for the **room instance id** — a ~7-digit decimal (e.g. `1076356`,
`1011658`) either as ASCII in the text column or a little-endian `u32`/`u64` in the hex; it may be
inside JSON (`{...}`) or a binary token.

- **Found** → add a "room from handshake" resolver that reads it at connect time and remove the
  recflare call in `main.cpp`/`room_lookup.*` (optionally keep `--room-url` as a fallback).
- **`AT AES decrypt FAILED`** → the envelope isn't CBC/CKA/CIA. Next guesses: IV = `VB`, or mode =
  CTR/GCM. (CBC is the strong favorite given `880 = 55×16` and the clean 32/16 key/IV.)

## Also open (separate threads, not blocking the above)

- **Client timeout disconnects** (8-player room, `Timeout / socketErrorCode: Success`): I traced
  LiteNetLibPP's threading — pings run on an independent `m_logic_thread` and the peer's
  `m_time_since_last_packet` resets on the **receive thread**, both independent of `poll_events`. So
  a `poll_events` stall (e.g. the recflare lookup) degrades relay latency but **cannot** cause the
  client timeout. A full 5-s silence means the server stopped sending *everything* → most likely the
  per-instance process **crashed/was killed** ~when the client went quiet. Decisive evidence = the
  server log for that instance (did it exit / OOM / stop logging?). Recommended hardening regardless:
  wrap `on_network_receive` handling in try/catch (one bad packet shouldn't drop all 8 peers) + a
  main-loop watchdog logging slow `poll_events` iterations. Dropping recflare (above) also removes
  the stall as a contributing factor.
- **RR game-networking room join**: earlier work (NamedMessageType 5/6, `RR_JoinResponse`,
  `RR_SelfJoinMarker`) was **reverted** (never committed) — the room still hangs on join. Findings
  are in `docs/client-agent-request-6.md`/`-7.md` if we resume it.
