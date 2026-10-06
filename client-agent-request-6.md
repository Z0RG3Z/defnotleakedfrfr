# Request #6: the game-networking room-join NamedMessage protocol

Context: the voice path (Dissonance over NGO NamedMessage type 1/2) works end to end. We are now
bringing up **general game networking** on the same transport, and the client **connects but hangs
joining a room**. A capture (`traffic.txt`) shows the join getting exactly this far:

1. LiteNetLib connect → `ConnectAccept` ✓
2. client → `ConnectionRequestMessage` (the RSA `AI/AT/VB/CKA/CIA/CPK` blobs) ✓
3. server → `ConnectionApprovedMessage` (version echo + tick + `{"DR":"Carrot"}`) ✓
4. **client → `NamedMessage` with `NamedMessageType = 5`** (below) — its identity
5. server → nothing it accepts → **client blocks here and never completes the join**

Our NamedMessage framing is known and correct for voice:
`[u16 NamedMessageType LE][i32 length LE][payload]`, type **1** = DissonanceToServer,
**2** = DissonanceToClient. Type **5** is new — we have never seen it before and don't know its
body framing or what reply the client expects.

## The exact bytes (NamedMessage body, 68 bytes, from ConnectionApproved+~60ms)

```
0500 64090000 00 41006c0073006f0044006500760069006e00 11000000 37003600350036003100310039003700390036003200340036003300320031003100340000... 00000000
```

Decoded by eye:
- `05 00` = NamedMessageType 5 (LE u16)
- `64 09 00 00 00` = ? (unknown — reads as u32 `0x0964`=2404 then a `00`; likely a sub-opcode /
  name hash, **not** a length)
- `09 00 00 00` + `41 00 6c 00 73 00 6f 00 44 00 65 00 76 00 69 00 6e 00` = UTF-16 string
  **"AlsoDevin"** (len 9) — the display name
- `11 00 00 00` + `37 00 36 00 …` = UTF-16 string **"76561197962463…"** (len 17) — a SteamID64
- trailing `00 00 00 00`

## Questions

**Q1 — identify NamedMessageType 5.** What subsystem registers/handles `NamedMessageType == 5`
on the server-receive side? What is the human name of this message (a room-join / player-registration
/ identity handshake)?

**Q2 — exact body framing of type 5.** Break down the bytes after `05 00`: what are
`64 09 00 00 00` (opcode? hash? version?), and confirm the two fields are
`[i32 charCount][UTF-16LE displayName]` then `[i32 charCount][UTF-16LE accountId]`, plus the
trailing `00 00 00 00`. List every field in order with its width/encoding.

**Q3 — the required server response (the thing it's blocked on).** After the client sends this,
what message must the server send back before the client considers itself "in the room"? Which
`NamedMessageType` (or NGO message) is it, and what is its exact layout? Does the server assign a
player/room id in that reply? Is a specific field (e.g. an assigned index, a room state blob, an
ack of the accountId) mandatory, or is any well-formed reply enough to unblock?

**Q4 — is NGO scene sync involved?** Does room join require NGO `NetworkSceneManager`
synchronization (a `SceneEventMessage` load/sync exchange) in this build, or is the whole room-join
handshake carried over these NamedMessage channels? If scene sync is required, what does the client
wait for (event type, scene hash source) and what must the server send?

**Q5 — enumerate the NamedMessageType space.** List all `NamedMessageType` values the client uses
for game networking (beyond voice's 1/2), with a one-line purpose each, so we can scope the rest of
the protocol rather than discovering it one hang at a time.
