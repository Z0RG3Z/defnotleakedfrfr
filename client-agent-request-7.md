# Request #7: what completes an RR room join (after JoinResponse)

Request #6 unblocked the request itself: the client sends `RRClientToServer`(5)/`RR_JoinRequest`(100),
and we now reply `RRServerToClient`(6)/`RR_JoinResponse`(101) = `{ bool Accepted, Room }`. Result:
**the client stops re-sending the JoinRequest** (so the reply is received and dequeued), but the room
UI **still never reports "joined"** — it sits idle (only keepalive + our TimeSync flow afterward).

So JoinResponse is received but not sufficient. Two hypotheses; please resolve which:

**Q1 — the join-complete trigger.** After the client dequeues `RR_JoinResponse`(101) and deserializes
its `Room`, what does the join state machine wait for before it reports the room joined? Our leading
guess is **`RR_SelfJoinMarker`(op 7)** (bare op, no body) — the "buffered state replayed, you are now
live" marker. Confirm:
- Is op 7 what the coroutine awaits? On the **direct** channel 6, or the **proxied** channel 4?
- Is it sufficient alone, or does completion also require the local player to be present in
  `Room.Players`, and/or a `RR_RoomUpdate`(102) / `RRClearBufferedRoomEvent`(23) first?
- Exact expected order from JoinResponse to "joined".

**Q2 — is the Room actually parsing?** The client advancing to the *voice* handshake does NOT prove
the Room body parsed (voice is independent). Please confirm the **client-side deserializer** for
`OCKHMGFANHD Room` and `EECOLELLELP Player` so we can rule out a silent parse stall. We currently
emit (all fields, `Mask = 0x0F`):

```
Room   = byte Mask=0x0F, ulong MasterClient, ulong PreviousMasterClient, u32 PlayerCount, Player[], Properties
Player = byte Mask=0x0F, ulong ClientId, string Name, int32 AccountId, string PlatformId, Properties
string = u32 charCount + UTF-16LE ;  Properties = the 5 bytes 34 00 00 00 00 echoed verbatim
```

Confirm or correct, specifically:
- **(a) Mask gating:** does the deserializer read each field only if its mask bit is set, in
  declaration order? Exact bit→field map for both masks. (If gated, `Mask=0x0F` should read every
  field — but confirm bit values: e.g. does Room bit 3 = PreviousMasterClient, and is reading it
  before Players correct?)
- **(b) Array count width** for `Player[]`: byte / u16 / u32 / bitpacked?
- **(c) AccountId:** raw `int32` or bitpacked int?
- **(d) `bool Accepted`:** single byte?
- **(e) Properties (`LGIGIHLJAPI`) layout:** what do those 5 bytes actually decode to (a count? a
  masked struct?)? What is the minimal **empty** Properties the deserializer accepts?

**Q3 — failure behavior.** If the `Room` deserializer hits a bad field, does it throw and silently
stall the join (matching our symptom), or log / disconnect? This tells us whether the hang is a
missing op‑7 marker (Q1) or a malformed Room (Q2).

**Q4 — MasterClient.** Any constraint on `MasterClient` (must be a real player id, may be 0/server,
must equal the joiner when alone)? We currently send the lowest client id in the room.
