quic-at-home is a toy implementation of a toy transport protocol derived from
QUIC. **It shouldn't be used, because it is bad.** The 3 kLOC of it get you
some cool features:

### Address ownership verification cookie

A client has to present a cookie that was previously by the server for it to
even consider shaking the client's hand. A cookie is an authentication tag of
user's IP address and port tuple produced by ChaCha20-Poly1305, but of course
any other AEAD will do just fine. This allows the server to not maintain any
per-cookie state.

To avoid the possibility of amplification attacks, cookies are sent only in
response to initial packets, which are always 1280 bytes in size.

See [internal/cookie](internal/cookie) for details.

### Noise IK handshake

Noise IK allows server to not keep any half-open connections around. When the
server receives a packet, it either accepts the connecction or rejects it.
Unfortunately this requires client to know the key of the server they are
connecting to.

### Best-effort message sequence service

Send messages to your peer! They will hopefully arrive. Some of them, maybe.
Regardless of outcome, if they arrive, they will in exactly the order they have
been sent, and each one will arrive at most once. No (or very large) size
limit, although harsh reality imposes one. Like IP fragmentation, but actually
good! plus congestion control and authenticated encryption on top. Or like
QUIC's DATAGRAM extension, but with fragmentation and extra guarantees about
order and no suspectibility to packet replay.

### IP migration

Stay connected while switching between Wi-Fi and LTE! Like QUIC's, but passive
migration only.

IP migration probes are implemented by sending a single ACK-eliciting packet to
both the last successfully probed address and the new one that the endpoint is
believed to be migrating to. Once a probe packet for address A is acknowledged
in a packet originating from that address, address A is used as the sending
address. Otherwise, if ACK of the probe originates from the old address,
migration is aborted.

### Terrible congestion controller

Congestion controller operates under assumption that transmission rate is always
application-bound. This leads to simpler congestion controller, which is always
in slow start. To deal with harsh reality of limited link capacities, whenever
congestion occurs, congestion window is reset.

And many more!

[internal/sec](internal/sec) implements Noise_IK_25519_ChaChaPoly_BLAKE2b

[internal/udp](internal/udp) implements ~~some terrible, cursed garbage~~ a UDP PacketConn
with GRO and GSO support (each, respectively, lets you receive and send UDP
packets without hogging CPU too hard.)

[stream_reassembler.go](stream_reassembler.go) contains ~~more cursed code~~ a thing that lets you put
fragments of a byte sequence back together, without terrible worst-case comp.
and memory complexities.
