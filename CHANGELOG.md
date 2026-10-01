# Changelog

## Unreleased

- Send from a chosen destination: `I2pService.send(b32, port, payload,
  fromB32: ...)` (and `I2pNode.sendMessage(..., fromHash: ...)`) signs the
  message with one of the node's shared destinations instead of its own, so
  the receiver sees that address as the sender and replies to it. An app can
  keep one address per account on a single node. Sending from a destination
  the node does not answer for is refused (returns false). `pickSender`
  chooses the signing destination and is covered by tests.
- Limitation: every destination on a node publishes the same inbound
  tunnels and embeds the same reply leases, so an observer comparing lease
  sets can tell that two addresses live on one node. Separate tunnel pools
  per destination would remove that link.

## 0.3.0

- Shared destinations: `I2pService.addSharedDestination(encSeed, signSeed)`
  makes the node answer for a destination whose seeds other nodes hold too
  (for example one derived from a chat room's name). The node publishes its
  LeaseSet2 with its own tunnels (to 4 floodfills, republished with the
  keepalive) and accepts application messages addressed to it;
  `I2pMessage.to` says which destination a message was sent to.
  `sharedDestinationAddress` computes such an address without answering.
  A floodfill keeps one lease set per destination, so each publish first
  looks the destination up and merges in the other nodes' unexpired leases
  (up to 12, next to its own): a lookup then reaches every node that
  published in the last ten minutes, not just the last one. Messages to a
  shared destination this node answers for skip the lease cache.
- LeaseSet stores carry a reply token: the floodfill confirms with a
  DeliveryStatus (logged as "N confirmed") and floods the store to the other
  floodfills closest to the key, as Java I2P and i2pd do only for stores
  with a token. Before, a lease set stayed on the floodfills the publisher
  chose, and a node with a different view of the network (a phone reseeded
  elsewhere) could not find it.
- Lease set lookups are iterative: when the floodfills closest in our own
  view do not hold the key, the closer floodfills their search replies name
  are asked next (up to three rounds), and remembered.
- Every application frame accepted or refused, and every application send
  with its outcome, is logged.
- Application frames version 2 carry the sender's reply leases, covered by
  the datagram signature: a receiver answers through them with no network
  database lookup, as a GET's responder does. That is what lets a first
  answer reach a newcomer whose own LeaseSet the responder's floodfills do
  not hold yet. Version 1 frames are still read.
- `tool/i2p_shared_dest.dart`: live check (20 of 20 greetings to a shared
  destination answered, median under a second).
- `rxDiag` also logs each application frame accepted or refused.

## 0.2.0

- Lasting identity: `I2pIdentity` (destination and router seeds) passed to
  `I2pService(identity:)` keeps the same `.b32.i2p` address across starts.
- Router cache: `I2pService(stateDir:)` saves the routers seen (those that
  worked first) to `routers.bin` and starts from it instead of reseeding,
  falling back to a reseed when it is too small or no gateway comes up.
- Application messages: opcode `'A'` frames (port, message id, time,
  recipient hash) inside the signed datagram; `I2pService.send` and
  `I2pService.messages`. Frames for another destination, older than ten
  minutes or already seen are dropped.
- Lease set lookups check the destination hash, the owner's signature and
  the expiry, and are cached until the leases end.
- Frame sends on a session time out after 15 s instead of waiting forever on
  a socket that stopped draining.
- Fix: a gateway session that ended (read error or Termination) made the
  serve loop spin on the dead socket without yielding, which froze the
  node's whole isolate (no timers, no receiving, one core busy) minutes
  after start. `Ntcp2Session.pumpI2np` now throws when the session has
  ended; the gateway is marked dead, replaced and the lease set republished
  within seconds.
- Fix: a frame read abandoned by a timeout stayed in flight while the next
  read started, so two readers shared one stream. The first frame after any
  30 s of quiet on a gateway session failed its MAC and killed the session:
  messages sent to a node more than half a minute after its tunnels came up
  were lost, and replies to a fetch or a message usually were. Reads are now
  handed on to the next caller.
- `I2pService(rxDiag:, directDelivery:)` diagnostics switches.
- `I2pService.b32` documented as the full "<52 chars>.b32.i2p" address.

## 0.1.0

- Initial extraction as a standalone package from the Aurora project.
- Pure-Dart I2P node: NTCP2 transport, inbound + outbound tunnel build/data,
  netDB lookups, LeaseSet2 publish/retrieve, repliable signed datagrams,
  content-discovery DHT (PROVIDE / FINDPROV) and a BitTorrent-style piece swarm.
- High-level `I2pService` facade running the node in a background isolate, with
  a pluggable `I2pContentStore` (no Flutter / app dependency).
