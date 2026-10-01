/*
 * Repliable datagrams + a tiny GET-by-sha256 request/response, pure Dart.
 *
 * A repliable datagram carries the sender's Destination so the receiver can
 * reply, and an Ed25519 signature over the payload so the sender is
 * authenticated:
 *   [391 source Destination (KeysAndCert)][64 Ed25519 signature][payload]
 *
 * The application payload is our own minimal content protocol:
 *   GET request : 'G' + sha256(32)
 *   DAT response: 'D' + sha256(32) + len(4 BE) + bytes
 * plus the requester's reply lease appended to a GET so the responder can route
 * the reply: ... + gatewayHash(32) + tunnelId(4).
 */
import 'dart:typed_data';

import 'i2p_crypto.dart';
import 'i2p_leaseset.dart';

const _destLen = 391;
const _sigLen = 64;

/// Extract the Ed25519 signing public key from a KeysAndCert (last 32 bytes of
/// the 128-byte signing field at offset 256).
Uint8List signPubOf(Uint8List keysAndCert) => keysAndCert.sublist(352, 384);

/// Extract the X25519 encryption key (first 32 bytes of the 256-byte field).
Uint8List encPubOf(Uint8List keysAndCert) => keysAndCert.sublist(0, 32);

Future<Uint8List> buildDatagram(Destination src, Uint8List payload) async {
  final sig = await I2pCrypto.ed25519Sign(src.signPriv, payload);
  final b = BytesBuilder();
  b.add(src.keysAndCert); // 391
  b.add(sig); // 64
  b.add(payload);
  return b.toBytes();
}

/// The destination an outgoing message is signed with: [main] when [from] is
/// null or names it, the one of [shared] that [from] names, or null when the
/// node does not answer for [from] (the caller must then refuse to send).
Destination? pickSender(Destination main, Iterable<Destination> shared, Uint8List? from) {
  if (from == null) return main;
  bool same(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  if (same(main.hash, from)) return main;
  for (final d in shared) {
    if (same(d.hash, from)) return d;
  }
  return null;
}

class ParsedDatagram {
  final Uint8List srcDest; // KeysAndCert (391)
  final Uint8List srcHash; // SHA-256(srcDest) = destination hash
  final Uint8List payload;
  final bool sigValid;
  ParsedDatagram(this.srcDest, this.srcHash, this.payload, this.sigValid);
}

Future<ParsedDatagram?> parseDatagram(Uint8List dg) async {
  if (dg.length < _destLen + _sigLen) return null;
  final src = dg.sublist(0, _destLen);
  final sig = dg.sublist(_destLen, _destLen + _sigLen);
  final payload = dg.sublist(_destLen + _sigLen);
  final valid =
      await I2pCrypto.ed25519Verify(signPubOf(src), payload, sig);
  return ParsedDatagram(src, I2pCrypto.sha256(src), payload, valid);
}

// ---- GET-by-sha256 application payload ----

/// A reply lease: the gateway router hash and the tunnel id to deliver into.
class ReplyLease {
  final Uint8List gatewayHash;
  final int tunnelId;
  ReplyLease(this.gatewayHash, this.tunnelId);
}

void _putLeases(BytesBuilder b, List<ReplyLease> leases) {
  b.addByte(leases.length);
  for (final l in leases) {
    b.add(l.gatewayHash);
    b.add([(l.tunnelId >> 24) & 0xff, (l.tunnelId >> 16) & 0xff,
          (l.tunnelId >> 8) & 0xff, l.tunnelId & 0xff]);
  }
}

List<ReplyLease> _getLeases(Uint8List p, int off) {
  final out = <ReplyLease>[];
  if (off >= p.length) return out;
  final n = p[off];
  var o = off + 1;
  for (var i = 0; i < n && o + 36 <= p.length; i++) {
    final gw = p.sublist(o, o + 32);
    final tid = (p[o + 32] << 24) | (p[o + 33] << 16) | (p[o + 34] << 8) | p[o + 35];
    out.add(ReplyLease(gw, tid));
    o += 36;
  }
  return out;
}

/// GET 'G' + sha256(32) + the requester's reply leases. The responder fans the
/// reply out to every embedded lease (gateway diversity, no lookup needed).
Uint8List buildGet(Uint8List sha256, List<ReplyLease> replyLeases) {
  final b = BytesBuilder();
  b.addByte(0x47);
  b.add(sha256);
  _putLeases(b, replyLeases);
  return b.toBytes();
}

class GetRequest {
  final Uint8List sha256;
  final List<ReplyLease> replyLeases;
  GetRequest(this.sha256, this.replyLeases);
}

GetRequest? parseGet(Uint8List payload) {
  if (payload.length < 33 || payload[0] != 0x47) return null;
  return GetRequest(payload.sublist(1, 33), _getLeases(payload, 33));
}

Uint8List buildDat(Uint8List sha256, Uint8List bytes) {
  final b = BytesBuilder();
  b.addByte(0x44); // 'D'
  b.add(sha256);
  b.add([(bytes.length >> 24) & 0xff, (bytes.length >> 16) & 0xff,
        (bytes.length >> 8) & 0xff, bytes.length & 0xff]);
  b.add(bytes);
  return b.toBytes();
}

class DatResponse {
  final Uint8List sha256;
  final Uint8List bytes;
  DatResponse(this.sha256, this.bytes);
}

DatResponse? parseDat(Uint8List payload) {
  if (payload.isEmpty || payload[0] != 0x44 || payload.length < 1 + 32 + 4) {
    return null;
  }
  final sha = payload.sublist(1, 33);
  final len = (payload[33] << 24) | (payload[34] << 16) | (payload[35] << 8) | payload[36];
  if (payload.length < 37 + len) return null;
  return DatResponse(sha, payload.sublist(37, 37 + len));
}

// ---- application messages ----
// APP 'A' | version | port u16 | msgId 8 | time u32 (seconds) | toHash 32
//     | (version 2) reply leases: count u8, count x (gatewayHash 32, tunnelId u32)
//     | payload
// Inside a repliable datagram, so the sender's Ed25519 signature covers the
// port, id, time, recipient and reply leases: a relay can't redirect it to
// another destination, and the receiver drops old or repeated frames. The
// reply leases let the receiver answer without looking the sender up in the
// network database (as a GET does), which is what makes a first answer to
// a newcomer work when the two nodes know different floodfills.

const opApp = 0x41;
const appHeaderLen = 1 + 1 + 2 + 8 + 4 + 32;

/// Largest application payload [buildApp] accepts.
const appMaxPayload = 32 * 1024;

class AppFrame {
  final int port;
  final Uint8List msgId; // 8
  final int timeSeconds;
  final Uint8List toHash; // 32
  final Uint8List payload;

  /// Where the sender can be reached (its inbound gateways); empty in
  /// version 1 frames.
  final List<ReplyLease> replyLeases;
  AppFrame(this.port, this.msgId, this.timeSeconds, this.toHash, this.payload, {this.replyLeases = const []});
}

Uint8List buildApp(AppFrame f) {
  if (f.payload.length > appMaxPayload) throw ArgumentError('payload over $appMaxPayload bytes');
  if (f.msgId.length != 8 || f.toHash.length != 32) throw ArgumentError('bad id or hash');
  final v2 = f.replyLeases.isNotEmpty;
  final b = BytesBuilder();
  b.add([opApp, v2 ? 2 : 1, (f.port >> 8) & 0xff, f.port & 0xff]);
  b.add(f.msgId);
  final t = f.timeSeconds;
  b.add([(t >> 24) & 0xff, (t >> 16) & 0xff, (t >> 8) & 0xff, t & 0xff]);
  b.add(f.toHash);
  if (v2) _putLeases(b, f.replyLeases.take(16).toList());
  b.add(f.payload);
  return b.toBytes();
}

AppFrame? parseApp(Uint8List p) {
  if (p.length < appHeaderLen || p[0] != opApp || (p[1] != 1 && p[1] != 2)) return null;
  final t = (p[12] << 24) | (p[13] << 16) | (p[14] << 8) | p[15];
  var at = appHeaderLen;
  var leases = const <ReplyLease>[];
  if (p[1] == 2) {
    if (p.length < at + 1) return null;
    final n = p[at];
    if (p.length < at + 1 + n * 36) return null;
    leases = _getLeases(p, at);
    at += 1 + n * 36;
  }
  return AppFrame((p[2] << 8) | p[3], p.sublist(4, 12), t, p.sublist(16, 48), p.sublist(at),
      replyLeases: leases);
}

// ---- content-routing (provider DHT) payloads ----
// PROVIDE  'P' + contentSha(32) + providerDestHash(32)
// FINDPROV 'F' + contentSha(32) + replyGatewayHash(32) + replyTunnelId(4)
// FPREPLY  'R' + contentSha(32) + count(1) + count*providerDestHash(32)

Uint8List buildProvide(Uint8List contentSha, Uint8List providerDestHash) =>
    Uint8List.fromList([0x50, ...contentSha, ...providerDestHash]);

/// (contentSha, providerDestHash) or null.
(Uint8List, Uint8List)? parseProvide(Uint8List p) {
  if (p.length != 65 || p[0] != 0x50) return null;
  return (p.sublist(1, 33), p.sublist(33, 65));
}

/// FINDPROV 'F' + contentSha(32) + the requester's reply leases.
Uint8List buildFindProv(Uint8List contentSha, List<ReplyLease> replyLeases) {
  final b = BytesBuilder();
  b.addByte(0x46);
  b.add(contentSha);
  _putLeases(b, replyLeases);
  return b.toBytes();
}

class FindProvReq {
  final Uint8List contentSha;
  final List<ReplyLease> replyLeases;
  FindProvReq(this.contentSha, this.replyLeases);
}

FindProvReq? parseFindProv(Uint8List p) {
  if (p.length < 33 || p[0] != 0x46) return null;
  return FindProvReq(p.sublist(1, 33), _getLeases(p, 33));
}

Uint8List buildFpReply(Uint8List contentSha, List<Uint8List> providers) {
  final b = BytesBuilder();
  b.addByte(0x52);
  b.add(contentSha);
  b.addByte(providers.length);
  for (final p in providers) {
    b.add(p);
  }
  return b.toBytes();
}

class FpReply {
  final Uint8List contentSha;
  final List<Uint8List> providers;
  FpReply(this.contentSha, this.providers);
}

FpReply? parseFpReply(Uint8List p) {
  if (p.length < 34 || p[0] != 0x52) return null;
  final sha = p.sublist(1, 33);
  final n = p[33];
  final out = <Uint8List>[];
  var o = 34;
  for (var i = 0; i < n && o + 32 <= p.length; i++) {
    out.add(p.sublist(o, o + 32));
    o += 32;
  }
  return FpReply(sha, out);
}
