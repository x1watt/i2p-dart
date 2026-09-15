/*
 * I2P Destination + LeaseSet2 (store type 3), pure Dart.
 *
 * A Destination is a KeysAndCert (Ed25519 sign + X25519 enc), identical in
 * layout to a RouterIdentity; its SHA-256 is the destination hash (b32 address).
 *
 * LeaseSet2 buffer (everything is signed, including the leading store-type byte):
 *   [0]      store type = 3 (standard LeaseSet2)
 *   [1..]    Destination (KeysAndCert, 391 bytes)
 *   +4       published timestamp (seconds, BE)
 *   +2       expires (offset seconds from published, BE)
 *   +2       flags (BE)
 *   +2       properties length (0)
 *   +1       encryption key count
 *     per:   key type(2) + key length(2) + key data       (X25519: 4, 32)
 *   +1       lease count
 *     per:   gateway hash(32) + tunnel id(4) + end date(seconds, BE)   = 40
 *   sig      Ed25519 over [0 .. end of leases]            (64 bytes)
 */
import 'dart:typed_data';

import 'i2p_crypto.dart';
import 'i2p_router.dart';

const leaseSetStoreType = 3;

class Lease2 {
  final Uint8List gatewayHash; // 32-byte router hash of the inbound gateway
  final int tunnelId;
  final int endDateSeconds;
  Lease2(this.gatewayHash, this.tunnelId, this.endDateSeconds);
}

class Destination {
  final Uint8List encPriv; // X25519
  final Uint8List encPub;
  final Uint8List signPriv; // Ed25519 seed
  final Uint8List signPub;
  final Uint8List keysAndCert; // 391-byte destination
  final Uint8List hash; // SHA-256(keysAndCert) = destination hash

  Destination._(this.encPriv, this.encPub, this.signPriv, this.signPub,
      this.keysAndCert, this.hash);

  /// A new destination, or the same one again from its two 32-byte seeds.
  static Future<Destination> generate({Uint8List? encSeed, Uint8List? signSeed}) async {
    final enc = await I2pCrypto.x25519Generate(encSeed);
    final sign = await I2pCrypto.ed25519Generate(signSeed);
    final kc = buildKeysAndCert(enc.pub, sign.pub);
    return Destination._(
        enc.priv, enc.pub, sign.priv, sign.pub, kc, I2pCrypto.sha256(kc));
  }

  /// Build and sign a LeaseSet2 buffer for these leases.
  Future<Uint8List> buildLeaseSet2(List<Lease2> leases,
      {int expiresOffset = 600}) async {
    final b = BytesBuilder();
    b.addByte(leaseSetStoreType); // [0] store type (signed)
    b.add(keysAndCert);
    final published = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    b.add(_be32(published));
    b.add(_be16(expiresOffset));
    b.add(_be16(0)); // flags
    b.add(_be16(0)); // properties length
    // encryption key section: one X25519 key (type 4)
    b.addByte(1);
    b.add(_be16(4)); // key type X25519
    b.add(_be16(32)); // key length
    b.add(encPub);
    // leases
    b.addByte(leases.length);
    for (final l in leases) {
      b.add(l.gatewayHash);
      b.add(_be32(l.tunnelId));
      b.add(_be32(l.endDateSeconds));
    }
    final unsigned = b.toBytes();
    final sig = await I2pCrypto.ed25519Sign(signPriv, unsigned);
    final out = BytesBuilder();
    out.add(unsigned);
    out.add(sig);
    return out.toBytes();
  }
}

class ParsedLease {
  final Uint8List gatewayHash; // 32
  final int tunnelId;
  final int endSeconds;
  ParsedLease(this.gatewayHash, this.tunnelId, this.endSeconds);
}

/// Parse the leases out of a LeaseSet2 buffer that begins at the Destination
/// (i.e. without the leading store-type byte, as carried in a DatabaseStore).
List<ParsedLease> parseLeaseSet2Leases(Uint8List ls) {
  try {
    var o = 391; // skip Destination (KeysAndCert, Ed25519+X25519 = 391 bytes)
    o += 4; // published
    o += 2; // expires
    o += 2; // flags
    final propsLen = (ls[o] << 8) | ls[o + 1];
    o += 2 + propsLen;
    final numKeys = ls[o];
    o += 1;
    for (var i = 0; i < numKeys; i++) {
      o += 2; // key type
      final klen = (ls[o] << 8) | ls[o + 1];
      o += 2 + klen;
    }
    final numLeases = ls[o];
    o += 1;
    final out = <ParsedLease>[];
    for (var i = 0; i < numLeases; i++) {
      final gw = ls.sublist(o, o + 32);
      final tid = (ls[o + 32] << 24) | (ls[o + 33] << 16) | (ls[o + 34] << 8) | ls[o + 35];
      final end = (ls[o + 36] << 24) | (ls[o + 37] << 16) | (ls[o + 38] << 8) | ls[o + 39];
      out.add(ParsedLease(gw, tid, end));
      o += 40;
    }
    return out;
  } catch (_) {
    return [];
  }
}

/// A LeaseSet2 whose signature and destination were checked.
class VerifiedLeaseSet {
  final Uint8List destination; // KeysAndCert of the owner
  final List<ParsedLease> leases;
  final int publishedSeconds;
  final int expiresSeconds;
  VerifiedLeaseSet(this.destination, this.leases, this.publishedSeconds, this.expiresSeconds);
}

/// Parse a LeaseSet2 (starting at the Destination, as carried in a
/// DatabaseStore) and accept it only when the destination hashes to
/// [wantHash], the owner's Ed25519 signature is valid and it has not expired.
/// Without this a floodfill could answer a lookup with somebody else's
/// tunnels. Offline-signed lease sets are not accepted (i2p-dart never makes
/// them).
Future<VerifiedLeaseSet?> verifyLeaseSet2(Uint8List ls, Uint8List wantHash,
    {int? nowSeconds}) async {
  try {
    // KeysAndCert: 256 + 128 + certificate (type, length, payload).
    final certLen = (ls[385] << 8) | ls[386];
    final destLen = 387 + certLen;
    final dest = ls.sublist(0, destLen);
    if (!_equal(I2pCrypto.sha256(dest), wantHash)) return null;
    // Only Ed25519 signing keys (KeyCertificate type 5, sig type 7).
    if (ls[384] != 5 || certLen < 4 || ((ls[387] << 8) | ls[388]) != 7) return null;
    var o = destLen;
    final published = (ls[o] << 24) | (ls[o + 1] << 16) | (ls[o + 2] << 8) | ls[o + 3];
    final expires = (ls[o + 4] << 8) | ls[o + 5];
    final flags = (ls[o + 6] << 8) | ls[o + 7];
    if (flags & 1 != 0) return null; // offline keys
    o += 8;
    final propsLen = (ls[o] << 8) | ls[o + 1];
    o += 2 + propsLen;
    final numKeys = ls[o++];
    for (var i = 0; i < numKeys; i++) {
      final klen = (ls[o + 2] << 8) | ls[o + 3];
      o += 4 + klen;
    }
    final numLeases = ls[o++];
    final leases = <ParsedLease>[];
    for (var i = 0; i < numLeases; i++) {
      final gw = ls.sublist(o, o + 32);
      final tid = (ls[o + 32] << 24) | (ls[o + 33] << 16) | (ls[o + 34] << 8) | ls[o + 35];
      final end = (ls[o + 36] << 24) | (ls[o + 37] << 16) | (ls[o + 38] << 8) | ls[o + 39];
      leases.add(ParsedLease(gw, tid, end));
      o += 40;
    }
    if (ls.length < o + 64) return null;
    final signed = Uint8List(1 + o)
      ..[0] = leaseSetStoreType
      ..setRange(1, 1 + o, ls);
    final sig = ls.sublist(o, o + 64);
    if (!await I2pCrypto.ed25519Verify(dest.sublist(352, 384), signed, sig)) return null;
    final now = nowSeconds ?? DateTime.now().millisecondsSinceEpoch ~/ 1000;
    if (published + expires < now) return null;
    return VerifiedLeaseSet(dest, leases, published, expires);
  } catch (_) {
    return null;
  }
}

bool _equal(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var d = 0;
  for (var i = 0; i < a.length; i++) {
    d |= a[i] ^ b[i];
  }
  return d == 0;
}

Uint8List _be32(int v) =>
    Uint8List.fromList([(v >> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff]);
Uint8List _be16(int v) => Uint8List.fromList([(v >> 8) & 0xff, v & 0xff]);
