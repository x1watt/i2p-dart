/*
 * I2pIdentity holds the secret seeds behind a node's lasting identity: its
 * destination (the .b32.i2p address peers reach) and its router. Keep the
 * bytes from [toBytes] somewhere safe (they are private keys) and pass them
 * back on the next start to keep the same address.
 *
 * Layout of [toBytes] (129 bytes):
 *   [0]        version = 1
 *   [1..32]    destination X25519 seed
 *   [33..64]   destination Ed25519 seed
 *   [65..96]   router X25519 seed (the NTCP2 static key)
 *   [97..128]  router Ed25519 seed
 */
import 'dart:math';
import 'dart:typed_data';

class I2pIdentity {
  final Uint8List destEnc;
  final Uint8List destSign;
  final Uint8List routerStatic;
  final Uint8List routerSign;

  I2pIdentity(this.destEnc, this.destSign, this.routerStatic, this.routerSign) {
    for (final s in [destEnc, destSign, routerStatic, routerSign]) {
      if (s.length != 32) throw ArgumentError('seeds are 32 bytes');
    }
  }

  static const _version = 1;
  static const length = 1 + 4 * 32;

  /// Fresh random seeds.
  factory I2pIdentity.generate() {
    final rnd = Random.secure();
    Uint8List seed() => Uint8List.fromList(List.generate(32, (_) => rnd.nextInt(256)));
    return I2pIdentity(seed(), seed(), seed(), seed());
  }

  Uint8List toBytes() {
    final out = Uint8List(length);
    out[0] = _version;
    out.setRange(1, 33, destEnc);
    out.setRange(33, 65, destSign);
    out.setRange(65, 97, routerStatic);
    out.setRange(97, 129, routerSign);
    return out;
  }

  /// Null when [b] is not an identity written by [toBytes].
  static I2pIdentity? fromBytes(Uint8List b) {
    if (b.length != length || b[0] != _version) return null;
    Uint8List at(int o) => Uint8List.fromList(b.sublist(o, o + 32));
    return I2pIdentity(at(1), at(33), at(65), at(97));
  }
}
