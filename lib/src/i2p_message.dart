/*
 * Application messages: what the node hands up for an 'A' frame, and the
 * checks a frame passes first.
 */
import 'dart:typed_data';

import 'i2p_datagram.dart';
import 'i2p_node.dart' show i2pBase32;

/// An application message from another destination.
class I2pMessage {
  /// Sender's destination hash (32 bytes); authenticated by the datagram
  /// signature.
  final Uint8List from;
  final int port;
  final Uint8List payload;
  final DateTime sent;

  /// The destination it was addressed to: ours, or one of the shared
  /// destinations this node answers for (null from older callers).
  final Uint8List? to;
  I2pMessage(this.from, this.port, this.payload, this.sent, {this.to});

  /// Sender's address, "<52 chars>.b32.i2p".
  String get fromB32 => '${i2pBase32(from)}.b32.i2p';

  /// The address it was sent to, or null.
  String? get toB32 => to == null ? null : '${i2pBase32(to!)}.b32.i2p';
}

/// Accepts a frame at most once, only when it is addressed to us and its
/// time is within [window] of ours. Remembers the last [capacity] ids per
/// sender and id; the time window bounds how long a replay could matter, so
/// the id memory only needs to cover it.
class AppGate {
  final Duration window;
  final int capacity;
  final _seen = <String, int>{}; // insertion ordered: oldest first

  AppGate({this.window = const Duration(minutes: 10), this.capacity = 4096});

  bool accept(Uint8List ourHash, Uint8List srcHash, AppFrame f, {int? nowSeconds}) =>
      acceptTo([ourHash], srcHash, f, nowSeconds: nowSeconds) != null;

  /// Like [accept] for a node that answers for several destinations
  /// ([ours]): the one the frame was addressed to, or null when it is
  /// refused.
  Uint8List? acceptTo(List<Uint8List> ours, Uint8List srcHash, AppFrame f, {int? nowSeconds}) {
    Uint8List? to;
    for (final h in ours) {
      if (_same(f.toHash, h)) to = h;
    }
    if (to == null) return null;
    final now = nowSeconds ?? DateTime.now().millisecondsSinceEpoch ~/ 1000;
    if ((now - f.timeSeconds).abs() > window.inSeconds) return null;
    final key = '${_hex(srcHash)}:${_hex(f.msgId)}';
    if (_seen.containsKey(key)) return null;
    _seen[key] = now;
    while (_seen.length > capacity) {
      _seen.remove(_seen.keys.first);
    }
    return to;
  }

  static bool _same(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  static String _hex(List<int> b) => b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
}
