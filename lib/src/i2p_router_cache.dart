/*
 * The netDB cache: RouterInfos the node saw, kept on disk so the next start
 * can skip the reseed download and dial routers that worked before.
 *
 * File `routers.bin`:
 *   'I2RC' | version 1 | count u16 BE | count x (flags u8 | length u16 BE | RouterInfo)
 * flags bit 0 = we completed a handshake with this router (tried first).
 */
import 'dart:io';
import 'dart:typed_data';

import 'i2p_structures.dart';

class CachedRouters {
  final List<RouterInfo> routers;
  /// Identity hashes (hex) of routers that worked for us before.
  final Set<String> good;
  CachedRouters(this.routers, this.good);
}

const _magic = [0x49, 0x32, 0x52, 0x43]; // I2RC

Uint8List encodeRouterCache(List<(Uint8List raw, bool good)> entries) {
  final b = BytesBuilder();
  b.add(_magic);
  b.addByte(1);
  final n = entries.length.clamp(0, 0xffff);
  b.add([(n >> 8) & 0xff, n & 0xff]);
  for (final (raw, good) in entries.take(n)) {
    if (raw.length > 0xffff) continue;
    b.addByte(good ? 1 : 0);
    b.add([(raw.length >> 8) & 0xff, raw.length & 0xff]);
    b.add(raw);
  }
  return b.toBytes();
}

/// Routers from a cache file, skipping any that are malformed or were
/// published more than [maxAge] ago. Empty on a bad file.
CachedRouters decodeRouterCache(Uint8List b,
    {Duration maxAge = const Duration(days: 30), int? nowMs}) {
  final routers = <RouterInfo>[];
  final good = <String>{};
  try {
    for (var i = 0; i < 4; i++) {
      if (b[i] != _magic[i]) return CachedRouters(routers, good);
    }
    if (b[4] != 1) return CachedRouters(routers, good);
    final n = (b[5] << 8) | b[6];
    final oldest = (nowMs ?? DateTime.now().millisecondsSinceEpoch) - maxAge.inMilliseconds;
    var o = 7;
    for (var i = 0; i < n && o + 3 <= b.length; i++) {
      final flags = b[o];
      final len = (b[o + 1] << 8) | b[o + 2];
      o += 3;
      if (o + len > b.length) break;
      final ri = parseRouterInfo(Uint8List.fromList(b.sublist(o, o + len)));
      o += len;
      if (ri == null || ri.publishedMs < oldest) continue;
      routers.add(ri);
      if (flags & 1 != 0) good.add(_hex(ri.identityHash));
    }
  } catch (_) {}
  return CachedRouters(routers, good);
}

CachedRouters loadRouterCache(String dir) {
  try {
    final f = File('$dir/routers.bin');
    if (!f.existsSync()) return CachedRouters([], {});
    return decodeRouterCache(f.readAsBytesSync());
  } catch (_) {
    return CachedRouters([], {});
  }
}

/// Writes atomically (temporary file, then rename).
void saveRouterCache(String dir, List<(Uint8List raw, bool good)> entries) {
  try {
    Directory(dir).createSync(recursive: true);
    final tmp = File('$dir/routers.bin.tmp');
    tmp.writeAsBytesSync(encodeRouterCache(entries), flush: true);
    tmp.renameSync('$dir/routers.bin');
  } catch (_) {}
}

String _hex(List<int> b) => b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
