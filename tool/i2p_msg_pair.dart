// Live check of application messages: two nodes (each in its own isolate,
// with a lasting identity and router cache under the state folder) send each
// other a 1 KiB and a 30 KiB message over the public I2P network, both ways.
// Every copy is counted, so a frame arriving twice shows as a failure.
//
//   dart run tool/i2p_msg_pair.dart [state folder] [--quiet] [--soak=MINUTES]
//
// --fresh-router keeps the destination but uses a new router identity.
// --no-direct sends through the outbound tunnel only.
// --rx logs every I2NP message arriving on a gateway session.
// --soak keeps both nodes up afterwards and sends 1 KiB each way once a
// minute, to watch delivery across tunnel rebuilds and republishing.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:i2p/i2p.dart';

const port = 4242;

Future<void> main(List<String> args) async {
  final dir = args.firstWhere((a) => !a.startsWith('--'), orElse: () => 'i2p-pair-state');
  final quiet = args.contains('--quiet');
  final soak = int.tryParse(args.firstWhere((a) => a.startsWith('--soak='), orElse: () => '--soak=0').substring(7)) ?? 0;
  final sw = Stopwatch()..start();
  String t() => '${(sw.elapsedMilliseconds / 1000).toStringAsFixed(1)}s';

  I2pService node(String name) {
    final state = Directory('$dir/$name')..createSync(recursive: true);
    final f = File('${state.path}/identity.key');
    var id = (f.existsSync() ? I2pIdentity.fromBytes(f.readAsBytesSync()) : null) ?? I2pIdentity.generate();
    f.writeAsBytesSync(id.toBytes());
    if (args.contains('--fresh-router')) {
      final r = I2pIdentity.generate();
      id = I2pIdentity(id.destEnc, id.destSign, r.routerStatic, r.routerSign);
    }
    return I2pService(
        rxDiag: args.contains('--rx'),
        directDelivery: !args.contains('--no-direct'),
        identity: id,
        stateDir: state.path,
        log: (m) {
          if (!quiet || m.contains('cache') || m.contains('reseed') || m.contains('up with')) print('${t()} [$name] $m');
        });
  }

  final a = node('a'), b = node('b');
  final ups = await Future.wait([a.ensureStarted(), b.ensureStarted()]);
  print('${t()} up: a=${ups[0]} ${a.b32}  b=${ups[1]} ${b.b32}');
  if (!ups.every((u) => u)) {
    a.stop();
    b.stop();
    exit(1);
  }

  // Tag -> copies received. A tag is one frame (one send attempt).
  final copies = <String, int>{};
  final got = <String, Completer<void>>{};
  void listen(I2pService s, String name) {
    s.messages.listen((m) {
      final text = utf8.decode(m.payload.sublist(0, m.payload.indexOf(0x0a)));
      copies[text] = (copies[text] ?? 0) + 1;
      print('${t()} [$name] got "$text" ${m.payload.length}b from ${m.fromB32.substring(0, 12)}... '
          'port ${m.port}, copy ${copies[text]}');
      final msg = text.split('/try').first;
      got[msg]?.complete();
    });
  }

  listen(a, 'a');
  listen(b, 'b');

  final rnd = Random(1);
  Future<bool> exchange(I2pService from, I2pService to, String name, int size) async {
    final done = got[name] = Completer<void>();
    for (var attempt = 1; attempt <= 6 && !done.isCompleted; attempt++) {
      final header = utf8.encode('$name/try$attempt\n');
      final body = Uint8List(size)..setAll(0, header);
      for (var i = header.length; i < size; i++) {
        body[i] = rnd.nextInt(256);
      }
      final ok = await from.send(to.b32!, port, body);
      print('${t()} sent $name try $attempt (${size}b): ${ok ? "a gateway took it" : "no gateway"}');
      await Future.any([done.future, Future<void>.delayed(const Duration(seconds: 20))]);
    }
    return done.isCompleted;
  }

  // Give the fresh lease sets a moment to reach the floodfills.
  await Future<void>.delayed(const Duration(seconds: 10));
  final results = <String, bool>{
    'a->b 1KiB': await exchange(a, b, 'a->b 1KiB', 1024),
    'b->a 1KiB': await exchange(b, a, 'b->a 1KiB', 1024),
    'a->b 30KiB': await exchange(a, b, 'a->b 30KiB', 30 * 1024),
    'b->a 30KiB': await exchange(b, a, 'b->a 30KiB', 30 * 1024),
  };
  // Late duplicates would show up here.
  await Future<void>.delayed(const Duration(seconds: 15));
  for (var m = 1; m <= soak; m++) {
    final ab = await exchange(a, b, 'soak $m a->b', 1024);
    final ba = await exchange(b, a, 'soak $m b->a', 1024);
    results['soak minute $m'] = ab && ba;
    print('${t()} soak minute $m: a->b ${ab ? "ok" : "lost"}, b->a ${ba ? "ok" : "lost"}');
    await Future<void>.delayed(const Duration(seconds: 30));
  }
  a.stop();
  b.stop();

  print('\n${t()} results');
  results.forEach((k, v) => print('  ${v ? "ok  " : "FAIL"} $k'));
  final dupes = copies.entries.where((e) => e.value > 1).toList();
  print(dupes.isEmpty ? '  ok   no frame delivered twice' : '  FAIL duplicates: $dupes');
  exit(results.values.every((v) => v) && dupes.isEmpty ? 0 : 1);
}
