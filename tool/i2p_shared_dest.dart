// Live check of shared destinations as a rendezvous: nodes A and B answer
// for the same destination (made from shared seeds, as a chat room's name
// would give), node C looks it up and greets it every 30 s. Every greeting
// that some member answers counts; the go/no-go line for using this as a
// room's meeting point is 80%.
//
//   dart run tool/i2p_shared_dest.dart [state folder] [--rounds=20] [--vandal] [--rx]
//
// --vandal adds node D, which also publishes the shared destination but
// never answers, to see how often a newcomer lands on a silent publisher.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:i2p/i2p.dart';

const port = 4243;

Future<void> main(List<String> args) async {
  final dir = args.firstWhere((a) => !a.startsWith('--'), orElse: () => 'i2p-shared-state');
  final rounds = int.tryParse(args.firstWhere((a) => a.startsWith('--rounds='), orElse: () => '--rounds=20').substring(9)) ?? 20;
  final vandal = args.contains('--vandal');
  final sw = Stopwatch()..start();
  String t() => '${(sw.elapsedMilliseconds / 1000).toStringAsFixed(1)}s';

  I2pService node(String name) {
    final state = Directory('$dir/$name')..createSync(recursive: true);
    final f = File('${state.path}/identity.key');
    final id = (f.existsSync() ? I2pIdentity.fromBytes(f.readAsBytesSync()) : null) ?? I2pIdentity.generate();
    f.writeAsBytesSync(id.toBytes());
    return I2pService(
        rxDiag: args.contains('--rx'),
        identity: id,
        stateDir: state.path,
        log: (m) {
          if (m.contains('up with') || m.contains('shared') || m.contains('from cache') || m.contains('app frame') ||
              m.contains('lost') || m.contains('no leases')) {
            print('${t()} [$name] $m');
          }
        });
  }

  Uint8List seed(String part) =>
      Uint8List.fromList(sha256.convert(utf8.encode('i2p-shared-dest-test/v1|ROOM|0|$part')).bytes);
  final enc = seed('enc'), sign = seed('sign');

  final names = ['a', 'b', 'c', if (vandal) 'd'];
  final nodes = {for (final n in names) n: node(n)};
  final ups = await Future.wait([for (final n in nodes.values) n.ensureStarted()]);
  print('${t()} up: ${[for (var i = 0; i < names.length; i++) '${names[i]}=${ups[i]}'].join(' ')}');
  if (!ups.every((u) => u)) exit(1);

  String? room;
  for (final n in [nodes['a']!, nodes['b']!, if (vandal) nodes['d']!]) {
    room = await n.addSharedDestination(enc, sign);
  }
  print('${t()} shared destination $room');

  // Members answer greetings sent to the room with their own name.
  for (final name in ['a', 'b']) {
    final s = nodes[name]!;
    s.messages.where((m) => m.port == port).listen((m) {
      final text = utf8.decode(m.payload);
      if (m.toB32 == room && text.startsWith('hello ')) {
        unawaited(s.send(m.fromB32, port, Uint8List.fromList(utf8.encode('$name answers ${text.substring(6)}'))));
      }
    });
  }
  final answered = <int, String>{};
  final c = nodes['c']!;
  c.messages.where((m) => m.port == port).listen((m) {
    final text = utf8.decode(m.payload);
    final parts = text.split(' ');
    final n = int.tryParse(parts.last);
    if (n != null && !answered.containsKey(n)) {
      answered[n] = parts.first;
      print('${t()} [c] greeting $n answered by ${parts.first}');
    }
  });

  // Let the shared LeaseSets reach the floodfills.
  await Future<void>.delayed(const Duration(seconds: 20));
  var sent = 0;
  final sentAt = <int, int>{};
  final latency = <int>[];
  c.messages.where((m) => m.port == port).listen((m) {
    final n = int.tryParse(utf8.decode(m.payload).split(' ').last);
    if (n != null && sentAt.containsKey(n)) latency.add(sw.elapsedMilliseconds - sentAt.remove(n)!);
  });
  for (var i = 1; i <= rounds; i++) {
    sentAt[i] = sw.elapsedMilliseconds;
    final ok = await c.send(room!, port, Uint8List.fromList(utf8.encode('hello $i')));
    if (ok) sent++;
    print('${t()} [c] greeting $i sent: $ok');
    await Future<void>.delayed(const Duration(seconds: 30));
  }
  await Future<void>.delayed(const Duration(seconds: 20));
  for (final n in nodes.values) {
    n.stop();
  }
  final byA = answered.values.where((v) => v == 'a').length, byB = answered.values.where((v) => v == 'b').length;
  latency.sort();
  final pct = rounds == 0 ? 0 : answered.length * 100 ~/ rounds;
  print('\n${t()} results: $rounds greetings, $sent taken by a gateway, ${answered.length} answered ($pct%): '
      'a $byA, b $byB${latency.isEmpty ? '' : '; median answer ${latency[latency.length ~/ 2] ~/ 1000} s'}');
  print(pct >= 80 ? '  GO: the shared destination works as a meeting point' : '  NO-GO: under 80%');
  exit(pct >= 80 ? 0 : 1);
}
