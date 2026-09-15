// Lasting identity, the router cache, lease set checks and application
// frames.   dart test test/identity_messages_test.dart
import 'dart:io';
import 'dart:typed_data';

import 'package:i2p/src/i2p_crypto.dart';
import 'package:i2p/src/i2p_datagram.dart';
import 'package:i2p/src/i2p_identity.dart';
import 'package:i2p/src/i2p_leaseset.dart';
import 'package:i2p/src/i2p_message.dart';
import 'package:i2p/src/i2p_router.dart';
import 'package:i2p/src/i2p_router_cache.dart';
import 'package:i2p/src/i2p_structures.dart';
import 'package:test/test.dart';

Uint8List bytes(int n, int v) => Uint8List.fromList(List.filled(n, v));

void main() {
  group('identity', () {
    test('bytes round trip', () {
      final id = I2pIdentity.generate();
      final back = I2pIdentity.fromBytes(id.toBytes())!;
      expect(back.toBytes(), id.toBytes());
      expect(I2pIdentity.fromBytes(Uint8List(10)), isNull);
      final wrongVersion = id.toBytes()..[0] = 9;
      expect(I2pIdentity.fromBytes(wrongVersion), isNull);
    });

    test('same seeds give the same destination and router', () async {
      final id = I2pIdentity.generate();
      final a = await Destination.generate(encSeed: id.destEnc, signSeed: id.destSign);
      final b = await Destination.generate(encSeed: id.destEnc, signSeed: id.destSign);
      expect(a.keysAndCert, b.keysAndCert);
      expect(a.hash, b.hash);
      expect(a.hash, I2pCrypto.sha256(a.keysAndCert));
      final other = await Destination.generate();
      expect(other.hash, isNot(a.hash));

      final r1 = await OurRouter.generate(staticSeed: id.routerStatic, signSeed: id.routerSign);
      final r2 = await OurRouter.generate(staticSeed: id.routerStatic, signSeed: id.routerSign);
      expect(r1.identityHash, r2.identityHash);
      expect(r1.staticPub, r2.staticPub);
    });
  });

  group('lease set', () {
    late Destination d;
    late Uint8List ls; // without the store type byte, as in a DatabaseStore
    final gw = bytes(32, 7);
    setUpAll(() async {
      d = await Destination.generate();
      final end = DateTime.now().millisecondsSinceEpoch ~/ 1000 + 600;
      ls = (await d.buildLeaseSet2([Lease2(gw, 1234, end), Lease2(bytes(32, 8), 99, end)])).sublist(1);
    });

    test('accepts the owner\'s lease set', () async {
      final v = await verifyLeaseSet2(ls, d.hash);
      expect(v, isNotNull);
      expect(v!.leases.length, 2);
      expect(v.leases.first.gatewayHash, gw);
      expect(v.leases.first.tunnelId, 1234);
      expect(v.destination, d.keysAndCert);
    });

    test('rejects another hash, a changed lease and an old one', () async {
      expect(await verifyLeaseSet2(ls, bytes(32, 1)), isNull);
      final tampered = Uint8List.fromList(ls);
      tampered[391 + 4 + 2 + 2 + 2 + 1 + 4 + 32 + 1 + 5] ^= 1; // first lease's gateway
      expect(await verifyLeaseSet2(tampered, d.hash), isNull);
      final later = DateTime.now().millisecondsSinceEpoch ~/ 1000 + 3600;
      expect(await verifyLeaseSet2(ls, d.hash, nowSeconds: later), isNull);
    });

    test('rejects a lease set signed by someone else', () async {
      // The attacker's own lease set, relabelled with the victim's destination.
      final attacker = await Destination.generate();
      final end = DateTime.now().millisecondsSinceEpoch ~/ 1000 + 600;
      final forged = (await attacker.buildLeaseSet2([Lease2(bytes(32, 9), 1, end)])).sublist(1);
      forged.setRange(0, 391, d.keysAndCert);
      expect(await verifyLeaseSet2(forged, d.hash), isNull);
    });
  });

  group('application frames', () {
    final us = bytes(32, 1), them = bytes(32, 2);
    AppFrame frame({Uint8List? to, int? time, int id = 5}) => AppFrame(
        4242,
        bytes(8, id),
        time ?? DateTime.now().millisecondsSinceEpoch ~/ 1000,
        to ?? us,
        Uint8List.fromList('t:message'.codeUnits));

    test('build and parse', () {
      final f = frame();
      final p = parseApp(buildApp(f))!;
      expect(p.port, 4242);
      expect(p.msgId, f.msgId);
      expect(p.timeSeconds, f.timeSeconds);
      expect(p.toHash, us);
      expect(String.fromCharCodes(p.payload), 't:message');
      expect(parseApp(Uint8List(10)), isNull);
      expect(() => buildApp(AppFrame(1, bytes(8, 0), 0, us, Uint8List(appMaxPayload + 1))),
          throwsArgumentError);
    });

    test('version 2 frames carry the sender\'s reply leases', () {
      final leases = [ReplyLease(bytes(32, 7), 1234), ReplyLease(bytes(32, 8), 99)];
      final p = parseApp(buildApp(AppFrame(4244, bytes(8, 1), 1000, us, Uint8List.fromList([1, 2, 3]),
          replyLeases: leases)))!;
      expect(p.replyLeases.map((l) => l.tunnelId), [1234, 99]);
      expect(p.replyLeases.first.gatewayHash, bytes(32, 7));
      expect(p.payload, [1, 2, 3]);
      expect(p.toHash, us);
    });

    test('the gate takes each frame once, only for us, only when fresh', () {
      final gate = AppGate();
      final f = frame();
      expect(gate.accept(us, them, f), isTrue);
      expect(gate.accept(us, them, f), isFalse, reason: 'duplicate or replay');
      expect(gate.accept(us, bytes(32, 3), f), isTrue, reason: 'same id, other sender');
      expect(gate.accept(us, them, frame(to: bytes(32, 4), id: 6)), isFalse, reason: 'not ours');
      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      expect(gate.accept(us, them, frame(time: now - 3600, id: 7)), isFalse, reason: 'old');
      expect(gate.accept(us, them, frame(time: now + 3600, id: 8)), isFalse, reason: 'future');
    });

    test('the gate forgets the oldest ids past its capacity', () {
      final gate = AppGate(capacity: 2);
      final a = frame(id: 1), b = frame(id: 2), c = frame(id: 3);
      expect(gate.accept(us, them, a), isTrue);
      expect(gate.accept(us, them, b), isTrue);
      expect(gate.accept(us, them, c), isTrue);
      expect(gate.accept(us, them, a), isTrue);
      expect(gate.accept(us, them, c), isFalse);
    });
  });

  group('shared destinations', () {
    test('the same seeds give every member the same address, and both lease sets verify', () async {
      final enc = bytes(32, 21), sign = bytes(32, 22);
      final a = await Destination.generate(encSeed: enc, signSeed: sign);
      final b = await Destination.generate(encSeed: enc, signSeed: sign);
      expect(a.hash, b.hash);
      final end = DateTime.now().millisecondsSinceEpoch ~/ 1000 + 600;
      // Two members publish the shared destination with their own gateways.
      final lsA = (await a.buildLeaseSet2([Lease2(bytes(32, 1), 11, end)])).sublist(1);
      final lsB = (await b.buildLeaseSet2([Lease2(bytes(32, 2), 22, end)])).sublist(1);
      expect((await verifyLeaseSet2(lsA, a.hash))!.leases.single.tunnelId, 11);
      expect((await verifyLeaseSet2(lsB, a.hash))!.leases.single.tunnelId, 22);
    });

    test('the gate takes frames for any destination the node answers for and says which', () {
      final gate = AppGate();
      final own = bytes(32, 1), shared = bytes(32, 5), other = bytes(32, 9), src = bytes(32, 2);
      AppFrame f(Uint8List to, int id) =>
          AppFrame(4243, bytes(8, id), DateTime.now().millisecondsSinceEpoch ~/ 1000, to, Uint8List(0));
      expect(gate.acceptTo([own, shared], src, f(shared, 1)), shared);
      expect(gate.acceptTo([own, shared], src, f(own, 2)), own);
      expect(gate.acceptTo([own, shared], src, f(other, 3)), isNull);
      expect(gate.acceptTo([own, shared], src, f(shared, 1)), isNull, reason: 'already seen');
    });
  });

  group('router cache', () {
    test('keeps routers, their order and the worked flag', () async {
      final a = await OurRouter.generate(), b = await OurRouter.generate();
      final enc = encodeRouterCache([(a.routerInfo, true), (b.routerInfo, false)]);
      final c = decodeRouterCache(enc);
      expect(c.routers.length, 2);
      expect(c.routers.first.identityHash, a.identityHash);
      expect(c.good, {hex(a.identityHash)});
      expect(c.routers.first.raw, a.routerInfo);
    });

    test('drops old routers and survives a bad file', () async {
      final a = await OurRouter.generate();
      final enc = encodeRouterCache([(a.routerInfo, false)]);
      final later = DateTime.now().add(const Duration(days: 40)).millisecondsSinceEpoch;
      expect(decodeRouterCache(enc, nowMs: later).routers, isEmpty);
      expect(decodeRouterCache(Uint8List.fromList([1, 2, 3])).routers, isEmpty);
      expect(decodeRouterCache(enc.sublist(0, enc.length - 10)).routers, isEmpty);
    });

    test('saves and loads from a folder', () async {
      final dir = await Directory.systemTemp.createTemp('i2p_cache');
      addTearDown(() => dir.delete(recursive: true));
      final a = await OurRouter.generate();
      saveRouterCache(dir.path, [(a.routerInfo, true)]);
      final c = loadRouterCache(dir.path);
      expect(c.routers.single.identityHash, a.identityHash);
      expect(loadRouterCache('${dir.path}/missing').routers, isEmpty);
      expect(parseRouterInfo(a.routerInfo)!.publishedMs, greaterThan(0));
    });
  });
}

String hex(List<int> b) => b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
