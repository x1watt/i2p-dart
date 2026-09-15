/*
 * I2pService — the high-level facade over the pure-Dart I2P node. It owns an
 * [I2pWorker], which runs the node in a dedicated background ISOLATE so its
 * crypto/network loops never starve the host app's UI isolate.
 *
 * The node is content-addressed: it serves and stores opaque blobs keyed by
 * their sha256. Bind it to your app's storage by passing an [I2pContentStore]
 * (or the lower-level get/put callbacks). It also keeps a callsign -> I2P
 * destination registry (fed from your app's beacons), fetches a blob by sha256
 * (from a known peer OR by content-routing discovery across the network), and
 * exposes pause()/resume() for a background-process governor (CPU / battery).
 *
 * This class is intentionally free of any Flutter or app-specific dependency —
 * logging and storage are injected.
 */
import 'dart:convert';
import 'dart:typed_data';

import 'i2p_identity.dart';
import 'i2p_leaseset.dart';
import 'i2p_node.dart' show i2pBase32;
import 'i2p_message.dart';
import 'i2p_worker.dart';

/// Pluggable, content-addressed blob store the node serves from and stores into.
/// Keys are the sha256 of the content, base64url-encoded without padding.
abstract class I2pContentStore {
  /// Return the bytes for [sha256B64u], or null if not held locally.
  Future<Uint8List?> get(String sha256B64u);

  /// Persist [bytes] (whose sha256 the caller has already verified) under an
  /// optional file [ext] hint. The store decides the on-disk layout.
  Future<void> put(Uint8List bytes, String ext);
}

/// Function-based content store, for callers that don't want to subclass.
class I2pCallbackStore implements I2pContentStore {
  final Future<Uint8List?> Function(String sha256B64u) onGet;
  final Future<void> Function(Uint8List bytes, String ext) onPut;
  I2pCallbackStore({required this.onGet, required this.onPut});

  @override
  Future<Uint8List?> get(String sha256B64u) => onGet(sha256B64u);
  @override
  Future<void> put(Uint8List bytes, String ext) => onPut(bytes, ext);
}

/// The `.b32.i2p` address of the destination made from these two 32-byte
/// seeds, without answering for it (see [I2pService.addSharedDestination]).
Future<String> sharedDestinationAddress(Uint8List encSeed, Uint8List signSeed) async {
  final d = await Destination.generate(encSeed: encSeed, signSeed: signSeed);
  return '${i2pBase32(d.hash)}.b32.i2p';
}

class I2pService {
  /// [store] backs content serving/storage (optional: a fetch-only node can omit
  /// it, but it will not be able to serve content to peers). [log] receives
  /// human-readable status lines. [netId] selects the I2P network (2 = the live
  /// public net; use an isolated id for a private testnet).
  ///
  /// [identity] keeps the same address across starts: pass the same
  /// [I2pIdentity] every time (keep its bytes secret; the service never
  /// writes them). [stateDir] is where the node caches the routers it saw, so
  /// the next start skips the reseed download.
  I2pService({
    I2pContentStore? store,
    void Function(String msg)? log,
    int netId = 2,
    I2pIdentity? identity,
    String? stateDir,
    bool rxDiag = false,
    bool directDelivery = true,
  })  : _store = store,
        _rxDiag = rxDiag,
        _direct = directDelivery,
        _log = log ?? ((_) {}),
        _netId = netId,
        _identity = identity,
        _stateDir = stateDir {
    _worker = I2pWorker(
      log: (m) => _log('I2P: $m'),
      onGet: _serve,
    );
  }

  final I2pContentStore? _store;
  final void Function(String msg) _log;
  final int _netId;
  final I2pIdentity? _identity;
  final String? _stateDir;
  final bool _rxDiag;
  final bool _direct;

  late final I2pWorker _worker;
  bool _started = false;
  bool _starting = false;
  bool _paused = false;
  String? _b32;
  final Map<String, Uint8List> _destByCallsign = {};

  bool get isUp => _started && !_paused;
  bool get isStarting => _starting;
  bool get isPaused => _paused;

  /// Our destination's address, "<52 chars>.b32.i2p", available once the node
  /// is up. Share this so peers can reach us.
  String? get b32 => _b32;

  /// Application messages sent to our destination (see [send]).
  Stream<I2pMessage> get messages => _worker.messages;

  /// Start the node (in its isolate) once (idempotent). Returns true when up.
  Future<bool> ensureStarted() async {
    if (_started) return true;
    if (_starting) return false;
    _starting = true;
    try {
      _b32 = await _worker.start(I2pWorkerConfig(
          netId: _netId, identity: _identity?.toBytes(), stateDir: _stateDir, rxDiag: _rxDiag, directDelivery: _direct));
      _started = _b32 != null;
      _log(_started
          ? 'node up (isolate), b32=$_b32'
          : 'node failed to start');
      if (_started) _pushRoster();
      return _started;
    } catch (e) {
      _log('start error: $e');
      return false;
    } finally {
      _starting = false;
    }
  }

  /// Suspend the node (governor / low-battery throttle): tears down tunnels and
  /// frees sessions in the worker isolate. Cheap to resume().
  Future<void> pause() async {
    if (!_started || _paused) return;
    _paused = true;
    await _worker.pause();
    _log('paused (throttled)');
  }

  Future<void> resume() async {
    if (!_started || !_paused) return;
    _paused = false;
    await _worker.resume();
    _pushRoster();
    _log('resumed');
  }

  /// Serve a sha256 (32 bytes) request from the bound content store (runs on the
  /// main isolate; bridged from the worker).
  Future<Uint8List?> _serve(Uint8List sha256) async {
    final s = _store;
    if (s == null) return null;
    return s.get(_b64u(sha256));
  }

  void _pushRoster() {
    if (_destByCallsign.isNotEmpty) {
      _worker.setRoster(_destByCallsign.values.toList());
    }
  }

  /// Record a callsign -> destination-hash mapping (from an incoming beacon).
  void registerDestination(String callsign, Uint8List destHash) {
    if (destHash.length != 32) return;
    _destByCallsign[callsign.toUpperCase()] = destHash;
    if (_started && !_paused) _pushRoster();
  }

  /// Register from a base32 b32 address ("<52chars>.b32.i2p").
  void registerB32(String callsign, String b32) {
    final h = decodeB32(b32);
    if (h != null) registerDestination(callsign, h);
  }

  Uint8List? destinationFor(String callsign) =>
      _destByCallsign[callsign.toUpperCase()];

  /// Fetch [sha256] from [callsign]'s destination and store it under [ext].
  /// Small blobs come back in one datagram; larger ones (> ~64 KiB) fall back to
  /// the swarm, seeded with this peer plus any other devices that have it.
  Future<bool> fetchFrom(String callsign, Uint8List sha256, String ext) async {
    final dest = destinationFor(callsign);
    if (!isUp || dest == null) return false;
    final direct = await _worker.fetch(dest, sha256);
    if (direct != null && direct.isNotEmpty) {
      return _persist(direct, sha256, ext, callsign);
    }
    return _persist(
        await _worker.swarmFetch(sha256, seed: [dest]), sha256, ext, callsign);
  }

  /// Fetch [sha256] directly from a b32 destination and store it under [ext].
  /// Small blobs arrive in one datagram; larger ones (> ~64 KiB) fall back to the
  /// swarm seeded with this destination.
  Future<bool> fetchByB32(String b32, Uint8List sha256, String ext) async {
    final dest = decodeB32(b32);
    if (!isUp || dest == null) return false;
    final direct = await _worker.fetch(dest, sha256);
    if (direct != null && direct.isNotEmpty) {
      return _persist(direct, sha256, ext, b32);
    }
    return _persist(
        await _worker.swarmFetch(sha256, seed: [dest]), sha256, ext, b32);
  }

  /// Discover any device(s) providing [sha256] across the network (no prior
  /// knowledge of who holds it) and collectively download it piece-by-piece from
  /// however many have it, storing the verified bytes under [ext].
  Future<bool> discover(Uint8List sha256, String ext) async {
    if (!isUp) return false;
    return _persist(await _worker.swarmFetch(sha256), sha256, ext, 'swarm');
  }

  /// Announce that we provide [sha256] so other devices can find it by hash.
  Future<void> announce(Uint8List sha256) async {
    if (isUp) await _worker.announce(sha256);
  }

  /// Send [payload] (up to 32 KiB) to the destination [b32] on [port]. Best
  /// effort, like a UDP datagram: true when one of its gateways took it; the
  /// receiver gets each message at most once, signed by our destination.
  Future<bool> send(String b32, int port, Uint8List payload) async {
    final dest = decodeB32(b32);
    if (!isUp || dest == null) return false;
    return _worker.send(dest, port, payload);
  }

  /// Answer for a destination whose seeds other nodes hold too, such as one
  /// derived from a chat room's name: the node publishes its LeaseSet2 with
  /// our tunnels, and [messages] addressed to it arrive with `to` set.
  /// Returns its address, or null while the node is down (add it again
  /// after a restart).
  Future<String?> addSharedDestination(Uint8List encSeed, Uint8List signSeed) async {
    if (!isUp) return null;
    return _worker.addShared(encSeed, signSeed);
  }

  Future<void> removeSharedDestination(String b32) async {
    final h = decodeB32(b32);
    if (isUp && h != null) await _worker.removeShared(h);
  }

  Future<bool> _persist(
      Uint8List? bytes, Uint8List sha256, String ext, String from) async {
    if (bytes == null || bytes.isEmpty) return false;
    await _store?.put(bytes, ext);
    _log('fetched ${_b64u(sha256)} from $from (${bytes.length}b)');
    return true;
  }

  void stop() {
    _worker.stop();
    _started = false;
    _b32 = null;
  }

  static String _b64u(Uint8List b) => base64Url.encode(b).replaceAll('=', '');

  /// Decode a "<52 base32 chars>.b32.i2p" address to the 32-byte dest hash.
  static Uint8List? decodeB32(String addr) {
    var s = addr.trim().toLowerCase();
    if (s.endsWith('.b32.i2p')) s = s.substring(0, s.length - 8);
    const alpha = 'abcdefghijklmnopqrstuvwxyz234567';
    var buffer = 0, bits = 0;
    final out = <int>[];
    for (final ch in s.codeUnits) {
      final v = alpha.indexOf(String.fromCharCode(ch));
      if (v < 0) return null;
      buffer = (buffer << 5) | v;
      bits += 5;
      if (bits >= 8) {
        bits -= 8;
        out.add((buffer >> bits) & 0xff);
      }
    }
    if (out.length < 32) return null;
    return Uint8List.fromList(out.sublist(0, 32));
  }
}
