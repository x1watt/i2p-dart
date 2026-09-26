// Inbound gateways are replaced before their tunnels expire, and leases never
// outlive them. Routers drop a tunnel ten minutes after it was built while
// the session to them stays up; before this rule a node went dark at about
// ten minutes and stayed dark.
import 'package:i2p/src/i2p_node.dart';
import 'package:test/test.dart';

void main() {
  final built = DateTime.utc(2026, 9, 26, 12);
  int sec(DateTime t) => t.millisecondsSinceEpoch ~/ 1000;

  test('a gateway ages after 5.5 minutes, so the four-minute check replaces it before ten', () {
    expect(GatewayClock.aging(built, built.add(const Duration(minutes: 5))), isFalse);
    expect(GatewayClock.aging(built, built.add(const Duration(minutes: 6))), isTrue);
    // The latest check that still sees it young is at 5.5 minutes; the next
    // one, four minutes later, must come before the tunnel ends.
    expect(
      GatewayClock.maxAge + const Duration(minutes: 4),
      lessThan(GatewayClock.tunnelLifetime),
    );
  });

  test('a lease ends with its tunnel, never ten minutes after publishing', () {
    final fresh = GatewayClock.leaseEnd(built, built);
    expect(fresh, sec(built.add(const Duration(minutes: 9, seconds: 30))));
    final late = GatewayClock.leaseEnd(built, built.add(const Duration(minutes: 8)));
    expect(late, fresh, reason: 'republishing does not extend an old tunnel');
    expect(late, lessThan(sec(built.add(GatewayClock.tunnelLifetime))));
  });

  test('aging gateways are retired only when they have replacements', () {
    // Two wanted, both aging, two new ones built: retire both.
    expect(GatewayClock.retireCount(total: 4, want: 2, aging: 2), 2);
    // Only one replacement could be built: keep one old one.
    expect(GatewayClock.retireCount(total: 3, want: 2, aging: 2), 1);
    // No replacement: keep them all rather than go dark.
    expect(GatewayClock.retireCount(total: 2, want: 2, aging: 2), 0);
    expect(GatewayClock.retireCount(total: 1, want: 2, aging: 1), 0);
    // Spares beyond the aging ones are not retired here.
    expect(GatewayClock.retireCount(total: 5, want: 2, aging: 1), 1);
  });
}
