import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sessionDuration, sessionRows } from '../src/pages/vpn-sessions';

test('session duration never includes time after the last observation', () => {
  assert.equal(sessionDuration(1000, 91000), '1m 30s');
  assert.equal(sessionDuration(1000, 1000 + 90061000), '1d 1h 1m 1s');
  assert.equal(sessionDuration(2000, 1000), '0m 0s');
});

test('sessions escape router fields, distinguish incomplete observations and monitoring gaps', () => {
  const row = { id: '1', publicKey: 'key', name: '<script>', interface: 'wg0', allowedIp: '10.0.0.2/32',
    endpoint: '198.51.100.1', startedAt: 1_000_000, lastSeenAt: 1_010_000, endedAt: null,
    rx: 123, tx: 456, endReason: '', partial: true };
  const html = sessionRows([row], 1_010_000, 1_020_000);
  assert.ok(html.includes('&lt;script&gt;'));
  assert.ok(!html.includes('<script>'));
  assert.ok(html.includes('Active'));
  assert.ok(html.includes('Partial observation'));
  assert.ok(html.includes('0m 10s'));
  assert.ok(sessionRows([row], 1_010_000, 1_200_000).includes('Monitoring gap'));
  assert.ok(sessionRows([{ ...row, endedAt: 1_010_000, endReason: 'endpoint-changed' }], null).includes('IP changed'));
  assert.ok(sessionRows([], null).includes('No observed sessions'));
});
