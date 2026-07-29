/**
 * Tests for webhook signature verification.
 *
 * Runs against the compiled output (`npm run build` first, which `pretest`
 * does) so what is tested is what ships. Uses node:test — no new
 * dependencies, keeping this library's zero-runtime-dependency property.
 */
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { test } from 'node:test';

import { verifyWebhookSignature } from '../dist/webhooks.js';

const SECRET = 'test_webhook_secret_abc123';
const BODY = JSON.stringify({
  event_type: 'user.verified',
  site_uuid: '0191e1a0-0000-7000-8000-000000000001',
  user_uuid: '0191e1a0-0000-7000-8000-0000000000aa',
  email: 'u@test.com',
  aegis_role: 'user',
  timestamp: 1700000000,
});

const now = () => String(Math.floor(Date.now() / 1000));

function sign(secret, timestamp, body) {
  const digest = createHmac('sha256', secret)
    .update(`${timestamp}.${body}`)
    .digest('hex');
  return `sha256=${digest}`;
}

test('valid signature passes', () => {
  const ts = now();
  assert.equal(verifyWebhookSignature(SECRET, sign(SECRET, ts, BODY), ts, BODY), true);
});

test('wrong secret fails', () => {
  const ts = now();
  assert.equal(verifyWebhookSignature('wrong', sign(SECRET, ts, BODY), ts, BODY), false);
});

test('tampered body fails', () => {
  const ts = now();
  assert.equal(verifyWebhookSignature(SECRET, sign(SECRET, ts, BODY), ts, BODY + 'x'), false);
});

test('stale timestamp fails', () => {
  const ts = String(Math.floor(Date.now() / 1000) - 400);
  assert.equal(verifyWebhookSignature(SECRET, sign(SECRET, ts, BODY), ts, BODY), false);
});

// --- the unsigned X-Aegis-Event header ------------------------------------
//
// The HMAC covers only "{timestamp}.{raw_body}". The event header is not
// signed, so a captured delivery replayed inside the freshness window with
// that header rewritten still verifies. A receiver dispatching on the header
// then acts on a forged event.

test('matching event header passes', () => {
  const ts = now();
  assert.equal(
    verifyWebhookSignature(SECRET, sign(SECRET, ts, BODY), ts, BODY, 300, 'user.verified'),
    true,
  );
});

test('rewritten event header is rejected', () => {
  const ts = now();
  assert.equal(
    verifyWebhookSignature(SECRET, sign(SECRET, ts, BODY), ts, BODY, 300, 'user.deleted'),
    false,
  );
});

test('event header check is opt-in', () => {
  const ts = now();
  assert.equal(verifyWebhookSignature(SECRET, sign(SECRET, ts, BODY), ts, BODY), true);
});

test('non-JSON body with an event type is rejected', () => {
  const ts = now();
  const body = 'not json at all';
  assert.equal(
    verifyWebhookSignature(SECRET, sign(SECRET, ts, body), ts, body, 300, 'user.verified'),
    false,
  );
});

test('JSON array body with an event type is rejected', () => {
  const ts = now();
  const body = '["user.verified"]';
  assert.equal(
    verifyWebhookSignature(SECRET, sign(SECRET, ts, body), ts, body, 300, 'user.verified'),
    false,
  );
});

test('body without an event_type is rejected', () => {
  const ts = now();
  const body = '{"user_uuid":"abc"}';
  assert.equal(
    verifyWebhookSignature(SECRET, sign(SECRET, ts, body), ts, body, 300, 'user.verified'),
    false,
  );
});

// --- parity with the Python implementations -------------------------------

test('non-hex signature is rejected', () => {
  const ts = now();
  assert.equal(verifyWebhookSignature(SECRET, 'sha256=' + 'z'.repeat(64), ts, BODY), false);
});

test('non-ASCII signature does not throw', () => {
  const ts = now();
  assert.equal(verifyWebhookSignature(SECRET, 'sha256=é'.repeat(10), ts, BODY), false);
});

test('trailing junk in the timestamp is rejected', () => {
  const ts = now();
  const dirty = `${ts}junk`;
  assert.equal(verifyWebhookSignature(SECRET, sign(SECRET, dirty, BODY), dirty, BODY), false);
});

test('missing signature header is rejected', () => {
  const ts = now();
  assert.equal(verifyWebhookSignature(SECRET, '', ts, BODY), false);
});
