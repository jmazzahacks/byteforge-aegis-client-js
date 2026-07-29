/**
 * Webhook signature verification for ByteForge Aegis webhooks.
 *
 * Aegis signs webhooks with HMAC-SHA256 over "{timestamp}.{body}" and sends
 * the result in the X-Aegis-Signature header as "sha256={hex_digest}".
 */
import { createHmac, timingSafeEqual } from 'crypto';

/** A SHA-256 HMAC rendered as hex — the only shape a signature may take. */
const HEX_DIGEST = /^[0-9a-fA-F]{64}$/;

/**
 * Whether the routing header agrees with the signed body.
 *
 * A body that is not JSON, not an object, or carries no event_type cannot
 * agree with anything, so it is rejected rather than waved through.
 */
function headerMatchesBody(headerEventType: string, body: string): boolean {
  let payload: unknown;
  try {
    payload = JSON.parse(body);
  } catch {
    return false;
  }

  if (typeof payload !== 'object' || payload === null) {
    return false;
  }

  return (payload as Record<string, unknown>).event_type === headerEventType;
}

/**
 * Verify an incoming Aegis webhook signature.
 *
 * IMPORTANT — pass eventType. The signature covers only the timestamp and
 * the body. The X-Aegis-Event header is NOT signed, so anyone holding a
 * captured delivery for your site can replay it within the freshness window
 * with that header rewritten to any event they like, and the signature
 * still verifies. If you dispatch on the header — the natural thing to do —
 * that is a forged event your handler will act on.
 *
 * Supplying eventType makes this function reject any delivery whose header
 * disagrees with the signed body. Omitting it leaves the check off, for
 * backwards compatibility only.
 *
 * @param secret - The webhook secret for this site (from site.webhook_secret)
 * @param signatureHeader - The value of the X-Aegis-Signature header
 * @param timestamp - The value of the X-Aegis-Timestamp header
 * @param body - The raw request body string. This must be the RAW bytes as
 *   received, not JSON.stringify() of a parsed object — re-serialising
 *   changes whitespace and unicode escaping, so the HMAC will not match.
 * @param toleranceSeconds - Maximum age of the webhook in seconds (default 300).
 *   Set to 0 to disable timestamp freshness checking.
 * @param eventType - The value of the X-Aegis-Event header. When supplied,
 *   verification fails unless it matches the signed body's event_type.
 *   Strongly recommended.
 * @returns true if the signature is valid (and timestamp is fresh, and the
 *   event header agrees with the body when supplied), false otherwise
 */
export function verifyWebhookSignature(
  secret: string,
  signatureHeader: string,
  timestamp: string,
  body: string,
  toleranceSeconds: number = 300,
  eventType?: string,
): boolean {
  if (!signatureHeader || !signatureHeader.startsWith('sha256=')) {
    return false;
  }

  const receivedDigest = signatureHeader.slice(7);

  // Match the Python implementations: reject anything that is not a hex
  // digest before comparing, so the two libraries accept the same inputs.
  if (!HEX_DIGEST.test(receivedDigest)) {
    return false;
  }

  // Check timestamp freshness
  if (toleranceSeconds > 0) {
    // Strict: parseInt would accept "1700000000junk", which Python's int()
    // rejects. The two libraries should not accept different input sets.
    if (!/^-?\d+$/.test(timestamp)) {
      return false;
    }
    const webhookTime = parseInt(timestamp, 10);
    if (isNaN(webhookTime)) {
      return false;
    }

    const currentTime = Math.floor(Date.now() / 1000);
    if (Math.abs(currentTime - webhookTime) > toleranceSeconds) {
      return false;
    }
  }

  // Compute expected signature
  const message = `${timestamp}.${body}`;
  const expectedDigest = createHmac('sha256', secret)
    .update(message)
    .digest('hex');

  // Constant-time comparison
  try {
    const expected = Buffer.from(expectedDigest, 'utf8');
    const received = Buffer.from(receivedDigest, 'utf8');

    if (expected.length !== received.length) {
      return false;
    }

    if (!timingSafeEqual(expected, received)) {
      return false;
    }
  } catch {
    return false;
  }

  if (eventType === undefined) {
    return true;
  }

  return headerMatchesBody(eventType, body);
}
