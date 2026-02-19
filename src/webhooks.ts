/**
 * Webhook signature verification for ByteForge Aegis webhooks.
 *
 * Aegis signs webhooks with HMAC-SHA256 over "{timestamp}.{body}" and sends
 * the result in the X-Aegis-Signature header as "sha256={hex_digest}".
 */
import { createHmac, timingSafeEqual } from 'crypto';

/**
 * Verify an incoming Aegis webhook signature.
 *
 * @param secret - The webhook secret for this site (from site.webhook_secret)
 * @param signatureHeader - The value of the X-Aegis-Signature header
 * @param timestamp - The value of the X-Aegis-Timestamp header
 * @param body - The raw request body string
 * @param toleranceSeconds - Maximum age of the webhook in seconds (default 300).
 *   Set to 0 to disable timestamp freshness checking.
 * @returns true if the signature is valid (and timestamp is fresh), false otherwise
 */
export function verifyWebhookSignature(
  secret: string,
  signatureHeader: string,
  timestamp: string,
  body: string,
  toleranceSeconds: number = 300,
): boolean {
  if (!signatureHeader || !signatureHeader.startsWith('sha256=')) {
    return false;
  }

  const receivedDigest = signatureHeader.slice(7);

  // Check timestamp freshness
  if (toleranceSeconds > 0) {
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

    return timingSafeEqual(expected, received);
  } catch {
    return false;
  }
}
