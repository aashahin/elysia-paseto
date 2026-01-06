import { Elysia } from "elysia";
import { decrypt, encrypt } from "paseto-ts/v4";

/**
 * PASETO Plugin for Elysia.js
 *
 * Provides secure token generation and verification using PASETO v4 (local tokens).
 * PASETO is more secure than JWT as it:
 * - Has only one secure algorithm choice per version (no algorithm confusion)
 * - Is immune to many JWT vulnerabilities
 * - Has built-in payload encryption for local tokens
 */
export interface PasetoPayload {
  [key: string]: any;

  exp?: string;
  iat?: string;
  nbf?: string;
}

export interface PasetoOptions {
  /**
   * Name of the plugin instance. Default: "paseto"
   */
  name?: string;

  /**
   * Secret key for signing/encrypting tokens (must be 32 bytes)
   */
  secret: string;

  /**
   * Token expiration time. Can be:
   * - Number in seconds
   * - String like "7d", "24h", "30m"
   */
  exp?: string | number;
}

/**
 * Convert expiration format to PASETO-compatible relative time string
 * Converts "7d", "24h", "30m" format to "7 days", "24 hours", "30 minutes"
 */
function convertExpiration(exp: string | number): string {
  if (typeof exp === "number") {
    // Convert seconds to appropriate unit
    if (exp % 86400 === 0) return `${exp / 86400} days`;
    if (exp % 3600 === 0) return `${exp / 3600} hours`;
    if (exp % 60 === 0) return `${exp / 60} minutes`;
    return `${exp} seconds`;
  }

  const units: Record<string, string> = {
    s: "seconds",
    m: "minutes",
    h: "hours",
    d: "days",
    w: "weeks"
  };

  const match = exp.match(/^(\d+)([smhdw])$/);
  if (!match) {
    throw new Error(`Invalid expiration format: ${exp}`);
  }

  const [, value, unit] = match;
  const unitName = units[unit ?? "s"];
  return `${value} ${unitName}`;
}

/**
 * Ensure secret is properly formatted for PASETO v4
 * Key must be 32 bytes and prepended with k4.local. (PASERK format)
 */
function prepareSecret(secret: string): string {
  // If already in PASERK format, return as-is
  if (secret.startsWith("k4.local.")) {
    return secret;
  }

  const encoder = new TextEncoder();
  const secretBytes = encoder.encode(secret);

  let keyBytes: Uint8Array;
  if (secretBytes.length < 32) {
    // Pad with zeros if too short
    keyBytes = new Uint8Array(32);
    keyBytes.set(secretBytes);
  } else if (secretBytes.length > 32) {
    // Truncate if too long
    keyBytes = secretBytes.slice(0, 32);
  } else {
    keyBytes = secretBytes;
  }

  // Convert to PASERK format: k4.local.[base64url-encoded key]
  return `k4.local.${Buffer.from(keyBytes).toString("base64url")}`;
}

export const paseto = (options?: PasetoOptions) => {
  const name = options?.name || "paseto";
  const secret = options?.secret;
  const exp = options?.exp;

  if (!secret) {
    throw new Error("PASETO secret is required");
  }

  const secretKey = prepareSecret(secret);
  const defaultExpiration = exp ? convertExpiration(exp) : "1 hour";

  return new Elysia({
    name: `plugin.${name}`
  }).decorate(name, {
    /**
     * Sign a payload and create a PASETO token
     */
    sign: async (payload: PasetoPayload): Promise<string> => {
      const tokenPayload: PasetoPayload = { ...payload };

      // Set expiration to relative time if not already set
      // PASETO will automatically convert it to ISO 8601
      if (!tokenPayload.exp && exp) {
        tokenPayload.exp = defaultExpiration;
      }

      // Use PASETO v4 local (encrypted + authenticated)
      // The library will automatically add iat and convert exp to ISO 8601
      return encrypt(secretKey, tokenPayload, {
        addIat: true, // Add issued-at timestamp
        addExp: !payload.exp, // Add default expiry if not provided
        validatePayload: true // Validate claim formats
      });
    },

    /**
     * Verify and decode a PASETO token
     */
    verify: async (token?: string): Promise<false | PasetoPayload> => {
      if (!token) return false;
      if (!token.startsWith("v4.local.")) { // Invalid token format
        console.warn("Invalid PASETO token format");
        return false;
      }

      try {
        // Decrypt and verify the token
        // PASETO automatically validates exp, nbf, and iat claims
        // Note: decrypt(key, token, options) - key is first parameter!
        const result = decrypt<PasetoPayload>(secretKey, token, {
          validatePayload: true // Validate registered claims
        });

        return result.payload;
      } catch (error) {
        console.error("PASETO verification failed:", error);
        return false;
      }
    }
  });
};
