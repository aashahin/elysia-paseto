import { beforeAll, describe, expect, it } from "bun:test";
import { Elysia } from "elysia";
import { paseto } from "../index.js";

describe("PASETO Plugin", () => {
  const testSecret = "test-secret-key-32-bytes-long!";
  let app: Elysia;

  beforeAll(() => {
    app = new Elysia().use(
      paseto({
        name: "paseto",
        secret: testSecret,
        exp: "1h",
      })
    );
  });

  describe("Token Generation", () => {
    it("should generate a valid PASETO token", async () => {
      const payload = {
        id: "user123",
        email: "test@example.com",
        role: "admin",
      };

      // @ts-ignore - Access the paseto decorator
      const token = await app.decorator.paseto.sign(payload);

      expect(token).toBeDefined();
      expect(typeof token).toBe("string");
      expect(token.startsWith("v4.local.")).toBe(true);
    });

    it("should include iat (issued at) timestamp automatically", async () => {
      const payload = { id: "user123" };

      // @ts-ignore
      const token = await app.decorator.paseto.sign(payload);
      // @ts-ignore
      const decoded = await app.decorator.paseto.verify(token);

      expect(decoded).toBeDefined();
      expect(decoded.iat).toBeDefined();
      expect(typeof decoded.iat).toBe("string");
    });

    it("should add exp (expiration) when configured", async () => {
      const payload = { id: "user123" };

      // @ts-ignore
      const token = await app.decorator.paseto.sign(payload);
      // @ts-ignore
      const decoded = await app.decorator.paseto.verify(token);

      expect(decoded).toBeDefined();
      expect(decoded.exp).toBeDefined();
      expect(typeof decoded.exp).toBe("string");

      // Verify expiration is in the future
      const expTime = new Date(decoded.exp).getTime();
      const now = Date.now();
      expect(expTime).toBeGreaterThan(now);
    });

    it("should respect custom expiration in payload", async () => {
      const customExp = new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString(); // 2 hours
      const payload = {
        id: "user123",
        exp: customExp,
      };

      // @ts-ignore
      const token = await app.decorator.paseto.sign(payload);
      // @ts-ignore
      const decoded = await app.decorator.paseto.verify(token);

      expect(decoded.exp).toBe(customExp);
    });

    it("should handle complex payloads with nested objects", async () => {
      const payload = {
        id: "user123",
        email: "test@example.com",
        metadata: {
          roles: ["admin", "moderator"],
          permissions: {
            read: true,
            write: true,
            delete: false,
          },
        },
        preferences: {
          theme: "dark",
          language: "en",
        },
      };

      // @ts-ignore
      const token = await app.decorator.paseto.sign(payload);
      // @ts-ignore
      const decoded = await app.decorator.paseto.verify(token);

      expect(decoded.id).toBe(payload.id);
      expect(decoded.email).toBe(payload.email);
      expect(decoded.metadata.roles).toEqual(payload.metadata.roles);
      expect(decoded.metadata.permissions.write).toBe(true);
      expect(decoded.preferences.theme).toBe("dark");
    });
  });

  describe("Token Verification", () => {
    it("should verify a valid token", async () => {
      const payload = { id: "user123", email: "test@example.com" };

      // @ts-ignore
      const token = await app.decorator.paseto.sign(payload);
      // @ts-ignore
      const decoded = await app.decorator.paseto.verify(token);

      expect(decoded).toBeDefined();
      expect(decoded).not.toBe(false);
      expect(decoded.id).toBe(payload.id);
      expect(decoded.email).toBe(payload.email);
    });

    it("should return false for invalid token", async () => {
      const invalidToken = "v3.local.invalid-token-here";

      // @ts-ignore
      const result = await app.decorator.paseto.verify(invalidToken);

      expect(result).toBe(false);
    });

    it("should return false for undefined token", async () => {
      // @ts-ignore
      const result = await app.decorator.paseto.verify(undefined);

      expect(result).toBe(false);
    });

    it("should return false for empty string token", async () => {
      // @ts-ignore
      const result = await app.decorator.paseto.verify("");

      expect(result).toBe(false);
    });

    it("should reject tampered tokens", async () => {
      const payload = { id: "user123", role: "user" };

      // @ts-ignore
      const token = await app.decorator.paseto.sign(payload);

      // Tamper with the token
      const tamperedToken = token.slice(0, -10) + "tampered!!";

      // @ts-ignore
      const result = await app.decorator.paseto.verify(tamperedToken);

      expect(result).toBe(false);
    });

    it("should reject tokens from different secret", async () => {
      const differentApp = new Elysia().use(
        paseto({
          name: "paseto",
          secret: "different-secret-key-32-bytes",
          exp: "1h",
        })
      );

      // @ts-ignore
      const token = await differentApp.decorator.paseto.sign({
        id: "user123",
      });

      // Try to verify with original app (different secret)
      // @ts-ignore
      const result = await app.decorator.paseto.verify(token);

      expect(result).toBe(false);
    });
  });

  describe("Token Expiration", () => {
    it("should reject expired tokens", async () => {
      const expiredApp = new Elysia().use(
        paseto({
          name: "paseto",
          secret: testSecret,
          exp: "1s", // 1 second expiration
        })
      );

      const payload = { id: "user123" };

      // @ts-ignore
      const token = await expiredApp.decorator.paseto.sign(payload);

      // Wait for token to expire
      await new Promise((resolve) => setTimeout(resolve, 1500));

      // @ts-ignore
      const result = await expiredApp.decorator.paseto.verify(token);

      expect(result).toBe(false);
    });

    it("should handle tokens without expiration", async () => {
      const noExpApp = new Elysia().use(
        paseto({
          name: "paseto",
          secret: testSecret,
        })
      );

      const payload = { id: "user123" };

      // @ts-ignore
      const token = await noExpApp.decorator.paseto.sign(payload);
      // @ts-ignore
      const decoded = await noExpApp.decorator.paseto.verify(token);

      expect(decoded).toBeDefined();
      expect(decoded).not.toBe(false);
    });
  });

  describe("Expiration String Parsing", () => {
    it("should parse seconds correctly", async () => {
      const app30s = new Elysia().use(
        paseto({
          name: "paseto",
          secret: testSecret,
          exp: "30s",
        })
      );

      // @ts-ignore
      const token = await app30s.decorator.paseto.sign({ id: "user123" });
      // @ts-ignore
      const decoded = await app30s.decorator.paseto.verify(token);

      const expTime = new Date(decoded.exp).getTime();
      const now = Date.now();
      const diff = expTime - now;

      // Should be approximately 30 seconds (within 1 second tolerance)
      expect(diff).toBeGreaterThan(29000);
      expect(diff).toBeLessThan(31000);
    });

    it("should parse minutes correctly", async () => {
      const app5m = new Elysia().use(
        paseto({
          name: "paseto",
          secret: testSecret,
          exp: "5m",
        })
      );

      // @ts-ignore
      const token = await app5m.decorator.paseto.sign({ id: "user123" });
      // @ts-ignore
      const decoded = await app5m.decorator.paseto.verify(token);

      const expTime = new Date(decoded.exp).getTime();
      const now = Date.now();
      const diff = expTime - now;

      // Should be approximately 5 minutes
      expect(diff).toBeGreaterThan(4.9 * 60 * 1000);
      expect(diff).toBeLessThan(5.1 * 60 * 1000);
    });

    it("should parse hours correctly", async () => {
      const app2h = new Elysia().use(
        paseto({
          name: "paseto",
          secret: testSecret,
          exp: "2h",
        })
      );

      // @ts-ignore
      const token = await app2h.decorator.paseto.sign({ id: "user123" });
      // @ts-ignore
      const decoded = await app2h.decorator.paseto.verify(token);

      const expTime = new Date(decoded.exp).getTime();
      const now = Date.now();
      const diff = expTime - now;

      // Should be approximately 2 hours
      expect(diff).toBeGreaterThan(1.9 * 60 * 60 * 1000);
      expect(diff).toBeLessThan(2.1 * 60 * 60 * 1000);
    });

    it("should parse days correctly", async () => {
      const app7d = new Elysia().use(
        paseto({
          name: "paseto",
          secret: testSecret,
          exp: "7d",
        })
      );

      // @ts-ignore
      const token = await app7d.decorator.paseto.sign({ id: "user123" });
      // @ts-ignore
      const decoded = await app7d.decorator.paseto.verify(token);

      const expTime = new Date(decoded.exp).getTime();
      const now = Date.now();
      const diff = expTime - now;

      // Should be approximately 7 days
      expect(diff).toBeGreaterThan(6.9 * 24 * 60 * 60 * 1000);
      expect(diff).toBeLessThan(7.1 * 24 * 60 * 60 * 1000);
    });

    it("should parse numeric expiration (seconds)", async () => {
      const app300 = new Elysia().use(
        paseto({
          name: "paseto",
          secret: testSecret,
          exp: 300, // 300 seconds
        })
      );

      // @ts-ignore
      const token = await app300.decorator.paseto.sign({ id: "user123" });
      // @ts-ignore
      const decoded = await app300.decorator.paseto.verify(token);

      const expTime = new Date(decoded.exp).getTime();
      const now = Date.now();
      const diff = expTime - now;

      // Should be approximately 300 seconds (5 minutes)
      expect(diff).toBeGreaterThan(290 * 1000);
      expect(diff).toBeLessThan(310 * 1000);
    });
  });

  describe("Security", () => {
    it("should generate different tokens for same payload", async () => {
      const payload = { id: "user123" };

      // @ts-ignore
      const token1 = await app.decorator.paseto.sign(payload);
      // @ts-ignore
      const token2 = await app.decorator.paseto.sign(payload);

      // Tokens should be different due to different timestamps
      expect(token1).not.toBe(token2);
    });

    it("should handle special characters in payload", async () => {
      const payload = {
        id: "user123",
        name: "Test User <script>alert('xss')</script>",
        description: "Quote: \"Hello\" and Apostrophe: 'World'",
        unicode: "مرحبا 你好 🚀",
      };

      // @ts-ignore
      const token = await app.decorator.paseto.sign(payload);
      // @ts-ignore
      const decoded = await app.decorator.paseto.verify(token);

      expect(decoded.name).toBe(payload.name);
      expect(decoded.description).toBe(payload.description);
      expect(decoded.unicode).toBe(payload.unicode);
    });

    it("should handle very long payloads", async () => {
      const longString = "a".repeat(10000);
      const payload = {
        id: "user123",
        data: longString,
      };

      // @ts-ignore
      const token = await app.decorator.paseto.sign(payload);
      // @ts-ignore
      const decoded = await app.decorator.paseto.verify(token);

      expect(decoded.data).toBe(longString);
    });
  });

  describe("Real-world Authentication Scenarios", () => {
    it("should handle user authentication flow", async () => {
      // Step 1: User signs in
      const userPayload = {
        id: "user123",
        email: "user@example.com",
        role: "admin",
        activeTenantId: "tenant456",
      };

      // @ts-ignore
      const accessToken = await app.decorator.paseto.sign(userPayload);

      // Step 2: Verify token on subsequent requests
      // @ts-ignore
      const decoded = await app.decorator.paseto.verify(accessToken);

      expect(decoded.id).toBe("user123");
      expect(decoded.email).toBe("user@example.com");
      expect(decoded.role).toBe("admin");
      expect(decoded.activeTenantId).toBe("tenant456");
    });

    it("should handle customer authentication flow", async () => {
      const customerPayload = {
        id: "customer789",
        tenantId: "tenant456",
        isGuest: false,
        emailVerified: true,
      };

      // @ts-ignore
      const token = await app.decorator.paseto.sign(customerPayload);
      // @ts-ignore
      const decoded = await app.decorator.paseto.verify(token);

      expect(decoded.id).toBe("customer789");
      expect(decoded.tenantId).toBe("tenant456");
      expect(decoded.isGuest).toBe(false);
      expect(decoded.emailVerified).toBe(true);
    });

    it("should handle session refresh scenario", async () => {
      // Original session
      const originalPayload = {
        id: "user123",
        sessionId: "session1",
      };

      // @ts-ignore
      const originalToken = await app.decorator.paseto.sign(originalPayload);

      // Simulate time passing
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Refresh with new session ID
      const refreshedPayload = {
        id: "user123",
        sessionId: "session2",
      };

      // @ts-ignore
      const refreshedToken = await app.decorator.paseto.sign(refreshedPayload);

      // Both should be valid but different
      // @ts-ignore
      const originalDecoded = await app.decorator.paseto.verify(originalToken);
      // @ts-ignore
      const refreshedDecoded =
        await app.decorator.paseto.verify(refreshedToken);

      expect(originalDecoded.sessionId).toBe("session1");
      expect(refreshedDecoded.sessionId).toBe("session2");
      expect(originalToken).not.toBe(refreshedToken);
    });

    it("should handle OAuth state token", async () => {
      const statePayload = {
        state: "random-state-value",
        provider: "google",
        redirectUrl: "https://example.com/callback",
      };

      const shortLivedApp = new Elysia().use(
        paseto({
          name: "paseto",
          secret: testSecret,
          exp: "10m", // Short-lived for OAuth
        })
      );

      // @ts-ignore
      const stateToken =
        await shortLivedApp.decorator.paseto.sign(statePayload);
      // @ts-ignore
      const decoded = await shortLivedApp.decorator.paseto.verify(stateToken);

      expect(decoded.state).toBe("random-state-value");
      expect(decoded.provider).toBe("google");
      expect(decoded.redirectUrl).toBe("https://example.com/callback");
    });
  });

  describe("Error Handling", () => {
    it("should throw error if secret is not provided", () => {
      expect(() => {
        new Elysia().use(
          paseto({
            name: "paseto",
            // @ts-ignore - intentionally missing secret
            secret: undefined,
          })
        );
      }).toThrow();
    });

    it("should handle malformed token gracefully", async () => {
      const malformedTokens = [
        "not-a-paseto-token",
        "v3.local.",
        "v4.local.something",
        "",
        null,
        undefined,
      ];

      for (const token of malformedTokens) {
        // @ts-ignore
        const result = await app.decorator.paseto.verify(token);
        expect(result).toBe(false);
      }
    });
  });

  describe("Plugin Configuration", () => {
    it("should use custom plugin name", async () => {
      const customApp = new Elysia().use(
        paseto({
          name: "customAuth",
          secret: testSecret,
        })
      );

      // @ts-ignore
      expect(customApp.decorator.customAuth).toBeDefined();
      // @ts-ignore
      expect(customApp.decorator.customAuth.sign).toBeDefined();
      // @ts-ignore
      expect(customApp.decorator.customAuth.verify).toBeDefined();
    });

    it("should work without explicit expiration", async () => {
      const noExpApp = new Elysia().use(
        paseto({
          name: "paseto",
          secret: testSecret,
        })
      );

      const payload = { id: "user123" };

      // @ts-ignore
      const token = await noExpApp.decorator.paseto.sign(payload);
      // @ts-ignore
      const decoded = await noExpApp.decorator.paseto.verify(token);

      expect(decoded).toBeDefined();
      expect(decoded.id).toBe("user123");
    });
  });
});
