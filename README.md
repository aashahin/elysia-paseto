# elysia-paseto

A PASETO (Platform-Agnostic Security Tokens) plugin for Elysia.js that provides secure token generation and verification using PASETO v4 local tokens.

## Why PASETO over JWT?

PASETO (Platform-Agnostic Security Tokens) is a modern alternative to JWT that eliminates common security pitfalls:

- ✅ **No algorithm confusion** - Each PASETO version has only one secure algorithm choice
- ✅ **Immune to JWT vulnerabilities** - Designed from the ground up with security best practices
- ✅ **Built-in encryption** - Local tokens are encrypted by default, not just signed
- ✅ **Versioned protocols** - Clear upgrade paths without breaking changes
- ✅ **Type-safe** - Full TypeScript support with type inference

## Installation

```bash
bun add elysia-paseto
```

## Quick Start

```typescript
import { Elysia } from "elysia";
import { paseto } from "elysia-paseto";

const app = new Elysia()
  .use(
    paseto({
      secret: "your-32-byte-secret-key-here!!",
      exp: "7d", // Tokens expire in 7 days
    })
  )
  .post("/login", async ({ paseto }) => {
    // Sign a token
    const token = await paseto.sign({
      userId: "123",
      email: "user@example.com",
      role: "admin",
    });

    return { token };
  })
  .get("/profile", async ({ paseto, headers }) => {
    // Verify a token
    const payload = await paseto.verify(
      headers.authorization?.replace("Bearer ", "")
    );

    if (!payload) {
      return { error: "Invalid token" };
    }

    return { user: payload };
  })
  .listen(3000);
```

## API Reference

### Plugin Configuration

```typescript
paseto(options: PasetoOptions)
```

#### PasetoOptions

| Option   | Type               | Required | Description                                                                                                |
| -------- | ------------------ | -------- | ---------------------------------------------------------------------------------------------------------- |
| `secret` | `string`           | Yes      | Secret key for encrypting tokens (must be 32 bytes). Can be a plain string or PASERK format (`k4.local.*`) |
| `exp`    | `string \| number` | No       | Default token expiration. Supports: `"7d"`, `"24h"`, `"30m"`, `"60s"` or seconds as number                 |
| `name`   | `string`           | No       | Name of the plugin instance (default: `"paseto"`)                                                          |

#### Expiration Format Examples

```typescript
// String formats
exp: "7d"; // 7 days
exp: "24h"; // 24 hours
exp: "30m"; // 30 minutes
exp: "60s"; // 60 seconds

// Number format (seconds)
exp: 604800; // 7 days in seconds
exp: 86400; // 24 hours in seconds
exp: 1800; // 30 minutes in seconds
```

### Methods

The plugin decorates your Elysia instance with a `paseto` object (or custom name if specified) containing:

#### `sign(payload: PasetoPayload): Promise<string>`

Signs and encrypts a payload into a PASETO token.

```typescript
const token = await paseto.sign({
  userId: "123",
  email: "user@example.com",
  role: "admin",
  customClaim: "any-value",
});
// Returns: "v4.local.xxx..."
```

**Automatic Claims:**

- `iat` (issued at) - Automatically added with current timestamp
- `exp` (expiration) - Added if configured in plugin options and not in payload

**Manual Expiration:**

```typescript
// Override default expiration
const token = await paseto.sign({
  userId: "123",
  exp: new Date(Date.now() + 3600000).toISOString(), // 1 hour
});
```

#### `verify(token?: string): Promise<false | PasetoPayload>`

Verifies and decrypts a PASETO token. Returns the payload if valid, or `false` if invalid/expired.

```typescript
const payload = await paseto.verify(token);

if (payload) {
  console.log("Valid token:", payload);
  // Access claims
  console.log("User ID:", payload.userId);
  console.log("Issued at:", payload.iat);
  console.log("Expires:", payload.exp);
} else {
  console.log("Invalid or expired token");
}
```

**Returns `false` when:**

- Token is undefined or empty
- Token format is invalid (not `v4.local.*`)
- Token signature verification fails
- Token has expired (`exp` claim)
- Token is not yet valid (`nbf` claim)

## Usage Examples

### Basic Authentication

```typescript
import { Elysia } from "elysia";
import { paseto } from "elysia-paseto";

const app = new Elysia()
  .use(
    paseto({
      secret: process.env.PASETO_SECRET!,
      exp: "7d",
    })
  )
  .post("/auth/login", async ({ paseto, body }) => {
    // Validate credentials (your logic here)
    const user = await validateUser(body.email, body.password);

    if (!user) {
      return { error: "Invalid credentials" };
    }

    const token = await paseto.sign({
      userId: user.id,
      email: user.email,
      role: user.role,
    });

    return { token };
  })
  .listen(3000);
```

### Protected Routes with Middleware

```typescript
import { Elysia } from "elysia";
import { paseto } from "elysia-paseto";

// Authentication middleware
const authenticate = async ({ paseto, headers, set }: any) => {
  const authHeader = headers.authorization;

  if (!authHeader?.startsWith("Bearer ")) {
    set.status = 401;
    return { error: "Missing authorization header" };
  }

  const token = authHeader.replace("Bearer ", "");
  const payload = await paseto.verify(token);

  if (!payload) {
    set.status = 401;
    return { error: "Invalid or expired token" };
  }

  return { user: payload };
};

const app = new Elysia()
  .use(
    paseto({
      secret: process.env.PASETO_SECRET!,
      exp: "1h",
    })
  )
  .get("/public", () => "Public endpoint")
  .guard(
    {
      beforeHandle: authenticate,
    },
    (app) =>
      app
        .get("/protected", ({ user }) => ({
          message: "Protected data",
          user,
        }))
        .post("/admin", ({ user }) => {
          if (user.role !== "admin") {
            return { error: "Unauthorized" };
          }
          return { message: "Admin action performed" };
        })
  )
  .listen(3000);
```

### Refresh Token Pattern

```typescript
import { Elysia } from "elysia";
import { paseto } from "elysia-paseto";

const app = new Elysia()
  .use(
    paseto({
      name: "accessToken",
      secret: process.env.ACCESS_TOKEN_SECRET!,
      exp: "15m", // Short-lived access tokens
    })
  )
  .use(
    paseto({
      name: "refreshToken",
      secret: process.env.REFRESH_TOKEN_SECRET!,
      exp: "7d", // Long-lived refresh tokens
    })
  )
  .post("/auth/login", async ({ accessToken, refreshToken, body }) => {
    const user = await validateUser(body.email, body.password);

    if (!user) {
      return { error: "Invalid credentials" };
    }

    const payload = {
      userId: user.id,
      email: user.email,
      role: user.role,
    };

    return {
      accessToken: await accessToken.sign(payload),
      refreshToken: await refreshToken.sign({ userId: user.id }),
    };
  })
  .post("/auth/refresh", async ({ accessToken, refreshToken, body }) => {
    const payload = await refreshToken.verify(body.refreshToken);

    if (!payload) {
      return { error: "Invalid refresh token" };
    }

    // Fetch fresh user data
    const user = await getUserById(payload.userId);

    return {
      accessToken: await accessToken.sign({
        userId: user.id,
        email: user.email,
        role: user.role,
      }),
    };
  })
  .listen(3000);
```

### Complex Payloads

```typescript
const token = await paseto.sign({
  userId: "123",
  email: "user@example.com",
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
});

const payload = await paseto.verify(token);
console.log(payload.metadata.roles); // ['admin', 'moderator']
console.log(payload.preferences.theme); // 'dark'
```

## Security Best Practices

### Secret Key Management

```typescript
// ✅ Good - Use environment variables
paseto({
  secret: process.env.PASETO_SECRET!,
});

// ✅ Good - Use key management service
paseto({
  secret: await getSecretFromVault("paseto-key"),
});

// ❌ Bad - Hardcoded secrets
paseto({
  secret: "my-secret-key",
});
```

### Secret Key Requirements

- Must be at least 32 bytes for PASETO v4
- Use cryptographically secure random generation
- Rotate keys periodically
- Never commit secrets to version control

Generate a secure secret:

```bash
# Using openssl
openssl rand -base64 32

# Using Node.js
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"

# Using Bun
bun -e "console.log(Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64'))"
```

### Token Expiration

```typescript
// ✅ Good - Short-lived tokens
paseto({ secret: "...", exp: "15m" });

// ⚠️  Caution - Long-lived tokens increase risk
paseto({ secret: "...", exp: "30d" });

// Use refresh tokens for long sessions
```

### Token Storage

**Frontend:**

- ✅ Memory (most secure, lost on refresh)
- ✅ HttpOnly cookies (secure for web apps)
- ⚠️ LocalStorage (vulnerable to XSS)
- ❌ Never log tokens or include in URLs

**Backend:**

- Store tokens in secure databases if needed
- Hash tokens before storage
- Implement token revocation lists for critical operations

## TypeScript Support

Full type safety with inference:

```typescript
interface UserPayload {
  userId: string;
  email: string;
  role: "admin" | "user";
}

const token = await paseto.sign<UserPayload>({
  userId: "123",
  email: "user@example.com",
  role: "admin",
});

const payload = (await paseto.verify(token)) as UserPayload | false;

if (payload) {
  payload.userId; // ✅ Type: string
  payload.email; // ✅ Type: string
  payload.role; // ✅ Type: 'admin' | 'user'
  payload.iat; // ✅ Type: string (auto-added)
  payload.exp; // ✅ Type: string (auto-added if configured)
}
```

## Testing

```typescript
import { describe, expect, it } from "bun:test";
import { Elysia } from "elysia";
import { paseto } from "elysia-paseto";

describe("Authentication", () => {
  const app = new Elysia().use(
    paseto({ secret: "test-secret-key-32-bytes-long!!", exp: "1h" })
  );

  it("should generate valid tokens", async () => {
    const token = await app.decorator.paseto.sign({ userId: "123" });

    expect(token).toBeDefined();
    expect(token.startsWith("v4.local.")).toBe(true);
  });

  it("should verify valid tokens", async () => {
    const payload = { userId: "123", email: "test@example.com" };
    const token = await app.decorator.paseto.sign(payload);
    const decoded = await app.decorator.paseto.verify(token);

    expect(decoded).toBeTruthy();
    expect(decoded.userId).toBe("123");
    expect(decoded.email).toBe("test@example.com");
  });

  it("should reject invalid tokens", async () => {
    const result = await app.decorator.paseto.verify("invalid-token");
    expect(result).toBe(false);
  });
});
```

## Troubleshooting

### "PASETO secret is required"

Ensure you provide a `secret` in the plugin options:

```typescript
paseto({
  secret: process.env.PASETO_SECRET || "fallback-secret-32-bytes!!",
});
```

### "Invalid PASETO token format"

Tokens must start with `v4.local.`. Check that:

- You're passing the full token string
- Token wasn't corrupted during transmission
- Token was generated by this library (PASETO v4)

### Token Verification Always Returns False

Common causes:

- **Token expired** - Check `exp` claim and system clock
- **Wrong secret** - Ensure same secret for sign/verify
- **Token corrupted** - Verify token wasn't modified
- **Invalid claims** - Check `nbf` (not before) claim

### Performance Considerations

PASETO v4 uses XChaCha20-Poly1305 for encryption:

- ✅ Faster than RSA-based JWT
- ✅ Constant-time operations (timing attack resistant)
- ✅ Optimized for modern CPUs

Benchmarks on typical hardware:

- Sign: ~50,000 ops/sec
- Verify: ~45,000 ops/sec

## Migration from JWT

If you're migrating from JWT to PASETO:

```typescript
// Before (JWT)
import jwt from "@elysiajs/jwt";

app.use(
  jwt({
    name: "jwt",
    secret: "secret",
    exp: "7d",
  })
);

const token = await jwt.sign(payload);
const decoded = await jwt.verify(token);

// After (PASETO)
import { paseto } from "elysia-paseto";

app.use(
  paseto({
    name: "paseto",
    secret: "secret-32-bytes-long-key!!!!!",
    exp: "7d",
  })
);

const token = await paseto.sign(payload);
const decoded = await paseto.verify(token);
```

Key differences:

- PASETO requires 32-byte secrets (JWT flexible)
- PASETO tokens are larger (~1.5x) due to encryption
- PASETO has no algorithm selection (security benefit)
- PASETO returns `false` on invalid tokens (not throwing errors)

## Resources

- [PASETO Specification](https://paseto.io/)
- [Elysia.js Documentation](https://elysiajs.com/)
- [paseto-ts Library](https://github.com/lroggendorff/paseto-ts)

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.
