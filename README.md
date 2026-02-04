# ByteForge Aegis Client - JavaScript/TypeScript

JavaScript/TypeScript client library for ByteForge Aegis multi-tenant authentication service.

## Installation

Install directly from GitHub:

```bash
npm install github:jmazzahacks/byteforge-aegis-client-js
```

Or with yarn:

```bash
yarn add github:jmazzahacks/byteforge-aegis-client-js
```

## Quick Start

```typescript
import { AuthClient } from 'byteforge-aegis-client-js';

// Initialize the client
const auth = new AuthClient({
  apiUrl: 'http://localhost:5678',
  siteId: 1, // Your site ID
});

// Register a new user
const registerResult = await auth.register('user@example.com', 'password123');
if (registerResult.success) {
  console.log('User registered:', registerResult.data);
}

// Login (returns auth token + refresh token)
const loginResult = await auth.login('user@example.com', 'password123');
if (loginResult.success) {
  console.log('Auth token:', loginResult.data.auth_token.token);
  console.log('Refresh token:', loginResult.data.refresh_token.token);
  // Tokens are automatically stored in the client
}

// Logout
await auth.logout();
```

## Configuration

### AuthClientConfig

```typescript
interface AuthClientConfig {
  apiUrl: string;         // Base URL of the auth API
  siteId?: number;        // Default site ID for user operations
  masterApiKey?: string;  // Master API key for admin operations
  autoRefresh?: boolean;  // Enable automatic token refresh (default: true)
  refreshBuffer?: number; // Seconds before expiration to refresh (default: 300)
}
```

### Example Configurations

**For Regular User Operations:**
```typescript
const auth = new AuthClient({
  apiUrl: 'https://auth.example.com',
  siteId: 1,
});
```

**For Admin Operations:**
```typescript
const adminAuth = new AuthClient({
  apiUrl: 'https://auth.example.com',
  masterApiKey: 'your-master-api-key',
});
```

## API Methods

### User Authentication

#### `register(email, password?, siteId?)`
Register a new user account. Password is optional - if omitted, user sets their password during email verification.

**Note:** This method may fail if the site has disabled self-registration (`allow_self_registration: false`).

```typescript
// With password (traditional flow)
const result = await auth.register('user@example.com', 'password123');

// Without password (simpler UX - user sets password via email)
const result = await auth.register('user@example.com');

if (result.success) {
  console.log('User created:', result.data);
} else {
  console.error('Error:', result.error);
}
```

#### `login(email, password, siteId?)`
Login a user and receive both an auth token (1 hour) and refresh token (7 days).

```typescript
const result = await auth.login('user@example.com', 'password123');
if (result.success) {
  console.log('Auth token:', result.data.auth_token.token);
  console.log('Refresh token:', result.data.refresh_token.token);
  // Tokens are automatically stored in the client
}
```

#### `refreshAuthToken()`
Manually refresh the auth token using the stored refresh token. This is called automatically when `autoRefresh` is enabled.

```typescript
const result = await auth.refreshAuthToken();
if (result.success) {
  console.log('New auth token:', result.data.auth_token.token);
  // If token rotation is enabled, a new refresh token is also returned
  if (result.data.refresh_token) {
    console.log('New refresh token:', result.data.refresh_token.token);
  }
}
```

#### `logout()`
Logout the current user and invalidate the token.

```typescript
await auth.logout();
```

#### `checkVerificationToken(token)`
Check if a verification token is valid and whether password setup is required. This is a non-destructive check (doesn't consume the token).

```typescript
const result = await auth.checkVerificationToken('verification-token-from-email');
if (result.success) {
  console.log('Password required:', result.data.password_required);
  console.log('Email:', result.data.email);
}
```

#### `verifyEmail(token, password?)`
Verify a user's email address with the token from the verification email. For admin-created users, password is required. For self-registered users, password is optional.

```typescript
// For self-registered users (already have password)
const result = await auth.verifyEmail('verification-token-from-email');

// For admin-created users (must set password)
const result = await auth.verifyEmail('verification-token-from-email', 'new-password');

if (result.success) {
  console.log('Email verified:', result.data);
}
```

### Password Management

#### `changePassword(oldPassword, newPassword)`
Change the password for the authenticated user.

```typescript
const result = await auth.changePassword('oldpass123', 'newpass456');
```

#### `requestPasswordReset(email, siteId?)`
Request a password reset email.

```typescript
const result = await auth.requestPasswordReset('user@example.com');
if (result.success) {
  console.log('Reset email sent');
}
```

#### `resetPassword(token, newPassword)`
Reset password using the token from the reset email.

```typescript
const result = await auth.resetPassword('reset-token-from-email', 'newpass123');
```

### Email Management

#### `requestEmailChange(newEmail)`
Request to change email address (requires authentication).

```typescript
const result = await auth.requestEmailChange('newemail@example.com');
```

#### `confirmEmailChange(token)`
Confirm email change with the token from the confirmation email.

```typescript
const result = await auth.confirmEmailChange('change-token-from-email');
```

### Admin User Methods

These methods require authentication as an admin user (Bearer token with admin role).

#### `adminListUsers()`
List all users for the authenticated admin's site. Returns users only for the admin's own site (auto-scoped by the backend).

```typescript
// Login as admin first
await auth.login('admin@example.com', 'password123');

// List users for admin's site
const result = await auth.adminListUsers();
if (result.success) {
  console.log('Users:', result.data);
  // [{ id: 1, email: 'user@example.com', role: 'user', is_verified: true, ... }]
}
```

### Admin Methods (Master API Key)

These methods require a master API key.

#### `registerAdmin(email, siteId, role?)`
Create a new user via admin API. The user will set their own password via email verification link (more secure than admin-set passwords).

```typescript
// Create a regular user (default role)
const result = await adminAuth.registerAdmin('user@example.com', 1);

// Create an admin user
const result = await adminAuth.registerAdmin('admin@example.com', 1, 'admin');
```

#### `createSite(siteData)`
Create a new site.

```typescript
const result = await adminAuth.createSite({
  name: 'My Site',
  domain: 'mysite.com',
  frontend_url: 'https://mysite.com',
  email_from: 'noreply@mysite.com',
  email_from_name: 'My Site',
  allow_self_registration: true, // optional, defaults to true
});
```

#### `getSite(siteId)`
Get site details by ID.

```typescript
const result = await adminAuth.getSite(1);
```

#### `listSites()`
List all sites.

```typescript
const result = await adminAuth.listSites();
if (result.success) {
  console.log('Sites:', result.data);
}
```

#### `updateSite(siteId, updates)`
Update site configuration.

```typescript
const result = await adminAuth.updateSite(1, {
  name: 'Updated Site Name',
  frontend_url: 'https://new-url.com',
});

// Disable self-registration for a site
const result = await adminAuth.updateSite(1, {
  allow_self_registration: false,
});
```

## Token Management

The client automatically manages authentication and refresh tokens:

```typescript
// Auth token methods
auth.setAuthToken('your-auth-token');
const authToken = auth.getAuthToken();
auth.clearAuthToken();

// Refresh token methods
auth.setRefreshToken('your-refresh-token');
const refreshToken = auth.getRefreshToken();
auth.clearRefreshToken();

// Clear all tokens
auth.clearAllTokens();

// Manual refresh (usually not needed with autoRefresh enabled)
await auth.refreshAuthToken();
```

### Auto-Refresh Behavior

When `autoRefresh` is enabled (default):
- **Proactive refresh**: Token is refreshed automatically 5 minutes before expiration
- **Reactive refresh**: On 401 response, the client automatically refreshes and retries the request

To disable auto-refresh:
```typescript
const auth = new AuthClient({
  apiUrl: 'https://auth.example.com',
  siteId: 1,
  autoRefresh: false,
});
```

### Persisting Tokens

If you need to persist tokens across page reloads:

```typescript
// After login, persist tokens
const result = await auth.login(email, password);
if (result.success) {
  localStorage.setItem('auth_token', result.data.auth_token.token);
  localStorage.setItem('refresh_token', result.data.refresh_token.token);
  localStorage.setItem('expires_at', result.data.auth_token.expires_at.toString());
}

// On app startup, restore tokens
const authToken = localStorage.getItem('auth_token');
const refreshToken = localStorage.getItem('refresh_token');
if (authToken) auth.setAuthToken(authToken);
if (refreshToken) auth.setRefreshToken(refreshToken);
```

## Migration Guide

If upgrading from v1.x, see [MIGRATION.md](./MIGRATION.md) for breaking changes and migration steps.

## Tenant Site Implementation

Verification and password reset emails link directly to your tenant site (using the site's `frontend_url`). Your site needs to implement these pages using the AuthClient.

### Email Verification Page (`/verify-email`)

This page handles both self-registered users (who already have a password) and admin-created users (who need to set a password).

```typescript
// app/verify-email/page.tsx
'use client';

import { useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { AuthClient } from 'byteforge-aegis-client-js';

type Status = 'loading' | 'password_required' | 'verifying' | 'success' | 'error';

export default function VerifyEmailPage() {
  const searchParams = useSearchParams();
  const [status, setStatus] = useState<Status>('loading');
  const [message, setMessage] = useState('Checking verification link...');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const token = searchParams.get('token');

  // Initialize client - uses relative URL if behind same nginx as Aegis API
  // Or set NEXT_PUBLIC_AUTH_API_URL for cross-domain setup
  const getClient = () => new AuthClient({
    apiUrl: process.env.NEXT_PUBLIC_AUTH_API_URL || '',
  });

  // Check token on page load
  useEffect(() => {
    if (!token) {
      setStatus('error');
      setMessage('Invalid verification link');
      return;
    }

    const checkToken = async () => {
      const client = getClient();
      const result = await client.checkVerificationToken(token);

      if (result.success) {
        setEmail(result.data.email);
        if (result.data.password_required) {
          // Admin-created user - show password form
          setStatus('password_required');
          setMessage('');
        } else {
          // Self-registered user - verify immediately
          await verifyEmail();
        }
      } else {
        setStatus('error');
        setMessage(result.error || 'Invalid or expired verification link');
      }
    };

    checkToken();
  }, [token]);

  const verifyEmail = async (userPassword?: string) => {
    if (!token) return;

    setStatus('verifying');
    setMessage('Verifying your email...');

    const client = getClient();
    const result = await client.verifyEmail(token, userPassword);

    if (result.success) {
      setStatus('success');
      setMessage('Email verified successfully!');
      // Optionally redirect: window.location.href = result.data.redirect_url;
    } else {
      setStatus('error');
      setMessage(result.error || 'Verification failed');
    }
  };

  const handlePasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (password.length < 8) {
      setMessage('Password must be at least 8 characters');
      return;
    }

    if (password !== confirmPassword) {
      setMessage('Passwords do not match');
      return;
    }

    await verifyEmail(password);
  };

  // Render based on status
  if (status === 'password_required') {
    return (
      <div>
        <h1>Set Your Password</h1>
        <p>Complete your account setup for {email}</p>
        <form onSubmit={handlePasswordSubmit}>
          <input
            type="password"
            placeholder="Password (min 8 characters)"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            minLength={8}
            required
          />
          <input
            type="password"
            placeholder="Confirm password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
          />
          {message && <p style={{ color: 'red' }}>{message}</p>}
          <button type="submit">Set Password & Verify</button>
        </form>
      </div>
    );
  }

  return (
    <div>
      <h1>Email Verification</h1>
      {status === 'loading' && <p>Checking verification link...</p>}
      {status === 'verifying' && <p>Verifying your email...</p>}
      {status === 'success' && <p style={{ color: 'green' }}>{message}</p>}
      {status === 'error' && <p style={{ color: 'red' }}>{message}</p>}
    </div>
  );
}
```

### Password Reset Page (`/reset-password`)

```typescript
// app/reset-password/page.tsx
'use client';

import { useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { AuthClient } from 'byteforge-aegis-client-js';

type Status = 'idle' | 'loading' | 'success' | 'error';

export default function ResetPasswordPage() {
  const searchParams = useSearchParams();
  const [status, setStatus] = useState<Status>('idle');
  const [message, setMessage] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const token = searchParams.get('token');

  const getClient = () => new AuthClient({
    apiUrl: process.env.NEXT_PUBLIC_AUTH_API_URL || '',
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!token) {
      setStatus('error');
      setMessage('Invalid reset link');
      return;
    }

    if (password.length < 8) {
      setStatus('error');
      setMessage('Password must be at least 8 characters');
      return;
    }

    if (password !== confirmPassword) {
      setStatus('error');
      setMessage('Passwords do not match');
      return;
    }

    setStatus('loading');
    setMessage('Resetting password...');

    const client = getClient();
    const result = await client.resetPassword(token, password);

    if (result.success) {
      setStatus('success');
      setMessage('Password reset successfully! You can now log in.');
    } else {
      setStatus('error');
      setMessage(result.error || 'Failed to reset password');
    }
  };

  if (!token) {
    return <p>Invalid reset link</p>;
  }

  return (
    <div>
      <h1>Reset Your Password</h1>
      {status !== 'success' ? (
        <form onSubmit={handleSubmit}>
          <input
            type="password"
            placeholder="New password (min 8 characters)"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            minLength={8}
            required
            disabled={status === 'loading'}
          />
          <input
            type="password"
            placeholder="Confirm new password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
            disabled={status === 'loading'}
          />
          {message && status === 'error' && <p style={{ color: 'red' }}>{message}</p>}
          <button type="submit" disabled={status === 'loading'}>
            {status === 'loading' ? 'Resetting...' : 'Reset Password'}
          </button>
        </form>
      ) : (
        <p style={{ color: 'green' }}>{message}</p>
      )}
    </div>
  );
}
```

### Email Change Confirmation Page (`/confirm-email-change`)

```typescript
// app/confirm-email-change/page.tsx
'use client';

import { useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { AuthClient } from 'byteforge-aegis-client-js';

type Status = 'loading' | 'success' | 'error';

export default function ConfirmEmailChangePage() {
  const searchParams = useSearchParams();
  const [status, setStatus] = useState<Status>('loading');
  const [message, setMessage] = useState('Confirming email change...');

  const token = searchParams.get('token');

  useEffect(() => {
    if (!token) {
      setStatus('error');
      setMessage('Invalid confirmation link');
      return;
    }

    const confirmChange = async () => {
      const client = new AuthClient({
        apiUrl: process.env.NEXT_PUBLIC_AUTH_API_URL || '',
      });

      const result = await client.confirmEmailChange(token);

      if (result.success) {
        setStatus('success');
        setMessage('Email changed successfully!');
      } else {
        setStatus('error');
        setMessage(result.error || 'Failed to confirm email change');
      }
    };

    confirmChange();
  }, [token]);

  return (
    <div>
      <h1>Email Change Confirmation</h1>
      {status === 'loading' && <p>Confirming email change...</p>}
      {status === 'success' && <p style={{ color: 'green' }}>{message}</p>}
      {status === 'error' && <p style={{ color: 'red' }}>{message}</p>}
    </div>
  );
}
```

### Configuration Notes

**Same-origin setup (recommended):** If your tenant site and Aegis API are behind the same nginx that routes `/api/*` to the backend, use an empty `apiUrl`:

```typescript
const client = new AuthClient({ apiUrl: '' });
```

**Cross-origin setup:** If your tenant site calls the Aegis API on a different domain, set the environment variable:

```bash
NEXT_PUBLIC_AUTH_API_URL=https://auth.example.com
```

```typescript
const client = new AuthClient({
  apiUrl: process.env.NEXT_PUBLIC_AUTH_API_URL,
});
```

## TypeScript Support

This package is written in TypeScript and includes full type definitions. All types are exported:

```typescript
import type {
  User,
  Site,
  AuthToken,
  RefreshToken,
  LoginResponse,
  RefreshTokenResponse,
} from 'byteforge-aegis-client-js';
```

## Error Handling

All methods return an `ApiResponse<T>` type:

```typescript
type ApiResponse<T> =
  | { success: true; data: T }
  | { success: false; error: string; statusCode: number };
```

Example error handling:

```typescript
const result = await auth.login(email, password);

if (!result.success) {
  if (result.statusCode === 403) {
    console.error('Email not verified');
  } else if (result.statusCode === 401) {
    console.error('Invalid credentials');
  } else {
    console.error('Error:', result.error);
  }
  return;
}

// Success - use result.data
console.log('Logged in:', result.data);
```

## License

MIT

## Author

Jason Byteforge (@jmazzahacks)
