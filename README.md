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

// Login
const loginResult = await auth.login('user@example.com', 'password123');
if (loginResult.success) {
  console.log('Logged in with token:', loginResult.data.token);
  // Token is automatically stored in the client
}

// Logout
await auth.logout();
```

## Configuration

### AuthClientConfig

```typescript
interface AuthClientConfig {
  apiUrl: string;        // Base URL of the auth API
  siteId?: number;       // Default site ID for user operations
  masterApiKey?: string; // Master API key for admin operations
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

#### `register(email, password, siteId?)`
Register a new user account.

```typescript
const result = await auth.register('user@example.com', 'password123');
if (result.success) {
  console.log('User created:', result.data);
} else {
  console.error('Error:', result.error);
}
```

#### `login(email, password, siteId?)`
Login a user and receive an authentication token.

```typescript
const result = await auth.login('user@example.com', 'password123');
if (result.success) {
  console.log('Token:', result.data.token);
  // Token is automatically stored
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
```

## Token Management

The client automatically manages authentication tokens:

```typescript
// Set token manually
auth.setAuthToken('your-token-here');

// Get current token
const token = auth.getAuthToken();

// Clear token
auth.clearAuthToken();
```

## Next.js Example

```typescript
// app/auth/verify-email/page.tsx
'use client';

import { useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { AuthClient } from 'byteforge-aegis-client-js';

export default function VerifyEmailPage() {
  const searchParams = useSearchParams();
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading');
  const [message, setMessage] = useState('');

  useEffect(() => {
    const token = searchParams.get('token');
    if (!token) {
      setStatus('error');
      setMessage('No verification token provided');
      return;
    }

    const auth = new AuthClient({
      apiUrl: process.env.NEXT_PUBLIC_AUTH_API_URL!,
    });

    auth.verifyEmail(token).then((result) => {
      if (result.success) {
        setStatus('success');
        setMessage('Email verified successfully!');
      } else {
        setStatus('error');
        setMessage(result.error);
      }
    });
  }, [searchParams]);

  return (
    <div>
      {status === 'loading' && <p>Verifying your email...</p>}
      {status === 'success' && <p>{message}</p>}
      {status === 'error' && <p>Error: {message}</p>}
    </div>
  );
}
```

## TypeScript Support

This package is written in TypeScript and includes full type definitions. All types are exported:

```typescript
import type { User, Site, AuthToken, LoginResponse } from 'byteforge-aegis-client-js';
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
