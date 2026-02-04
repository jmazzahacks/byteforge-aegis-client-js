# Migration Guide: v1.x to v2.0 (Refresh Token Support)

This guide covers breaking changes when upgrading to the refresh token release.

## Breaking Changes

### Login Response Structure

The login response structure has changed. The token is now nested under `auth_token` and a new `refresh_token` is included.

**Before (v1.x):**
```typescript
interface LoginResponse {
  token: string;
  user_id: number;
  site_id: number;
  expires_at: number;
  created_at: number;
}

// Usage
const result = await client.login(email, password);
if (result.success) {
  const token = result.data.token;
  const userId = result.data.user_id;
}
```

**After (v2.0):**
```typescript
interface LoginResponse {
  auth_token: {
    token: string;
    user_id: number;
    site_id: number;
    expires_at: number;
    created_at: number;
  };
  refresh_token: {
    token: string;
    user_id: number;
    site_id: number;
    expires_at: number;
  };
}

// Usage
const result = await client.login(email, password);
if (result.success) {
  const token = result.data.auth_token.token;
  const userId = result.data.auth_token.user_id;
  const refreshToken = result.data.refresh_token.token;
}
```

## Migration Steps

### 1. Update Login Handling

Find all places where you access `response.data.token` after login and update them:

```typescript
// Before
const result = await client.login(email, password);
if (result.success) {
  localStorage.setItem('token', result.data.token);
  localStorage.setItem('expires_at', result.data.expires_at.toString());
}

// After
const result = await client.login(email, password);
if (result.success) {
  localStorage.setItem('token', result.data.auth_token.token);
  localStorage.setItem('refresh_token', result.data.refresh_token.token);
  localStorage.setItem('expires_at', result.data.auth_token.expires_at.toString());
}
```

### 2. Update Token Restoration (Optional but Recommended)

If you persist tokens to localStorage/sessionStorage, update your restoration logic:

```typescript
// Before
const token = localStorage.getItem('token');
if (token) {
  client.setAuthToken(token);
}

// After
const token = localStorage.getItem('token');
const refreshToken = localStorage.getItem('refresh_token');
if (token) {
  client.setAuthToken(token);
}
if (refreshToken) {
  client.setRefreshToken(refreshToken);
}
```

### 3. Enable Auto-Refresh (New Feature)

The client now supports automatic token refresh. This is enabled by default.

```typescript
// Auto-refresh is enabled by default
const client = new AuthClient({
  apiUrl: 'https://auth.example.com',
  siteId: 1,
});

// To disable auto-refresh
const client = new AuthClient({
  apiUrl: 'https://auth.example.com',
  siteId: 1,
  autoRefresh: false,
});

// To customize refresh buffer (default: 300 seconds = 5 minutes before expiration)
const client = new AuthClient({
  apiUrl: 'https://auth.example.com',
  siteId: 1,
  refreshBuffer: 600, // Refresh 10 minutes before expiration
});
```

### 4. Manual Token Refresh (Optional)

You can manually refresh tokens if needed:

```typescript
const result = await client.refreshAuthToken();
if (result.success) {
  // New auth token is automatically set on the client
  // If token rotation is enabled, new refresh token is also set

  // Persist new tokens if using localStorage
  localStorage.setItem('token', result.data.auth_token.token);
  if (result.data.refresh_token) {
    localStorage.setItem('refresh_token', result.data.refresh_token.token);
  }
}
```

### 5. Update Logout Handling

The client now clears both auth and refresh tokens on logout:

```typescript
await client.logout();
// Both tokens are automatically cleared

// If using localStorage, also clear persisted tokens
localStorage.removeItem('token');
localStorage.removeItem('refresh_token');
localStorage.removeItem('expires_at');
```

## New Methods

### `setRefreshToken(token: string)`
Set the refresh token manually (e.g., when restoring from storage).

### `getRefreshToken(): string | undefined`
Get the current refresh token.

### `clearRefreshToken()`
Clear only the refresh token.

### `clearAllTokens()`
Clear both auth and refresh tokens.

### `refreshAuthToken(): Promise<ApiResponse<RefreshTokenResponse>>`
Manually refresh the auth token using the stored refresh token.

## New Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `autoRefresh` | `boolean` | `true` | Automatically refresh tokens before expiration and on 401 responses |
| `refreshBuffer` | `number` | `300` | Seconds before expiration to trigger proactive refresh |

## Backend Compatibility

This client version requires the backend to support the `/api/auth/refresh` endpoint. Ensure your backend is updated before deploying the new client.

## Questions?

If you encounter issues during migration, please open an issue on GitHub.
