/**
 * TypeScript types for the multi-tenant authentication API
 */

/**
 * A site or user may be addressed by its legacy integer id or its UUID string
 * during the int->UUID migration. The API accepts either form.
 */
export type Identifier = number | string;

// ============================================================================
// Configuration
// ============================================================================

export interface AuthClientConfig {
  /** Base URL of the authentication API (e.g., 'https://auth.example.com') */
  apiUrl: string;
  /** Site identifier for this application (integer id or UUID; required for user operations) */
  siteId?: Identifier;
  /** Master API key for administrative operations (site management, admin user creation) */
  masterApiKey?: string;
  /**
   * Per-tenant secret sent as X-Tenant-Api-Key on public auth endpoints
   * (register, login, verify-email, request-password-reset, reset-password,
   * check-verification-token). Must live on the tenant's backend; never ship
   * in browser-shipped code.
   */
  tenantApiKey?: string;
  /** Enable automatic token refresh (default: true) */
  autoRefresh?: boolean;
  /** Seconds before expiration to trigger proactive refresh (default: 300 = 5 minutes) */
  refreshBuffer?: number;
}

// ============================================================================
// User Types
// ============================================================================

export type UserRole = 'user' | 'admin';

export interface User {
  id: number;
  /** Globally-unique user identifier (UUIDv7). Source of truth during the int->UUID migration. */
  uuid?: string;
  site_id: number;
  /** Globally-unique id of the site this user belongs to. */
  site_uuid?: string;
  email: string;
  is_verified: boolean;
  role: UserRole;
  created_at: number;
  updated_at: number;
}

export interface AuthToken {
  token: string;
  user_id: number;
  site_id: number;
  expires_at: number;
  created_at: number;
}

export interface RefreshToken {
  token: string;
  user_id: number;
  site_id: number;
  expires_at: number;
}

// ============================================================================
// Site Types
// ============================================================================

export interface Site {
  id: number;
  /** Globally-unique site identifier (UUIDv7). Source of truth during the int->UUID migration. */
  uuid?: string;
  name: string;
  domain: string;
  frontend_url: string;
  verification_redirect_url?: string;
  email_from: string;
  email_from_name: string;
  created_at: number;
  updated_at: number;
  allow_self_registration: boolean;
  webhook_url?: string;
  webhook_secret?: string;
  tenant_api_key?: string;
  mailgun_domain?: string;
  mailgun_api_key?: string;
}

export interface CreateSiteRequest {
  name: string;
  domain: string;
  frontend_url: string;
  verification_redirect_url?: string;
  email_from: string;
  email_from_name: string;
  allow_self_registration?: boolean;
  webhook_url?: string;
  mailgun_domain?: string;
  mailgun_api_key?: string;
}

export interface UpdateSiteRequest {
  name?: string;
  domain?: string;
  frontend_url?: string;
  verification_redirect_url?: string;
  email_from?: string;
  email_from_name?: string;
  allow_self_registration?: boolean;
  webhook_url?: string | null;
  regenerate_webhook_secret?: boolean;
  regenerate_tenant_api_key?: boolean;
  mailgun_domain?: string | null;
  mailgun_api_key?: string | null;
}

// ============================================================================
// Authentication Request/Response Types
// ============================================================================

export interface RegisterRequest {
  site_id: Identifier;
  email: string;
  password?: string;  // Optional - if not provided, user sets via email verification
}

export interface RegisterResponse {
  user: User;
}

export interface LoginRequest {
  site_id: Identifier;
  email: string;
  password: string;
}

export interface LoginResponse {
  auth_token: AuthToken;
  refresh_token: RefreshToken;
}

export interface RefreshTokenRequest {
  refresh_token: string;
}

export interface RefreshTokenResponse {
  auth_token: AuthToken;
  refresh_token?: RefreshToken;
}

export interface LogoutRequest {
  token: string;
}

export interface VerifyEmailRequest {
  site_id: Identifier;
  token: string;
  password?: string;
}

export interface VerifyEmailResponse {
  user: User;
  redirect_url: string;
}

export interface CheckVerificationTokenRequest {
  site_id: Identifier;
  token: string;
}

export interface CheckVerificationTokenResponse {
  password_required: boolean;
  email: string;
}

export interface ChangePasswordRequest {
  old_password: string;
  new_password: string;
}

export interface RequestPasswordResetRequest {
  site_id: Identifier;
  email: string;
}

export interface ResetPasswordRequest {
  site_id: Identifier;
  token: string;
  new_password: string;
}

export interface RequestEmailChangeRequest {
  new_email: string;
}

export interface ConfirmEmailChangeRequest {
  token: string;
}

// ============================================================================
// Admin Request/Response Types
// ============================================================================

export interface AdminRegisterRequest {
  site_id: Identifier;
  email: string;
  role?: UserRole;
}

export interface TenantAdminRegisterRequest {
  email: string;
  role?: UserRole;
}

// ============================================================================
// Webhook Types
// ============================================================================

export interface WebhookHeaders {
  'X-Aegis-Signature': string;
  'X-Aegis-Event': string;
  'X-Aegis-Timestamp': string;
}

// ============================================================================
// Error Response
// ============================================================================

export interface ErrorResponse {
  error: string;
}

// ============================================================================
// API Response Wrapper
// ============================================================================

export type ApiResponse<T> =
  | { success: true; data: T }
  | { success: false; error: string; statusCode: number };
