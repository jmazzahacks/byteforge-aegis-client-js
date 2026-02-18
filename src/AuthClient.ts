/**
 * AuthClient - JavaScript/TypeScript client for multi-tenant authentication API
 */

import type {
  AuthClientConfig,
  User,
  UserRole,
  Site,
  CreateSiteRequest,
  UpdateSiteRequest,
  RegisterRequest,
  LoginRequest,
  LoginResponse,
  RefreshTokenResponse,
  VerifyEmailRequest,
  VerifyEmailResponse,
  CheckVerificationTokenResponse,
  ChangePasswordRequest,
  RequestPasswordResetRequest,
  ResetPasswordRequest,
  RequestEmailChangeRequest,
  ConfirmEmailChangeRequest,
  AdminRegisterRequest,
  ApiResponse,
} from './types';

export class AuthClient {
  private apiUrl: string;
  private siteId?: number;
  private masterApiKey?: string;
  private authToken?: string;
  private refreshToken?: string;
  private authTokenExpiresAt?: number;
  private autoRefresh: boolean;
  private refreshBuffer: number;

  constructor(config: AuthClientConfig) {
    this.apiUrl = config.apiUrl.replace(/\/$/, ''); // Remove trailing slash
    this.siteId = config.siteId;
    this.masterApiKey = config.masterApiKey;
    this.autoRefresh = config.autoRefresh ?? true;
    this.refreshBuffer = config.refreshBuffer ?? 300; // 5 minutes default
  }

  /**
   * Set the authentication token for authenticated requests
   */
  setAuthToken(token: string): void {
    this.authToken = token;
  }

  /**
   * Clear the authentication token
   */
  clearAuthToken(): void {
    this.authToken = undefined;
    this.authTokenExpiresAt = undefined;
  }

  /**
   * Get the current authentication token
   */
  getAuthToken(): string | undefined {
    return this.authToken;
  }

  /**
   * Set the refresh token
   */
  setRefreshToken(token: string): void {
    this.refreshToken = token;
  }

  /**
   * Get the current refresh token
   */
  getRefreshToken(): string | undefined {
    return this.refreshToken;
  }

  /**
   * Clear the refresh token
   */
  clearRefreshToken(): void {
    this.refreshToken = undefined;
  }

  /**
   * Clear all tokens (auth and refresh)
   */
  clearAllTokens(): void {
    this.authToken = undefined;
    this.authTokenExpiresAt = undefined;
    this.refreshToken = undefined;
  }

  /**
   * Set both auth and refresh tokens from login response
   */
  setTokensFromLoginResponse(response: LoginResponse): void {
    this.authToken = response.auth_token.token;
    this.authTokenExpiresAt = response.auth_token.expires_at;
    this.refreshToken = response.refresh_token.token;
  }

  /**
   * Check if auth token needs refresh
   */
  private shouldRefreshToken(): boolean {
    if (!this.authTokenExpiresAt || !this.refreshToken) {
      return false;
    }
    const now = Math.floor(Date.now() / 1000);
    return this.authTokenExpiresAt - now < this.refreshBuffer;
  }

  /**
   * Make an HTTP request to the API
   */
  private async request<T>(
    endpoint: string,
    options: RequestInit = {},
    skipAutoRefresh: boolean = false
  ): Promise<ApiResponse<T>> {
    // Proactive refresh if token is about to expire
    if (!skipAutoRefresh && this.autoRefresh && this.shouldRefreshToken()) {
      await this.refreshAuthToken();
    }

    const url = `${this.apiUrl}${endpoint}`;

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...((options.headers as Record<string, string>) || {}),
    };

    // Add auth token if available
    if (this.authToken) {
      headers['Authorization'] = `Bearer ${this.authToken}`;
    }

    // Add master API key if available (for admin operations)
    if (this.masterApiKey) {
      headers['X-API-Key'] = this.masterApiKey;
    }

    try {
      const response = await fetch(url, {
        ...options,
        headers,
      });

      const data = await response.json() as any;

      // Handle 401 with automatic refresh retry
      if (response.status === 401 && !skipAutoRefresh && this.refreshToken) {
        const refreshResult = await this.refreshAuthToken();
        if (refreshResult.success) {
          // Retry original request with new token
          return this.request<T>(endpoint, options, true);
        }
      }

      if (response.ok) {
        return { success: true, data: data as T };
      } else {
        return {
          success: false,
          error: data.error || 'Unknown error',
          statusCode: response.status,
        };
      }
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Network error',
        statusCode: 0,
      };
    }
  }

  // ============================================================================
  // Health Check
  // ============================================================================

  /**
   * Check if the backend API is healthy
   */
  async healthCheck(): Promise<ApiResponse<{ status: string }>> {
    return this.request<{ status: string }>('/api/health', {
      method: 'GET',
    });
  }

  /**
   * Refresh the auth token using the refresh token
   */
  async refreshAuthToken(): Promise<ApiResponse<RefreshTokenResponse>> {
    if (!this.refreshToken) {
      return {
        success: false,
        error: 'No refresh token available',
        statusCode: 0,
      };
    }

    const response = await this.request<RefreshTokenResponse>(
      '/api/auth/refresh',
      {
        method: 'POST',
        body: JSON.stringify({ refresh_token: this.refreshToken }),
      },
      true // Skip auto-refresh to avoid infinite loop
    );

    if (response.success) {
      this.authToken = response.data.auth_token.token;
      this.authTokenExpiresAt = response.data.auth_token.expires_at;

      // Update refresh token if rotation provided new one
      if (response.data.refresh_token) {
        this.refreshToken = response.data.refresh_token.token;
      }
    }

    return response;
  }

  /**
   * Get a site by its domain (public endpoint)
   */
  async getSiteByDomain(domain: string): Promise<ApiResponse<Site>> {
    return this.request<Site>(`/api/sites/by-domain?domain=${encodeURIComponent(domain)}`, {
      method: 'GET',
    });
  }

  // ============================================================================
  // User Authentication Methods
  // ============================================================================

  /**
   * Register a new user.
   * If password is provided, user can login after email verification.
   * If password is omitted, user will set their password during email verification.
   */
  async register(email: string, password?: string, siteId?: number): Promise<ApiResponse<User>> {
    const site = siteId || this.siteId;
    if (!site) {
      throw new Error('siteId is required for registration');
    }

    const body: RegisterRequest = { site_id: site, email };
    if (password) {
      body.password = password;
    }

    return this.request<User>('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify(body),
    });
  }

  /**
   * Login a user
   */
  async login(email: string, password: string, siteId?: number): Promise<ApiResponse<LoginResponse>> {
    const site = siteId || this.siteId;
    if (!site) {
      throw new Error('siteId is required for login');
    }

    const response = await this.request<LoginResponse>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        site_id: site,
        email,
        password,
      } as LoginRequest),
    });

    // Automatically set tokens on successful login
    if (response.success) {
      this.setTokensFromLoginResponse(response.data);
    }

    return response;
  }

  /**
   * Logout the current user
   */
  async logout(): Promise<ApiResponse<{ message: string }>> {
    if (!this.authToken) {
      throw new Error('No auth token available for logout');
    }

    const response = await this.request<{ message: string }>('/api/auth/logout', {
      method: 'POST',
      body: JSON.stringify({ token: this.authToken }),
    });

    // Clear all tokens after logout (regardless of response)
    this.clearAllTokens();

    return response;
  }

  /**
   * Check verification token status without consuming it.
   * Used to determine if password form should be shown.
   */
  async checkVerificationToken(token: string): Promise<ApiResponse<CheckVerificationTokenResponse>> {
    return this.request<CheckVerificationTokenResponse>('/api/auth/check-verification-token', {
      method: 'POST',
      body: JSON.stringify({ token }),
    });
  }

  /**
   * Verify email address with token.
   * For admin-created users, password is required.
   * For self-registered users, password is optional/ignored.
   */
  async verifyEmail(token: string, password?: string): Promise<ApiResponse<VerifyEmailResponse>> {
    const body: VerifyEmailRequest = { token };
    if (password) {
      body.password = password;
    }
    return this.request<VerifyEmailResponse>('/api/auth/verify-email', {
      method: 'POST',
      body: JSON.stringify(body),
    });
  }

  /**
   * Change password (requires authentication)
   */
  async changePassword(oldPassword: string, newPassword: string): Promise<ApiResponse<User>> {
    if (!this.authToken) {
      throw new Error('Authentication required for password change');
    }

    return this.request<User>('/api/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({
        old_password: oldPassword,
        new_password: newPassword,
      } as ChangePasswordRequest),
    });
  }

  /**
   * Request password reset email
   */
  async requestPasswordReset(email: string, siteId?: number): Promise<ApiResponse<{ message: string }>> {
    const site = siteId || this.siteId;
    if (!site) {
      throw new Error('siteId is required for password reset');
    }

    return this.request<{ message: string }>('/api/auth/request-password-reset', {
      method: 'POST',
      body: JSON.stringify({
        site_id: site,
        email,
      } as RequestPasswordResetRequest),
    });
  }

  /**
   * Reset password with token
   */
  async resetPassword(token: string, newPassword: string): Promise<ApiResponse<User>> {
    return this.request<User>('/api/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify({
        token,
        new_password: newPassword,
      } as ResetPasswordRequest),
    });
  }

  /**
   * Request email change (requires authentication)
   */
  async requestEmailChange(newEmail: string): Promise<ApiResponse<{ message: string; token: string }>> {
    if (!this.authToken) {
      throw new Error('Authentication required for email change');
    }

    return this.request<{ message: string; token: string }>('/api/auth/request-email-change', {
      method: 'POST',
      body: JSON.stringify({
        new_email: newEmail,
      } as RequestEmailChangeRequest),
    });
  }

  /**
   * Confirm email change with token
   */
  async confirmEmailChange(token: string): Promise<ApiResponse<User>> {
    return this.request<User>('/api/auth/confirm-email-change', {
      method: 'POST',
      body: JSON.stringify({ token } as ConfirmEmailChangeRequest),
    });
  }

  // ============================================================================
  // Admin User Methods (require admin authentication)
  // ============================================================================

  /**
   * List all users for the authenticated admin's site.
   * Requires authentication as an admin user (Bearer token with admin role).
   * Returns users only for the admin's own site (auto-scoped by the backend).
   */
  async adminListUsers(): Promise<ApiResponse<User[]>> {
    if (!this.authToken) {
      throw new Error('Authentication required for listing users');
    }

    return this.request<User[]>('/api/admin/users', {
      method: 'GET',
    });
  }

  // ============================================================================
  // Admin Methods (require master API key)
  // ============================================================================

  /**
   * Register a user via admin (requires master API key).
   * User will set their own password via email verification link.
   */
  async registerAdmin(email: string, siteId: number, role?: UserRole): Promise<ApiResponse<User>> {
    if (!this.masterApiKey) {
      throw new Error('Master API key required for admin registration');
    }

    const body: AdminRegisterRequest = {
      site_id: siteId,
      email,
    };
    if (role) {
      body.role = role;
    }

    return this.request<User>('/api/admin/register', {
      method: 'POST',
      body: JSON.stringify(body),
    });
  }

  /**
   * Create a new site (requires master API key)
   */
  async createSite(siteData: CreateSiteRequest): Promise<ApiResponse<Site>> {
    if (!this.masterApiKey) {
      throw new Error('Master API key required for site creation');
    }

    return this.request<Site>('/api/sites', {
      method: 'POST',
      body: JSON.stringify(siteData),
    });
  }

  /**
   * Get a site by ID (requires master API key)
   */
  async getSite(siteId: number): Promise<ApiResponse<Site>> {
    if (!this.masterApiKey) {
      throw new Error('Master API key required for site retrieval');
    }

    return this.request<Site>(`/api/sites/${siteId}`, {
      method: 'GET',
    });
  }

  /**
   * List all sites (requires master API key)
   */
  async listSites(): Promise<ApiResponse<Site[]>> {
    if (!this.masterApiKey) {
      throw new Error('Master API key required for listing sites');
    }

    return this.request<Site[]>('/api/sites', {
      method: 'GET',
    });
  }

  /**
   * List all users for a specific site (requires master API key)
   */
  async listUsersBySite(siteId: number): Promise<ApiResponse<User[]>> {
    if (!this.masterApiKey) {
      throw new Error('Master API key required for listing site users');
    }

    return this.request<User[]>(`/api/sites/${siteId}/users`, {
      method: 'GET',
    });
  }

  /**
   * Update a site (requires master API key)
   */
  async updateSite(siteId: number, updates: UpdateSiteRequest): Promise<ApiResponse<Site>> {
    if (!this.masterApiKey) {
      throw new Error('Master API key required for site update');
    }

    return this.request<Site>(`/api/sites/${siteId}`, {
      method: 'PUT',
      body: JSON.stringify(updates),
    });
  }
}
