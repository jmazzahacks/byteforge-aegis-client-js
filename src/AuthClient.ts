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

  constructor(config: AuthClientConfig) {
    this.apiUrl = config.apiUrl.replace(/\/$/, ''); // Remove trailing slash
    this.siteId = config.siteId;
    this.masterApiKey = config.masterApiKey;
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
  }

  /**
   * Get the current authentication token
   */
  getAuthToken(): string | undefined {
    return this.authToken;
  }

  /**
   * Make an HTTP request to the API
   */
  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<ApiResponse<T>> {
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
   * Register a new user
   */
  async register(email: string, password: string, siteId?: number): Promise<ApiResponse<User>> {
    const site = siteId || this.siteId;
    if (!site) {
      throw new Error('siteId is required for registration');
    }

    return this.request<User>('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        site_id: site,
        email,
        password,
      } as RegisterRequest),
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

    // Automatically set the auth token on successful login
    if (response.success) {
      this.setAuthToken(response.data.token);
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

    // Clear the token after logout
    if (response.success) {
      this.clearAuthToken();
    }

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

    return this.request<Site>('/api/admin/sites', {
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

    return this.request<Site>(`/api/admin/sites/${siteId}`, {
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

    return this.request<Site[]>('/api/admin/sites', {
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

    return this.request<Site>(`/api/admin/sites/${siteId}`, {
      method: 'PUT',
      body: JSON.stringify(updates),
    });
  }
}
