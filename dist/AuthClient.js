"use strict";
/**
 * AuthClient - JavaScript/TypeScript client for multi-tenant authentication API
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthClient = void 0;
class AuthClient {
    constructor(config) {
        this.apiUrl = config.apiUrl.replace(/\/$/, ''); // Remove trailing slash
        this.siteId = config.siteId;
        this.masterApiKey = config.masterApiKey;
        this.autoRefresh = config.autoRefresh ?? true;
        this.refreshBuffer = config.refreshBuffer ?? 300; // 5 minutes default
    }
    /**
     * Set the authentication token for authenticated requests
     */
    setAuthToken(token) {
        this.authToken = token;
    }
    /**
     * Clear the authentication token
     */
    clearAuthToken() {
        this.authToken = undefined;
        this.authTokenExpiresAt = undefined;
    }
    /**
     * Get the current authentication token
     */
    getAuthToken() {
        return this.authToken;
    }
    /**
     * Set the refresh token
     */
    setRefreshToken(token) {
        this.refreshToken = token;
    }
    /**
     * Get the current refresh token
     */
    getRefreshToken() {
        return this.refreshToken;
    }
    /**
     * Clear the refresh token
     */
    clearRefreshToken() {
        this.refreshToken = undefined;
    }
    /**
     * Clear all tokens (auth and refresh)
     */
    clearAllTokens() {
        this.authToken = undefined;
        this.authTokenExpiresAt = undefined;
        this.refreshToken = undefined;
    }
    /**
     * Set both auth and refresh tokens from login response
     */
    setTokensFromLoginResponse(response) {
        this.authToken = response.auth_token.token;
        this.authTokenExpiresAt = response.auth_token.expires_at;
        this.refreshToken = response.refresh_token.token;
    }
    /**
     * Check if auth token needs refresh
     */
    shouldRefreshToken() {
        if (!this.authTokenExpiresAt || !this.refreshToken) {
            return false;
        }
        const now = Math.floor(Date.now() / 1000);
        return this.authTokenExpiresAt - now < this.refreshBuffer;
    }
    /**
     * Make an HTTP request to the API
     */
    async request(endpoint, options = {}, skipAutoRefresh = false) {
        // Proactive refresh if token is about to expire
        if (!skipAutoRefresh && this.autoRefresh && this.shouldRefreshToken()) {
            await this.refreshAuthToken();
        }
        const url = `${this.apiUrl}${endpoint}`;
        const headers = {
            'Content-Type': 'application/json',
            ...(options.headers || {}),
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
            const data = await response.json();
            // Handle 401 with automatic refresh retry
            if (response.status === 401 && !skipAutoRefresh && this.refreshToken) {
                const refreshResult = await this.refreshAuthToken();
                if (refreshResult.success) {
                    // Retry original request with new token
                    return this.request(endpoint, options, true);
                }
            }
            if (response.ok) {
                return { success: true, data: data };
            }
            else {
                return {
                    success: false,
                    error: data.error || 'Unknown error',
                    statusCode: response.status,
                };
            }
        }
        catch (error) {
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
    async healthCheck() {
        return this.request('/api/health', {
            method: 'GET',
        });
    }
    /**
     * Refresh the auth token using the refresh token
     */
    async refreshAuthToken() {
        if (!this.refreshToken) {
            return {
                success: false,
                error: 'No refresh token available',
                statusCode: 0,
            };
        }
        const response = await this.request('/api/auth/refresh', {
            method: 'POST',
            body: JSON.stringify({ refresh_token: this.refreshToken }),
        }, true // Skip auto-refresh to avoid infinite loop
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
    async getSiteByDomain(domain) {
        return this.request(`/api/sites/by-domain?domain=${encodeURIComponent(domain)}`, {
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
    async register(email, password, siteId) {
        const site = siteId || this.siteId;
        if (!site) {
            throw new Error('siteId is required for registration');
        }
        const body = { site_id: site, email };
        if (password) {
            body.password = password;
        }
        return this.request('/api/auth/register', {
            method: 'POST',
            body: JSON.stringify(body),
        });
    }
    /**
     * Login a user
     */
    async login(email, password, siteId) {
        const site = siteId || this.siteId;
        if (!site) {
            throw new Error('siteId is required for login');
        }
        const response = await this.request('/api/auth/login', {
            method: 'POST',
            body: JSON.stringify({
                site_id: site,
                email,
                password,
            }),
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
    async logout() {
        if (!this.authToken) {
            throw new Error('No auth token available for logout');
        }
        const response = await this.request('/api/auth/logout', {
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
    async checkVerificationToken(token) {
        return this.request('/api/auth/check-verification-token', {
            method: 'POST',
            body: JSON.stringify({ token }),
        });
    }
    /**
     * Verify email address with token.
     * For admin-created users, password is required.
     * For self-registered users, password is optional/ignored.
     */
    async verifyEmail(token, password) {
        const body = { token };
        if (password) {
            body.password = password;
        }
        return this.request('/api/auth/verify-email', {
            method: 'POST',
            body: JSON.stringify(body),
        });
    }
    /**
     * Change password (requires authentication)
     */
    async changePassword(oldPassword, newPassword) {
        if (!this.authToken) {
            throw new Error('Authentication required for password change');
        }
        return this.request('/api/auth/change-password', {
            method: 'POST',
            body: JSON.stringify({
                old_password: oldPassword,
                new_password: newPassword,
            }),
        });
    }
    /**
     * Request password reset email
     */
    async requestPasswordReset(email, siteId) {
        const site = siteId || this.siteId;
        if (!site) {
            throw new Error('siteId is required for password reset');
        }
        return this.request('/api/auth/request-password-reset', {
            method: 'POST',
            body: JSON.stringify({
                site_id: site,
                email,
            }),
        });
    }
    /**
     * Reset password with token
     */
    async resetPassword(token, newPassword) {
        return this.request('/api/auth/reset-password', {
            method: 'POST',
            body: JSON.stringify({
                token,
                new_password: newPassword,
            }),
        });
    }
    /**
     * Request email change (requires authentication)
     */
    async requestEmailChange(newEmail) {
        if (!this.authToken) {
            throw new Error('Authentication required for email change');
        }
        return this.request('/api/auth/request-email-change', {
            method: 'POST',
            body: JSON.stringify({
                new_email: newEmail,
            }),
        });
    }
    /**
     * Confirm email change with token
     */
    async confirmEmailChange(token) {
        return this.request('/api/auth/confirm-email-change', {
            method: 'POST',
            body: JSON.stringify({ token }),
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
    async adminListUsers() {
        if (!this.authToken) {
            throw new Error('Authentication required for listing users');
        }
        return this.request('/api/admin/users', {
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
    async registerAdmin(email, siteId, role) {
        if (!this.masterApiKey) {
            throw new Error('Master API key required for admin registration');
        }
        const body = {
            site_id: siteId,
            email,
        };
        if (role) {
            body.role = role;
        }
        return this.request('/api/admin/register', {
            method: 'POST',
            body: JSON.stringify(body),
        });
    }
    /**
     * Create a new site (requires master API key)
     */
    async createSite(siteData) {
        if (!this.masterApiKey) {
            throw new Error('Master API key required for site creation');
        }
        return this.request('/api/admin/sites', {
            method: 'POST',
            body: JSON.stringify(siteData),
        });
    }
    /**
     * Get a site by ID (requires master API key)
     */
    async getSite(siteId) {
        if (!this.masterApiKey) {
            throw new Error('Master API key required for site retrieval');
        }
        return this.request(`/api/admin/sites/${siteId}`, {
            method: 'GET',
        });
    }
    /**
     * List all sites (requires master API key)
     */
    async listSites() {
        if (!this.masterApiKey) {
            throw new Error('Master API key required for listing sites');
        }
        return this.request('/api/admin/sites', {
            method: 'GET',
        });
    }
    /**
     * Update a site (requires master API key)
     */
    async updateSite(siteId, updates) {
        if (!this.masterApiKey) {
            throw new Error('Master API key required for site update');
        }
        return this.request(`/api/admin/sites/${siteId}`, {
            method: 'PUT',
            body: JSON.stringify(updates),
        });
    }
}
exports.AuthClient = AuthClient;
//# sourceMappingURL=AuthClient.js.map