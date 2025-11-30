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
    }
    /**
     * Get the current authentication token
     */
    getAuthToken() {
        return this.authToken;
    }
    /**
     * Make an HTTP request to the API
     */
    async request(endpoint, options = {}) {
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
        return this.request('/health', {
            method: 'GET',
        });
    }
    // ============================================================================
    // User Authentication Methods
    // ============================================================================
    /**
     * Register a new user
     */
    async register(email, password, siteId) {
        const site = siteId || this.siteId;
        if (!site) {
            throw new Error('siteId is required for registration');
        }
        return this.request('/api/auth/register', {
            method: 'POST',
            body: JSON.stringify({
                site_id: site,
                email,
                password,
            }),
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
        // Automatically set the auth token on successful login
        if (response.success) {
            this.setAuthToken(response.data.token);
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
        // Clear the token after logout
        if (response.success) {
            this.clearAuthToken();
        }
        return response;
    }
    /**
     * Verify email address with token
     */
    async verifyEmail(token) {
        return this.request('/api/auth/verify-email', {
            method: 'POST',
            body: JSON.stringify({ token }),
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
    // Admin Methods (require master API key)
    // ============================================================================
    /**
     * Register an admin user (requires master API key)
     */
    async registerAdmin(email, password, siteId) {
        if (!this.masterApiKey) {
            throw new Error('Master API key required for admin registration');
        }
        return this.request('/api/admin/register', {
            method: 'POST',
            body: JSON.stringify({
                site_id: siteId,
                email,
                password,
            }),
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