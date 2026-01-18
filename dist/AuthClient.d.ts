/**
 * AuthClient - JavaScript/TypeScript client for multi-tenant authentication API
 */
import type { AuthClientConfig, User, UserRole, Site, CreateSiteRequest, UpdateSiteRequest, LoginResponse, VerifyEmailResponse, CheckVerificationTokenResponse, ApiResponse } from './types';
export declare class AuthClient {
    private apiUrl;
    private siteId?;
    private masterApiKey?;
    private authToken?;
    constructor(config: AuthClientConfig);
    /**
     * Set the authentication token for authenticated requests
     */
    setAuthToken(token: string): void;
    /**
     * Clear the authentication token
     */
    clearAuthToken(): void;
    /**
     * Get the current authentication token
     */
    getAuthToken(): string | undefined;
    /**
     * Make an HTTP request to the API
     */
    private request;
    /**
     * Check if the backend API is healthy
     */
    healthCheck(): Promise<ApiResponse<{
        status: string;
    }>>;
    /**
     * Get a site by its domain (public endpoint)
     */
    getSiteByDomain(domain: string): Promise<ApiResponse<Site>>;
    /**
     * Register a new user.
     * If password is provided, user can login after email verification.
     * If password is omitted, user will set their password during email verification.
     */
    register(email: string, password?: string, siteId?: number): Promise<ApiResponse<User>>;
    /**
     * Login a user
     */
    login(email: string, password: string, siteId?: number): Promise<ApiResponse<LoginResponse>>;
    /**
     * Logout the current user
     */
    logout(): Promise<ApiResponse<{
        message: string;
    }>>;
    /**
     * Check verification token status without consuming it.
     * Used to determine if password form should be shown.
     */
    checkVerificationToken(token: string): Promise<ApiResponse<CheckVerificationTokenResponse>>;
    /**
     * Verify email address with token.
     * For admin-created users, password is required.
     * For self-registered users, password is optional/ignored.
     */
    verifyEmail(token: string, password?: string): Promise<ApiResponse<VerifyEmailResponse>>;
    /**
     * Change password (requires authentication)
     */
    changePassword(oldPassword: string, newPassword: string): Promise<ApiResponse<User>>;
    /**
     * Request password reset email
     */
    requestPasswordReset(email: string, siteId?: number): Promise<ApiResponse<{
        message: string;
    }>>;
    /**
     * Reset password with token
     */
    resetPassword(token: string, newPassword: string): Promise<ApiResponse<User>>;
    /**
     * Request email change (requires authentication)
     */
    requestEmailChange(newEmail: string): Promise<ApiResponse<{
        message: string;
        token: string;
    }>>;
    /**
     * Confirm email change with token
     */
    confirmEmailChange(token: string): Promise<ApiResponse<User>>;
    /**
     * List all users for the authenticated admin's site.
     * Requires authentication as an admin user (Bearer token with admin role).
     * Returns users only for the admin's own site (auto-scoped by the backend).
     */
    adminListUsers(): Promise<ApiResponse<User[]>>;
    /**
     * Register a user via admin (requires master API key).
     * User will set their own password via email verification link.
     */
    registerAdmin(email: string, siteId: number, role?: UserRole): Promise<ApiResponse<User>>;
    /**
     * Create a new site (requires master API key)
     */
    createSite(siteData: CreateSiteRequest): Promise<ApiResponse<Site>>;
    /**
     * Get a site by ID (requires master API key)
     */
    getSite(siteId: number): Promise<ApiResponse<Site>>;
    /**
     * List all sites (requires master API key)
     */
    listSites(): Promise<ApiResponse<Site[]>>;
    /**
     * Update a site (requires master API key)
     */
    updateSite(siteId: number, updates: UpdateSiteRequest): Promise<ApiResponse<Site>>;
}
//# sourceMappingURL=AuthClient.d.ts.map