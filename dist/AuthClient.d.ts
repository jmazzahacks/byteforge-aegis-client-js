/**
 * AuthClient - JavaScript/TypeScript client for multi-tenant authentication API
 */
import type { AuthClientConfig, User, Site, CreateSiteRequest, UpdateSiteRequest, LoginResponse, ApiResponse } from './types';
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
     * Register a new user
     */
    register(email: string, password: string, siteId?: number): Promise<ApiResponse<User>>;
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
     * Verify email address with token
     */
    verifyEmail(token: string): Promise<ApiResponse<User>>;
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
     * Register an admin user (requires master API key)
     */
    registerAdmin(email: string, password: string, siteId: number): Promise<ApiResponse<User>>;
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