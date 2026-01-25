/**
 * TypeScript types for the multi-tenant authentication API
 */
export interface AuthClientConfig {
    /** Base URL of the authentication API (e.g., 'https://auth.example.com') */
    apiUrl: string;
    /** Site ID for this application (required for user operations) */
    siteId?: number;
    /** Master API key for administrative operations (site management, admin user creation) */
    masterApiKey?: string;
}
export type UserRole = 'user' | 'admin';
export interface User {
    id: number;
    site_id: number;
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
export interface Site {
    id: number;
    name: string;
    domain: string;
    frontend_url: string;
    verification_redirect_url?: string;
    api_key: string;
    email_from: string;
    email_from_name: string;
    created_at: number;
    updated_at: number;
    allow_self_registration: boolean;
}
export interface CreateSiteRequest {
    name: string;
    domain: string;
    frontend_url: string;
    verification_redirect_url?: string;
    email_from: string;
    email_from_name: string;
    allow_self_registration?: boolean;
}
export interface UpdateSiteRequest {
    name?: string;
    domain?: string;
    frontend_url?: string;
    verification_redirect_url?: string;
    email_from?: string;
    email_from_name?: string;
    allow_self_registration?: boolean;
}
export interface RegisterRequest {
    site_id: number;
    email: string;
    password?: string;
}
export interface RegisterResponse {
    user: User;
}
export interface LoginRequest {
    site_id: number;
    email: string;
    password: string;
}
export interface LoginResponse {
    token: string;
    user_id: number;
    site_id: number;
    expires_at: number;
    created_at: number;
}
export interface LogoutRequest {
    token: string;
}
export interface VerifyEmailRequest {
    token: string;
    password?: string;
}
export interface VerifyEmailResponse {
    user: User;
    redirect_url: string;
}
export interface CheckVerificationTokenRequest {
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
    site_id: number;
    email: string;
}
export interface ResetPasswordRequest {
    token: string;
    new_password: string;
}
export interface RequestEmailChangeRequest {
    new_email: string;
}
export interface ConfirmEmailChangeRequest {
    token: string;
}
export interface AdminRegisterRequest {
    site_id: number;
    email: string;
    role?: UserRole;
}
export interface ErrorResponse {
    error: string;
}
export type ApiResponse<T> = {
    success: true;
    data: T;
} | {
    success: false;
    error: string;
    statusCode: number;
};
//# sourceMappingURL=types.d.ts.map