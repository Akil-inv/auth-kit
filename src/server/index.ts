export { AuthService } from './auth-service';
export type { LoginResult, SignedIn, NeedsCode, UserSecurity, OpenRequest } from './auth-service';
export { AuthError } from './types';
export type { Actor, AuthConfig, AuthEvent, AuthUser, Db, Delivery, Link, LinkPurpose, SecretBox, UserAdapter } from './types';
export { hashPassword, verifyPassword, passwordProblem, totpAt, currentStep, base32Decode } from './crypto';
export { smtpDelivery, smtpDeliveryFromEnv, defaultTemplates } from './email';
export type { SmtpOptions, MailDelivery, EmailTemplate, EmailContent } from './email';
