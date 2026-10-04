/**
 * What an app provides to auth-kit, and what auth-kit hands back.
 *
 * The app keeps its own users table (with whatever else it needs: names,
 * roles, teams). auth-kit reads and changes only what sign-in needs through
 * a UserAdapter, and keeps its own security state in its own tables
 * (sql/001_auth_kit.sql): verification, sessions, two-factor, one-time links.
 */

/** The fields auth-kit needs from the app's user. */
export type AuthUser = {
  id: string;
  email: string;
  /** auth-kit's own format (scrypt$…), or the app's older format if verifyLegacyHash is given. Null: no password yet. */
  passwordHash: string | null;
  name?: string | null;
};

/** The person making a request, from their access token. */
export type Actor = { id: string; email: string; claims: Record<string, unknown> };

export interface UserAdapter {
  /** Find by email, ignoring case. */
  findByEmail(email: string): Promise<AuthUser | null>;
  findById(id: string): Promise<AuthUser | null>;
  setPasswordHash(id: string, hash: string): Promise<void>;
  /** Change the sign-in email. Throw if another user has it. */
  setEmail(id: string, email: string): Promise<void>;
  /** Remove the user, or anonymise them if other records point at them. */
  deleteUser(id: string): Promise<void>;
  /** Extra claims for the access token, e.g. { role: 'ADMIN' }. */
  claims(user: AuthUser): Record<string, unknown> | Promise<Record<string, unknown>>;
  /** Whether this person may use the admin functions at all. */
  isAdmin(actor: Actor): boolean | Promise<boolean>;
  /** Whether this admin may act on this user (e.g. an admin may not change a super admin). */
  canManage?(actor: Actor, target: AuthUser): boolean | Promise<boolean>;
  /** Check a password against a hash made before auth-kit (e.g. bcrypt). It is re-hashed on success. */
  verifyLegacyHash?(password: string, hash: string): Promise<boolean>;
}

/** Postgres access: $1, $2… parameters, rows back. Prisma: (sql, p) => prisma.$queryRawUnsafe(sql, ...p). */
export type Db = { query<T = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<T[]> };

export type LinkPurpose = 'reset_password' | 'invite' | 'verify_email' | 'change_email';

/** A link ready to give to someone. path is relative to the web app; url is set when publicUrl is configured. */
export type Link = {
  purpose: LinkPurpose; path: string; url: string | null; expiresAt: Date; to: string;
  /** With email on: whether it was emailed. False means sending failed (sendError says why); pass it on by hand. */
  sent?: boolean;
  sendError?: string;
};

/**
 * How links reach people. Without it (the default), nothing is sent: links
 * are returned to the admin to pass on, and forgot-password / email-change
 * requests wait in the admin's queue.
 */
export interface Delivery {
  send(message: { link: Link; user: AuthUser; appName: string }): Promise<void>;
  /** For the admin's status line, e.g. "smtp.example.com:587, from no-reply@example.com". */
  describe?(): string;
  /** Send a test message (the admin's "Send test email"). */
  sendTest?(to: string, appName: string): Promise<void>;
}

/** Wraps two-factor secrets before they are stored, e.g. with the app's field encryption. */
export type SecretBox = { seal(plain: string): string; open(sealed: string): string };

export type AuthEvent = {
  type:
    | 'login' | 'login_failed' | 'login_2fa_failed'
    | 'password_changed' | 'password_reset' | 'password_reset_requested'
    | 'email_verified' | 'email_changed' | 'email_change_requested'
    | 'link_created' | 'request_dismissed'
    | 'two_factor_enabled' | 'two_factor_disabled' | 'two_factor_reset' | 'recovery_codes_regenerated'
    | 'signed_out_everywhere' | 'user_deleted' | 'email_failed';
  /** Who did it: the user themselves, or an admin. Null when unknown (e.g. a failed sign-in for an unknown email). */
  actorId: string | null;
  userId: string | null;
  detail?: Record<string, unknown>;
};

export type AuthConfig = {
  /** HS256 secret for access tokens. Use the app's existing JWT secret to keep its guards working. */
  jwtSecret: string;
  /** Access token lifetime in seconds. Default 24 hours. */
  accessTokenTtl?: number;
  /** Shown in authenticator apps. */
  appName: string;
  /** e.g. https://hr.example.com. Required with delivery (emails carry full links); otherwise links are relative and the admin's browser completes them. */
  publicUrl?: string;
  /** Web pages the links open. Defaults: /reset-password, /verify-email. */
  pages?: { resetPassword?: string; verifyEmail?: string };
  /** Link lifetimes in hours. Defaults: reset 24, invite 168, verify 168. */
  linkTtlHours?: { reset?: number; invite?: number; verify?: number };
  passwordMinLength?: number;
  delivery?: Delivery;
  secretBox?: SecretBox;
  onEvent?: (event: AuthEvent) => void | Promise<void>;
};

export class AuthError extends Error {
  constructor(public readonly status: 400 | 401 | 403 | 404 | 409 | 410 | 429 | 502, message: string, public readonly code: string) {
    super(message);
  }
}
