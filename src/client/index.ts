/**
 * Browser client for the auth-kit routes. Framework-free; the React screens
 * (auth-kit/react) use it, and any other front end can too.
 */

export type ClientUser = { id: string; email: string } & Record<string, unknown>;
export type SignedIn = { status: 'signed_in'; accessToken: string; user: ClientUser };
export type NeedsCode = { status: 'two_factor_required'; challenge: string };
export type LoginResult = SignedIn | NeedsCode;
export type LinkPurpose = 'reset_password' | 'invite' | 'verify_email' | 'change_email';
export type Link = { purpose: LinkPurpose; path: string; url: string | null; expiresAt: string; to: string; sent?: boolean; sendError?: string };
export type UserSecurity = {
  userId: string; emailVerified: boolean; twoFactor: boolean; pendingEmail: string | null;
  lastLoginAt: string | null; passwordSet: boolean;
};
export type OpenRequest = {
  id: string; kind: 'password_reset' | 'email_change'; createdAt: string;
  user: { id: string; email: string; name: string | null }; newEmail: string | null;
};

export class AuthClientError extends Error {
  constructor(public status: number, message: string, public code: string) {
    super(message);
  }
}

export type AuthClientOptions = {
  /** Where the routes are. Default "/api/auth". */
  baseUrl?: string;
  /** The signed-in person's access token. */
  getToken?: () => string | null | undefined;
  fetch?: typeof fetch;
};

export type AuthClient = ReturnType<typeof createAuthClient>;

export function createAuthClient(options: AuthClientOptions = {}) {
  const base = (options.baseUrl ?? '/api/auth').replace(/\/$/, '');
  const f = options.fetch ?? ((...a: Parameters<typeof fetch>) => fetch(...a));

  async function call<T>(method: string, path: string, body?: unknown, auth = true): Promise<T> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    const token = auth ? options.getToken?.() : null;
    if (token) headers.Authorization = `Bearer ${token}`;
    let res: Response;
    try {
      res = await f(`${base}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    } catch {
      throw new AuthClientError(0, "Couldn't reach the server. Check your connection and try again.", 'network');
    }
    const text = await res.text();
    let data: any = null;
    try { data = text ? JSON.parse(text) : null; } catch { /* not JSON */ }
    if (!res.ok) {
      const message = Array.isArray(data?.message) ? data.message.join(' ') : data?.message;
      throw new AuthClientError(res.status, message || `Something went wrong (${res.status}).`, data?.code ?? 'error');
    }
    return data as T;
  }

  const post = <T>(path: string, body: unknown = {}, auth = true) => call<T>('POST', path, body, auth);

  return {
    // No sign-in needed
    login: (email: string, password: string) => post<LoginResult>('/login', { email, password }, false),
    loginTwoFactor: (challenge: string, code: string) => post<SignedIn>('/login/two-factor', { challenge, code }, false),
    forgotPassword: (email: string) => post<{ message: string }>('/forgot-password', { email }, false),
    describeLink: (token: string) => post<{ purpose: LinkPurpose; email: string; expiresAt: string }>('/link', { token }, false),
    resetPassword: (token: string, password: string) => post<LoginResult>('/reset-password', { token, password }, false),
    verifyEmail: (token: string) => post<{ email: string }>('/verify-email', { token }, false),

    // The signed-in person
    me: () => call<UserSecurity & { email: string; twoFactorAvailable?: boolean }>('GET', '/me'),
    changePassword: (currentPassword: string, newPassword: string) => post<SignedIn>('/password', { currentPassword, newPassword }),
    requestEmailChange: (password: string, newEmail: string) => post<{ message: string }>('/email', { password, newEmail }),
    twoFactorSetup: () => post<{ secret: string; otpauthUrl: string; qrSvg: string }>('/two-factor/setup'),
    twoFactorEnable: (code: string) => post<{ recoveryCodes: string[] }>('/two-factor/enable', { code }),
    twoFactorDisable: (password: string, code: string) => post<{ ok: true }>('/two-factor/disable', { password, code }),
    regenerateRecoveryCodes: (password: string, code: string) => post<{ recoveryCodes: string[] }>('/two-factor/recovery-codes', { password, code }),

    // Admin
    admin: {
      settings: () => call<{ email: { on: boolean; description: string | null } }>('GET', '/admin/settings'),
      testEmail: (to: string) => post<{ message: string }>('/admin/test-email', { to }),
      summaries: (userIds: string[]) => post<Record<string, UserSecurity>>('/admin/summaries', { userIds }),
      requests: () => call<OpenRequest[]>('GET', '/admin/requests'),
      approveRequest: (id: string) => post<Link>(`/admin/requests/${encodeURIComponent(id)}/approve`),
      dismissRequest: (id: string) => post<{ ok: true }>(`/admin/requests/${encodeURIComponent(id)}/dismiss`),
      inviteLink: (userId: string) => post<Link>(`/admin/users/${encodeURIComponent(userId)}/invite-link`),
      resetLink: (userId: string) => post<Link>(`/admin/users/${encodeURIComponent(userId)}/reset-link`),
      setEmail: (userId: string, email: string) => post<{ ok: true }>(`/admin/users/${encodeURIComponent(userId)}/email`, { email }),
      resetTwoFactor: (userId: string) => post<{ ok: true }>(`/admin/users/${encodeURIComponent(userId)}/reset-two-factor`),
      signOutEverywhere: (userId: string) => post<{ ok: true }>(`/admin/users/${encodeURIComponent(userId)}/sign-out`),
      deleteUser: (userId: string) => call<{ ok: true }>('DELETE', `/admin/users/${encodeURIComponent(userId)}`),
    },
  };
}

/** A link's full address, for copying: the server's url, or this site plus its path. */
export function linkUrl(link: Pick<Link, 'url' | 'path'>): string {
  if (link.url) return link.url;
  return typeof window !== 'undefined' ? `${window.location.origin}${link.path}` : link.path;
}

/** Copy text, also on plain-http sites where navigator.clipboard is unavailable. */
export async function copyText(text: string): Promise<boolean> {
  try {
    if (typeof navigator !== 'undefined' && navigator.clipboard && (typeof window === 'undefined' || window.isSecureContext)) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch { /* fall back */ }
  if (typeof document === 'undefined') return false;
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.setAttribute('readonly', '');
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try { ok = document.execCommand('copy'); } catch { ok = false; }
  document.body.removeChild(ta);
  return ok;
}
