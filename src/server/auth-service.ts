import { randomUUID } from 'crypto';
import QRCode from 'qrcode';
import {
  DUMMY_HASH, hashPassword, isOwnHash, matchTotp, newTotpSecret, normaliseRecoveryCode, otpauthUrl,
  passwordProblem, randomToken, recoveryCodes, sha256, signJwt, verifyJwt, verifyPassword,
} from './crypto';
import { RequestRow, State, Store } from './store';
import { Actor, AuthConfig, AuthError, AuthEvent, AuthUser, Db, Link, LinkPurpose, UserAdapter } from './types';

export type SignedIn = { status: 'signed_in'; accessToken: string; user: { id: string; email: string } & Record<string, unknown> };
export type NeedsCode = { status: 'two_factor_required'; challenge: string };
export type LoginResult = SignedIn | NeedsCode;

export type UserSecurity = {
  userId: string;
  emailVerified: boolean;
  twoFactor: boolean;
  pendingEmail: string | null;
  lastLoginAt: Date | null;
  passwordSet: boolean;
};

export type OpenRequest = {
  id: string; kind: 'password_reset' | 'email_change'; createdAt: Date;
  user: { id: string; email: string; name: string | null }; newEmail: string | null;
};

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const HOUR = 3600 * 1000;

/**
 * Everything auth-kit does, independent of the web framework. The Nest
 * module (auth-kit/nest) puts REST routes in front of it; another framework
 * can call it directly.
 */
export class AuthService {
  private store: Store;
  private failures = new Map<string, { count: number; until: number }>();
  private challenges = new Map<string, number>();
  private current = new Map<string, { tv: number; at: number }>();

  constructor(private config: AuthConfig, private users: UserAdapter, db: Db) {
    if (!config.jwtSecret || config.jwtSecret.length < 16) throw new Error('auth-kit: jwtSecret must be at least 16 characters.');
    this.store = new Store(db);
  }

  // ─── Signing in ─────────────────────────────────────────────────────────

  async login(email: string, password: string): Promise<LoginResult> {
    const key = String(email ?? '').trim().toLowerCase();
    this.throttle(`login:${key}`);
    const user = key ? await this.users.findByEmail(key) : null;
    const ok = await this.checkPassword(user, String(password ?? ''));
    if (!user || !ok) {
      this.fail(`login:${key}`);
      await this.emit({ type: 'login_failed', actorId: user?.id ?? null, userId: user?.id ?? null, detail: { email: key } });
      throw new AuthError(401, 'Wrong email or password.', 'invalid_credentials');
    }
    const state = await this.store.state(user.id);
    if (!state.emailVerifiedAt) {
      throw new AuthError(403, 'Finish setting up your account first, using the link you were given.', 'not_verified');
    }
    this.failures.delete(`login:${key}`);
    if (state.totpEnabledAt) {
      const challenge = signJwt({ sub: user.id, purpose: '2fa', tv: state.tokenVersion, jti: randomUUID() }, this.config.jwtSecret, 300);
      return { status: 'two_factor_required', challenge };
    }
    return this.signIn(user, state);
  }

  /** Second step: a code from the authenticator app, or a recovery code. */
  async loginTwoFactor(challenge: string, code: string): Promise<SignedIn> {
    const c = verifyJwt<{ sub: string; purpose: string; tv: number; jti: string }>(String(challenge ?? ''), this.config.jwtSecret);
    if (!c || c.purpose !== '2fa') throw new AuthError(401, 'That sign-in has expired. Start again.', 'challenge_expired');
    const tries = (this.challenges.get(c.jti) ?? 0) + 1;
    this.challenges.set(c.jti, tries);
    if (tries > 5) throw new AuthError(429, 'Too many wrong codes. Start signing in again.', 'too_many_codes');
    const user = await this.users.findById(c.sub);
    const state = await this.store.state(c.sub);
    if (!user || state.tokenVersion !== c.tv || !state.totpEnabledAt) {
      throw new AuthError(401, 'That sign-in has expired. Start again.', 'challenge_expired');
    }
    if (!(await this.useSecondFactor(state, code))) {
      await this.emit({ type: 'login_2fa_failed', actorId: user.id, userId: user.id });
      throw new AuthError(401, 'That code is not right. Check your authenticator app and try again.', 'invalid_code');
    }
    this.challenges.delete(c.jti);
    return this.signIn(user, await this.store.state(user.id));
  }

  /** A valid, current access token's holder, or null. Checks it has not been signed out. */
  async verifyAccessToken(token: string): Promise<Actor | null> {
    const p = verifyJwt<Record<string, any>>(String(token ?? ''), this.config.jwtSecret);
    if (!p || typeof p.sub !== 'string' || p.purpose) return null;
    if (!(await this.isCurrent(p.sub, p.tv))) return null;
    const { sub, email, tv, iat, exp, ...claims } = p;
    return { id: sub, email, claims };
  }

  /**
   * For an app that checks tokens itself (e.g. with passport-jwt): whether a
   * token with this token version is still valid. Tokens issued before
   * auth-kit carry no version and count as version 0.
   */
  async isCurrent(userId: string, tokenVersion: number | undefined): Promise<boolean> {
    const hit = this.current.get(userId);
    let tv: number;
    if (hit && Date.now() - hit.at < 10_000) tv = hit.tv;
    else {
      tv = (await this.store.state(userId)).tokenVersion;
      this.current.set(userId, { tv, at: Date.now() });
    }
    return (tokenVersion ?? 0) === tv;
  }

  // ─── Forgotten password and one-time links ──────────────────────────────

  /**
   * Always says the same thing, so it can't be used to find out who has an
   * account. With email delivery the link is sent; without, the request
   * waits for an admin.
   */
  async forgotPassword(email: string): Promise<{ message: string }> {
    const key = String(email ?? '').trim().toLowerCase();
    this.throttle(`forgot:${key}`);
    this.fail(`forgot:${key}`); // counts requests, not failures
    const user = EMAIL.test(key) ? await this.users.findByEmail(key) : null;
    if (user) {
      if (this.config.delivery) await this.issueLink(user, 'reset_password', null, null);
      else await this.store.addRequest(user.id, 'password_reset', null);
      await this.emit({ type: 'password_reset_requested', actorId: user.id, userId: user.id });
    }
    return {
      message: this.config.delivery
        ? 'If that email has an account, a link to reset the password is on its way.'
        : 'If that email has an account, an administrator has been asked to send you a reset link.',
    };
  }

  /** What a link is for, so its page can say so ("Set a password for ann@…"). */
  async describeLink(token: string) {
    const row = await this.store.link(sha256(String(token ?? '')));
    if (!row) throw new AuthError(404, 'This link is not valid. Ask for a new one.', 'link_invalid');
    if (row.usedAt) throw new AuthError(410, 'This link has already been used. Ask for a new one if you still need it.', 'link_used');
    if (row.expiresAt.getTime() < Date.now()) throw new AuthError(410, 'This link has expired. Ask for a new one.', 'link_expired');
    const user = await this.users.findById(row.userId);
    if (!user) throw new AuthError(404, 'This link is not valid. Ask for a new one.', 'link_invalid');
    return { purpose: row.purpose, email: row.newEmail ?? user.email, expiresAt: row.expiresAt };
  }

  /** Set a password from a reset or invite link. Proves the email too, and ends other sessions. */
  async resetPassword(token: string, password: string): Promise<SignedIn | NeedsCode> {
    const { row, user } = await this.openLink(token, ['reset_password', 'invite']);
    const problem = passwordProblem(String(password ?? ''), user.email, this.minLength());
    if (problem) throw new AuthError(400, problem, 'weak_password');
    if (!(await this.store.useLink(row.tokenHash))) throw new AuthError(410, 'This link has already been used.', 'link_used');
    await this.users.setPasswordHash(user.id, await hashPassword(password));
    await this.store.update(user.id, { passwordChangedAt: new Date(), emailVerifiedAt: new Date(), bumpTokenVersion: true });
    await this.store.closeRequests(user.id, 'password_reset', null, 'link_used');
    this.current.delete(user.id);
    await this.emit({ type: 'password_reset', actorId: user.id, userId: user.id, detail: { via: row.purpose } });
    const state = await this.store.state(user.id);
    if (state.totpEnabledAt) {
      // A reset link is not a second factor: still ask for the code.
      return { status: 'two_factor_required', challenge: signJwt({ sub: user.id, purpose: '2fa', tv: state.tokenVersion, jti: randomUUID() }, this.config.jwtSecret, 300) };
    }
    return this.signIn(user, state);
  }

  /** Confirm an email address: a new account's, or the new one in an email change. */
  async verifyEmail(token: string): Promise<{ email: string }> {
    const { row, user } = await this.openLink(token, ['verify_email', 'change_email']);
    if (!(await this.store.useLink(row.tokenHash))) throw new AuthError(410, 'This link has already been used.', 'link_used');
    if (row.purpose === 'change_email' && row.newEmail) {
      await this.setEmailChecked(user, row.newEmail);
      await this.store.update(user.id, { emailVerifiedAt: new Date(), bumpTokenVersion: true });
      this.current.delete(user.id);
      await this.emit({ type: 'email_changed', actorId: user.id, userId: user.id, detail: { from: user.email, to: row.newEmail } });
      return { email: row.newEmail };
    }
    await this.store.update(user.id, { emailVerifiedAt: new Date() });
    await this.emit({ type: 'email_verified', actorId: user.id, userId: user.id });
    return { email: user.email };
  }

  // ─── The signed-in person ───────────────────────────────────────────────

  async me(actor: Actor): Promise<UserSecurity & { email: string }> {
    const user = await this.mustFind(actor.id);
    return { email: user.email, ...this.summary(user, await this.store.state(user.id), await this.store.pendingEmailChange(user.id)) };
  }

  /** Change your own password. Other sessions end; this one gets a new token. */
  async changePassword(actor: Actor, current: string, next: string): Promise<SignedIn> {
    const user = await this.mustFind(actor.id);
    this.throttle(`password:${user.id}`);
    if (!(await this.checkPassword(user, String(current ?? '')))) {
      this.fail(`password:${user.id}`);
      throw new AuthError(400, 'Your current password is not right.', 'invalid_credentials');
    }
    const problem = passwordProblem(String(next ?? ''), user.email, this.minLength());
    if (problem) throw new AuthError(400, problem, 'weak_password');
    if (current === next) throw new AuthError(400, 'Choose a password different from the current one.', 'same_password');
    await this.users.setPasswordHash(user.id, await hashPassword(next));
    await this.store.update(user.id, { passwordChangedAt: new Date(), bumpTokenVersion: true });
    this.current.delete(user.id);
    await this.emit({ type: 'password_changed', actorId: user.id, userId: user.id });
    return this.signIn(user, await this.store.state(user.id), false);
  }

  /** Ask to move to another email. It changes only once the new address is confirmed. */
  async requestEmailChange(actor: Actor, password: string, newEmail: string): Promise<{ message: string }> {
    const user = await this.mustFind(actor.id);
    if (!(await this.checkPassword(user, String(password ?? '')))) throw new AuthError(400, 'Your password is not right.', 'invalid_credentials');
    const email = this.cleanEmail(newEmail);
    if (email === user.email.toLowerCase()) throw new AuthError(400, 'That is already your email.', 'same_email');
    const other = await this.users.findByEmail(email);
    if (other && other.id !== user.id) throw new AuthError(409, 'Another account uses that email.', 'email_taken');
    await this.emit({ type: 'email_change_requested', actorId: user.id, userId: user.id, detail: { to: email } });
    if (this.config.delivery) {
      await this.issueLink(user, 'change_email', email, null);
      return { message: `A link to confirm ${email} is on its way to that address. Your email changes once you open it.` };
    }
    await this.store.addRequest(user.id, 'email_change', email);
    return { message: `An administrator will send you a link to confirm ${email}. Your email changes once you open it.` };
  }

  // ─── Two-factor ─────────────────────────────────────────────────────────

  /** Start setting up an authenticator app. Not on until a code from it is checked. */
  async twoFactorSetup(actor: Actor): Promise<{ secret: string; otpauthUrl: string; qrSvg: string }> {
    const user = await this.mustFind(actor.id);
    const state = await this.store.state(user.id);
    if (state.totpEnabledAt) throw new AuthError(409, 'Two-factor is already on. Turn it off first to set up a new app.', 'already_on');
    const secret = newTotpSecret();
    await this.store.update(user.id, { totpSecret: this.seal(secret), totpLastStep: null });
    const url = otpauthUrl(secret, user.email, this.config.appName);
    const qrSvg = await QRCode.toString(url, { type: 'svg', margin: 1, errorCorrectionLevel: 'M' });
    return { secret, otpauthUrl: url, qrSvg };
  }

  /** Turn two-factor on with a first code. Returns recovery codes, shown once. */
  async twoFactorEnable(actor: Actor, code: string): Promise<{ recoveryCodes: string[] }> {
    const state = await this.store.state(actor.id);
    if (state.totpEnabledAt) throw new AuthError(409, 'Two-factor is already on.', 'already_on');
    if (!state.totpSecret) throw new AuthError(400, 'Start the set-up first.', 'no_setup');
    const step = matchTotp(this.open(state.totpSecret), String(code ?? ''));
    if (step === null) throw new AuthError(400, 'That code is not right. Check the time on your phone and try the newest code.', 'invalid_code');
    const codes = recoveryCodes();
    await this.store.update(actor.id, { totpEnabledAt: new Date(), totpLastStep: step, recoveryCodes: codes.map(sha256) });
    await this.emit({ type: 'two_factor_enabled', actorId: actor.id, userId: actor.id });
    return { recoveryCodes: codes };
  }

  async twoFactorDisable(actor: Actor, password: string, code: string): Promise<void> {
    const user = await this.mustFind(actor.id);
    const state = await this.store.state(user.id);
    if (!state.totpEnabledAt) return;
    if (!(await this.checkPassword(user, String(password ?? '')))) throw new AuthError(400, 'Your password is not right.', 'invalid_credentials');
    if (!(await this.useSecondFactor(state, code))) throw new AuthError(400, 'That code is not right.', 'invalid_code');
    await this.store.update(user.id, { totpSecret: null, totpEnabledAt: null, totpLastStep: null, recoveryCodes: [] });
    await this.emit({ type: 'two_factor_disabled', actorId: user.id, userId: user.id });
  }

  async regenerateRecoveryCodes(actor: Actor, password: string, code: string): Promise<{ recoveryCodes: string[] }> {
    const user = await this.mustFind(actor.id);
    const state = await this.store.state(user.id);
    if (!state.totpEnabledAt) throw new AuthError(400, 'Two-factor is off.', 'not_on');
    if (!(await this.checkPassword(user, String(password ?? '')))) throw new AuthError(400, 'Your password is not right.', 'invalid_credentials');
    if (!(await this.useSecondFactor(state, code, false))) throw new AuthError(400, 'That code is not right.', 'invalid_code');
    const codes = recoveryCodes();
    await this.store.update(user.id, { recoveryCodes: codes.map(sha256) });
    await this.emit({ type: 'recovery_codes_regenerated', actorId: user.id, userId: user.id });
    return { recoveryCodes: codes };
  }

  // ─── Admin ──────────────────────────────────────────────────────────────

  /** Security details for a list of users (for an admin's user list). */
  async adminSummaries(actor: Actor, userIds: string[]): Promise<Record<string, UserSecurity>> {
    await this.mustBeAdmin(actor);
    const ids = [...new Set(userIds.map(String))].slice(0, 1000);
    const states = await this.store.states(ids);
    const out: Record<string, UserSecurity> = {};
    for (const id of ids) {
      const user = await this.users.findById(id);
      if (user) out[id] = this.summary(user, states.get(id)!, await this.store.pendingEmailChange(id));
    }
    return out;
  }

  async adminRequests(actor: Actor): Promise<OpenRequest[]> {
    await this.mustBeAdmin(actor);
    const out: OpenRequest[] = [];
    for (const r of await this.store.openRequests()) {
      const user = await this.users.findById(r.userId);
      if (user && (await this.allowed(actor, user))) {
        out.push({ id: r.id, kind: r.kind, createdAt: r.createdAt, newEmail: r.newEmail, user: { id: user.id, email: user.email, name: user.name ?? null } });
      }
    }
    return out;
  }

  /**
   * A new account the app has just created: mark it unconfirmed and make the
   * invite link (sets the first password, confirms the email).
   */
  async adminInvite(actor: Actor, userId: string): Promise<Link> {
    const user = await this.manage(actor, userId);
    await this.store.update(user.id, { emailVerifiedAt: null }, true);
    return this.issueLink(user, 'invite', null, actor.id);
  }

  /** A link for the user to choose a new password. The admin never sees the password. */
  async adminResetLink(actor: Actor, userId: string): Promise<Link> {
    const user = await this.manage(actor, userId);
    const state = await this.store.state(user.id);
    // Someone who never finished setting up gets a fresh invite instead.
    const purpose: LinkPurpose = state.emailVerifiedAt ? 'reset_password' : 'invite';
    const link = await this.issueLink(user, purpose, null, actor.id);
    await this.store.closeRequests(user.id, 'password_reset', actor.id, 'link_created');
    return link;
  }

  /** Act on a request: a reset link, or a link to confirm the new email. */
  async adminApproveRequest(actor: Actor, requestId: string): Promise<Link> {
    const req = await this.openRequest(requestId);
    const user = await this.manage(actor, req.userId);
    let link: Link;
    if (req.kind === 'password_reset') link = await this.adminResetLink(actor, user.id);
    else {
      const taken = await this.users.findByEmail(req.newEmail!);
      if (taken && taken.id !== user.id) throw new AuthError(409, `Another account now uses ${req.newEmail}.`, 'email_taken');
      link = await this.issueLink(user, 'change_email', req.newEmail, actor.id);
    }
    await this.store.closeRequest(req.id, actor.id, 'link_created');
    return link;
  }

  async adminDismissRequest(actor: Actor, requestId: string): Promise<void> {
    const req = await this.openRequest(requestId);
    await this.manage(actor, req.userId);
    await this.store.closeRequest(req.id, actor.id, 'dismissed');
    await this.emit({ type: 'request_dismissed', actorId: actor.id, userId: req.userId, detail: { kind: req.kind } });
  }

  /** Change someone's sign-in email directly. The admin vouches for it; their sessions end. */
  async adminSetEmail(actor: Actor, userId: string, newEmail: string): Promise<void> {
    const user = await this.manage(actor, userId);
    const email = this.cleanEmail(newEmail);
    if (email === user.email.toLowerCase()) return;
    await this.setEmailChecked(user, email);
    await this.store.update(user.id, { emailVerifiedAt: new Date(), bumpTokenVersion: true });
    await this.store.cancelLinks(user.id, ['change_email']);
    await this.store.closeRequests(user.id, 'email_change', actor.id, 'superseded');
    this.current.delete(user.id);
    await this.emit({ type: 'email_changed', actorId: actor.id, userId: user.id, detail: { from: user.email, to: email } });
  }

  /** For someone who lost their phone and recovery codes. They can set it up again after signing in. */
  async adminResetTwoFactor(actor: Actor, userId: string): Promise<void> {
    const user = await this.manage(actor, userId);
    await this.store.update(user.id, { totpSecret: null, totpEnabledAt: null, totpLastStep: null, recoveryCodes: [] });
    await this.emit({ type: 'two_factor_reset', actorId: actor.id, userId: user.id });
  }

  async adminSignOutEverywhere(actor: Actor, userId: string): Promise<void> {
    const user = await this.manage(actor, userId);
    await this.store.update(user.id, { bumpTokenVersion: true });
    this.current.delete(user.id);
    await this.emit({ type: 'signed_out_everywhere', actorId: actor.id, userId: user.id });
  }

  async adminDeleteUser(actor: Actor, userId: string): Promise<void> {
    if (actor.id === userId) throw new AuthError(400, "You can't delete your own account.", 'self');
    const user = await this.manage(actor, userId);
    await this.users.deleteUser(user.id);
    // Keep the state row with a new token version, so any token still held stops working.
    await this.store.update(user.id, { totpSecret: null, totpEnabledAt: null, recoveryCodes: [], bumpTokenVersion: true });
    await this.store.cancelLinks(user.id);
    await this.store.closeRequests(user.id, 'password_reset', actor.id, 'superseded');
    await this.store.closeRequests(user.id, 'email_change', actor.id, 'superseded');
    this.current.delete(user.id);
    await this.emit({ type: 'user_deleted', actorId: actor.id, userId: user.id, detail: { email: user.email } });
  }

  // ─── Inside ─────────────────────────────────────────────────────────────

  private async signIn(user: AuthUser, state: State, recordLogin = true): Promise<SignedIn> {
    const claims = await this.users.claims(user);
    const ttl = this.config.accessTokenTtl ?? 24 * 3600;
    const accessToken = signJwt({ ...claims, sub: user.id, email: user.email, tv: state.tokenVersion }, this.config.jwtSecret, ttl);
    if (recordLogin) {
      await this.store.update(user.id, { lastLoginAt: new Date() });
      await this.emit({ type: 'login', actorId: user.id, userId: user.id, detail: { twoFactor: !!state.totpEnabledAt } });
    }
    return { status: 'signed_in', accessToken, user: { ...claims, id: user.id, email: user.email } };
  }

  private async checkPassword(user: AuthUser | null, password: string): Promise<boolean> {
    if (!user || !user.passwordHash) {
      await verifyPassword(password, DUMMY_HASH);
      return false;
    }
    if (isOwnHash(user.passwordHash)) return verifyPassword(password, user.passwordHash);
    if (!this.users.verifyLegacyHash) return false;
    const ok = await this.users.verifyLegacyHash(password, user.passwordHash);
    // Move to auth-kit's hash the first time it is used.
    if (ok) await this.users.setPasswordHash(user.id, await hashPassword(password));
    return ok;
  }

  /** An authenticator code (not reused) or an unused recovery code, which is then spent. */
  private async useSecondFactor(state: State, code: string, allowRecovery = true): Promise<boolean> {
    const c = String(code ?? '').trim();
    if (/^\d{3}\s?\d{3}$/.test(c) && state.totpSecret) {
      const step = matchTotp(this.open(state.totpSecret), c.replace(/\s/g, ''));
      if (step === null || (state.totpLastStep !== null && step <= state.totpLastStep)) return false;
      await this.store.update(state.userId, { totpLastStep: step });
      return true;
    }
    if (!allowRecovery) return false;
    const hash = sha256(normaliseRecoveryCode(c));
    if (!state.recoveryCodes.includes(hash)) return false;
    await this.store.update(state.userId, { recoveryCodes: state.recoveryCodes.filter((h) => h !== hash) });
    return true;
  }

  private async issueLink(user: AuthUser, purpose: LinkPurpose, newEmail: string | null, by: string | null): Promise<Link> {
    const token = randomToken();
    const ttl = this.config.linkTtlHours ?? {};
    const hours = purpose === 'reset_password' ? ttl.reset ?? 24 : purpose === 'invite' ? ttl.invite ?? 168 : ttl.verify ?? 168;
    const expiresAt = new Date(Date.now() + hours * HOUR);
    await this.store.addLink({ tokenHash: sha256(token), userId: user.id, purpose, newEmail, createdBy: by, expiresAt });
    const page = purpose === 'reset_password' || purpose === 'invite'
      ? this.config.pages?.resetPassword ?? '/reset-password'
      : this.config.pages?.verifyEmail ?? '/verify-email';
    const path = `${page}?token=${token}`;
    const link: Link = { purpose, path, url: this.config.publicUrl ? `${this.config.publicUrl.replace(/\/$/, '')}${path}` : null, expiresAt, to: newEmail ?? user.email };
    await this.emit({ type: 'link_created', actorId: by ?? user.id, userId: user.id, detail: { purpose, expiresAt: expiresAt.toISOString() } });
    if (this.config.delivery) await this.config.delivery.send({ link, user, appName: this.config.appName });
    return link;
  }

  private async openLink(token: string, purposes: LinkPurpose[]) {
    const row = await this.store.link(sha256(String(token ?? '')));
    if (!row || !purposes.includes(row.purpose)) throw new AuthError(404, 'This link is not valid. Ask for a new one.', 'link_invalid');
    if (row.usedAt) throw new AuthError(410, 'This link has already been used. Ask for a new one if you still need it.', 'link_used');
    if (row.expiresAt.getTime() < Date.now()) throw new AuthError(410, 'This link has expired. Ask for a new one.', 'link_expired');
    const user = await this.users.findById(row.userId);
    if (!user) throw new AuthError(404, 'This link is not valid. Ask for a new one.', 'link_invalid');
    return { row, user };
  }

  private async openRequest(id: string): Promise<RequestRow> {
    const req = await this.store.request(String(id ?? ''));
    if (!req) throw new AuthError(404, 'That request was not found.', 'not_found');
    if (req.handledAt) throw new AuthError(409, 'That request has already been dealt with.', 'handled');
    return req;
  }

  private async setEmailChecked(user: AuthUser, email: string) {
    const other = await this.users.findByEmail(email);
    if (other && other.id !== user.id) throw new AuthError(409, 'Another account uses that email.', 'email_taken');
    await this.users.setEmail(user.id, email);
  }

  private summary(user: AuthUser, state: State, pendingEmail: string | null): UserSecurity {
    return {
      userId: user.id,
      emailVerified: !!state.emailVerifiedAt,
      twoFactor: !!state.totpEnabledAt,
      pendingEmail,
      lastLoginAt: state.lastLoginAt,
      passwordSet: !!user.passwordHash && !!state.emailVerifiedAt,
    };
  }

  private cleanEmail(email: string): string {
    const e = String(email ?? '').trim().toLowerCase();
    if (!EMAIL.test(e) || e.length > 254) throw new AuthError(400, 'Enter a valid email address.', 'invalid_email');
    return e;
  }

  private async mustFind(id: string): Promise<AuthUser> {
    const u = await this.users.findById(id);
    if (!u) throw new AuthError(404, 'That user was not found.', 'not_found');
    return u;
  }

  private async mustBeAdmin(actor: Actor) {
    if (!(await this.users.isAdmin(actor))) throw new AuthError(403, 'Only an administrator can do this.', 'forbidden');
  }

  private async allowed(actor: Actor, target: AuthUser) {
    return this.users.canManage ? this.users.canManage(actor, target) : true;
  }

  private async manage(actor: Actor, userId: string): Promise<AuthUser> {
    await this.mustBeAdmin(actor);
    const user = await this.mustFind(String(userId ?? ''));
    if (!(await this.allowed(actor, user))) throw new AuthError(403, "You can't manage this user's account.", 'forbidden');
    return user;
  }

  private minLength() {
    return this.config.passwordMinLength ?? 10;
  }

  private seal(s: string) {
    return this.config.secretBox ? this.config.secretBox.seal(s) : s;
  }

  private open(s: string) {
    return this.config.secretBox ? this.config.secretBox.open(s) : s;
  }

  // Slows guessing: 10 tries per key in 15 minutes.
  private throttle(key: string) {
    const f = this.failures.get(key);
    if (f && f.count >= 10 && f.until > Date.now()) {
      throw new AuthError(429, 'Too many attempts. Wait 15 minutes and try again.', 'too_many_attempts');
    }
  }

  private fail(key: string) {
    const f = this.failures.get(key);
    const live = f && f.until > Date.now();
    this.failures.set(key, { count: live ? f!.count + 1 : 1, until: live ? f!.until : Date.now() + 15 * 60 * 1000 });
    if (this.failures.size > 10_000) {
      for (const [k, v] of this.failures) if (v.until < Date.now()) this.failures.delete(k);
    }
  }

  private async emit(e: AuthEvent) {
    try {
      await this.config.onEvent?.(e);
    } catch {
      /* an audit hook must never break sign-in */
    }
  }
}

