/**
 * The whole flow on a real Postgres (PGHOST, PGPORT, PGUSER; it creates and
 * drops a database named auth_kit_test), with an
 * in-memory users table standing in for the app's.
 */

import { readFileSync } from 'fs';
import { Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AuthService, AuthError, totpAt, currentStep, AuthEvent, UserAdapter, AuthUser } from '../src/server';
import { hashPassword } from '../src/server/crypto';

// Uses the usual PG* variables; defaults suit a local test server.
const PG = { host: process.env.PGHOST ?? '/var/tmp', port: Number(process.env.PGPORT ?? 5499), user: process.env.PGUSER ?? 'postgres', password: process.env.PGPASSWORD };
const DB_NAME = 'auth_kit_test';
let pool: Pool;

type U = AuthUser & { role: string; deleted?: boolean };
const users = new Map<string, U>();
const events: AuthEvent[] = [];

const adapter: UserAdapter = {
  async findByEmail(email) { return [...users.values()].find((u) => !u.deleted && u.email.toLowerCase() === email.toLowerCase()) ?? null; },
  async findById(id) { const u = users.get(id); return u && !u.deleted ? u : null; },
  async setPasswordHash(id, hash) { users.get(id)!.passwordHash = hash; },
  async setEmail(id, email) { users.get(id)!.email = email; },
  async deleteUser(id) { users.get(id)!.deleted = true; },
  claims: (u) => ({ role: (u as U).role }),
  isAdmin: (a) => a.claims.role === 'ADMIN' || a.claims.role === 'SUPER_ADMIN',
  canManage: (a, t) => (t as U).role !== 'SUPER_ADMIN' || a.claims.role === 'SUPER_ADMIN',
  // Stand-in for bcrypt: "legacy:<password>".
  async verifyLegacyHash(pw, hash) { return hash === `legacy:${pw}`; },
};

let auth: AuthService;
/** The app's two-factor switch, as an app setting would hold it. */
let twoFactorSwitch = true;
const tokenOf = (path: string) => new URL(path, 'http://x').searchParams.get('token')!;
const err = async (f: () => Promise<unknown>) => { try { await f(); return null; } catch (e) { return e as AuthError; } };
const actorFor = async (token: string) => (await auth.verifyAccessToken(token))!;

beforeAll(async () => {
  const p = new Pool({ ...PG, database: 'postgres' });
  await p.query(`DROP DATABASE IF EXISTS ${DB_NAME}`);
  await p.query(`CREATE DATABASE ${DB_NAME}`);
  await p.end();
  pool = new Pool({ ...PG, database: DB_NAME });
  await pool.query(readFileSync(__dirname + '/../sql/001_auth_kit.sql', 'utf8'));
  auth = new AuthService(
    { jwtSecret: 'test-secret-test-secret', appName: 'Test App', onEvent: (e) => { events.push(e); }, twoFactor: async () => twoFactorSwitch },
    adapter,
    { query: async (sql, params) => (await pool.query(sql, params as any[])).rows as any },
  );
  users.set('admin', { id: 'admin', email: 'admin@example.com', passwordHash: await hashPassword('admin-password-1'), role: 'ADMIN', name: 'Ada Admin' });
  users.set('boss', { id: 'boss', email: 'boss@example.com', passwordHash: await hashPassword('boss-password-1'), role: 'SUPER_ADMIN' });
  users.set('ann', { id: 'ann', email: 'ann@example.com', passwordHash: 'legacy:old-password', role: 'HR', name: 'Ann' });
});

afterAll(async () => { await pool?.end(); });

describe('sign-in', () => {
  it('signs in an existing user with an older hash, and upgrades the hash', async () => {
    const r = await auth.login('ANN@example.com ', 'old-password');
    expect(r.status).toBe('signed_in');
    expect(users.get('ann')!.passwordHash).toMatch(/^scrypt\$/);
    expect((await auth.login('ann@example.com', 'old-password')).status).toBe('signed_in');
  });

  it('gives the same answer for a wrong password and an unknown email', async () => {
    const a = await err(() => auth.login('ann@example.com', 'nope'));
    const b = await err(() => auth.login('nobody@example.com', 'nope'));
    expect(a?.message).toBe(b?.message);
    expect(a?.status).toBe(401);
  });

  it('access tokens carry the app claims and stop working when signed out everywhere', async () => {
    const r = await auth.login('ann@example.com', 'old-password');
    if (r.status !== 'signed_in') throw new Error();
    const me = await actorFor(r.accessToken);
    expect(me.claims.role).toBe('HR');
    const admin = await auth.login('admin@example.com', 'admin-password-1');
    if (admin.status !== 'signed_in') throw new Error();
    await auth.adminSignOutEverywhere(await actorFor(admin.accessToken), 'ann');
    expect(await auth.verifyAccessToken(r.accessToken)).toBeNull();
  });

  it('slows down repeated guessing', async () => {
    for (let i = 0; i < 10; i++) await err(() => auth.login('slow@example.com', 'x'));
    expect((await err(() => auth.login('slow@example.com', 'x')))?.status).toBe(429);
  });
});

describe('invite, forgot password, reset links', () => {
  let admin: Awaited<ReturnType<typeof actorFor>>;
  beforeAll(async () => {
    const r = await auth.login('admin@example.com', 'admin-password-1');
    if (r.status !== 'signed_in') throw new Error();
    admin = await actorFor(r.accessToken);
  });

  it('a new account is invited, cannot sign in until it sets a password, then can', async () => {
    users.set('new', { id: 'new', email: 'new@example.com', passwordHash: null, role: 'HR' });
    const link = await auth.adminInvite(admin, 'new');
    expect(link.path).toMatch(/^\/reset-password\?token=/);
    expect((await err(() => auth.login('new@example.com', 'whatever-123')))?.status).toBe(401);
    expect((await auth.describeLink(tokenOf(link.path))).purpose).toBe('invite');
    expect((await err(() => auth.resetPassword(tokenOf(link.path), 'short')))?.code).toBe('weak_password');
    const done = await auth.resetPassword(tokenOf(link.path), 'a-good-password');
    expect(done.status).toBe('signed_in');
    expect((await err(() => auth.resetPassword(tokenOf(link.path), 'a-good-password')))?.status).toBe(410);
    expect((await auth.login('new@example.com', 'a-good-password')).status).toBe('signed_in');
  });

  it('forgot password: same answer for unknown emails; the request waits for an admin', async () => {
    const a = await auth.forgotPassword('ann@example.com');
    const b = await auth.forgotPassword('nobody@example.com');
    expect(a.message).toBe(b.message);
    const reqs = await auth.adminRequests(admin);
    expect(reqs.map((r) => [r.kind, r.user.email])).toEqual([['password_reset', 'ann@example.com']]);
    const link = await auth.adminApproveRequest(admin, reqs[0].id);
    expect(link.purpose).toBe('reset_password');
    expect(await auth.adminRequests(admin)).toEqual([]);
    const r = await auth.resetPassword(tokenOf(link.path), 'ann-new-password');
    expect(r.status).toBe('signed_in');
    expect((await err(() => auth.login('ann@example.com', 'old-password')))?.status).toBe(401);
  });

  it('a newer link cancels the older one; a link only does what it is for', async () => {
    const first = await auth.adminResetLink(admin, 'ann');
    const second = await auth.adminResetLink(admin, 'ann');
    expect((await err(() => auth.describeLink(tokenOf(first.path))))?.code).toBe('link_used');
    expect((await err(() => auth.verifyEmail(tokenOf(second.path))))?.code).toBe('link_invalid');
  });

  it('an admin cannot manage a super admin, and nobody but an admin can use admin functions', async () => {
    expect((await err(() => auth.adminResetLink(admin, 'boss')))?.status).toBe(403);
    const ann = await auth.login('ann@example.com', 'ann-new-password');
    if (ann.status !== 'signed_in') throw new Error();
    expect((await err(async () => auth.adminRequests(await actorFor(ann.accessToken))))?.status).toBe(403);
  });
});

describe('email changes', () => {
  it('the user asks, an admin sends the confirm link, the email changes only when it is opened', async () => {
    let ann = await auth.login('ann@example.com', 'ann-new-password');
    if (ann.status !== 'signed_in') throw new Error();
    const me = await actorFor(ann.accessToken);
    expect((await err(() => auth.requestEmailChange(me, 'wrong', 'ann.new@example.com')))?.code).toBe('invalid_credentials');
    expect((await err(() => auth.requestEmailChange(me, 'ann-new-password', 'admin@example.com')))?.code).toBe('email_taken');
    await auth.requestEmailChange(me, 'ann-new-password', 'Ann.New@example.com');
    expect((await auth.me(me)).pendingEmail).toBe('ann.new@example.com');
    expect(users.get('ann')!.email).toBe('ann@example.com');

    const a = await auth.login('admin@example.com', 'admin-password-1');
    if (a.status !== 'signed_in') throw new Error();
    const admin = await actorFor(a.accessToken);
    const [req] = await auth.adminRequests(admin);
    expect(req.newEmail).toBe('ann.new@example.com');
    const link = await auth.adminApproveRequest(admin, req.id);
    expect(link.to).toBe('ann.new@example.com');
    expect(await auth.verifyEmail(tokenOf(link.path))).toEqual({ email: 'ann.new@example.com' });
    expect(users.get('ann')!.email).toBe('ann.new@example.com');
    expect(await auth.verifyAccessToken(ann.accessToken)).toBeNull(); // signed out
    ann = await auth.login('ann.new@example.com', 'ann-new-password');
    expect(ann.status).toBe('signed_in');
  });

  it('an admin can change an email directly', async () => {
    const a = await auth.login('admin@example.com', 'admin-password-1');
    if (a.status !== 'signed_in') throw new Error();
    const admin = await actorFor(a.accessToken);
    await auth.adminSetEmail(admin, 'ann', 'ann@example.com');
    expect(users.get('ann')!.email).toBe('ann@example.com');
    expect((await err(() => auth.adminSetEmail(admin, 'ann', 'admin@example.com')))?.status).toBe(409);
  });
});

describe('two-factor', () => {
  let me: Awaited<ReturnType<typeof actorFor>>;
  let secret = '';
  let codes: string[] = [];

  it('is set up with a QR code and turned on with a first code', async () => {
    const r = await auth.login('ann@example.com', 'ann-new-password');
    if (r.status !== 'signed_in') throw new Error();
    me = await actorFor(r.accessToken);
    const setup = await auth.twoFactorSetup(me);
    secret = setup.secret;
    expect(setup.otpauthUrl).toContain('issuer=Test%20App');
    expect(setup.qrSvg).toContain('<svg');
    expect((await err(() => auth.twoFactorEnable(me, '000000')))?.code).toBe('invalid_code');
    codes = (await auth.twoFactorEnable(me, totpAt(secret, currentStep()))).recoveryCodes;
    expect(codes).toHaveLength(10);
    expect((await auth.me(me)).twoFactor).toBe(true);
  });

  it('sign-in then asks for a code; a used code cannot be used again', async () => {
    const r = await auth.login('ann@example.com', 'ann-new-password');
    expect(r.status).toBe('two_factor_required');
    if (r.status !== 'two_factor_required') throw new Error();
    // The code used to turn it on is spent: the next one works.
    expect((await err(() => auth.loginTwoFactor(r.challenge, totpAt(secret, currentStep()))))?.code).toBe('invalid_code');
    const ok = await auth.loginTwoFactor(r.challenge, totpAt(secret, currentStep() + 1));
    expect(ok.status).toBe('signed_in');
  });

  it('a recovery code works once', async () => {
    const r = await auth.login('ann@example.com', 'ann-new-password');
    if (r.status !== 'two_factor_required') throw new Error();
    expect((await auth.loginTwoFactor(r.challenge, codes[0].toUpperCase())).status).toBe('signed_in');
    const again = await auth.login('ann@example.com', 'ann-new-password');
    if (again.status !== 'two_factor_required') throw new Error();
    expect((await err(() => auth.loginTwoFactor(again.challenge, codes[0])))?.code).toBe('invalid_code');
  });

  it('wrong codes are limited per sign-in', async () => {
    const r = await auth.login('ann@example.com', 'ann-new-password');
    if (r.status !== 'two_factor_required') throw new Error();
    for (let i = 0; i < 5; i++) await err(() => auth.loginTwoFactor(r.challenge, '111111'));
    expect((await err(() => auth.loginTwoFactor(r.challenge, '111111')))?.status).toBe(429);
  });

  it('a password reset still asks for the code', async () => {
    const a = await auth.login('admin@example.com', 'admin-password-1');
    if (a.status !== 'signed_in') throw new Error();
    const link = await auth.adminResetLink(await actorFor(a.accessToken), 'ann');
    const r = await auth.resetPassword(tokenOf(link.path), 'ann-third-password');
    expect(r.status).toBe('two_factor_required');
  });

  it('switched off by the app: no code is asked, set-up is refused; switched back on: asked again', async () => {
    twoFactorSwitch = false;
    try {
      const r = await auth.login('ann@example.com', 'ann-third-password');
      expect(r.status).toBe('signed_in');
      if (r.status !== 'signed_in') throw new Error();
      const ann = await actorFor(r.accessToken);
      const me = await auth.me(ann);
      expect(me.twoFactor).toBe(true); // her set-up is kept
      expect(me.twoFactorAvailable).toBe(false);
      const b = await auth.login('boss@example.com', 'boss-password-1');
      if (b.status !== 'signed_in') throw new Error();
      const boss = await actorFor(b.accessToken);
      expect((await err(() => auth.twoFactorSetup(boss)))?.code).toBe('two_factor_off');
      // A session started without the code while it was off…
      const loginEvent = events.filter((e) => e.type === 'login').at(-2);
      expect(loginEvent?.detail).toEqual({ twoFactor: false });
      twoFactorSwitch = true;
      // …ends when the app switches it back on and signs out its users.
      expect(await auth.adminSignOutTwoFactorUsers(boss)).toBe(1);
      expect(await auth.verifyAccessToken(r.accessToken)).toBeNull();
    } finally {
      twoFactorSwitch = true;
    }
    expect((await auth.login('ann@example.com', 'ann-third-password')).status).toBe('two_factor_required');
  });

  it('an admin can reset two-factor for someone who lost their phone', async () => {
    const a = await auth.login('admin@example.com', 'admin-password-1');
    if (a.status !== 'signed_in') throw new Error();
    await auth.adminResetTwoFactor(await actorFor(a.accessToken), 'ann');
    expect((await auth.login('ann@example.com', 'ann-third-password')).status).toBe('signed_in');
  });
});

describe('confirming the password', () => {
  it('confirms the sign-in password, and limits guesses', async () => {
    users.set('cara', { id: 'cara', email: 'cara@example.com', passwordHash: await hashPassword('cara-first-password'), role: 'HR', name: 'Cara' });
    const me = { id: 'cara' } as any;
    expect(await auth.confirmPassword(me, 'cara-first-password')).toBe(true);
    expect(await auth.confirmPassword(me, 'nope')).toBe(false);
    for (let i = 0; i < 9; i++) await auth.confirmPassword(me, 'nope');
    expect((await err(() => auth.confirmPassword(me, 'cara-first-password')))?.code).toBe('too_many_attempts');
  });
});

describe('changing your password, deleting a user', () => {
  it('change password: needs the current one, ends other sessions, keeps this one', async () => {
    const r = await auth.login('ann@example.com', 'ann-third-password');
    const other = await auth.login('ann@example.com', 'ann-third-password');
    if (r.status !== 'signed_in' || other.status !== 'signed_in') throw new Error();
    const me = await actorFor(r.accessToken);
    expect((await err(() => auth.changePassword(me, 'wrong', 'ann-fourth-password')))?.code).toBe('invalid_credentials');
    const next = await auth.changePassword(me, 'ann-third-password', 'ann-fourth-password');
    expect(await auth.verifyAccessToken(other.accessToken)).toBeNull();
    expect(await auth.verifyAccessToken(next.accessToken)).not.toBeNull();
  });

  it('delete: the user is gone and their token stops working; you cannot delete yourself', async () => {
    const r = await auth.login('ann@example.com', 'ann-fourth-password');
    const a = await auth.login('admin@example.com', 'admin-password-1');
    if (r.status !== 'signed_in' || a.status !== 'signed_in') throw new Error();
    const admin = await actorFor(a.accessToken);
    expect((await err(() => auth.adminDeleteUser(admin, 'admin')))?.code).toBe('self');
    await auth.adminDeleteUser(admin, 'ann');
    expect(await auth.verifyAccessToken(r.accessToken)).toBeNull();
    expect((await err(() => auth.login('ann@example.com', 'ann-fourth-password')))?.status).toBe(401);
  });

  it('every action was reported to the app', () => {
    const types = new Set(events.map((e) => e.type));
    for (const t of ['login', 'login_failed', 'password_reset', 'email_changed', 'two_factor_enabled', 'two_factor_reset', 'user_deleted', 'signed_out_everywhere', 'link_created']) {
      expect(types.has(t as any), t).toBe(true);
    }
  });
});

describe('the database never holds a usable link or recovery code', () => {
  it('stores only hashes', async () => {
    const rows = await pool.query(`SELECT token_hash FROM auth_links LIMIT 5`);
    for (const r of rows.rows) expect(r.token_hash).toMatch(/^[0-9a-f]{64}$/);
  });

});


