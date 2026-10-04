/** Email delivery against a real SMTP server (smtp-server), plus what happens when sending fails. */
import { readFileSync } from 'fs';
import { Pool } from 'pg';
import { SMTPServer } from 'smtp-server';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AuthService, AuthUser, UserAdapter, smtpDelivery, smtpDeliveryFromEnv } from '../src/server';
import { hashPassword } from '../src/server/crypto';

const PG = { host: process.env.PGHOST ?? '/var/tmp', port: Number(process.env.PGPORT ?? 5499), user: process.env.PGUSER ?? 'postgres', password: process.env.PGPASSWORD };
const PORT = 2526;
type Mail = { to: string[]; raw: string };
const inbox: Mail[] = [];

// Quoted-printable bodies wrap long lines; undo that to find the link.
const decode = (raw: string) => raw.replace(/=\r?\n/g, '').replace(/=([0-9A-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
const linkIn = (m: Mail) => /https:\/\/hr\.example\.com\/[a-z-]+\?token=[A-Za-z0-9_-]+/.exec(decode(m.raw))?.[0] ?? null;
const tokenOf = (url: string) => new URL(url).searchParams.get('token')!;

const users = new Map<string, AuthUser & { role: string }>();
const adapter: UserAdapter = {
  async findByEmail(e) { return [...users.values()].find((u) => u.email === e.toLowerCase()) ?? null; },
  async findById(id) { return users.get(id) ?? null; },
  async setPasswordHash(id, h) { users.get(id)!.passwordHash = h; },
  async setEmail(id, e) { users.get(id)!.email = e; },
  async deleteUser(id) { users.delete(id); },
  claims: (u) => ({ role: (users.get(u.id) as any).role }),
  isAdmin: (a) => a.claims.role === 'ADMIN',
};

let pool: Pool;
let smtp: SMTPServer;
let auth: AuthService;
let broken: AuthService;
const db = () => ({ query: async (s: string, v?: unknown[]) => (await pool.query(s, v as any[])).rows as any });
const err = async (f: () => Promise<unknown>) => { try { await f(); return null; } catch (e) { return e as any; } };

beforeAll(async () => {
  const p = new Pool({ ...PG, database: 'postgres' });
  await p.query('DROP DATABASE IF EXISTS auth_kit_email_test');
  await p.query('CREATE DATABASE auth_kit_email_test');
  await p.end();
  pool = new Pool({ ...PG, database: 'auth_kit_email_test' });
  await pool.query(readFileSync(__dirname + '/../sql/001_auth_kit.sql', 'utf8'));

  smtp = new SMTPServer({
    authOptional: true, disabledCommands: ['STARTTLS'], logger: false,
    onAuth: (a, _s, cb) => (a.username === 'mailer' && a.password === 'secret' ? cb(null, { user: 'mailer' }) : cb(new Error('Invalid username or password'))),
    onData(stream, session, cb) {
      let raw = '';
      stream.on('data', (c) => (raw += c));
      stream.on('end', () => { inbox.push({ to: session.envelope.rcptTo.map((r) => r.address), raw }); cb(); });
    },
  });
  await new Promise<void>((r) => smtp.listen(PORT, '127.0.0.1', r));

  const base = { jwtSecret: 'email-test-secret-123', appName: 'HR Scoring', publicUrl: 'https://hr.example.com' };
  auth = new AuthService({ ...base, delivery: smtpDelivery({ host: '127.0.0.1', port: PORT, user: 'mailer', password: 'secret', from: 'HR Scoring <no-reply@example.com>' }) }, adapter, db());
  // Nothing listens on this port: every send fails.
  broken = new AuthService({ ...base, delivery: smtpDelivery({ host: '127.0.0.1', port: PORT + 1, from: 'x@example.com' }) }, adapter, db());

  users.set('admin', { id: 'admin', email: 'admin@example.com', passwordHash: await hashPassword('admin-password-1'), role: 'ADMIN' });
  users.set('ann', { id: 'ann', email: 'ann@example.com', passwordHash: await hashPassword('ann-password-1'), role: 'HR', name: 'Ann' });
});

afterAll(async () => { smtp?.close(); await pool?.end(); });

async function adminActor(svc = auth) {
  const r = await svc.login('admin@example.com', 'admin-password-1');
  if (r.status !== 'signed_in') throw new Error();
  return (await svc.verifyAccessToken(r.accessToken))!;
}

describe('with an email server', () => {
  it('forgot password emails the link straight to the person; no admin request', async () => {
    const r = await auth.forgotPassword('ann@example.com');
    expect(r.message).toMatch(/on its way/);
    const mail = inbox.pop()!;
    expect(mail.to).toEqual(['ann@example.com']);
    expect(decode(mail.raw)).toMatch(/Subject: Reset your HR Scoring password/);
    const url = linkIn(mail)!;
    expect(url).toMatch(/^https:\/\/hr\.example\.com\/reset-password\?token=/);
    expect(await auth.adminRequests(await adminActor())).toEqual([]);
    expect((await auth.resetPassword(tokenOf(url), 'ann-new-password')).status).toBe('signed_in');
  });

  it('an invite is emailed and also returned to the admin', async () => {
    users.set('new', { id: 'new', email: 'new@example.com', passwordHash: null, role: 'HR', name: 'Nur' });
    const link = await auth.adminInvite(await adminActor(), 'new');
    expect(link.sent).toBe(true);
    const mail = inbox.pop()!;
    expect(mail.to).toEqual(['new@example.com']);
    expect(decode(mail.raw)).toContain('Choose your password');
    expect(linkIn(mail)).toBe(link.url);
  });

  it('an email change goes to the NEW address', async () => {
    const r = await auth.login('ann@example.com', 'ann-new-password');
    if (r.status !== 'signed_in') throw new Error();
    const res = await auth.requestEmailChange((await auth.verifyAccessToken(r.accessToken))!, 'ann-new-password', 'ann.lee@example.com');
    expect(res.message).toMatch(/on its way to that address/);
    const mail = inbox.pop()!;
    expect(mail.to).toEqual(['ann.lee@example.com']);
    await auth.verifyEmail(tokenOf(linkIn(mail)!));
    expect(users.get('ann')!.email).toBe('ann.lee@example.com');
  });

  it('settings and the test email', async () => {
    const admin = await adminActor();
    expect((await auth.adminSettings(admin)).email).toEqual({ on: true, description: '127.0.0.1:2526 as mailer, from HR Scoring <no-reply@example.com>' });
    await auth.adminTestEmail(admin, 'admin@example.com');
    expect(inbox.pop()!.to).toEqual(['admin@example.com']);
  });

  it('a wrong SMTP password is reported by the test email', async () => {
    const bad = new AuthService(
      { jwtSecret: 'email-test-secret-123', appName: 'T', publicUrl: 'https://hr.example.com', delivery: smtpDelivery({ host: '127.0.0.1', port: PORT, user: 'mailer', password: 'nope', from: 'x@example.com' }) },
      adapter, db(),
    );
    const e = await err(async () => bad.adminTestEmail(await adminActor(bad), 'admin@example.com'));
    expect(e?.status).toBe(502);
    expect(e?.message).toMatch(/Couldn't send: .*Invalid username or password/i);
  });
});

describe('when sending fails, nothing is lost', () => {
  it('forgot password falls back to the admin queue', async () => {
    await broken.forgotPassword('admin@example.com');
    const reqs = await broken.adminRequests(await adminActor(broken));
    expect(reqs.map((r) => r.kind)).toContain('password_reset');
  });

  it('an admin link comes back marked not sent, with the reason, to copy by hand', async () => {
    const link = await broken.adminResetLink(await adminActor(broken), 'new');
    expect(link.sent).toBe(false);
    expect(link.sendError).toMatch(/ECONNREFUSED|connect/i);
    expect(link.url).toMatch(/^https:\/\/hr\.example\.com\/reset-password\?token=/);
  });
});

describe('configuration', () => {
  it('without SMTP_HOST, email is off; with it, settings come from the environment', () => {
    expect(smtpDeliveryFromEnv({})).toBeUndefined();
    const d = smtpDeliveryFromEnv({ SMTP_HOST: 'smtp.example.com', SMTP_PORT: '465', SMTP_USER: 'u', SMTP_PASSWORD: 'p', MAIL_FROM: 'HR <hr@example.com>' })!;
    expect(d.describe()).toBe('smtp.example.com:465 as u, from HR <hr@example.com>');
    expect(() => smtpDeliveryFromEnv({ SMTP_HOST: 'smtp.example.com' })).toThrow(/from is required/);
  });

  it('emailing links needs publicUrl', () => {
    expect(() => new AuthService({ jwtSecret: 'x'.repeat(20), appName: 'T', delivery: { send: async () => {} } }, adapter, db())).toThrow(/publicUrl/);
  });
});
