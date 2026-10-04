/** The Nest module: routes, error responses, the public-route marker. */
import 'reflect-metadata';
import { CanActivate, ExecutionContext, INestApplication, Inject, Injectable } from '@nestjs/common';
import { APP_GUARD, Reflector } from '@nestjs/core';
import { Test } from '@nestjs/testing';
import { Pool } from 'pg';
import request from 'supertest';
import { readFileSync } from 'fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AuthKitModule, AUTH_SERVICE } from '../src/nest';
import { AuthUser, UserAdapter } from '../src/server';
import { hashPassword } from '../src/server/crypto';

const PG = { host: process.env.PGHOST ?? '/var/tmp', port: Number(process.env.PGPORT ?? 5499), user: process.env.PGUSER ?? 'postgres', password: process.env.PGPASSWORD };
const IS_PUBLIC = 'isPublic';

/** Like an app's global guard: everything needs a token unless marked public. */
@Injectable()
class AppGuard implements CanActivate {
  constructor(@Inject(Reflector) private reflector: Reflector) {}
  canActivate(ctx: ExecutionContext) {
    if (this.reflector.getAllAndOverride(IS_PUBLIC, [ctx.getHandler(), ctx.getClass()])) return true;
    return /^Bearer /.test(ctx.switchToHttp().getRequest().headers.authorization ?? '');
  }
}

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

let app: INestApplication;
let pool: Pool;

beforeAll(async () => {
  const p = new Pool({ ...PG, database: 'postgres' });
  await p.query('DROP DATABASE IF EXISTS auth_kit_nest_test');
  await p.query('CREATE DATABASE auth_kit_nest_test');
  await p.end();
  pool = new Pool({ ...PG, database: 'auth_kit_nest_test' });
  await pool.query(readFileSync(__dirname + '/../sql/001_auth_kit.sql', 'utf8'));
  users.set('a', { id: 'a', email: 'admin@example.com', passwordHash: await hashPassword('admin-password-1'), role: 'ADMIN' });
  users.set('b', { id: 'b', email: 'bob@example.com', passwordHash: await hashPassword('bob-password-1'), role: 'USER' });
  const mod = await Test.createTestingModule({
    imports: [AuthKitModule.forRootAsync({
      useFactory: () => ({ config: { jwtSecret: 'nest-test-secret-123', appName: 'T' }, users: adapter, db: { query: async (s, v) => (await pool.query(s, v as any[])).rows as any } }),
      publicRoute: { key: IS_PUBLIC, value: true },
    })],
    providers: [{ provide: APP_GUARD, useClass: AppGuard }],
  }).compile();
  app = mod.createNestApplication();
  await app.init();
});

afterAll(async () => { await app?.close(); await pool?.end(); });

describe('routes', () => {
  it('login is public and returns a token; wrong password is a 401 with a code', async () => {
    const bad = await request(app.getHttpServer()).post('/api/auth/login').send({ email: 'bob@example.com', password: 'x' });
    expect(bad.status).toBe(401);
    expect(bad.body).toMatchObject({ code: 'invalid_credentials', message: 'Wrong email or password.' });
    const ok = await request(app.getHttpServer()).post('/api/auth/login').send({ email: 'bob@example.com', password: 'bob-password-1' });
    expect(ok.status).toBe(200);
    expect(ok.body.status).toBe('signed_in');
    expect(ok.body.user.role).toBe('USER');
  });

  it('forgot-password is public; me needs a valid token', async () => {
    expect((await request(app.getHttpServer()).post('/api/auth/forgot-password').send({ email: 'x@example.com' })).status).toBe(200);
    expect((await request(app.getHttpServer()).get('/api/auth/me')).status).toBe(403); // the app guard
    expect((await request(app.getHttpServer()).get('/api/auth/me').set('Authorization', 'Bearer junk')).status).toBe(401);
  });

  it('admin routes: refused to a non-admin, work for an admin', async () => {
    const bob = (await request(app.getHttpServer()).post('/api/auth/login').send({ email: 'bob@example.com', password: 'bob-password-1' })).body.accessToken;
    const admin = (await request(app.getHttpServer()).post('/api/auth/login').send({ email: 'admin@example.com', password: 'admin-password-1' })).body.accessToken;
    expect((await request(app.getHttpServer()).get('/api/auth/admin/requests').set('Authorization', `Bearer ${bob}`)).status).toBe(403);
    const link = await request(app.getHttpServer()).post('/api/auth/admin/users/b/reset-link').set('Authorization', `Bearer ${admin}`);
    expect(link.status).toBe(200);
    expect(link.body.path).toMatch(/^\/reset-password\?token=/);
    const token = new URLSearchParams(link.body.path.split('?')[1]).get('token');
    const done = await request(app.getHttpServer()).post('/api/auth/reset-password').send({ token, password: 'bob-new-password' });
    expect(done.body.status).toBe('signed_in');
    expect((await request(app.getHttpServer()).get('/api/auth/me').set('Authorization', `Bearer ${bob}`)).status).toBe(401);
  });

  it('AuthService can be injected by the app', () => {
    expect(app.get(AUTH_SERVICE).verifyAccessToken).toBeTypeOf('function');
  });
});
