import {
  Body, Controller, Delete, DynamicModule, Get, Headers, HttpCode, HttpException, Inject, Module, Param, Post,
  Provider, SetMetadata, Type,
} from '@nestjs/common';
import { AuthService } from '../server/auth-service';
import { Actor, AuthConfig, AuthError, Db, UserAdapter } from '../server/types';

export const AUTH_SERVICE = Symbol('AUTH_KIT_SERVICE');

export type AuthKitOptions = {
  config: AuthConfig;
  users: UserAdapter;
  db: Db;
};

export type AuthKitAsyncOptions = {
  imports?: any[];
  inject?: any[];
  useFactory: (...deps: any[]) => AuthKitOptions | Promise<AuthKitOptions>;
  /** Where the routes live. Default "api/auth". */
  path?: string;
  /**
   * The app's "no sign-in needed" marker, if it has a global guard, e.g.
   * { key: IS_PUBLIC_KEY, value: true }. Put on login, forgot-password and
   * the link routes.
   */
  publicRoute?: { key: string; value: unknown };
};

/** Turns AuthError into the matching HTTP response; anything else is rethrown. */
async function run<T>(f: () => Promise<T>): Promise<T> {
  try {
    return await f();
  } catch (e) {
    if (e instanceof AuthError) throw new HttpException({ statusCode: e.status, message: e.message, code: e.code }, e.status);
    throw e;
  }
}

function makeController(path: string): Type<any> {
  @Controller(path)
  class AuthKitController {
    constructor(@Inject(AUTH_SERVICE) private auth: AuthService) {}

    private async actor(header: string | undefined): Promise<Actor> {
      const token = /^Bearer (.+)$/i.exec(header ?? '')?.[1] ?? '';
      const actor = await this.auth.verifyAccessToken(token);
      if (!actor) throw new HttpException({ statusCode: 401, message: 'Sign in again.', code: 'signed_out' }, 401);
      return actor;
    }

    // ─── No sign-in needed ───
    @Post('login') @HttpCode(200)
    login(@Body() b: { email: string; password: string }) {
      return run(() => this.auth.login(b?.email, b?.password));
    }

    @Post('login/two-factor') @HttpCode(200)
    loginTwoFactor(@Body() b: { challenge: string; code: string }) {
      return run(() => this.auth.loginTwoFactor(b?.challenge, b?.code));
    }

    @Post('forgot-password') @HttpCode(200)
    forgot(@Body() b: { email: string }) {
      return run(() => this.auth.forgotPassword(b?.email));
    }

    @Post('link') @HttpCode(200)
    describeLink(@Body() b: { token: string }) {
      return run(() => this.auth.describeLink(b?.token));
    }

    @Post('reset-password') @HttpCode(200)
    resetPassword(@Body() b: { token: string; password: string }) {
      return run(() => this.auth.resetPassword(b?.token, b?.password));
    }

    @Post('verify-email') @HttpCode(200)
    verifyEmail(@Body() b: { token: string }) {
      return run(() => this.auth.verifyEmail(b?.token));
    }

    // ─── The signed-in person ───
    @Get('me')
    async me(@Headers('authorization') h: string) {
      const a = await this.actor(h);
      return run(() => this.auth.me(a));
    }

    @Post('password') @HttpCode(200)
    async changePassword(@Headers('authorization') h: string, @Body() b: { currentPassword: string; newPassword: string }) {
      const a = await this.actor(h);
      return run(() => this.auth.changePassword(a, b?.currentPassword, b?.newPassword));
    }

    @Post('email') @HttpCode(200)
    async changeEmail(@Headers('authorization') h: string, @Body() b: { password: string; newEmail: string }) {
      const a = await this.actor(h);
      return run(() => this.auth.requestEmailChange(a, b?.password, b?.newEmail));
    }

    @Post('two-factor/setup') @HttpCode(200)
    async tfSetup(@Headers('authorization') h: string) {
      const a = await this.actor(h);
      return run(() => this.auth.twoFactorSetup(a));
    }

    @Post('two-factor/enable') @HttpCode(200)
    async tfEnable(@Headers('authorization') h: string, @Body() b: { code: string }) {
      const a = await this.actor(h);
      return run(() => this.auth.twoFactorEnable(a, b?.code));
    }

    @Post('two-factor/disable') @HttpCode(200)
    async tfDisable(@Headers('authorization') h: string, @Body() b: { password: string; code: string }) {
      const a = await this.actor(h);
      await run(() => this.auth.twoFactorDisable(a, b?.password, b?.code));
      return { ok: true };
    }

    @Post('two-factor/recovery-codes') @HttpCode(200)
    async tfCodes(@Headers('authorization') h: string, @Body() b: { password: string; code: string }) {
      const a = await this.actor(h);
      return run(() => this.auth.regenerateRecoveryCodes(a, b?.password, b?.code));
    }

    // ─── Admin ───
    @Post('admin/summaries') @HttpCode(200)
    async summaries(@Headers('authorization') h: string, @Body() b: { userIds: string[] }) {
      const a = await this.actor(h);
      return run(() => this.auth.adminSummaries(a, Array.isArray(b?.userIds) ? b.userIds : []));
    }

    @Get('admin/settings')
    async settings(@Headers('authorization') h: string) {
      const a = await this.actor(h);
      return run(() => this.auth.adminSettings(a));
    }

    @Post('admin/test-email') @HttpCode(200)
    async testEmail(@Headers('authorization') h: string, @Body() b: { to: string }) {
      const a = await this.actor(h);
      return run(() => this.auth.adminTestEmail(a, b?.to));
    }

    @Get('admin/requests')
    async requests(@Headers('authorization') h: string) {
      const a = await this.actor(h);
      return run(() => this.auth.adminRequests(a));
    }

    @Post('admin/requests/:id/approve') @HttpCode(200)
    async approve(@Headers('authorization') h: string, @Param('id') id: string) {
      const a = await this.actor(h);
      return run(() => this.auth.adminApproveRequest(a, id));
    }

    @Post('admin/requests/:id/dismiss') @HttpCode(200)
    async dismiss(@Headers('authorization') h: string, @Param('id') id: string) {
      const a = await this.actor(h);
      await run(() => this.auth.adminDismissRequest(a, id));
      return { ok: true };
    }

    @Post('admin/users/:id/invite-link') @HttpCode(200)
    async invite(@Headers('authorization') h: string, @Param('id') id: string) {
      const a = await this.actor(h);
      return run(() => this.auth.adminInvite(a, id));
    }

    @Post('admin/users/:id/reset-link') @HttpCode(200)
    async resetLink(@Headers('authorization') h: string, @Param('id') id: string) {
      const a = await this.actor(h);
      return run(() => this.auth.adminResetLink(a, id));
    }

    @Post('admin/users/:id/email') @HttpCode(200)
    async setEmail(@Headers('authorization') h: string, @Param('id') id: string, @Body() b: { email: string }) {
      const a = await this.actor(h);
      await run(() => this.auth.adminSetEmail(a, id, b?.email));
      return { ok: true };
    }

    @Post('admin/users/:id/reset-two-factor') @HttpCode(200)
    async resetTf(@Headers('authorization') h: string, @Param('id') id: string) {
      const a = await this.actor(h);
      await run(() => this.auth.adminResetTwoFactor(a, id));
      return { ok: true };
    }

    @Post('admin/users/:id/sign-out') @HttpCode(200)
    async signOut(@Headers('authorization') h: string, @Param('id') id: string) {
      const a = await this.actor(h);
      await run(() => this.auth.adminSignOutEverywhere(a, id));
      return { ok: true };
    }

    @Delete('admin/users/:id')
    async remove(@Headers('authorization') h: string, @Param('id') id: string) {
      const a = await this.actor(h);
      await run(() => this.auth.adminDeleteUser(a, id));
      return { ok: true };
    }
  }
  return AuthKitController;
}

const PUBLIC_HANDLERS = ['login', 'loginTwoFactor', 'forgot', 'describeLink', 'resetPassword', 'verifyEmail'];

/**
 * Sign-in, verification, password reset, two-factor and admin user
 * management as REST routes, for a NestJS app:
 *
 *   AuthKitModule.forRootAsync({
 *     inject: [PrismaService],
 *     useFactory: (prisma) => ({ config: {...}, users: myAdapter(prisma), db: { query: (s, p) => prisma.$queryRawUnsafe(s, ...(p ?? [])) } }),
 *     publicRoute: { key: IS_PUBLIC_KEY, value: true },
 *   })
 *
 * Inject AUTH_SERVICE to use AuthService directly (e.g. in the app's JWT guard).
 */
@Module({})
export class AuthKitModule {
  static forRootAsync(options: AuthKitAsyncOptions): DynamicModule {
    const controller = makeController(options.path ?? 'api/auth');
    if (options.publicRoute) {
      for (const name of PUBLIC_HANDLERS) {
        const d = Object.getOwnPropertyDescriptor(controller.prototype, name)!;
        SetMetadata(options.publicRoute.key, options.publicRoute.value)(controller.prototype, name, d);
      }
    }
    const provider: Provider = {
      provide: AUTH_SERVICE,
      inject: options.inject ?? [],
      useFactory: async (...deps: any[]) => {
        const o = await options.useFactory(...deps);
        return new AuthService(o.config, o.users, o.db);
      },
    };
    return {
      module: AuthKitModule,
      global: true,
      imports: options.imports ?? [],
      controllers: [controller],
      providers: [provider],
      exports: [provider],
    };
  }
}
