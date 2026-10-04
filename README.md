# auth-kit

Sign-in and account management you can add to any NestJS + React app:

- **Sign in**, with optional **two-factor** (authenticator app codes, plus one-time recovery codes).
- **New accounts** are invited with a link that sets the first password and confirms the email.
- **Forgot password**, and **reset links** created by an admin.
- **Email changes**: a user asks and confirms the new address with a link; an admin can also change it directly.
- **Admin tools**: reset link, change email, reset two-factor, sign out everywhere, delete user.
- **Sessions end** when a password or email changes, or when an admin signs someone out.

Your app keeps its own users table, with its own names, roles and so on. auth-kit reaches it through a small adapter, and keeps its own security state in three tables of its own.

**Email is optional.** Out of the box nothing is emailed: an admin creates a link and passes it on, and forgotten passwords and email changes wait in an admin queue. Add SMTP settings when a mail server is available (step 6), and links are then emailed automatically.

## Contents

- [What's inside](#whats-inside)
- [Add it to an app](#add-it-to-an-app)
- [REST routes](#rest-routes)
- [Security notes](#security-notes)
- [Development](#development)

## What's inside

| Import | What it is |
|---|---|
| `@akil-inv/auth-kit/server` | `AuthService`, framework-free; the adapter and config types |
| `@akil-inv/auth-kit/nest` | `AuthKitModule`: the REST routes for a NestJS app |
| `@akil-inv/auth-kit/client` | A browser API client, plus `copyText` and `linkUrl` |
| `@akil-inv/auth-kit/react` | Screens: `LoginForm`, `ForgotPasswordForm`, `ResetPasswordForm`, `VerifyEmail`, `AccountSecurity`, `UserSecurityActions`, `UserSecurityBadges`, `AuthRequestsPanel` |
| `@akil-inv/auth-kit/sql/001_auth_kit.sql` | The tables (Postgres) |

## Add it to an app

### 1. Install

Build a tarball and vendor it. This avoids needing git or registry access at build time:

```bash
cd auth-kit && npm ci && npm run pack:release      # → akil-inv-auth-kit-0.1.0.tgz
cp akil-inv-auth-kit-0.1.0.tgz ../my-app/vendor/
cd ../my-app/api && npm i ../vendor/akil-inv-auth-kit-0.1.0.tgz
```

### 2. Add the tables

Copy `sql/001_auth_kit.sql` into your migrations (for Prisma, a new migration folder with this as `migration.sql`).

### 3. Write the user adapter

```ts
import { UserAdapter } from '@akil-inv/auth-kit/server';

export const users = (prisma: PrismaService): UserAdapter => ({
  findByEmail: (email) => prisma.user.findFirst({ where: { email: { equals: email, mode: 'insensitive' } } }),
  findById: (id) => prisma.user.findUnique({ where: { id } }),
  setPasswordHash: async (id, passwordHash) => { await prisma.user.update({ where: { id }, data: { passwordHash } }); },
  setEmail: async (id, email) => { await prisma.user.update({ where: { id }, data: { email } }); },
  deleteUser: async (id) => { await prisma.user.delete({ where: { id } }); },   // or anonymise if referenced
  claims: (u: any) => ({ role: u.role }),
  isAdmin: (actor) => actor.claims.role === 'ADMIN',
  canManage: (actor, target: any) => target.role !== 'SUPER_ADMIN' || actor.claims.role === 'SUPER_ADMIN',
  verifyLegacyHash: (pw, hash) => bcrypt.compare(pw, hash),   // existing passwords keep working, then upgrade
});
```

### 4. Register the module (NestJS)

```ts
AuthKitModule.forRootAsync({
  inject: [PrismaService, ConfigService],
  useFactory: (prisma, config) => ({
    config: { jwtSecret: config.get('JWT_SECRET'), appName: 'My App' },
    users: users(prisma),
    db: { query: (sql, params = []) => prisma.$queryRawUnsafe(sql, ...params) },
  }),
  publicRoute: { key: IS_PUBLIC_KEY, value: true },   // if the app has a global auth guard
})
```

**Use the app's existing JWT secret.** Access tokens carry `sub`, `email`, your `claims` and `tv` (the token version), so existing guards keep working.

To end sessions on sign-out-everywhere, check the version in your guard:

```ts
constructor(@Inject(AUTH_SERVICE) private auth: AuthService) { ... }
async validate(payload) {
  if (!(await this.auth.isCurrent(payload.sub, payload.tv))) throw new UnauthorizedException();
  return payload;
}
```

### 5. Add the screens (React / Next.js)

```tsx
'use client';
import { createAuthClient } from '@akil-inv/auth-kit/client';
import { AuthKitProvider, LoginForm } from '@akil-inv/auth-kit/react';

const client = createAuthClient({ baseUrl: '/api/auth', getToken: () => localStorage.getItem('token') });

<AuthKitProvider client={client} theme={myTheme}>
  <LoginForm onSignedIn={({ accessToken, user }) => { save(accessToken, user); router.push('/'); }} />
</AuthKitProvider>
```

You need these pages, each wrapped in `AuthKitProvider`:

| Page | Component |
|---|---|
| `/login` | `LoginForm` |
| `/forgot-password` | `ForgotPasswordForm` |
| `/reset-password?token=…` | `ResetPasswordForm token={…}` (covers both reset and invite links) |
| `/verify-email?token=…` | `VerifyEmail token={…}` |
| account settings | `AccountSecurity onTokenChanged={…}` |
| your users admin page | `AuthRequestsPanel`, plus `UserSecurityActions` and `UserSecurityBadges` per user (`useUserSecurity(ids)` loads the details) |

**Styling.** The screens use Tailwind classes. Add the package to Tailwind's `content` list:

```js
'./node_modules/@akil-inv/auth-kit/dist/react/**/*.js'
```

Then pass `theme` (a partial `AuthTheme` of class names) to match your design. Not on Tailwind? Pass your own class names.

### 6. Email (optional, any time later)

Without email, auth-kit works by hand:
- An admin copies invite and reset links and sends them however suits (Teams, chat, their own email).
- Forgotten passwords and email changes wait in the admin's Sign-in requests panel.

When an SMTP server is available, it can be a company relay, Amazon SES (SMTP interface), Microsoft 365, Google Workspace or SendGrid. Pass it as `delivery`, along with `publicUrl`:

```ts
import { smtpDelivery, smtpDeliveryFromEnv } from '@akil-inv/auth-kit/server';

config: {
  ...,
  publicUrl: 'https://hr.example.com',     // emailed links need the full address
  delivery: smtpDeliveryFromEnv(),         // undefined (email off) unless SMTP_HOST is set
  // or: smtpDelivery({ host, port: 587, user, password, from: 'HR <no-reply@example.com>' })
}
```

| Environment variable | Meaning |
|---|---|
| `SMTP_HOST` | Turns email on |
| `SMTP_PORT` | 587 by default; 465 for TLS from the start; 25 for an internal relay |
| `SMTP_SECURE` | `true` for port 465 |
| `SMTP_USER`, `SMTP_PASSWORD` | Leave empty for a relay that needs no sign-in |
| `MAIL_FROM` | Required, e.g. `HR Scoring <no-reply@example.com>` |
| `MAIL_REPLY_TO` | Optional |
| `SMTP_REJECT_UNAUTHORIZED` | `false` only for an internal relay with its own certificate |

**With email on:**
- Forgot-password and email-change links go straight to the person. Email-change links go to the *new* address.
- Invite and reset links an admin creates are emailed **and** still shown to the admin to copy.
- `EmailStatus` (React) shows admins which mode is on and has **Send a test email**.

**If a send fails**, nothing is lost:
- The admin sees the link marked "couldn't be emailed", with the reason.
- Forgotten passwords and email changes fall back to the admin queue.

**Wording.** Change it with `smtpDelivery({ templates: { invite: (v) => ({ subject, text, html }) } })`.

### 7. Optional

| Option | What it does |
|---|---|
| `delivery` | Emails links (see step 6). Any object with `send({ link, user, appName })` works, e.g. an API-based mail service. |
| `secretBox: { seal, open }` | Encrypts two-factor secrets at rest, e.g. with your app's field encryption. |
| `onEvent(e)` | Every sign-in, failure, reset, change and admin action, for your audit log. |
| `passwordMinLength` | Minimum password length. Default 10. |
| `linkTtlHours` | How long links last. Default: reset 24h, invite 7 days, verify 7 days. |
| `accessTokenTtl` | Access token lifetime in seconds. Default 24h. |

## REST routes

All routes are under `api/auth` by default.

**No sign-in needed:**

| Method | Route | Body |
|---|---|---|
| POST | `login` | `{email, password}` → `{status:'signed_in', accessToken, user}` or `{status:'two_factor_required', challenge}` |
| POST | `login/two-factor` | `{challenge, code}` |
| POST | `forgot-password` | `{email}` |
| POST | `link` | `{token}` |
| POST | `reset-password` | `{token, password}` |
| POST | `verify-email` | `{token}` |

**Signed in:**

| Method | Route | Body |
|---|---|---|
| GET | `me` | |
| POST | `password` | `{currentPassword, newPassword}` |
| POST | `email` | `{password, newEmail}` |
| POST | `two-factor/setup` | |
| POST | `two-factor/enable` | `{code}` |
| POST | `two-factor/disable` | `{password, code}` |
| POST | `two-factor/recovery-codes` | `{password, code}` |

**Admin:**

| Method | Route | Body |
|---|---|---|
| GET | `admin/settings` | → `{email: {on, description}}` |
| POST | `admin/test-email` | `{to}` |
| POST | `admin/summaries` | `{userIds}` |
| GET | `admin/requests` | |
| POST | `admin/requests/:id/approve` | |
| POST | `admin/requests/:id/dismiss` | |
| POST | `admin/users/:id/invite-link` | |
| POST | `admin/users/:id/reset-link` | |
| POST | `admin/users/:id/email` | `{email}` |
| POST | `admin/users/:id/reset-two-factor` | |
| POST | `admin/users/:id/sign-out` | |
| DELETE | `admin/users/:id` | |

Errors come back as `{statusCode, message, code}`. The `message` is written for the person using the app.

## Security notes

**Passwords**
- Hashed with scrypt from Node itself, so there's no native module to build.
- Hashes from before auth-kit (e.g. bcrypt) are checked through `verifyLegacyHash`, then upgraded.
- A wrong email and a wrong password take the same time and get the same answer.

**Links and recovery codes**
- Links are 256-bit random and work once.
- Only their SHA-256 is stored; the same goes for recovery codes.
- A new link replaces any unused one of the same kind.

**Two-factor**
- Codes are RFC 6238 TOTP, 30 seconds, ±1 step for clock drift.
- A code can't be reused.
- Each sign-in allows 5 tries.
- A password reset still asks for the code.

**Throttling**
- 10 attempts per email per 15 minutes, for sign-in, forgot-password and password changes.
- Counts are kept in memory, per server process.

**Forgot password** gives the same answer whether or not the email has an account.

**Sessions** end through the token version. Deleting a user also bumps it, so a token held by a deleted user stops working.

## Development

```bash
npm ci
npm test        # needs Postgres: PGHOST / PGPORT / PGUSER (creates auth_kit_test databases)
npm run build
```
