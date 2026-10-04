import nodemailer from 'nodemailer';
import { AuthUser, Delivery, Link } from './types';

/**
 * Email delivery over SMTP: a company mail relay, Amazon SES (its SMTP
 * interface), Microsoft 365, Gmail/Workspace, SendGrid… anything that
 * speaks SMTP. Without it, auth-kit emails nothing and admins pass links on.
 */
export type SmtpOptions = {
  host: string;
  /** 587 (STARTTLS) by default; 465 with secure: true; 25 for an internal relay. */
  port?: number;
  /** true for port 465 (TLS from the start). Default: true only when port is 465. */
  secure?: boolean;
  /** Leave out for a relay that needs no sign-in. */
  user?: string;
  password?: string;
  /** e.g. 'HR Scoring <no-reply@example.com>'. Must be an address the server may send as. */
  from: string;
  replyTo?: string;
  /** For an internal relay with its own certificate. Default true. */
  rejectUnauthorized?: boolean;
  /** Change the wording of the emails. */
  templates?: Partial<Record<Link['purpose'], EmailTemplate>>;
};

export type EmailContent = { subject: string; text: string; html: string };
export type EmailTemplate = (v: { link: Link; url: string; user: AuthUser; appName: string; expires: string }) => EmailContent;

export interface MailDelivery extends Delivery {
  /** Check the server answers and accepts the sign-in. Throws with the server's reason. */
  verify(): Promise<void>;
  /** For status screens: "smtp.example.com:587 as no-reply@example.com". */
  describe(): string;
  sendTest(to: string, appName: string): Promise<void>;
}

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));

function layout(appName: string, heading: string, lines: string[], button: { label: string; url: string } | null, foot: string) {
  const html = `<!doctype html><html><body style="margin:0;background:#f4f4f7;padding:24px 12px;font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;color:#1d1b26">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:520px;background:#ffffff;border-radius:12px;padding:28px">
<tr><td style="font-size:13px;color:#6b6880;padding-bottom:8px">${esc(appName)}</td></tr>
<tr><td style="font-size:20px;font-weight:600;padding-bottom:14px">${esc(heading)}</td></tr>
${lines.map((l) => `<tr><td style="font-size:15px;line-height:1.55;padding-bottom:12px">${l}</td></tr>`).join('')}
${button ? `<tr><td style="padding:8px 0 18px"><a href="${esc(button.url)}" style="display:inline-block;background:#4c1d95;color:#ffffff;text-decoration:none;font-weight:600;font-size:15px;padding:12px 20px;border-radius:8px">${esc(button.label)}</a></td></tr>
<tr><td style="font-size:12px;color:#6b6880;padding-bottom:12px;word-break:break-all">Or open this address: ${esc(button.url)}</td></tr>` : ''}
<tr><td style="font-size:12px;color:#6b6880;border-top:1px solid #ececf2;padding-top:12px">${esc(foot)}</td></tr>
</table></td></tr></table></body></html>`;
  return html;
}

const IGNORE = "If you didn't expect this email, you can ignore it; nothing changes unless the link is opened.";

export const defaultTemplates: Record<Link['purpose'], EmailTemplate> = {
  invite: ({ url, appName, expires, user }) => ({
    subject: `Your ${appName} account`,
    text: `An account has been created for you in ${appName}${user.name ? `, ${user.name}` : ''}.\n\nChoose your password here (the link works once, until ${expires}):\n${url}\n\nYou'll then sign in with ${user.email}.\n\n${IGNORE}`,
    html: layout(appName, 'Set up your account', [
      `An account has been created for you${user.name ? `, ${esc(user.name)}` : ''}. Choose a password to finish setting it up; you'll sign in with <b>${esc(user.email)}</b>.`,
    ], { label: 'Choose your password', url }, `The link works once, until ${expires}. ${IGNORE}`),
  }),
  reset_password: ({ url, appName, expires }) => ({
    subject: `Reset your ${appName} password`,
    text: `Use this link to choose a new password (it works once, until ${expires}):\n${url}\n\nOther places you're signed in will be signed out.\n\n${IGNORE}`,
    html: layout(appName, 'Reset your password', [
      'Use the button to choose a new password. Other places you’re signed in will be signed out.',
    ], { label: 'Choose a new password', url }, `The link works once, until ${expires}. ${IGNORE}`),
  }),
  change_email: ({ url, appName, expires, link }) => ({
    subject: `Confirm your new ${appName} email`,
    text: `Confirm that you'll sign in to ${appName} with ${link.to} from now on (the link works once, until ${expires}):\n${url}\n\n${IGNORE}`,
    html: layout(appName, 'Confirm your new email', [
      `Confirm that you’ll sign in with <b>${esc(link.to)}</b> from now on. Your email changes when you open the link.`,
    ], { label: 'Confirm this email', url }, `The link works once, until ${expires}. ${IGNORE}`),
  }),
  verify_email: ({ url, appName, expires }) => ({
    subject: `Confirm your ${appName} email`,
    text: `Confirm your email address (the link works once, until ${expires}):\n${url}\n\n${IGNORE}`,
    html: layout(appName, 'Confirm your email', ['Confirm this is your email address.'], { label: 'Confirm', url }, `The link works once, until ${expires}. ${IGNORE}`),
  }),
};

export function smtpDelivery(o: SmtpOptions): MailDelivery {
  if (!o.host) throw new Error('auth-kit email: host is required.');
  if (!o.from) throw new Error('auth-kit email: from is required (e.g. "HR Scoring <no-reply@example.com>").');
  const port = o.port ?? 587;
  const transport = nodemailer.createTransport({
    host: o.host,
    port,
    secure: o.secure ?? port === 465,
    auth: o.user ? { user: o.user, pass: o.password ?? '' } : undefined,
    tls: { rejectUnauthorized: o.rejectUnauthorized ?? true },
    connectionTimeout: 10_000,
    greetingTimeout: 10_000,
    socketTimeout: 20_000,
  });
  const templates = { ...defaultTemplates, ...o.templates };

  return {
    async send({ link, user, appName }) {
      if (!link.url) throw new Error('auth-kit email: set publicUrl so emailed links are complete addresses.');
      const expires = link.expiresAt.toUTCString().replace(/:\d\d GMT$/, ' UTC');
      const content = templates[link.purpose]({ link, url: link.url, user, appName, expires });
      await transport.sendMail({ from: o.from, replyTo: o.replyTo, to: link.to, ...content });
    },
    async verify() {
      await transport.verify();
    },
    describe() {
      return `${o.host}:${port}${o.user ? ` as ${o.user}` : ''}, from ${o.from}`;
    },
    async sendTest(to, appName) {
      await transport.sendMail({
        from: o.from, replyTo: o.replyTo, to,
        subject: `${appName}: test email`,
        text: `This is a test from ${appName}. Email is working: sign-in links will be sent to people directly.`,
        html: layout(appName, 'Email is working', ['This is a test. Sign-in links will now be sent to people directly.'], null, 'Sent from the Users page.'),
      });
    },
  };
}

/**
 * Email settings from environment variables, or undefined when SMTP_HOST is
 * not set (links are then passed on by an admin):
 *   SMTP_HOST, SMTP_PORT, SMTP_SECURE (true/false), SMTP_USER, SMTP_PASSWORD,
 *   MAIL_FROM, MAIL_REPLY_TO, SMTP_REJECT_UNAUTHORIZED (true/false)
 */
export function smtpDeliveryFromEnv(env: NodeJS.ProcessEnv = process.env): MailDelivery | undefined {
  if (!env.SMTP_HOST) return undefined;
  const bool = (v: string | undefined) => (v === undefined || v === '' ? undefined : /^(1|true|yes)$/i.test(v));
  return smtpDelivery({
    host: env.SMTP_HOST,
    port: env.SMTP_PORT ? Number(env.SMTP_PORT) : undefined,
    secure: bool(env.SMTP_SECURE),
    user: env.SMTP_USER || undefined,
    password: env.SMTP_PASSWORD || undefined,
    from: env.MAIL_FROM ?? '',
    replyTo: env.MAIL_REPLY_TO || undefined,
    rejectUnauthorized: bool(env.SMTP_REJECT_UNAUTHORIZED),
  });
}
