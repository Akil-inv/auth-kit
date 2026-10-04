'use client';

import { createContext, ReactNode, useContext, useState } from 'react';
import { AuthClient, AuthClientError, Link, copyText, linkUrl } from '../client';

/**
 * Class names for every element the screens draw. The defaults are Tailwind
 * classes for a light page; pass your own (all or some) to AuthKitProvider to
 * match your app. With Tailwind, add this package's dist to `content` so the
 * defaults are generated.
 */
export type AuthTheme = {
  card: string; title: string; text: string; muted: string; label: string; input: string;
  button: string; secondary: string; danger: string; error: string; success: string; link: string;
  code: string; badge: string; badgeWarn: string; badgeOk: string; divider: string;
};

export const lightTheme: AuthTheme = {
  card: 'rounded-xl border border-slate-200 bg-white p-6 shadow-sm',
  title: 'text-lg font-semibold text-slate-900',
  text: 'text-sm text-slate-700',
  muted: 'text-sm text-slate-500',
  label: 'mb-1 block text-sm font-medium text-slate-700',
  input: 'w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 outline-none focus:border-slate-900 focus:ring-1 focus:ring-slate-900 disabled:opacity-60',
  button: 'inline-flex items-center justify-center rounded-lg bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-50',
  secondary: 'inline-flex items-center justify-center rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm text-slate-800 hover:border-slate-500 disabled:cursor-not-allowed disabled:opacity-50',
  danger: 'inline-flex items-center justify-center rounded-lg border border-red-300 bg-white px-3 py-2 text-sm text-red-700 hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-50',
  error: 'rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800',
  success: 'rounded-lg border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-800',
  link: 'text-sm font-medium text-slate-900 underline underline-offset-2 hover:text-slate-600',
  code: 'rounded bg-slate-100 px-1.5 py-0.5 font-mono text-sm text-slate-900',
  badge: 'inline-flex items-center rounded-full bg-slate-100 px-2 py-0.5 text-xs text-slate-700',
  badgeWarn: 'inline-flex items-center rounded-full bg-amber-100 px-2 py-0.5 text-xs text-amber-800',
  badgeOk: 'inline-flex items-center rounded-full bg-emerald-100 px-2 py-0.5 text-xs text-emerald-800',
  divider: 'border-t border-slate-200',
};

type Ctx = { client: AuthClient; t: AuthTheme };
const AuthKitContext = createContext<Ctx | null>(null);

export function AuthKitProvider({ client, theme, children }: { client: AuthClient; theme?: Partial<AuthTheme>; children: ReactNode }) {
  return <AuthKitContext.Provider value={{ client, t: { ...lightTheme, ...theme } }}>{children}</AuthKitContext.Provider>;
}

export function useAuthKit(): Ctx {
  const c = useContext(AuthKitContext);
  if (!c) throw new Error('auth-kit: wrap these screens in <AuthKitProvider client={...}>.');
  return c;
}

export const messageOf = (e: unknown) => (e instanceof AuthClientError || e instanceof Error ? e.message : 'Something went wrong.');

/** Runs an action with busy and error state. */
export function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = async <T,>(f: () => Promise<T>): Promise<T | undefined> => {
    setBusy(true);
    setError(null);
    try {
      return await f();
    } catch (e) {
      setError(messageOf(e));
      return undefined;
    } finally {
      setBusy(false);
    }
  };
  return { busy, error, setError, run };
}

export function Field({ label, id, hint, ...input }: { label: string; id: string; hint?: string } & React.InputHTMLAttributes<HTMLInputElement>) {
  const { t } = useAuthKit();
  return (
    <div>
      <label htmlFor={id} className={t.label}>{label}</label>
      <input id={id} name={id} className={t.input} {...input} />
      {hint && <p className={`mt-1 ${t.muted}`}>{hint}</p>}
    </div>
  );
}

export function Alert({ kind, children }: { kind: 'error' | 'success'; children: ReactNode }) {
  const { t } = useAuthKit();
  if (!children) return null;
  return <div role={kind === 'error' ? 'alert' : 'status'} className={kind === 'error' ? t.error : t.success}>{children}</div>;
}

export function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const { t } = useAuthKit();
  const [done, setDone] = useState<null | boolean>(null);
  return (
    <button type="button" className={t.secondary}
      onClick={async () => { setDone(await copyText(text)); setTimeout(() => setDone(null), 2000); }}>
      {done === true ? 'Copied' : done === false ? 'Select and copy' : label}
    </button>
  );
}

const PURPOSE_TEXT: Record<Link['purpose'], string> = {
  invite: 'Invite link: they choose a password and their account is ready.',
  reset_password: 'Reset link: they choose a new password.',
  verify_email: 'Confirmation link: confirms their email.',
  change_email: 'Confirmation link: their sign-in email changes when they open it.',
};

/** A one-time link to pass on, with a copy button. */
export function LinkBox({ link, onClose }: { link: Link; onClose?: () => void }) {
  const { t } = useAuthKit();
  const url = linkUrl(link);
  const expires = new Date(link.expiresAt).toLocaleString(undefined, { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
  return (
    <div className={`space-y-2 ${t.success}`}>
      <p>{PURPOSE_TEXT[link.purpose]} Send it to <strong>{link.to}</strong>. It works once, until {expires}.</p>
      <div className="flex flex-wrap items-center gap-2">
        <input readOnly value={url} onFocus={(e) => e.currentTarget.select()} aria-label="Link" className={`${t.input} min-w-0 flex-1 font-mono text-xs`} />
        <CopyButton text={url} label="Copy link" />
        {onClose && <button type="button" className={t.secondary} onClick={onClose}>Done</button>}
      </div>
    </div>
  );
}
