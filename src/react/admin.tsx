'use client';

import { FormEvent, useCallback, useEffect, useState } from 'react';
import { Link, OpenRequest, UserSecurity } from '../client';
import { Alert, Field, LinkBox, useAction, useAuthKit } from './ui';

/** Small status badges for a user list: not set up, two-factor on, email change waiting. */
export function UserSecurityBadges({ summary }: { summary?: UserSecurity | null }) {
  const { t } = useAuthKit();
  if (!summary) return null;
  return (
    <span className="inline-flex flex-wrap gap-1">
      {!summary.passwordSet && <span className={t.badgeWarn}>Not set up yet</span>}
      {summary.twoFactor && <span className={t.badgeOk}>Two-factor</span>}
      {summary.pendingEmail && <span className={t.badge}>Email change waiting</span>}
    </span>
  );
}

/** Load security summaries for the users on screen. */
export function useUserSecurity(userIds: string[]) {
  const { client } = useAuthKit();
  const [data, setData] = useState<Record<string, UserSecurity>>({});
  const key = [...userIds].sort().join(',');
  const reload = useCallback(() => {
    if (!key) return Promise.resolve();
    return client.admin.summaries(key.split(',')).then(setData).catch(() => setData({}));
  }, [client, key]);
  useEffect(() => { reload(); }, [reload]);
  return { summaries: data, reload };
}

/**
 * An admin's sign-in actions for one user: a reset (or invite) link,
 * change email, reset two-factor, sign out everywhere, delete.
 */
export function UserSecurityActions({ user, summary, onChanged, onDeleted, isSelf = false }: {
  user: { id: string; email: string; name?: string | null };
  summary?: UserSecurity | null;
  onChanged?: () => void;
  onDeleted?: () => void;
  isSelf?: boolean;
}) {
  const { client, t } = useAuthKit();
  const { busy, error, run, setError } = useAction();
  const [link, setLink] = useState<Link | null>(null);
  const [mode, setMode] = useState<'none' | 'email' | 'delete'>('none');
  const [email, setEmail] = useState('');
  const [confirm, setConfirm] = useState('');
  const [notice, setNotice] = useState<string | null>(null);
  const who = user.name || user.email;
  const setUp = summary ? summary.passwordSet : true;

  const act = async (f: () => Promise<unknown>, message: string) => {
    setNotice(null);
    const r = await run(f);
    if (r !== undefined) { setNotice(message); onChanged?.(); }
  };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2">
        <button type="button" className={t.secondary} disabled={busy}
          onClick={async () => { setNotice(null); const l = await run(() => (setUp ? client.admin.resetLink(user.id) : client.admin.inviteLink(user.id))); if (l) { setLink(l); onChanged?.(); } }}>
          {setUp ? 'Password reset link' : 'Invite link'}
        </button>
        <button type="button" className={t.secondary} disabled={busy} onClick={() => { setMode(mode === 'email' ? 'none' : 'email'); setEmail(user.email); setError(null); }}>Change email…</button>
        {summary?.twoFactor && (
          <button type="button" className={t.secondary} disabled={busy}
            onClick={() => window.confirm(`Turn off two-factor for ${who}? They can set it up again after signing in.`) && act(() => client.admin.resetTwoFactor(user.id), `Two-factor is off for ${who}.`)}>
            Reset two-factor
          </button>
        )}
        {!isSelf && (
          <button type="button" className={t.secondary} disabled={busy}
            onClick={() => act(() => client.admin.signOutEverywhere(user.id), `${who} is signed out everywhere.`)}>
            Sign out everywhere
          </button>
        )}
        {!isSelf && (
          <button type="button" className={t.danger} disabled={busy} onClick={() => { setMode(mode === 'delete' ? 'none' : 'delete'); setConfirm(''); setError(null); }}>Delete…</button>
        )}
      </div>

      {link && <LinkBox link={link} onClose={() => setLink(null)} />}
      {notice && <Alert kind="success">{notice}</Alert>}

      {mode === 'email' && (
        <form className="space-y-3" noValidate onSubmit={async (e: FormEvent) => {
          e.preventDefault();
          const r = await run(() => client.admin.setEmail(user.id, email));
          if (r) { setMode('none'); setNotice(`${who} now signs in with ${email.trim().toLowerCase()}. Their sessions were ended.`); onChanged?.(); }
        }}>
          <Field label={`New sign-in email for ${who}`} id={`email-${user.id}`} type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoFocus
            hint="Changes straight away; you are vouching for the address. They are signed out everywhere." />
          <div className="flex gap-2">
            <button type="submit" className={t.button} disabled={busy || !email || email.trim().toLowerCase() === user.email.toLowerCase()}>Save email</button>
            <button type="button" className={t.secondary} onClick={() => setMode('none')}>Cancel</button>
          </div>
        </form>
      )}

      {mode === 'delete' && (
        <form className="space-y-3" noValidate onSubmit={async (e: FormEvent) => {
          e.preventDefault();
          const r = await run(() => client.admin.deleteUser(user.id));
          if (r) { setMode('none'); onDeleted?.(); onChanged?.(); }
        }}>
          <Field label={`Type ${user.email} to delete this account`} id={`delete-${user.id}`} value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="off" autoFocus
            hint="They can no longer sign in. Records they made stay, without their name where the app removes it." />
          <div className="flex gap-2">
            <button type="submit" className={t.danger} disabled={busy || confirm.trim().toLowerCase() !== user.email.toLowerCase()}>Delete account</button>
            <button type="button" className={t.secondary} onClick={() => setMode('none')}>Cancel</button>
          </div>
        </form>
      )}

      <Alert kind="error">{error}</Alert>
    </div>
  );
}

const ago = (iso: string) => {
  const m = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h} h ago`;
  return new Date(iso).toLocaleDateString(undefined, { day: 'numeric', month: 'short' });
};

/**
 * Forgotten passwords and email changes waiting for an admin (when links
 * are passed on by hand rather than emailed). Shows nothing when there are none.
 */
export function AuthRequestsPanel({ onChanged, title = 'Sign-in requests' }: { onChanged?: () => void; title?: string }) {
  const { client, t } = useAuthKit();
  const { busy, error, run } = useAction();
  const [requests, setRequests] = useState<OpenRequest[] | null>(null);
  const [links, setLinks] = useState<Record<string, Link>>({});
  const load = useCallback(() => client.admin.requests().then(setRequests).catch(() => setRequests([])), [client]);
  useEffect(() => { load(); }, [load]);

  const shown = (requests ?? []).length + Object.keys(links).length;
  if (!shown) return null;
  return (
    <section className={`space-y-3 ${t.card}`}>
      <h2 className={t.title}>{title}</h2>
      <ul className="space-y-3">
        {Object.entries(links).map(([id, link]) => (
          <li key={id}><LinkBox link={link} onClose={() => setLinks(({ [id]: _, ...rest }) => rest)} /></li>
        ))}
        {(requests ?? []).map((r) => (
          <li key={r.id} className="flex flex-wrap items-center gap-3">
            <p className={`min-w-0 flex-1 ${t.text}`}>
              <strong>{r.user.name || r.user.email}</strong>{r.user.name ? ` (${r.user.email})` : ''}{' '}
              {r.kind === 'password_reset' ? 'forgot their password' : <>wants to change their email to <strong>{r.newEmail}</strong></>}
              <span className={t.muted}> · {ago(r.createdAt)}</span>
            </p>
            <button type="button" className={t.button} disabled={busy}
              onClick={async () => { const l = await run(() => client.admin.approveRequest(r.id)); if (l) { setLinks((x) => ({ ...x, [r.id]: l })); await load(); onChanged?.(); } }}>
              {r.kind === 'password_reset' ? 'Create reset link' : 'Create confirm link'}
            </button>
            <button type="button" className={t.secondary} disabled={busy}
              onClick={async () => { const ok = await run(() => client.admin.dismissRequest(r.id)); if (ok) await load(); }}>
              Dismiss
            </button>
          </li>
        ))}
      </ul>
      <Alert kind="error">{error}</Alert>
    </section>
  );
}
