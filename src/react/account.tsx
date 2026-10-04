'use client';

import { FormEvent, useCallback, useEffect, useState } from 'react';
import { SignedIn, UserSecurity } from '../client';
import { Alert, CopyButton, Field, useAction, useAuthKit } from './ui';

type Me = UserSecurity & { email: string };

/**
 * The signed-in person's own security: password, email, two-factor.
 * onTokenChanged receives the new access token after a password change
 * (the old one stops working).
 */
export function AccountSecurity({ onTokenChanged, minLength = 10 }: { onTokenChanged: (r: SignedIn) => void; minLength?: number }) {
  const { client, t } = useAuthKit();
  const [me, setMe] = useState<Me | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(() => client.me().then(setMe).catch((e) => setError(e.message)), [client]);
  useEffect(() => { load(); }, [load]);

  if (error) return <Alert kind="error">{error}</Alert>;
  if (!me) return <p className={t.muted}>Loading…</p>;
  return (
    <div className="space-y-6">
      <PasswordSection minLength={minLength} onTokenChanged={onTokenChanged} />
      <EmailSection me={me} onChanged={load} />
      <TwoFactorSection me={me} onChanged={load} />
    </div>
  );
}

function PasswordSection({ minLength, onTokenChanged }: { minLength: number; onTokenChanged: (r: SignedIn) => void }) {
  const { client, t } = useAuthKit();
  const { busy, error, run } = useAction();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [done, setDone] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const r = await run(() => client.changePassword(current, next));
    if (!r) return;
    onTokenChanged(r);
    setCurrent(''); setNext(''); setConfirm(''); setDone(true);
  };
  return (
    <form onSubmit={submit} className={`space-y-4 ${t.card}`} noValidate>
      <h2 className={t.title}>Password</h2>
      <Field label="Current password" id="current-password" type="password" autoComplete="current-password" value={current} onChange={(e) => { setCurrent(e.target.value); setDone(false); }} />
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="New password" id="new-password" type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} hint={`At least ${minLength} characters.`} />
        <Field label="Type it again" id="confirm-password" type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
      </div>
      <Alert kind="error">{error}</Alert>
      {done && <Alert kind="success">Password changed. Anywhere else you were signed in has been signed out.</Alert>}
      <button type="submit" className={t.button} disabled={busy || !current || next.length < minLength || next !== confirm}>
        {busy ? 'Saving…' : 'Change password'}
      </button>
    </form>
  );
}

function EmailSection({ me, onChanged }: { me: Me; onChanged: () => void }) {
  const { client, t } = useAuthKit();
  const { busy, error, run } = useAction();
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [done, setDone] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const r = await run(() => client.requestEmailChange(password, email));
    if (!r) return;
    setDone(r.message); setOpen(false); setEmail(''); setPassword('');
    onChanged();
  };
  return (
    <section className={`space-y-4 ${t.card}`}>
      <h2 className={t.title}>Email</h2>
      <p className={t.text}>You sign in with <strong>{me.email}</strong>.</p>
      {me.pendingEmail && !done && <p className={t.muted}>Waiting to confirm a change to <strong>{me.pendingEmail}</strong>.</p>}
      {done && <Alert kind="success">{done}</Alert>}
      {open ? (
        <form onSubmit={submit} className="space-y-4" noValidate>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="New email" id="new-email" type="email" autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} autoFocus />
            <Field label="Your password" id="email-password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </div>
          <p className={t.muted}>Your email changes only once the new address is confirmed with a link.</p>
          <Alert kind="error">{error}</Alert>
          <div className="flex gap-2">
            <button type="submit" className={t.button} disabled={busy || !email || !password}>{busy ? 'Sending…' : 'Change email'}</button>
            <button type="button" className={t.secondary} onClick={() => setOpen(false)}>Cancel</button>
          </div>
        </form>
      ) : (
        <button type="button" className={t.secondary} onClick={() => { setOpen(true); setDone(null); }}>Change email…</button>
      )}
    </section>
  );
}

function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const { t } = useAuthKit();
  const text = codes.join('\n');
  const download = () => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([`Recovery codes. Each works once, instead of an authenticator code.\n\n${text}\n`], { type: 'text/plain' }));
    a.download = 'recovery-codes.txt';
    a.click();
    URL.revokeObjectURL(a.href);
  };
  return (
    <div className="space-y-3">
      <Alert kind="success">Save these recovery codes somewhere safe, like a password manager. If you lose your phone, each one gets you in once. They won&apos;t be shown again.</Alert>
      <ul className="grid grid-cols-2 gap-2 sm:grid-cols-5">
        {codes.map((c) => <li key={c} className={`${t.code} text-center`}>{c}</li>)}
      </ul>
      <div className="flex flex-wrap gap-2">
        <CopyButton text={text} label="Copy codes" />
        <button type="button" className={t.secondary} onClick={download}>Download</button>
        <button type="button" className={t.button} onClick={onDone}>I&apos;ve saved them</button>
      </div>
    </div>
  );
}

function TwoFactorSection({ me, onChanged }: { me: Me; onChanged: () => void }) {
  const { client, t } = useAuthKit();
  const { busy, error, run, setError } = useAction();
  const [setup, setSetup] = useState<{ secret: string; qrSvg: string } | null>(null);
  const [mode, setMode] = useState<'idle' | 'disable' | 'codes'>('idle');
  const [code, setCode] = useState('');
  const [password, setPassword] = useState('');
  const [codes, setCodes] = useState<string[] | null>(null);
  const reset = () => { setMode('idle'); setCode(''); setPassword(''); setError(null); };

  if (codes) return (
    <section className={`space-y-4 ${t.card}`}>
      <h2 className={t.title}>Two-factor sign-in</h2>
      <RecoveryCodes codes={codes} onDone={() => { setCodes(null); onChanged(); }} />
    </section>
  );

  return (
    <section className={`space-y-4 ${t.card}`}>
      <div className="flex items-center justify-between gap-3">
        <h2 className={t.title}>Two-factor sign-in</h2>
        <span className={me.twoFactor ? t.badgeOk : t.badge}>{me.twoFactor ? 'On' : 'Off'}</span>
      </div>
      {!me.twoFactor && !setup && (
        <>
          <p className={t.muted}>After your password, you&apos;ll also enter a 6-digit code from an app on your phone (Google Authenticator, Microsoft Authenticator, 1Password…). Someone with your password alone can&apos;t get in.</p>
          <Alert kind="error">{error}</Alert>
          <button type="button" className={t.button} disabled={busy} onClick={async () => { const s = await run(() => client.twoFactorSetup()); if (s) setSetup(s); }}>
            {busy ? 'Starting…' : 'Set up two-factor'}
          </button>
        </>
      )}
      {!me.twoFactor && setup && (
        <form className="space-y-4" noValidate onSubmit={async (e) => {
          e.preventDefault();
          const r = await run(() => client.twoFactorEnable(code));
          if (r) { setSetup(null); setCode(''); setCodes(r.recoveryCodes); }
        }}>
          <ol className={`list-decimal space-y-1 pl-5 ${t.text}`}>
            <li>In your authenticator app, add an account and scan this code.</li>
            <li>Enter the 6-digit code the app shows.</li>
          </ol>
          <div className="flex flex-wrap items-start gap-6">
            <div className="h-44 w-44 rounded-lg bg-white p-2" aria-label="QR code to scan" dangerouslySetInnerHTML={{ __html: setup.qrSvg }} />
            <div className="min-w-0 flex-1 space-y-3">
              <p className={t.muted}>Can&apos;t scan? Enter this key instead:</p>
              <p className={`${t.code} inline-block break-all`}>{setup.secret.match(/.{1,4}/g)!.join(' ')}</p>
              <Field label="Code from the app" id="totp" inputMode="numeric" autoComplete="one-time-code" maxLength={7} placeholder="123456"
                value={code} onChange={(e) => setCode(e.target.value.replace(/[^0-9 ]/g, ''))} />
            </div>
          </div>
          <Alert kind="error">{error}</Alert>
          <div className="flex gap-2">
            <button type="submit" className={t.button} disabled={busy || code.replace(/\s/g, '').length !== 6}>{busy ? 'Checking…' : 'Turn on'}</button>
            <button type="button" className={t.secondary} onClick={() => { setSetup(null); setCode(''); setError(null); }}>Cancel</button>
          </div>
        </form>
      )}
      {me.twoFactor && mode === 'idle' && (
        <>
          <p className={t.muted}>You enter a code from your authenticator app when you sign in. Lost your phone? Use a recovery code, or ask an administrator to reset two-factor.</p>
          <div className="flex flex-wrap gap-2">
            <button type="button" className={t.secondary} onClick={() => setMode('codes')}>New recovery codes…</button>
            <button type="button" className={t.danger} onClick={() => setMode('disable')}>Turn off…</button>
          </div>
        </>
      )}
      {me.twoFactor && mode !== 'idle' && (
        <form className="space-y-4" noValidate onSubmit={async (e) => {
          e.preventDefault();
          if (mode === 'disable') {
            const r = await run(() => client.twoFactorDisable(password, code));
            if (r) { reset(); onChanged(); }
          } else {
            const r = await run(() => client.regenerateRecoveryCodes(password, code));
            if (r) { reset(); setCodes(r.recoveryCodes); }
          }
        }}>
          <p className={t.muted}>{mode === 'disable' ? 'Confirm with your password and a current code to turn two-factor off.' : 'Confirm to replace your recovery codes. The old ones stop working.'}</p>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Your password" id="tf-password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
            <Field label={mode === 'disable' ? 'Code (or a recovery code)' : 'Code from the app'} id="tf-code" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} />
          </div>
          <Alert kind="error">{error}</Alert>
          <div className="flex gap-2">
            <button type="submit" className={mode === 'disable' ? t.danger : t.button} disabled={busy || !password || code.trim().length < 6}>
              {busy ? 'Checking…' : mode === 'disable' ? 'Turn off two-factor' : 'Make new codes'}
            </button>
            <button type="button" className={t.secondary} onClick={reset}>Cancel</button>
          </div>
        </form>
      )}
    </section>
  );
}
