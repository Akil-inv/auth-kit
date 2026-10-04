'use client';

import { FormEvent, ReactNode, useEffect, useState } from 'react';
import { LinkPurpose, SignedIn } from '../client';
import { Alert, Field, useAction, useAuthKit } from './ui';

/** Sign in: email and password, then the two-factor code when it is on. */
export function LoginForm({ onSignedIn, forgotPasswordHref = '/forgot-password', title = 'Sign in', footer }: {
  onSignedIn: (result: SignedIn) => void;
  forgotPasswordHref?: string | null;
  title?: string;
  footer?: ReactNode;
}) {
  const { client, t } = useAuthKit();
  const { busy, error, run } = useAction();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [challenge, setChallenge] = useState<string | null>(null);

  if (challenge) {
    return <TwoFactorStep challenge={challenge} onSignedIn={onSignedIn} onBack={() => setChallenge(null)} />;
  }
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const r = await run(() => client.login(email, password));
    if (!r) return;
    if (r.status === 'two_factor_required') setChallenge(r.challenge);
    else onSignedIn(r);
  };
  return (
    <form onSubmit={submit} className={`space-y-4 ${t.card}`} noValidate>
      <h1 className={t.title}>{title}</h1>
      <Field label="Email" id="email" type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} autoFocus />
      <Field label="Password" id="password" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
      <Alert kind="error">{error}</Alert>
      <button type="submit" className={`${t.button} w-full`} disabled={busy || !email || !password}>{busy ? 'Signing in…' : 'Sign in'}</button>
      {forgotPasswordHref && <p className="text-center"><a href={forgotPasswordHref} className={t.link}>Forgot your password?</a></p>}
      {footer}
    </form>
  );
}

/** The code from the authenticator app, or a recovery code. */
export function TwoFactorStep({ challenge, onSignedIn, onBack }: { challenge: string; onSignedIn: (r: SignedIn) => void; onBack?: () => void }) {
  const { client, t } = useAuthKit();
  const { busy, error, run } = useAction();
  const [code, setCode] = useState('');
  const [recovery, setRecovery] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const r = await run(() => client.loginTwoFactor(challenge, code));
    if (r) onSignedIn(r);
  };
  return (
    <form onSubmit={submit} className={`space-y-4 ${t.card}`} noValidate>
      <h1 className={t.title}>Two-factor check</h1>
      <p className={t.muted}>
        {recovery ? 'Enter one of the recovery codes you saved. Each works once.' : 'Enter the 6-digit code from your authenticator app.'}
      </p>
      {recovery ? (
        <Field key="r" label="Recovery code" id="code" autoComplete="off" placeholder="xxxx-xxxx" value={code} onChange={(e) => setCode(e.target.value)} autoFocus />
      ) : (
        <Field key="c" label="Code" id="code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9 ]*" maxLength={7} placeholder="123456"
          value={code} onChange={(e) => setCode(e.target.value.replace(/[^0-9 ]/g, ''))} autoFocus />
      )}
      <Alert kind="error">{error}</Alert>
      <button type="submit" className={`${t.button} w-full`} disabled={busy || code.trim().length < 6}>{busy ? 'Checking…' : 'Continue'}</button>
      <div className="flex justify-between">
        <button type="button" className={t.link} onClick={() => { setRecovery(!recovery); setCode(''); }}>
          {recovery ? 'Use the app code instead' : 'Use a recovery code'}
        </button>
        {onBack && <button type="button" className={t.link} onClick={onBack}>Start again</button>}
      </div>
    </form>
  );
}

/** Ask for a reset link. Says the same thing whether or not the email has an account. */
export function ForgotPasswordForm({ signInHref = '/login' }: { signInHref?: string }) {
  const { client, t } = useAuthKit();
  const { busy, error, run } = useAction();
  const [email, setEmail] = useState('');
  const [done, setDone] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const r = await run(() => client.forgotPassword(email));
    if (r) setDone(r.message);
  };
  return (
    <form onSubmit={submit} className={`space-y-4 ${t.card}`} noValidate>
      <h1 className={t.title}>Forgot your password?</h1>
      {done ? (
        <Alert kind="success">{done}</Alert>
      ) : (
        <>
          <p className={t.muted}>Enter the email you sign in with.</p>
          <Field label="Email" id="email" type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} autoFocus />
          <Alert kind="error">{error}</Alert>
          <button type="submit" className={`${t.button} w-full`} disabled={busy || !email}>{busy ? 'Sending…' : 'Ask for a reset link'}</button>
        </>
      )}
      <p className="text-center"><a href={signInHref} className={t.link}>Back to sign in</a></p>
    </form>
  );
}

/** Choose a password from a reset or invite link. Signs in when done (after the code, if two-factor is on). */
export function ResetPasswordForm({ token, onSignedIn, signInHref = '/login', minLength = 10 }: {
  token: string; onSignedIn: (r: SignedIn) => void; signInHref?: string; minLength?: number;
}) {
  const { client, t } = useAuthKit();
  const { busy, error, run } = useAction();
  const [info, setInfo] = useState<{ purpose: LinkPurpose; email: string } | null>(null);
  const [bad, setBad] = useState<string | null>(null);
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [challenge, setChallenge] = useState<string | null>(null);

  useEffect(() => {
    if (!token) { setBad('This link is missing its code. Open the full link you were given.'); return; }
    client.describeLink(token).then(setInfo).catch((e) => setBad(e.message));
  }, [client, token]);

  if (challenge) return <TwoFactorStep challenge={challenge} onSignedIn={onSignedIn} />;
  const invite = info?.purpose === 'invite';
  const mismatch = confirm.length > 0 && confirm !== password;
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const r = await run(() => client.resetPassword(token, password));
    if (!r) return;
    if (r.status === 'two_factor_required') setChallenge(r.challenge);
    else onSignedIn(r);
  };
  return (
    <form onSubmit={submit} className={`space-y-4 ${t.card}`} noValidate>
      <h1 className={t.title}>{invite ? 'Set up your account' : 'Choose a new password'}</h1>
      {bad ? (
        <>
          <Alert kind="error">{bad}</Alert>
          <p className="text-center"><a href={signInHref} className={t.link}>Go to sign in</a></p>
        </>
      ) : !info ? (
        <p className={t.muted}>Checking the link…</p>
      ) : (
        <>
          <p className={t.muted}>
            {invite ? <>Choose a password for <strong>{info.email}</strong>. You&apos;ll use it with this email to sign in.</> : <>For <strong>{info.email}</strong>. Other places you&apos;re signed in will be signed out.</>}
          </p>
          <input type="email" autoComplete="username" value={info.email} readOnly hidden />
          <Field label="New password" id="new-password" type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)}
            hint={`At least ${minLength} characters. A short sentence is easy to remember.`} autoFocus />
          <Field label="Type it again" id="confirm-password" type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
          {mismatch && <p className={t.muted}>The two don&apos;t match yet.</p>}
          <Alert kind="error">{error}</Alert>
          <button type="submit" className={`${t.button} w-full`} disabled={busy || password.length < minLength || password !== confirm}>
            {busy ? 'Saving…' : invite ? 'Set password and sign in' : 'Save and sign in'}
          </button>
        </>
      )}
    </form>
  );
}

/** Opens a confirmation link: confirms an email, or completes an email change. */
export function VerifyEmail({ token, signInHref = '/login', onVerified }: { token: string; signInHref?: string; onVerified?: (email: string) => void }) {
  const { client, t } = useAuthKit();
  const [state, setState] = useState<{ ok: boolean; text: string } | null>(null);
  useEffect(() => {
    if (!token) { setState({ ok: false, text: 'This link is missing its code. Open the full link you were given.' }); return; }
    let live = true;
    client.verifyEmail(token)
      .then((r) => { if (!live) return; setState({ ok: true, text: `Confirmed. You now sign in with ${r.email}.` }); onVerified?.(r.email); })
      .catch((e) => live && setState({ ok: false, text: e.message }));
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [client, token]);
  return (
    <div className={`space-y-4 ${t.card}`}>
      <h1 className={t.title}>Confirm your email</h1>
      {state ? <Alert kind={state.ok ? 'success' : 'error'}>{state.text}</Alert> : <p className={t.muted}>Confirming…</p>}
      {state && <p className="text-center"><a href={signInHref} className={t.link}>Go to sign in</a></p>}
    </div>
  );
}
