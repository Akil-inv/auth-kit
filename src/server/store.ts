import { randomUUID } from 'crypto';
import { Db, LinkPurpose } from './types';

/** auth-kit's own tables (sql/001_auth_kit.sql). */

export type State = {
  userId: string;
  emailVerifiedAt: Date | null;
  tokenVersion: number;
  totpSecret: string | null;
  totpEnabledAt: Date | null;
  totpLastStep: number | null;
  recoveryCodes: string[];
  passwordChangedAt: Date | null;
  lastLoginAt: Date | null;
};

export type LinkRow = {
  tokenHash: string; userId: string; purpose: LinkPurpose; newEmail: string | null;
  createdBy: string | null; createdAt: Date; expiresAt: Date; usedAt: Date | null;
};

export type RequestRow = {
  id: string; userId: string; kind: 'password_reset' | 'email_change'; newEmail: string | null;
  createdAt: Date; handledAt: Date | null; handledBy: string | null; outcome: string | null;
};

const date = (v: unknown) => (v == null ? null : new Date(v as string));

function toState(r: any): State {
  return {
    userId: r.user_id,
    emailVerifiedAt: date(r.email_verified_at),
    tokenVersion: Number(r.token_version),
    totpSecret: r.totp_secret ?? null,
    totpEnabledAt: date(r.totp_enabled_at),
    totpLastStep: r.totp_last_step == null ? null : Number(r.totp_last_step),
    recoveryCodes: r.recovery_codes ?? [],
    passwordChangedAt: date(r.password_changed_at),
    lastLoginAt: date(r.last_login_at),
  };
}

/** A user with no row existed before auth-kit: verified, no two-factor. */
export const LEGACY_STATE = (userId: string): State => ({
  userId, emailVerifiedAt: new Date(0), tokenVersion: 0, totpSecret: null, totpEnabledAt: null,
  totpLastStep: null, recoveryCodes: [], passwordChangedAt: null, lastLoginAt: null,
});

const STATE_COLUMNS: Record<keyof Omit<State, 'userId'>, string> = {
  emailVerifiedAt: 'email_verified_at',
  tokenVersion: 'token_version',
  totpSecret: 'totp_secret',
  totpEnabledAt: 'totp_enabled_at',
  totpLastStep: 'totp_last_step',
  recoveryCodes: 'recovery_codes',
  passwordChangedAt: 'password_changed_at',
  lastLoginAt: 'last_login_at',
};

export class Store {
  constructor(private db: Db) {}

  async state(userId: string): Promise<State> {
    const rows = await this.db.query(`SELECT * FROM "auth_state" WHERE "user_id" = $1`, [userId]);
    return rows.length ? toState(rows[0]) : LEGACY_STATE(userId);
  }

  async states(userIds: string[]): Promise<Map<string, State>> {
    const out = new Map<string, State>();
    if (!userIds.length) return out;
    const rows = await this.db.query(`SELECT * FROM "auth_state" WHERE "user_id" = ANY($1::text[])`, [userIds]);
    for (const r of rows) out.set((r as any).user_id, toState(r));
    for (const id of userIds) if (!out.has(id)) out.set(id, LEGACY_STATE(id));
    return out;
  }

  /** Change some fields, creating the row (as a legacy user) if needed. */
  async update(userId: string, patch: Partial<Omit<State, 'userId' | 'tokenVersion'>> & { bumpTokenVersion?: boolean }, fresh = false) {
    const sets: string[] = [];
    const values: unknown[] = [userId];
    for (const [k, v] of Object.entries(patch)) {
      if (k === 'bumpTokenVersion') continue;
      const col = STATE_COLUMNS[k as keyof typeof STATE_COLUMNS];
      if (!col) continue;
      values.push(v);
      sets.push(`"${col}" = $${values.length}`);
    }
    if (patch.bumpTokenVersion) sets.push(`"token_version" = "token_version" + 1`);
    sets.push(`"updated_at" = now()`);
    // A missing row is a user from before auth-kit (verified), unless this is a new account.
    await this.db.query(
      `INSERT INTO "auth_state" ("user_id", "email_verified_at") VALUES ($1, ${fresh ? 'NULL' : `'epoch'::timestamptz`})
       ON CONFLICT ("user_id") DO NOTHING`,
      [userId],
    );
    await this.db.query(`UPDATE "auth_state" SET ${sets.join(', ')} WHERE "user_id" = $1`, values);
  }

  async deleteUser(userId: string) {
    await this.db.query(`DELETE FROM "auth_links" WHERE "user_id" = $1`, [userId]);
    await this.db.query(`DELETE FROM "auth_requests" WHERE "user_id" = $1`, [userId]);
    await this.db.query(`DELETE FROM "auth_state" WHERE "user_id" = $1`, [userId]);
  }

  // ─── Links ───

  async addLink(l: Omit<LinkRow, 'createdAt' | 'usedAt'>) {
    // A new link of the same kind replaces any unused one.
    await this.db.query(
      `UPDATE "auth_links" SET "used_at" = now() WHERE "user_id" = $1 AND "purpose" = $2 AND "used_at" IS NULL`,
      [l.userId, l.purpose],
    );
    await this.db.query(
      `INSERT INTO "auth_links" ("token_hash", "user_id", "purpose", "new_email", "created_by", "expires_at") VALUES ($1, $2, $3, $4, $5, $6)`,
      [l.tokenHash, l.userId, l.purpose, l.newEmail, l.createdBy, l.expiresAt],
    );
  }

  async link(tokenHash: string): Promise<LinkRow | null> {
    const rows = await this.db.query<any>(`SELECT * FROM "auth_links" WHERE "token_hash" = $1`, [tokenHash]);
    if (!rows.length) return null;
    const r = rows[0];
    return {
      tokenHash: r.token_hash, userId: r.user_id, purpose: r.purpose, newEmail: r.new_email, createdBy: r.created_by,
      createdAt: new Date(r.created_at), expiresAt: new Date(r.expires_at), usedAt: date(r.used_at),
    };
  }

  /** Mark a link used; false if it was already used (two clicks at once). */
  async useLink(tokenHash: string): Promise<boolean> {
    const rows = await this.db.query(
      `UPDATE "auth_links" SET "used_at" = now() WHERE "token_hash" = $1 AND "used_at" IS NULL RETURNING "token_hash"`,
      [tokenHash],
    );
    return rows.length === 1;
  }

  async cancelLinks(userId: string, purposes?: LinkPurpose[]) {
    await this.db.query(
      `UPDATE "auth_links" SET "used_at" = now() WHERE "user_id" = $1 AND "used_at" IS NULL${purposes ? ` AND "purpose" = ANY($2::text[])` : ''}`,
      purposes ? [userId, purposes] : [userId],
    );
  }

  // ─── Requests ───

  async addRequest(userId: string, kind: RequestRow['kind'], newEmail: string | null): Promise<string> {
    // One open request of each kind per person: a repeat replaces it.
    await this.db.query(
      `UPDATE "auth_requests" SET "handled_at" = now(), "outcome" = 'superseded' WHERE "user_id" = $1 AND "kind" = $2 AND "handled_at" IS NULL`,
      [userId, kind],
    );
    const id = randomUUID();
    await this.db.query(
      `INSERT INTO "auth_requests" ("id", "user_id", "kind", "new_email") VALUES ($1, $2, $3, $4)`,
      [id, userId, kind, newEmail],
    );
    return id;
  }

  async openRequests(): Promise<RequestRow[]> {
    const rows = await this.db.query<any>(`SELECT * FROM "auth_requests" WHERE "handled_at" IS NULL ORDER BY "created_at"`);
    return rows.map((r) => ({
      id: r.id, userId: r.user_id, kind: r.kind, newEmail: r.new_email, createdAt: new Date(r.created_at),
      handledAt: null, handledBy: null, outcome: null,
    }));
  }

  async request(id: string): Promise<RequestRow | null> {
    const rows = await this.db.query<any>(`SELECT * FROM "auth_requests" WHERE "id" = $1`, [id]);
    if (!rows.length) return null;
    const r = rows[0];
    return {
      id: r.id, userId: r.user_id, kind: r.kind, newEmail: r.new_email, createdAt: new Date(r.created_at),
      handledAt: date(r.handled_at), handledBy: r.handled_by, outcome: r.outcome,
    };
  }

  async closeRequests(userId: string, kind: RequestRow['kind'], by: string | null, outcome: string) {
    await this.db.query(
      `UPDATE "auth_requests" SET "handled_at" = now(), "handled_by" = $3, "outcome" = $4 WHERE "user_id" = $1 AND "kind" = $2 AND "handled_at" IS NULL`,
      [userId, kind, by, outcome],
    );
  }

  async closeRequest(id: string, by: string, outcome: string) {
    await this.db.query(
      `UPDATE "auth_requests" SET "handled_at" = now(), "handled_by" = $2, "outcome" = $3 WHERE "id" = $1 AND "handled_at" IS NULL`,
      [id, by, outcome],
    );
  }

  async pendingEmailChange(userId: string): Promise<string | null> {
    const rows = await this.db.query<any>(
      `SELECT "new_email" FROM "auth_requests" WHERE "user_id" = $1 AND "kind" = 'email_change' AND "handled_at" IS NULL
       UNION ALL
       SELECT "new_email" FROM "auth_links" WHERE "user_id" = $1 AND "purpose" = 'change_email' AND "used_at" IS NULL AND "expires_at" > now()
       LIMIT 1`,
      [userId],
    );
    return rows[0]?.new_email ?? null;
  }
}
