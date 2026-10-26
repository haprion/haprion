"""The schema, as one migration (B360, B369, 26-10-26).

Ninety-one migrations, 0001 to 0091, built this schema one change at a time,
each with a downgrade. Haprion 0.99 is installed afresh rather than upgraded
from them, and a schema is never downgraded (B360), so this one replaces them:
the same tables, functions, triggers, grants and first rows, taken from what
the ninety-one made and compared with it in a disposable cluster. They are in
Git's history before this file, each with the reasoning behind its change.

What differs from what they made, on purpose:

- `job_operation_allowed` holds for every row. 0087 added it `not valid`, for
  the jobs of three operations it retired; a new database has none.
- The web holds no grant on `traffic_log` itself. 0083 left its column grants
  for the interface from before `traffic_log_read`, which is what the web reads.

Three checks are also written with one pair of parentheses fewer, which is how
PostgreSQL prints what it was given; it reads them alike.

The rules the schema keeps are the grants, listed column by column beside each
table, and what a role may not choose is a default or a trigger. The roles are
the four contract roles - `app_web`, `app_worker`, `app_poller`,
`app_collector` - which the installation connects its service accounts to
(platform step 2). The migration role owns everything, and only root can be it.
Each area below says what its roles may do and why.

A database from before this revision is not upgraded: `check-compatibility`
refuses it, and Haprion is installed afresh (install.md, *Removing*). A change
from here on is a new migration after this one, and has no downgrade.
"""

from __future__ import annotations

from alembic import op

revision = "0100"
down_revision = None
branch_labels = None
depends_on = None

ROLLBACK_SAFE = False
ROLLBACK_SAFE_BECAUSE = "the baseline: no release before it runs on this schema"

#
# alembic makes `alembic_version` itself. The web reads the revision, and
# nothing else of it, so that /healthz can say whether this release runs on
# the schema (B332).
#
REVISION = r"""
GRANT SELECT(version_num) ON TABLE public.alembic_version TO app_web;
"""


#
# Accounts, sessions, sign-in and the audit trail.
#
# The web authenticates people, so it reads accounts, and writes the columns
# an admin's page changes - listed one by one. `created_at` and `updated_at`
# are a default and a trigger, so an edit cannot be backdated. The last active
# admin cannot be demoted, disabled or deleted, nor - while sign-in through the
# provider is on - the last break-glass admin: `app_user_keep_an_admin` refuses
# the change under a transaction lock, so two admins disabling each other at
# the same moment cannot both pass. A local account always has an Argon2id
# hash and an account through the provider never has one; that account is
# bound to the provider's issuer and subject, and its name is for display.
#
# `login_attempt` and `audit_event` are append-only by grant: the web adds and
# reads and can change or delete nothing, so a lockout outlives the process it
# locks out, and the record outlives an intrusion into the web. An unlock is a
# row in `login_unlock`, not failures deleted. The worker writes the audit rows
# of what it ran. Old rows are removed by `haprion-retention`, as the
# migration role.
#
# `oidc_provider` is one row. The web writes its settings and the sealed client
# secret, which it cannot open; a trigger raises `revision` on every change, so
# a Verify recorded against one revision says nothing about the next. A
# sign-in in progress is a row of `oidc_login`, used once.
#
ACCOUNTS = r"""
CREATE FUNCTION public.app_user_keep_an_admin() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    begin
        perform pg_advisory_xact_lock(hashtext('app_user_keep_an_admin'));
        if not exists (select 1 from app_user where role = 'admin' and not disabled) then
            raise exception 'the last active admin cannot be demoted, disabled or deleted'
                using errcode = 'check_violation';
        end if;
        if exists (select 1 from oidc_provider where enabled)
           and not exists (select 1 from app_user
                            where role = 'admin' and not disabled and break_glass) then
            raise exception 'sign-in through the provider is on and needs an active break-glass admin'
                using errcode = 'check_violation';
        end if;
        return null;
    end;
    $$;

CREATE FUNCTION public.app_user_touch() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    begin
        new.updated_at := statement_timestamp();
        return new;
    end;
    $$;

CREATE FUNCTION public.oidc_provider_touch() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
begin
    new.updated_at := statement_timestamp();
    if (new.issuer, new.client_id, new.client_secret_sealed, new.key_id, new.auth_method,
        new.scopes, new.username_claim, new.groups_claim, new.admin_group, new.reader_group,
        new.button_text, new.prompt_login, new.logout_mode, new.local_login,
        new.ca_pem)
       is distinct from
       (old.issuer, old.client_id, old.client_secret_sealed, old.key_id, old.auth_method,
        old.scopes, old.username_claim, old.groups_claim, old.admin_group, old.reader_group,
        old.button_text, old.prompt_login, old.logout_mode, old.local_login,
        old.ca_pem) then
        new.revision := old.revision + 1;
    end if;
    return new;
end;
$$;

CREATE TABLE public.app_user (
    id bigint NOT NULL,
    username text NOT NULL,
    username_normalised text GENERATED ALWAYS AS (lower(username)) STORED,
    password_hash text,
    role text NOT NULL,
    disabled boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    updated_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    source text DEFAULT 'local'::text NOT NULL,
    break_glass boolean DEFAULT false NOT NULL,
    oidc_issuer text,
    oidc_subject text,
    CONSTRAINT app_user_break_glass_local CHECK (((NOT break_glass) OR (source = 'local'::text))),
    CONSTRAINT app_user_hash_by_source CHECK ((((source = 'local'::text) AND (password_hash IS NOT NULL) AND (password_hash ~~ '$argon2id$%'::text)) OR ((source = 'oidc'::text) AND (password_hash IS NULL)))),
    CONSTRAINT app_user_oidc_identity CHECK ((((oidc_issuer IS NULL) = (oidc_subject IS NULL)) AND ((source = 'oidc'::text) OR (oidc_issuer IS NULL)))),
    CONSTRAINT app_user_oidc_issuer_shape CHECK (((oidc_issuer IS NULL) OR ((length(oidc_issuer) >= 8) AND (length(oidc_issuer) <= 512)))),
    CONSTRAINT app_user_oidc_subject_shape CHECK (((oidc_subject IS NULL) OR ((length(oidc_subject) >= 1) AND (length(oidc_subject) <= 255)))),
    CONSTRAINT app_user_role_allowed CHECK ((role = ANY (ARRAY['admin'::text, 'reader'::text]))),
    CONSTRAINT app_user_source_allowed CHECK ((source = ANY (ARRAY['local'::text, 'oidc'::text]))),
    CONSTRAINT app_user_username_shape CHECK (((length(username) >= 1) AND (length(username) <= 64)))
);
ALTER TABLE public.app_user ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.app_user_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);
ALTER TABLE ONLY public.app_user
    ADD CONSTRAINT app_user_oidc_identity_unique UNIQUE (oidc_issuer, oidc_subject);
ALTER TABLE ONLY public.app_user
    ADD CONSTRAINT app_user_pkey PRIMARY KEY (id);
CREATE UNIQUE INDEX app_user_username_key ON public.app_user USING btree (username_normalised);
CREATE TRIGGER app_user_keep_an_admin AFTER UPDATE OF role, disabled, break_glass ON public.app_user FOR EACH ROW WHEN (((old.role = 'admin'::text) AND (NOT old.disabled) AND ((new.role <> 'admin'::text) OR new.disabled OR (old.break_glass AND (NOT new.break_glass))))) EXECUTE FUNCTION public.app_user_keep_an_admin();
CREATE TRIGGER app_user_keep_an_admin_on_delete AFTER DELETE ON public.app_user FOR EACH ROW WHEN (((old.role = 'admin'::text) AND (NOT old.disabled))) EXECUTE FUNCTION public.app_user_keep_an_admin();
CREATE TRIGGER app_user_touch BEFORE UPDATE ON public.app_user FOR EACH ROW EXECUTE FUNCTION public.app_user_touch();
GRANT DELETE ON TABLE public.app_user TO app_web;
GRANT SELECT(id) ON TABLE public.app_user TO app_web;
GRANT SELECT(username),INSERT(username) ON TABLE public.app_user TO app_web;
GRANT SELECT(username_normalised) ON TABLE public.app_user TO app_web;
GRANT SELECT(password_hash),INSERT(password_hash),UPDATE(password_hash) ON TABLE public.app_user TO app_web;
GRANT SELECT(role),INSERT(role),UPDATE(role) ON TABLE public.app_user TO app_web;
GRANT SELECT(disabled),UPDATE(disabled) ON TABLE public.app_user TO app_web;
GRANT SELECT(created_at) ON TABLE public.app_user TO app_web;
GRANT SELECT(updated_at) ON TABLE public.app_user TO app_web;
GRANT SELECT(source),INSERT(source) ON TABLE public.app_user TO app_web;
GRANT SELECT(break_glass),INSERT(break_glass),UPDATE(break_glass) ON TABLE public.app_user TO app_web;
GRANT SELECT(oidc_issuer),INSERT(oidc_issuer) ON TABLE public.app_user TO app_web;
GRANT SELECT(oidc_subject),INSERT(oidc_subject) ON TABLE public.app_user TO app_web;

CREATE TABLE public.app_session (
    token_hash bytea NOT NULL,
    user_id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    id_token text,
    CONSTRAINT app_session_expiry CHECK ((expires_at > created_at)),
    CONSTRAINT app_session_hash_sha256 CHECK ((octet_length(token_hash) = 32)),
    CONSTRAINT app_session_id_token_shape CHECK (((id_token IS NULL) OR ((length(id_token) >= 1) AND (length(id_token) <= 16384))))
);
ALTER TABLE ONLY public.app_session
    ADD CONSTRAINT app_session_pkey PRIMARY KEY (token_hash);
CREATE INDEX app_session_expiry_idx ON public.app_session USING btree (expires_at);
CREATE INDEX app_session_user_idx ON public.app_session USING btree (user_id);
GRANT SELECT(token_hash),INSERT(token_hash) ON TABLE public.app_session TO app_web;
GRANT SELECT(user_id),INSERT(user_id) ON TABLE public.app_session TO app_web;
GRANT SELECT(created_at) ON TABLE public.app_session TO app_web;
GRANT SELECT(last_seen_at),UPDATE(last_seen_at) ON TABLE public.app_session TO app_web;
GRANT SELECT(expires_at),INSERT(expires_at) ON TABLE public.app_session TO app_web;
GRANT SELECT(revoked_at),UPDATE(revoked_at) ON TABLE public.app_session TO app_web;
GRANT SELECT(id_token),INSERT(id_token) ON TABLE public.app_session TO app_web;
ALTER TABLE ONLY public.app_session
    ADD CONSTRAINT app_session_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.app_user(id) ON DELETE CASCADE;

CREATE TABLE public.login_attempt (
    id bigint NOT NULL,
    at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    username_normalised text NOT NULL,
    client_ip inet NOT NULL,
    succeeded boolean NOT NULL,
    CONSTRAINT login_attempt_username_shape CHECK (((length(username_normalised) >= 1) AND (length(username_normalised) <= 64)))
);
ALTER TABLE public.login_attempt ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.login_attempt_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);
ALTER TABLE ONLY public.login_attempt
    ADD CONSTRAINT login_attempt_pkey PRIMARY KEY (id);
CREATE INDEX login_attempt_at_idx ON public.login_attempt USING btree (at DESC);
CREATE INDEX login_attempt_pair_idx ON public.login_attempt USING btree (username_normalised, client_ip, at DESC);
GRANT SELECT(id) ON TABLE public.login_attempt TO app_web;
GRANT SELECT(at) ON TABLE public.login_attempt TO app_web;
GRANT SELECT(username_normalised),INSERT(username_normalised) ON TABLE public.login_attempt TO app_web;
GRANT SELECT(client_ip),INSERT(client_ip) ON TABLE public.login_attempt TO app_web;
GRANT SELECT(succeeded),INSERT(succeeded) ON TABLE public.login_attempt TO app_web;

CREATE TABLE public.login_unlock (
    id bigint NOT NULL,
    at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    username_normalised text NOT NULL,
    actor text NOT NULL,
    CONSTRAINT login_unlock_actor_shape CHECK (((length(actor) >= 1) AND (length(actor) <= 64))),
    CONSTRAINT login_unlock_username_shape CHECK (((length(username_normalised) >= 1) AND (length(username_normalised) <= 64)))
);
ALTER TABLE public.login_unlock ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.login_unlock_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);
ALTER TABLE ONLY public.login_unlock
    ADD CONSTRAINT login_unlock_pkey PRIMARY KEY (id);
CREATE INDEX login_unlock_name_idx ON public.login_unlock USING btree (username_normalised, at DESC);
GRANT SELECT(id) ON TABLE public.login_unlock TO app_web;
GRANT SELECT(at) ON TABLE public.login_unlock TO app_web;
GRANT SELECT(username_normalised),INSERT(username_normalised) ON TABLE public.login_unlock TO app_web;
GRANT SELECT(actor),INSERT(actor) ON TABLE public.login_unlock TO app_web;

CREATE TABLE public.oidc_provider (
    singleton boolean DEFAULT true NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    issuer text,
    client_id text,
    client_secret_sealed bytea,
    key_id text,
    auth_method text DEFAULT 'client_secret_basic'::text NOT NULL,
    scopes text DEFAULT 'openid profile email'::text NOT NULL,
    username_claim text DEFAULT 'preferred_username'::text NOT NULL,
    groups_claim text DEFAULT 'groups'::text NOT NULL,
    admin_group text,
    reader_group text,
    button_text text DEFAULT 'Sign in with SSO'::text NOT NULL,
    prompt_login boolean DEFAULT false NOT NULL,
    logout_mode text DEFAULT 'app'::text NOT NULL,
    local_login text DEFAULT 'break_glass_only'::text NOT NULL,
    ca_pem text,
    revision integer DEFAULT 0 NOT NULL,
    verified_revision integer,
    updated_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    updated_by text,
    CONSTRAINT oidc_provider_auth_method CHECK ((auth_method = ANY (ARRAY['client_secret_basic'::text, 'client_secret_post'::text]))),
    CONSTRAINT oidc_provider_button_shape CHECK (((length(button_text) >= 1) AND (length(button_text) <= 64))),
    CONSTRAINT oidc_provider_ca_shape CHECK (((ca_pem IS NULL) OR ((length(ca_pem) >= 1) AND (length(ca_pem) <= 65536)))),
    CONSTRAINT oidc_provider_claim_shape CHECK ((((length(username_claim) >= 1) AND (length(username_claim) <= 128)) AND ((length(groups_claim) >= 1) AND (length(groups_claim) <= 128)))),
    CONSTRAINT oidc_provider_client_id_shape CHECK (((client_id IS NULL) OR ((length(client_id) >= 1) AND (length(client_id) <= 256)))),
    CONSTRAINT oidc_provider_enabled_complete CHECK (((NOT enabled) OR ((issuer IS NOT NULL) AND (client_id IS NOT NULL) AND (client_secret_sealed IS NOT NULL) AND ((admin_group IS NOT NULL) OR (reader_group IS NOT NULL)) AND (verified_revision IS NOT NULL) AND (verified_revision = revision)))),
    CONSTRAINT oidc_provider_group_shape CHECK ((((admin_group IS NULL) OR ((length(admin_group) >= 1) AND (length(admin_group) <= 256))) AND ((reader_group IS NULL) OR ((length(reader_group) >= 1) AND (length(reader_group) <= 256))))),
    CONSTRAINT oidc_provider_issuer_shape CHECK (((issuer IS NULL) OR ((issuer ~~ 'https://%'::text) AND (length(issuer) <= 512)))),
    CONSTRAINT oidc_provider_key_id_shape CHECK (((key_id IS NULL) OR ((length(key_id) >= 1) AND (length(key_id) <= 128)))),
    CONSTRAINT oidc_provider_local_login CHECK ((local_login = ANY (ARRAY['all'::text, 'break_glass_only'::text]))),
    CONSTRAINT oidc_provider_logout_mode CHECK ((logout_mode = ANY (ARRAY['app'::text, 'provider'::text]))),
    CONSTRAINT oidc_provider_scopes_shape CHECK ((((length(scopes) >= 6) AND (length(scopes) <= 512)) AND (scopes ~ '(^| )openid( |$)'::text))),
    CONSTRAINT oidc_provider_secret_keyed CHECK (((client_secret_sealed IS NULL) = (key_id IS NULL))),
    CONSTRAINT oidc_provider_secret_shape CHECK (((client_secret_sealed IS NULL) OR (octet_length(client_secret_sealed) <= 4096))),
    CONSTRAINT oidc_provider_singleton CHECK (singleton),
    CONSTRAINT oidc_provider_updated_by_shape CHECK (((updated_by IS NULL) OR ((length(updated_by) >= 1) AND (length(updated_by) <= 64))))
);
ALTER TABLE ONLY public.oidc_provider
    ADD CONSTRAINT oidc_provider_pkey PRIMARY KEY (singleton);
CREATE TRIGGER oidc_provider_needs_break_glass AFTER UPDATE OF enabled ON public.oidc_provider FOR EACH ROW WHEN ((new.enabled AND (NOT old.enabled))) EXECUTE FUNCTION public.app_user_keep_an_admin();
CREATE TRIGGER oidc_provider_touch BEFORE UPDATE ON public.oidc_provider FOR EACH ROW EXECUTE FUNCTION public.oidc_provider_touch();
GRANT SELECT(enabled),UPDATE(enabled) ON TABLE public.oidc_provider TO app_web;
GRANT SELECT(issuer),UPDATE(issuer) ON TABLE public.oidc_provider TO app_web;
GRANT SELECT(client_id),UPDATE(client_id) ON TABLE public.oidc_provider TO app_web;
GRANT SELECT(client_secret_sealed),UPDATE(client_secret_sealed) ON TABLE public.oidc_provider TO app_web;
GRANT SELECT(key_id),UPDATE(key_id) ON TABLE public.oidc_provider TO app_web;
GRANT SELECT(auth_method),UPDATE(auth_method) ON TABLE public.oidc_provider TO app_web;
GRANT SELECT(scopes),UPDATE(scopes) ON TABLE public.oidc_provider TO app_web;
GRANT SELECT(username_claim),UPDATE(username_claim) ON TABLE public.oidc_provider TO app_web;
GRANT SELECT(groups_claim),UPDATE(groups_claim) ON TABLE public.oidc_provider TO app_web;
GRANT SELECT(admin_group),UPDATE(admin_group) ON TABLE public.oidc_provider TO app_web;
GRANT SELECT(reader_group),UPDATE(reader_group) ON TABLE public.oidc_provider TO app_web;
GRANT SELECT(button_text),UPDATE(button_text) ON TABLE public.oidc_provider TO app_web;
GRANT SELECT(prompt_login),UPDATE(prompt_login) ON TABLE public.oidc_provider TO app_web;
GRANT SELECT(logout_mode),UPDATE(logout_mode) ON TABLE public.oidc_provider TO app_web;
GRANT SELECT(local_login),UPDATE(local_login) ON TABLE public.oidc_provider TO app_web;
GRANT SELECT(ca_pem),UPDATE(ca_pem) ON TABLE public.oidc_provider TO app_web;
GRANT SELECT(revision) ON TABLE public.oidc_provider TO app_web;
GRANT SELECT(verified_revision),UPDATE(verified_revision) ON TABLE public.oidc_provider TO app_web;
GRANT SELECT(updated_at) ON TABLE public.oidc_provider TO app_web;
GRANT SELECT(updated_by),UPDATE(updated_by) ON TABLE public.oidc_provider TO app_web;
INSERT INTO public.oidc_provider DEFAULT VALUES;

CREATE TABLE public.oidc_login (
    state text NOT NULL,
    nonce text NOT NULL,
    verifier text NOT NULL,
    mode text NOT NULL,
    pre_session_hash bytea NOT NULL,
    created_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    used_at timestamp with time zone,
    CONSTRAINT oidc_login_mode CHECK ((mode = ANY (ARRAY['sign_in'::text, 'test'::text]))),
    CONSTRAINT oidc_login_nonce_shape CHECK (((length(nonce) >= 32) AND (length(nonce) <= 128))),
    CONSTRAINT oidc_login_pre_session_shape CHECK ((octet_length(pre_session_hash) = 32)),
    CONSTRAINT oidc_login_state_shape CHECK (((length(state) >= 32) AND (length(state) <= 128))),
    CONSTRAINT oidc_login_verifier_shape CHECK (((length(verifier) >= 43) AND (length(verifier) <= 128)))
);
ALTER TABLE ONLY public.oidc_login
    ADD CONSTRAINT oidc_login_pkey PRIMARY KEY (state);
CREATE INDEX oidc_login_created_idx ON public.oidc_login USING btree (created_at);
GRANT SELECT(state),INSERT(state) ON TABLE public.oidc_login TO app_web;
GRANT SELECT(nonce),INSERT(nonce) ON TABLE public.oidc_login TO app_web;
GRANT SELECT(verifier),INSERT(verifier) ON TABLE public.oidc_login TO app_web;
GRANT SELECT(mode),INSERT(mode) ON TABLE public.oidc_login TO app_web;
GRANT SELECT(pre_session_hash),INSERT(pre_session_hash) ON TABLE public.oidc_login TO app_web;
GRANT SELECT(created_at) ON TABLE public.oidc_login TO app_web;
GRANT SELECT(used_at),UPDATE(used_at) ON TABLE public.oidc_login TO app_web;

CREATE TABLE public.audit_event (
    id bigint NOT NULL,
    at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    actor text,
    action text NOT NULL,
    cluster text,
    request_id uuid,
    detail jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT audit_event_action_shape CHECK (((length(action) >= 1) AND (length(action) <= 64))),
    CONSTRAINT audit_event_cluster_shape CHECK (((cluster IS NULL) OR (cluster ~ '^[a-z][a-z0-9-]{0,62}$'::text)))
);
ALTER TABLE public.audit_event ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.audit_event_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);
ALTER TABLE ONLY public.audit_event
    ADD CONSTRAINT audit_event_pkey PRIMARY KEY (id);
CREATE INDEX audit_event_at_idx ON public.audit_event USING btree (at DESC);
CREATE INDEX audit_event_certificate_takeout_idx ON public.audit_event USING btree (((detail ->> 'certificate'::text)), id DESC) WHERE (action = ANY (ARRAY['certificate_export'::text, 'certificate_download'::text]));
CREATE INDEX audit_event_cluster_idx ON public.audit_event USING btree (cluster, at DESC);
CREATE INDEX audit_event_request_idx ON public.audit_event USING btree (request_id);
GRANT SELECT(id) ON TABLE public.audit_event TO app_web;
GRANT SELECT(at) ON TABLE public.audit_event TO app_web;
GRANT SELECT(actor),INSERT(actor) ON TABLE public.audit_event TO app_web;
GRANT INSERT(actor) ON TABLE public.audit_event TO app_worker;
GRANT SELECT(action),INSERT(action) ON TABLE public.audit_event TO app_web;
GRANT INSERT(action) ON TABLE public.audit_event TO app_worker;
GRANT SELECT(cluster),INSERT(cluster) ON TABLE public.audit_event TO app_web;
GRANT INSERT(cluster) ON TABLE public.audit_event TO app_worker;
GRANT SELECT(request_id),INSERT(request_id) ON TABLE public.audit_event TO app_web;
GRANT INSERT(request_id) ON TABLE public.audit_event TO app_worker;
GRANT SELECT(detail),INSERT(detail) ON TABLE public.audit_event TO app_web;
GRANT INSERT(detail) ON TABLE public.audit_event TO app_worker;
"""


#
# The job queue: what the web may ask for, and what only the worker may say.
#
# The web inserts four columns of a job: the operation, its cluster, its
# payload and an idempotency key, which is how a resubmitted form is
# recognised. The state, the request ID and the timestamps are defaults, and
# `payload_hash` is the database's own reading of the payload
# (`job_payload_hash`), so a compromised web process cannot choose them or
# claim another request's ID. The worker claims and finishes jobs and inserts
# none. `job_operation_allowed` is the list of
# what may be queued at all: a job row is what the worker runs as root.
#
# `job_claim_gate` pauses the worker's claims while a release restarts it; a
# moment rather than a flag, so a release killed before clearing it does not
# stop the queue for good. `hold_jobs_queued_before` holds the jobs queued
# before the machine's last boot, which a restored manager would otherwise run
# again, until an admin answers (`held_decision`, the web's alone).
# `job_attention_evidence` names the jobs Needs attention reads - the newest
# finished one per cluster, step and subject - which the pruning keeps; its
# twin in Python is `jobs.keyed_states`, and the database suite holds the two
# to one answer.
#
# What an admin has acknowledged in Needs attention is `attention_ack`, the
# web's. What the nodes did on their own is `node_event`, written by the
# poller by comparing each status reading with `node_event_state`.
#
JOBS = r"""
CREATE FUNCTION public.job_payload_hash() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    begin
        new.payload_hash := sha256(convert_to(new.payload::text, 'UTF8'));
        return new;
    end;
    $$;

CREATE FUNCTION public.hold_jobs_queued_before(boot timestamp with time zone) RETURNS SETOF bigint
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
        update job
           set held_since = statement_timestamp(), held_decision = null, held_decided_by = null
         where state in ('pending', 'running')
           and (boot is null or created_at < boot)
           and (held_since is null or boot is null or held_since < boot)
        returning id
    $$;

REVOKE ALL ON FUNCTION public.hold_jobs_queued_before(boot timestamp with time zone) FROM PUBLIC;
GRANT ALL ON FUNCTION public.hold_jobs_queued_before(boot timestamp with time zone) TO app_worker;

CREATE FUNCTION public.job_attention_evidence() RETURNS SETOF bigint
    LANGUAGE sql STABLE
    AS $$
        with ran as (
            select id, cluster, operation, state, created_at,
                   --
                   -- `ending_step`: the deploy a Publish & deploy or a node
                   -- change ran after its own step, when its answer is there.
                   --
                   case
                       when operation in ('changes_publish', 'cluster_node')
                        and payload->'deploy' = 'true'::jsonb
                        and jsonb_typeof(
                                result->(case operation
                                             when 'changes_publish' then 'publish'
                                             else 'node' end)) = 'object'
                       then case
                                when jsonb_typeof(result->'step') = 'string'
                                 and result->>'step' in ('deploy', 'cert_deploy')
                                then result->>'step'
                                when jsonb_typeof(result->'operation') = 'string'
                                 and result->>'operation' = 'cert_deploy'
                                then 'cert_deploy'
                                else 'deploy'
                            end
                       else operation
                   end as ending,
                   --
                   -- `SUBJECT_FIELDS`: what the operation acted on inside its
                   -- cluster; any other operation is about the cluster itself.
                   --
                   case operation
                       when 'cert_issue' then payload->'domain'
                       when 'cert_scep' then payload->'id'
                       when 'cert_import' then payload->'id'
                       when 'cert_request' then payload->'id'
                       when 'cert_receiver' then payload->'receiver'
                       when 'cert_publish' then payload->'certificates'
                       when 'cert_target' then payload->'certificates'
                       when 'cert_delete' then payload->'certificates'
                       when 'server_state' then payload->'object'
                       when 'dynamic_unblock' then payload->'object'
                       when 'dns_profile_apply' then payload->'profile'
                       when 'ndes_profile_apply' then payload->'profile'
                   end as named
              from job
             where state not in ('pending', 'running')
               --
               -- `coalesce`: a refusal with no error in its result is a run,
               -- and `not` over the null the test gives it would drop it.
               --
               and not coalesce(state = 'blocked'
                                and jsonb_typeof(result->'error'->'code') = 'string'
                                and result->'error'->>'code' = 'held_discarded', false)
        ),
        --
        -- A list of strings, or null for anything else. Taken apart first:
        -- SQL does not promise to test `jsonb_typeof` before an array
        -- function is called on a scalar.
        --
        listed as (
            select ran.*,
                   case when jsonb_typeof(named) = 'array' then named end as list
              from ran
        ),
        lists as (
            select listed.*,
                   coalesce(jsonb_array_length(list) > 0
                            and not exists (select 1 from jsonb_array_elements(list) as element
                                             where jsonb_typeof(element) <> 'string'),
                            false) as of_strings
              from listed
        ),
        --
        -- `subjects`: a string is one subject, a list of strings one per
        -- certificate in it, anything else the cluster itself ('').
        --
        subjects as (
            select id, cluster, operation, ending, created_at, named #>> '{}' as subject
              from lists
             where jsonb_typeof(named) = 'string'
            union all
            select lists.id, lists.cluster, lists.operation, lists.ending, lists.created_at, item
              from lists, jsonb_array_elements_text(lists.list) as item
             where lists.of_strings
            union all
            select id, cluster, operation, ending, created_at, ''
              from lists
             where jsonb_typeof(named) is distinct from 'string' and not of_strings
        ),
        steps as (
            select id, cluster, operation as step, subject, created_at from subjects
            union all
            select id, cluster, ending, subject, created_at from subjects
             where ending <> operation
        )
        select distinct on (cluster, step, subject) id
          from steps
         order by cluster, step, subject, created_at desc, id desc
    $$;

REVOKE ALL ON FUNCTION public.job_attention_evidence() FROM PUBLIC;
GRANT ALL ON FUNCTION public.job_attention_evidence() TO app_web;

CREATE TABLE public.job (
    id bigint NOT NULL,
    request_id uuid DEFAULT gen_random_uuid() NOT NULL,
    operation text NOT NULL,
    cluster text,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL,
    state text DEFAULT 'pending'::text NOT NULL,
    claim_token uuid,
    worker_id text,
    lease_until timestamp with time zone,
    created_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    exit_code smallint,
    outcome text,
    result jsonb,
    stderr_excerpt text,
    idempotency_key uuid,
    payload_hash bytea NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    held_since timestamp with time zone,
    held_decision text,
    held_decided_by text,
    CONSTRAINT job_attempts_not_negative CHECK ((attempts >= 0)),
    CONSTRAINT job_cluster_presence CHECK (((operation = ANY (ARRAY['cert_issue'::text, 'cert_publish'::text, 'cert_target'::text, 'dns_profile_apply'::text, 'cert_delete'::text, 'ndes_profile_apply'::text, 'cert_scep'::text, 'cert_receiver'::text, 'cert_import'::text, 'cert_request'::text])) = (cluster IS NULL))),
    CONSTRAINT job_cluster_shape CHECK (((cluster IS NULL) OR (cluster ~ '^[a-z][a-z0-9-]{0,62}$'::text))),
    CONSTRAINT job_finished_has_time CHECK (((state = ANY (ARRAY['pending'::text, 'running'::text])) OR (finished_at IS NOT NULL))),
    CONSTRAINT job_held_decided_by CHECK ((((held_decision IS NULL) = (held_decided_by IS NULL)) AND (char_length(held_decided_by) <= 64))),
    CONSTRAINT job_held_decision CHECK ((held_decision = ANY (ARRAY['run'::text, 'discard'::text]))),
    CONSTRAINT job_held_decision_needs_hold CHECK (((held_decision IS NULL) OR (held_since IS NOT NULL))),
    CONSTRAINT job_outcome_allowed CHECK (((outcome IS NULL) OR (outcome = ANY (ARRAY['done'::text, 'partial'::text, 'failed'::text, 'blocked'::text, 'unknown'::text])))),
    CONSTRAINT job_running_is_held CHECK (((state <> 'running'::text) OR ((claim_token IS NOT NULL) AND (lease_until IS NOT NULL) AND (worker_id IS NOT NULL) AND (started_at IS NOT NULL)))),
    CONSTRAINT job_state_allowed CHECK ((state = ANY (ARRAY['pending'::text, 'running'::text, 'done'::text, 'partial'::text, 'failed'::text, 'blocked'::text, 'unknown'::text]))),
    CONSTRAINT job_stderr_bounded CHECK (((stderr_excerpt IS NULL) OR (octet_length(stderr_excerpt) <= 65536)))
);
ALTER TABLE public.job ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.job_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);
ALTER TABLE ONLY public.job
    ADD CONSTRAINT job_pkey PRIMARY KEY (id);
ALTER TABLE public.job
    ADD CONSTRAINT job_operation_allowed CHECK ((operation = ANY (ARRAY['backup_run'::text, 'backup_schedule'::text, 'cert_delete'::text, 'cert_deploy'::text, 'cert_import'::text, 'cert_issue'::text, 'cert_publish'::text, 'cert_receiver'::text, 'cert_request'::text, 'cert_scep'::text, 'cert_target'::text, 'changes_publish'::text, 'cluster_define'::text, 'cluster_node'::text, 'deploy'::text, 'dns_profile_apply'::text, 'dynamic_unblock'::text, 'ndes_profile_apply'::text, 'node_restore'::text, 'node_restore_discard'::text, 'node_restore_prepare'::text, 'node_restore_preview'::text, 'node_restore_status'::text, 'revert'::text, 'server_state'::text])));
CREATE INDEX job_claimable_idx ON public.job USING btree (created_at, id) WHERE (state = 'pending'::text);
CREATE INDEX job_cluster_idx ON public.job USING btree (cluster, created_at DESC);
CREATE UNIQUE INDEX job_idempotency_key ON public.job USING btree (idempotency_key) WHERE (idempotency_key IS NOT NULL);
CREATE INDEX job_lease_idx ON public.job USING btree (lease_until) WHERE (state = 'running'::text);
CREATE UNIQUE INDEX job_one_active_certificate ON public.job USING btree ((true)) WHERE ((cluster IS NULL) AND (state = ANY (ARRAY['pending'::text, 'running'::text])));
CREATE UNIQUE INDEX job_one_active_per_cluster ON public.job USING btree (cluster) WHERE (state = ANY (ARRAY['pending'::text, 'running'::text]));
CREATE UNIQUE INDEX job_request_id_key ON public.job USING btree (request_id);
CREATE TRIGGER job_payload_hash BEFORE INSERT ON public.job FOR EACH ROW EXECUTE FUNCTION public.job_payload_hash();
GRANT SELECT(id) ON TABLE public.job TO app_web;
GRANT SELECT(id) ON TABLE public.job TO app_worker;
GRANT SELECT(request_id) ON TABLE public.job TO app_web;
GRANT SELECT(request_id) ON TABLE public.job TO app_worker;
GRANT SELECT(operation),INSERT(operation) ON TABLE public.job TO app_web;
GRANT SELECT(operation) ON TABLE public.job TO app_worker;
GRANT SELECT(cluster),INSERT(cluster) ON TABLE public.job TO app_web;
GRANT SELECT(cluster) ON TABLE public.job TO app_worker;
GRANT SELECT(payload),INSERT(payload) ON TABLE public.job TO app_web;
GRANT SELECT(payload) ON TABLE public.job TO app_worker;
GRANT SELECT(state) ON TABLE public.job TO app_web;
GRANT SELECT(state),UPDATE(state) ON TABLE public.job TO app_worker;
GRANT SELECT(claim_token),UPDATE(claim_token) ON TABLE public.job TO app_worker;
GRANT SELECT(worker_id),UPDATE(worker_id) ON TABLE public.job TO app_worker;
GRANT SELECT(lease_until),UPDATE(lease_until) ON TABLE public.job TO app_worker;
GRANT SELECT(created_at) ON TABLE public.job TO app_web;
GRANT SELECT(created_at) ON TABLE public.job TO app_worker;
GRANT SELECT(started_at) ON TABLE public.job TO app_web;
GRANT SELECT(started_at),UPDATE(started_at) ON TABLE public.job TO app_worker;
GRANT SELECT(finished_at) ON TABLE public.job TO app_web;
GRANT SELECT(finished_at),UPDATE(finished_at) ON TABLE public.job TO app_worker;
GRANT SELECT(exit_code) ON TABLE public.job TO app_web;
GRANT SELECT(exit_code),UPDATE(exit_code) ON TABLE public.job TO app_worker;
GRANT SELECT(outcome) ON TABLE public.job TO app_web;
GRANT SELECT(outcome),UPDATE(outcome) ON TABLE public.job TO app_worker;
GRANT SELECT(result) ON TABLE public.job TO app_web;
GRANT SELECT(result),UPDATE(result) ON TABLE public.job TO app_worker;
GRANT SELECT(stderr_excerpt) ON TABLE public.job TO app_web;
GRANT SELECT(stderr_excerpt),UPDATE(stderr_excerpt) ON TABLE public.job TO app_worker;
GRANT SELECT(idempotency_key),INSERT(idempotency_key) ON TABLE public.job TO app_web;
GRANT SELECT(idempotency_key) ON TABLE public.job TO app_worker;
GRANT SELECT(payload_hash) ON TABLE public.job TO app_web;
GRANT SELECT(payload_hash) ON TABLE public.job TO app_worker;
GRANT SELECT(attempts) ON TABLE public.job TO app_web;
GRANT SELECT(attempts),UPDATE(attempts) ON TABLE public.job TO app_worker;
GRANT SELECT(held_since) ON TABLE public.job TO app_web;
GRANT SELECT(held_since),UPDATE(held_since) ON TABLE public.job TO app_worker;
GRANT SELECT(held_decision),UPDATE(held_decision) ON TABLE public.job TO app_web;
GRANT SELECT(held_decision) ON TABLE public.job TO app_worker;
GRANT SELECT(held_decided_by),UPDATE(held_decided_by) ON TABLE public.job TO app_web;
GRANT SELECT(held_decided_by) ON TABLE public.job TO app_worker;

CREATE TABLE public.job_claim_gate (
    only_row boolean DEFAULT true NOT NULL,
    paused_until timestamp with time zone,
    paused_by text,
    CONSTRAINT job_claim_gate_only_row_check CHECK (only_row),
    CONSTRAINT job_claim_gate_paused_by_check CHECK (((paused_by IS NULL) OR (length(paused_by) <= 200)))
);
ALTER TABLE ONLY public.job_claim_gate
    ADD CONSTRAINT job_claim_gate_pkey PRIMARY KEY (only_row);
GRANT SELECT(paused_until) ON TABLE public.job_claim_gate TO app_worker;
INSERT INTO public.job_claim_gate (only_row) VALUES (true);

CREATE TABLE public.attention_ack (
    kind text NOT NULL,
    cluster text DEFAULT ''::text NOT NULL,
    subject text NOT NULL,
    acknowledged_by text NOT NULL,
    acknowledged_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    CONSTRAINT attention_ack_acknowledged_by_check CHECK (((length(acknowledged_by) >= 1) AND (length(acknowledged_by) <= 64))),
    CONSTRAINT attention_ack_cluster_check CHECK ((length(cluster) <= 64)),
    CONSTRAINT attention_ack_kind_check CHECK (((length(kind) >= 1) AND (length(kind) <= 32))),
    CONSTRAINT attention_ack_subject_check CHECK (((length(subject) >= 1) AND (length(subject) <= 256)))
);
ALTER TABLE ONLY public.attention_ack
    ADD CONSTRAINT attention_ack_pkey PRIMARY KEY (kind, cluster, subject);
GRANT DELETE ON TABLE public.attention_ack TO app_web;
GRANT SELECT(kind),INSERT(kind) ON TABLE public.attention_ack TO app_web;
GRANT SELECT(cluster),INSERT(cluster) ON TABLE public.attention_ack TO app_web;
GRANT SELECT(subject),INSERT(subject) ON TABLE public.attention_ack TO app_web;
GRANT SELECT(acknowledged_by),INSERT(acknowledged_by) ON TABLE public.attention_ack TO app_web;
GRANT SELECT(acknowledged_at) ON TABLE public.attention_ack TO app_web;

CREATE TABLE public.node_event (
    id bigint NOT NULL,
    at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    cluster text NOT NULL,
    node text NOT NULL,
    event text NOT NULL,
    subject text NOT NULL,
    detail jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT node_event_event_check CHECK ((event = ANY (ARRAY['server_down'::text, 'server_up'::text, 'vip_moved'::text, 'node_silent'::text, 'node_back'::text])))
);
ALTER TABLE public.node_event ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.node_event_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);
ALTER TABLE ONLY public.node_event
    ADD CONSTRAINT node_event_pkey PRIMARY KEY (id);
CREATE INDEX node_event_at ON public.node_event USING btree (at DESC, id DESC);
CREATE INDEX node_event_cluster_at ON public.node_event USING btree (cluster, at DESC);
GRANT SELECT(id) ON TABLE public.node_event TO app_web;
GRANT INSERT(at) ON TABLE public.node_event TO app_poller;
GRANT SELECT(at) ON TABLE public.node_event TO app_web;
GRANT INSERT(cluster) ON TABLE public.node_event TO app_poller;
GRANT SELECT(cluster) ON TABLE public.node_event TO app_web;
GRANT INSERT(node) ON TABLE public.node_event TO app_poller;
GRANT SELECT(node) ON TABLE public.node_event TO app_web;
GRANT INSERT(event) ON TABLE public.node_event TO app_poller;
GRANT SELECT(event) ON TABLE public.node_event TO app_web;
GRANT INSERT(subject) ON TABLE public.node_event TO app_poller;
GRANT SELECT(subject) ON TABLE public.node_event TO app_web;
GRANT INSERT(detail) ON TABLE public.node_event TO app_poller;
GRANT SELECT(detail) ON TABLE public.node_event TO app_web;

CREATE TABLE public.node_event_state (
    cluster text NOT NULL,
    kind text NOT NULL,
    subject text NOT NULL,
    value text NOT NULL,
    CONSTRAINT node_event_state_kind_check CHECK ((kind = ANY (ARRAY['server'::text, 'vip'::text, 'node'::text])))
);
ALTER TABLE ONLY public.node_event_state
    ADD CONSTRAINT node_event_state_pkey PRIMARY KEY (cluster, kind, subject);
GRANT DELETE ON TABLE public.node_event_state TO app_poller;
GRANT SELECT(cluster),INSERT(cluster) ON TABLE public.node_event_state TO app_poller;
GRANT SELECT(kind),INSERT(kind) ON TABLE public.node_event_state TO app_poller;
GRANT SELECT(subject),INSERT(subject) ON TABLE public.node_event_state TO app_poller;
GRANT SELECT(value),INSERT(value),UPDATE(value) ON TABLE public.node_event_state TO app_poller;
"""


#
# What the poller read, so that no page reaches a node or a helper.
#
# A read made while somebody looks at a screen fails while somebody looks at a
# screen. The poller asks on its own schedule and writes the answer here, one
# row per cluster and kind (one row for the cluster list and the manager's
# certificates); the pages read it. `observed_at` is set by a trigger, so how
# old an answer is is the database's word, not the poller's. An answer is the
# engine's envelope kept whole, since the envelope is versioned by the engine
# and unpacking it here would be a second definition of it.
#
# The poller inserts and updates and deletes nothing, except where a row is
# derived and rebuilt every pass: the search's values, and the packages
# waiting. `version_diff` holds what each version changed, which never changes
# once the version exists. `cluster_pass` says when the poller last read a
# cluster through, from which start, so a page can tell whether a reading was
# taken after a job ended. The worker reads the version history, so that
# recovery can tell after a restart whether a job's version was made.
#
READINGS = r"""
CREATE FUNCTION public.cluster_status_observed_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    begin
        new.observed_at := statement_timestamp();
        return new;
    end;
    $$;

CREATE FUNCTION public.cluster_inventory_observed_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    begin
        new.observed_at := statement_timestamp();
        return new;
    end;
    $$;

CREATE FUNCTION public.cluster_history_observed_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    begin
        new.observed_at := statement_timestamp();
        return new;
    end;
    $$;

CREATE FUNCTION public.cluster_backups_observed_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    begin
        new.observed_at := statement_timestamp();
        return new;
    end;
    $$;

CREATE FUNCTION public.cluster_certificates_observed_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    begin
        new.observed_at := statement_timestamp();
        return new;
    end;
    $$;

CREATE FUNCTION public.cluster_network_observed_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    begin
        new.observed_at := statement_timestamp();
        return new;
    end;
    $$;

CREATE FUNCTION public.cluster_objects_observed_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    begin
        new.observed_at := statement_timestamp();
        return new;
    end;
    $$;

CREATE FUNCTION public.cluster_settings_observed_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    begin
        new.observed_at := statement_timestamp();
        return new;
    end;
    $$;

CREATE FUNCTION public.cluster_list_observed_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    begin
        new.observed_at := statement_timestamp();
        return new;
    end;
    $$;

CREATE FUNCTION public.manager_certificates_observed_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    begin
        new.observed_at := statement_timestamp();
        return new;
    end;
    $$;

CREATE TABLE public.cluster_status (
    cluster text NOT NULL,
    observed_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    outcome text NOT NULL,
    result jsonb NOT NULL,
    warnings jsonb DEFAULT '[]'::jsonb NOT NULL,
    error jsonb,
    poll_error text,
    CONSTRAINT cluster_status_cluster_shape CHECK ((cluster ~ '^[a-z][a-z0-9-]{0,62}$'::text)),
    CONSTRAINT cluster_status_outcome_allowed CHECK ((outcome = ANY (ARRAY['done'::text, 'partial'::text, 'failed'::text, 'unavailable'::text])))
);
ALTER TABLE ONLY public.cluster_status
    ADD CONSTRAINT cluster_status_pkey PRIMARY KEY (cluster);
CREATE TRIGGER cluster_status_observed_at BEFORE UPDATE ON public.cluster_status FOR EACH ROW EXECUTE FUNCTION public.cluster_status_observed_at();
GRANT SELECT(cluster),INSERT(cluster) ON TABLE public.cluster_status TO app_poller;
GRANT SELECT(cluster) ON TABLE public.cluster_status TO app_web;
GRANT SELECT(observed_at) ON TABLE public.cluster_status TO app_poller;
GRANT SELECT(observed_at) ON TABLE public.cluster_status TO app_web;
GRANT SELECT(outcome),INSERT(outcome),UPDATE(outcome) ON TABLE public.cluster_status TO app_poller;
GRANT SELECT(outcome) ON TABLE public.cluster_status TO app_web;
GRANT SELECT(result),INSERT(result),UPDATE(result) ON TABLE public.cluster_status TO app_poller;
GRANT SELECT(result) ON TABLE public.cluster_status TO app_web;
GRANT SELECT(warnings),INSERT(warnings),UPDATE(warnings) ON TABLE public.cluster_status TO app_poller;
GRANT SELECT(warnings) ON TABLE public.cluster_status TO app_web;
GRANT SELECT(error),INSERT(error),UPDATE(error) ON TABLE public.cluster_status TO app_poller;
GRANT SELECT(error) ON TABLE public.cluster_status TO app_web;
GRANT SELECT(poll_error),INSERT(poll_error),UPDATE(poll_error) ON TABLE public.cluster_status TO app_poller;
GRANT SELECT(poll_error) ON TABLE public.cluster_status TO app_web;

CREATE TABLE public.cluster_inventory (
    cluster text NOT NULL,
    observed_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    outcome text NOT NULL,
    result jsonb NOT NULL,
    warnings jsonb DEFAULT '[]'::jsonb NOT NULL,
    error jsonb,
    poll_error text,
    CONSTRAINT cluster_inventory_cluster_shape CHECK ((cluster ~ '^[a-z][a-z0-9-]{0,62}$'::text)),
    CONSTRAINT cluster_inventory_outcome_allowed CHECK ((outcome = ANY (ARRAY['done'::text, 'failed'::text, 'unavailable'::text])))
);
ALTER TABLE ONLY public.cluster_inventory
    ADD CONSTRAINT cluster_inventory_pkey PRIMARY KEY (cluster);
CREATE TRIGGER cluster_inventory_observed_at BEFORE UPDATE ON public.cluster_inventory FOR EACH ROW EXECUTE FUNCTION public.cluster_inventory_observed_at();
GRANT SELECT(cluster),INSERT(cluster) ON TABLE public.cluster_inventory TO app_poller;
GRANT SELECT(cluster) ON TABLE public.cluster_inventory TO app_web;
GRANT SELECT(observed_at) ON TABLE public.cluster_inventory TO app_poller;
GRANT SELECT(observed_at) ON TABLE public.cluster_inventory TO app_web;
GRANT SELECT(outcome),INSERT(outcome),UPDATE(outcome) ON TABLE public.cluster_inventory TO app_poller;
GRANT SELECT(outcome) ON TABLE public.cluster_inventory TO app_web;
GRANT SELECT(result),INSERT(result),UPDATE(result) ON TABLE public.cluster_inventory TO app_poller;
GRANT SELECT(result) ON TABLE public.cluster_inventory TO app_web;
GRANT SELECT(warnings),INSERT(warnings),UPDATE(warnings) ON TABLE public.cluster_inventory TO app_poller;
GRANT SELECT(warnings) ON TABLE public.cluster_inventory TO app_web;
GRANT SELECT(error),INSERT(error),UPDATE(error) ON TABLE public.cluster_inventory TO app_poller;
GRANT SELECT(error) ON TABLE public.cluster_inventory TO app_web;
GRANT SELECT(poll_error),INSERT(poll_error),UPDATE(poll_error) ON TABLE public.cluster_inventory TO app_poller;
GRANT SELECT(poll_error) ON TABLE public.cluster_inventory TO app_web;

CREATE TABLE public.cluster_history (
    cluster text NOT NULL,
    observed_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    outcome text NOT NULL,
    result jsonb NOT NULL,
    warnings jsonb DEFAULT '[]'::jsonb NOT NULL,
    error jsonb,
    poll_error text,
    CONSTRAINT cluster_history_cluster_shape CHECK ((cluster ~ '^[a-z][a-z0-9-]{0,62}$'::text)),
    CONSTRAINT cluster_history_outcome_allowed CHECK ((outcome = ANY (ARRAY['done'::text, 'failed'::text, 'unavailable'::text])))
);
ALTER TABLE ONLY public.cluster_history
    ADD CONSTRAINT cluster_history_pkey PRIMARY KEY (cluster);
CREATE TRIGGER cluster_history_observed_at BEFORE UPDATE ON public.cluster_history FOR EACH ROW EXECUTE FUNCTION public.cluster_history_observed_at();
GRANT SELECT(cluster),INSERT(cluster) ON TABLE public.cluster_history TO app_poller;
GRANT SELECT(cluster) ON TABLE public.cluster_history TO app_web;
GRANT SELECT(cluster) ON TABLE public.cluster_history TO app_worker;
GRANT SELECT(observed_at) ON TABLE public.cluster_history TO app_poller;
GRANT SELECT(observed_at) ON TABLE public.cluster_history TO app_web;
GRANT SELECT(observed_at) ON TABLE public.cluster_history TO app_worker;
GRANT SELECT(outcome),INSERT(outcome),UPDATE(outcome) ON TABLE public.cluster_history TO app_poller;
GRANT SELECT(outcome) ON TABLE public.cluster_history TO app_web;
GRANT SELECT(outcome) ON TABLE public.cluster_history TO app_worker;
GRANT SELECT(result),INSERT(result),UPDATE(result) ON TABLE public.cluster_history TO app_poller;
GRANT SELECT(result) ON TABLE public.cluster_history TO app_web;
GRANT SELECT(result) ON TABLE public.cluster_history TO app_worker;
GRANT SELECT(warnings),INSERT(warnings),UPDATE(warnings) ON TABLE public.cluster_history TO app_poller;
GRANT SELECT(warnings) ON TABLE public.cluster_history TO app_web;
GRANT SELECT(warnings) ON TABLE public.cluster_history TO app_worker;
GRANT SELECT(error),INSERT(error),UPDATE(error) ON TABLE public.cluster_history TO app_poller;
GRANT SELECT(error) ON TABLE public.cluster_history TO app_web;
GRANT SELECT(error) ON TABLE public.cluster_history TO app_worker;
GRANT SELECT(poll_error),INSERT(poll_error),UPDATE(poll_error) ON TABLE public.cluster_history TO app_poller;
GRANT SELECT(poll_error) ON TABLE public.cluster_history TO app_web;
GRANT SELECT(poll_error) ON TABLE public.cluster_history TO app_worker;

CREATE TABLE public.cluster_backups (
    cluster text NOT NULL,
    observed_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    outcome text NOT NULL,
    result jsonb NOT NULL,
    warnings jsonb DEFAULT '[]'::jsonb NOT NULL,
    error jsonb,
    poll_error text,
    CONSTRAINT cluster_backups_cluster_shape CHECK ((cluster ~ '^[a-z][a-z0-9-]{0,62}$'::text)),
    CONSTRAINT cluster_backups_outcome_allowed CHECK ((outcome = ANY (ARRAY['done'::text, 'partial'::text, 'failed'::text, 'unavailable'::text])))
);
ALTER TABLE ONLY public.cluster_backups
    ADD CONSTRAINT cluster_backups_pkey PRIMARY KEY (cluster);
CREATE TRIGGER cluster_backups_observed_at BEFORE UPDATE ON public.cluster_backups FOR EACH ROW EXECUTE FUNCTION public.cluster_backups_observed_at();
GRANT SELECT(cluster),INSERT(cluster) ON TABLE public.cluster_backups TO app_poller;
GRANT SELECT(cluster) ON TABLE public.cluster_backups TO app_web;
GRANT SELECT(observed_at) ON TABLE public.cluster_backups TO app_poller;
GRANT SELECT(observed_at) ON TABLE public.cluster_backups TO app_web;
GRANT SELECT(outcome),INSERT(outcome),UPDATE(outcome) ON TABLE public.cluster_backups TO app_poller;
GRANT SELECT(outcome) ON TABLE public.cluster_backups TO app_web;
GRANT SELECT(result),INSERT(result),UPDATE(result) ON TABLE public.cluster_backups TO app_poller;
GRANT SELECT(result) ON TABLE public.cluster_backups TO app_web;
GRANT SELECT(warnings),INSERT(warnings),UPDATE(warnings) ON TABLE public.cluster_backups TO app_poller;
GRANT SELECT(warnings) ON TABLE public.cluster_backups TO app_web;
GRANT SELECT(error),INSERT(error),UPDATE(error) ON TABLE public.cluster_backups TO app_poller;
GRANT SELECT(error) ON TABLE public.cluster_backups TO app_web;
GRANT SELECT(poll_error),INSERT(poll_error),UPDATE(poll_error) ON TABLE public.cluster_backups TO app_poller;
GRANT SELECT(poll_error) ON TABLE public.cluster_backups TO app_web;

CREATE TABLE public.cluster_certificates (
    cluster text NOT NULL,
    observed_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    outcome text NOT NULL,
    result jsonb NOT NULL,
    warnings jsonb DEFAULT '[]'::jsonb NOT NULL,
    error jsonb,
    poll_error text,
    CONSTRAINT cluster_certificates_cluster_shape CHECK ((cluster ~ '^[a-z][a-z0-9-]{0,62}$'::text)),
    CONSTRAINT cluster_certificates_outcome_allowed CHECK ((outcome = ANY (ARRAY['done'::text, 'failed'::text, 'unavailable'::text])))
);
ALTER TABLE ONLY public.cluster_certificates
    ADD CONSTRAINT cluster_certificates_pkey PRIMARY KEY (cluster);
CREATE TRIGGER cluster_certificates_observed_at BEFORE UPDATE ON public.cluster_certificates FOR EACH ROW EXECUTE FUNCTION public.cluster_certificates_observed_at();
GRANT SELECT(cluster),INSERT(cluster) ON TABLE public.cluster_certificates TO app_poller;
GRANT SELECT(cluster) ON TABLE public.cluster_certificates TO app_web;
GRANT SELECT(observed_at) ON TABLE public.cluster_certificates TO app_poller;
GRANT SELECT(observed_at) ON TABLE public.cluster_certificates TO app_web;
GRANT SELECT(outcome),INSERT(outcome),UPDATE(outcome) ON TABLE public.cluster_certificates TO app_poller;
GRANT SELECT(outcome) ON TABLE public.cluster_certificates TO app_web;
GRANT SELECT(result),INSERT(result),UPDATE(result) ON TABLE public.cluster_certificates TO app_poller;
GRANT SELECT(result) ON TABLE public.cluster_certificates TO app_web;
GRANT SELECT(warnings),INSERT(warnings),UPDATE(warnings) ON TABLE public.cluster_certificates TO app_poller;
GRANT SELECT(warnings) ON TABLE public.cluster_certificates TO app_web;
GRANT SELECT(error),INSERT(error),UPDATE(error) ON TABLE public.cluster_certificates TO app_poller;
GRANT SELECT(error) ON TABLE public.cluster_certificates TO app_web;
GRANT SELECT(poll_error),INSERT(poll_error),UPDATE(poll_error) ON TABLE public.cluster_certificates TO app_poller;
GRANT SELECT(poll_error) ON TABLE public.cluster_certificates TO app_web;

CREATE TABLE public.cluster_network (
    cluster text NOT NULL,
    observed_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    outcome text NOT NULL,
    result jsonb NOT NULL,
    warnings jsonb DEFAULT '[]'::jsonb NOT NULL,
    error jsonb,
    poll_error text,
    CONSTRAINT cluster_network_cluster_shape CHECK ((cluster ~ '^[a-z][a-z0-9-]{0,62}$'::text)),
    CONSTRAINT cluster_network_outcome_allowed CHECK ((outcome = ANY (ARRAY['done'::text, 'failed'::text, 'unavailable'::text])))
);
ALTER TABLE ONLY public.cluster_network
    ADD CONSTRAINT cluster_network_pkey PRIMARY KEY (cluster);
CREATE TRIGGER cluster_network_observed_at BEFORE UPDATE ON public.cluster_network FOR EACH ROW EXECUTE FUNCTION public.cluster_network_observed_at();
GRANT SELECT(cluster),INSERT(cluster) ON TABLE public.cluster_network TO app_poller;
GRANT SELECT(cluster) ON TABLE public.cluster_network TO app_web;
GRANT SELECT(observed_at) ON TABLE public.cluster_network TO app_poller;
GRANT SELECT(observed_at) ON TABLE public.cluster_network TO app_web;
GRANT SELECT(outcome),INSERT(outcome),UPDATE(outcome) ON TABLE public.cluster_network TO app_poller;
GRANT SELECT(outcome) ON TABLE public.cluster_network TO app_web;
GRANT SELECT(result),INSERT(result),UPDATE(result) ON TABLE public.cluster_network TO app_poller;
GRANT SELECT(result) ON TABLE public.cluster_network TO app_web;
GRANT SELECT(warnings),INSERT(warnings),UPDATE(warnings) ON TABLE public.cluster_network TO app_poller;
GRANT SELECT(warnings) ON TABLE public.cluster_network TO app_web;
GRANT SELECT(error),INSERT(error),UPDATE(error) ON TABLE public.cluster_network TO app_poller;
GRANT SELECT(error) ON TABLE public.cluster_network TO app_web;
GRANT SELECT(poll_error),INSERT(poll_error),UPDATE(poll_error) ON TABLE public.cluster_network TO app_poller;
GRANT SELECT(poll_error) ON TABLE public.cluster_network TO app_web;

CREATE TABLE public.cluster_objects (
    cluster text NOT NULL,
    observed_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    outcome text NOT NULL,
    result jsonb NOT NULL,
    warnings jsonb DEFAULT '[]'::jsonb NOT NULL,
    error jsonb,
    poll_error text,
    CONSTRAINT cluster_objects_cluster_shape CHECK ((cluster ~ '^[a-z][a-z0-9-]{0,62}$'::text)),
    CONSTRAINT cluster_objects_outcome_allowed CHECK ((outcome = ANY (ARRAY['done'::text, 'failed'::text, 'unavailable'::text])))
);
ALTER TABLE ONLY public.cluster_objects
    ADD CONSTRAINT cluster_objects_pkey PRIMARY KEY (cluster);
CREATE TRIGGER cluster_objects_observed_at BEFORE UPDATE ON public.cluster_objects FOR EACH ROW EXECUTE FUNCTION public.cluster_objects_observed_at();
GRANT SELECT(cluster),INSERT(cluster) ON TABLE public.cluster_objects TO app_poller;
GRANT SELECT(cluster) ON TABLE public.cluster_objects TO app_web;
GRANT SELECT(observed_at) ON TABLE public.cluster_objects TO app_poller;
GRANT SELECT(observed_at) ON TABLE public.cluster_objects TO app_web;
GRANT SELECT(outcome),INSERT(outcome),UPDATE(outcome) ON TABLE public.cluster_objects TO app_poller;
GRANT SELECT(outcome) ON TABLE public.cluster_objects TO app_web;
GRANT SELECT(result),INSERT(result),UPDATE(result) ON TABLE public.cluster_objects TO app_poller;
GRANT SELECT(result) ON TABLE public.cluster_objects TO app_web;
GRANT SELECT(warnings),INSERT(warnings),UPDATE(warnings) ON TABLE public.cluster_objects TO app_poller;
GRANT SELECT(warnings) ON TABLE public.cluster_objects TO app_web;
GRANT SELECT(error),INSERT(error),UPDATE(error) ON TABLE public.cluster_objects TO app_poller;
GRANT SELECT(error) ON TABLE public.cluster_objects TO app_web;
GRANT SELECT(poll_error),INSERT(poll_error),UPDATE(poll_error) ON TABLE public.cluster_objects TO app_poller;
GRANT SELECT(poll_error) ON TABLE public.cluster_objects TO app_web;

CREATE TABLE public.cluster_settings (
    cluster text NOT NULL,
    observed_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    outcome text NOT NULL,
    result jsonb NOT NULL,
    warnings jsonb DEFAULT '[]'::jsonb NOT NULL,
    error jsonb,
    poll_error text,
    CONSTRAINT cluster_settings_cluster_shape CHECK ((cluster ~ '^[a-z][a-z0-9-]{0,62}$'::text)),
    CONSTRAINT cluster_settings_outcome_allowed CHECK ((outcome = ANY (ARRAY['done'::text, 'failed'::text, 'unavailable'::text])))
);
ALTER TABLE ONLY public.cluster_settings
    ADD CONSTRAINT cluster_settings_pkey PRIMARY KEY (cluster);
CREATE TRIGGER cluster_settings_observed_at BEFORE UPDATE ON public.cluster_settings FOR EACH ROW EXECUTE FUNCTION public.cluster_settings_observed_at();
GRANT SELECT(cluster),INSERT(cluster) ON TABLE public.cluster_settings TO app_poller;
GRANT SELECT(cluster) ON TABLE public.cluster_settings TO app_web;
GRANT SELECT(observed_at) ON TABLE public.cluster_settings TO app_poller;
GRANT SELECT(observed_at) ON TABLE public.cluster_settings TO app_web;
GRANT SELECT(outcome),INSERT(outcome),UPDATE(outcome) ON TABLE public.cluster_settings TO app_poller;
GRANT SELECT(outcome) ON TABLE public.cluster_settings TO app_web;
GRANT SELECT(result),INSERT(result),UPDATE(result) ON TABLE public.cluster_settings TO app_poller;
GRANT SELECT(result) ON TABLE public.cluster_settings TO app_web;
GRANT SELECT(warnings),INSERT(warnings),UPDATE(warnings) ON TABLE public.cluster_settings TO app_poller;
GRANT SELECT(warnings) ON TABLE public.cluster_settings TO app_web;
GRANT SELECT(error),INSERT(error),UPDATE(error) ON TABLE public.cluster_settings TO app_poller;
GRANT SELECT(error) ON TABLE public.cluster_settings TO app_web;
GRANT SELECT(poll_error),INSERT(poll_error),UPDATE(poll_error) ON TABLE public.cluster_settings TO app_poller;
GRANT SELECT(poll_error) ON TABLE public.cluster_settings TO app_web;

CREATE TABLE public.cluster_list (
    id smallint DEFAULT 1 NOT NULL,
    observed_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    clusters jsonb NOT NULL,
    CONSTRAINT cluster_list_is_array CHECK ((jsonb_typeof(clusters) = 'array'::text)),
    CONSTRAINT cluster_list_one_row CHECK ((id = 1))
);
ALTER TABLE ONLY public.cluster_list
    ADD CONSTRAINT cluster_list_pkey PRIMARY KEY (id);
CREATE TRIGGER cluster_list_observed_at BEFORE UPDATE ON public.cluster_list FOR EACH ROW EXECUTE FUNCTION public.cluster_list_observed_at();
GRANT SELECT(id) ON TABLE public.cluster_list TO app_poller;
GRANT SELECT(id) ON TABLE public.cluster_list TO app_web;
GRANT SELECT(observed_at) ON TABLE public.cluster_list TO app_poller;
GRANT SELECT(observed_at) ON TABLE public.cluster_list TO app_web;
GRANT SELECT(clusters),INSERT(clusters),UPDATE(clusters) ON TABLE public.cluster_list TO app_poller;
GRANT SELECT(clusters) ON TABLE public.cluster_list TO app_web;

CREATE TABLE public.cluster_pass (
    cluster text NOT NULL,
    began_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    settled_from timestamp with time zone,
    CONSTRAINT cluster_pass_cluster_shape CHECK ((cluster ~ '^[a-z][a-z0-9-]{0,62}$'::text))
);
ALTER TABLE ONLY public.cluster_pass
    ADD CONSTRAINT cluster_pass_pkey PRIMARY KEY (cluster);
GRANT SELECT(cluster),INSERT(cluster) ON TABLE public.cluster_pass TO app_poller;
GRANT SELECT(cluster) ON TABLE public.cluster_pass TO app_web;
GRANT SELECT(began_at),UPDATE(began_at) ON TABLE public.cluster_pass TO app_poller;
GRANT SELECT(began_at) ON TABLE public.cluster_pass TO app_web;
GRANT SELECT(settled_from),UPDATE(settled_from) ON TABLE public.cluster_pass TO app_poller;
GRANT SELECT(settled_from) ON TABLE public.cluster_pass TO app_web;

CREATE TABLE public.manager_certificates (
    id smallint DEFAULT 1 NOT NULL,
    observed_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    outcome text NOT NULL,
    result jsonb NOT NULL,
    warnings jsonb DEFAULT '[]'::jsonb NOT NULL,
    error jsonb,
    poll_error text,
    CONSTRAINT manager_certificates_one_row CHECK ((id = 1)),
    CONSTRAINT manager_certificates_outcome_allowed CHECK ((outcome = ANY (ARRAY['done'::text, 'failed'::text, 'unavailable'::text])))
);
ALTER TABLE ONLY public.manager_certificates
    ADD CONSTRAINT manager_certificates_pkey PRIMARY KEY (id);
CREATE TRIGGER manager_certificates_observed_at BEFORE UPDATE ON public.manager_certificates FOR EACH ROW EXECUTE FUNCTION public.manager_certificates_observed_at();
GRANT SELECT(id) ON TABLE public.manager_certificates TO app_poller;
GRANT SELECT(id) ON TABLE public.manager_certificates TO app_web;
GRANT SELECT(observed_at) ON TABLE public.manager_certificates TO app_poller;
GRANT SELECT(observed_at) ON TABLE public.manager_certificates TO app_web;
GRANT SELECT(outcome),INSERT(outcome),UPDATE(outcome) ON TABLE public.manager_certificates TO app_poller;
GRANT SELECT(outcome) ON TABLE public.manager_certificates TO app_web;
GRANT SELECT(result),INSERT(result),UPDATE(result) ON TABLE public.manager_certificates TO app_poller;
GRANT SELECT(result) ON TABLE public.manager_certificates TO app_web;
GRANT SELECT(warnings),INSERT(warnings),UPDATE(warnings) ON TABLE public.manager_certificates TO app_poller;
GRANT SELECT(warnings) ON TABLE public.manager_certificates TO app_web;
GRANT SELECT(error),INSERT(error),UPDATE(error) ON TABLE public.manager_certificates TO app_poller;
GRANT SELECT(error) ON TABLE public.manager_certificates TO app_web;
GRANT SELECT(poll_error),INSERT(poll_error),UPDATE(poll_error) ON TABLE public.manager_certificates TO app_poller;
GRANT SELECT(poll_error) ON TABLE public.manager_certificates TO app_web;

CREATE TABLE public.version_diff (
    cluster text NOT NULL,
    commit text NOT NULL,
    recorded_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    diff jsonb NOT NULL,
    CONSTRAINT version_diff_cluster_shape CHECK ((cluster ~ '^[a-z][a-z0-9-]{0,62}$'::text)),
    CONSTRAINT version_diff_commit_shape CHECK ((commit ~ '^[0-9a-f]{40,64}$'::text)),
    CONSTRAINT version_diff_is_object CHECK ((jsonb_typeof(diff) = 'object'::text)),
    CONSTRAINT version_diff_size CHECK ((octet_length((diff)::text) <= 1048576))
);
ALTER TABLE ONLY public.version_diff
    ADD CONSTRAINT version_diff_pkey PRIMARY KEY (cluster, commit);
GRANT SELECT(cluster),INSERT(cluster) ON TABLE public.version_diff TO app_poller;
GRANT SELECT(cluster) ON TABLE public.version_diff TO app_web;
GRANT SELECT(commit),INSERT(commit) ON TABLE public.version_diff TO app_poller;
GRANT SELECT(commit) ON TABLE public.version_diff TO app_web;
GRANT SELECT(recorded_at) ON TABLE public.version_diff TO app_poller;
GRANT SELECT(recorded_at) ON TABLE public.version_diff TO app_web;
GRANT SELECT(diff),INSERT(diff) ON TABLE public.version_diff TO app_poller;
GRANT SELECT(diff) ON TABLE public.version_diff TO app_web;

CREATE TABLE public.search_entry (
    cluster text,
    source text NOT NULL,
    kind text NOT NULL,
    title text NOT NULL,
    label text DEFAULT ''::text NOT NULL,
    value text NOT NULL,
    href text NOT NULL,
    admin_only boolean DEFAULT false NOT NULL,
    CONSTRAINT search_entry_cluster_shape CHECK ((cluster ~ '^[a-z][a-z0-9-]{0,62}$'::text)),
    CONSTRAINT search_entry_href_local CHECK (((href ~ '^/[^/]'::text) OR (href = '/'::text))),
    CONSTRAINT search_entry_kind_allowed CHECK ((kind = ANY (ARRAY['proxy'::text, 'address'::text, 'certificate'::text, 'cluster'::text]))),
    CONSTRAINT search_entry_label_size CHECK ((length(label) <= 64)),
    CONSTRAINT search_entry_manager_has_no_cluster CHECK (((cluster IS NULL) = (source = 'manager'::text))),
    CONSTRAINT search_entry_source_allowed CHECK ((source = ANY (ARRAY['objects'::text, 'network'::text, 'cert_list'::text, 'status'::text, 'cluster_list'::text, 'manager'::text]))),
    CONSTRAINT search_entry_title_size CHECK (((length(title) >= 1) AND (length(title) <= 255))),
    CONSTRAINT search_entry_value_size CHECK (((length(value) >= 1) AND (length(value) <= 512)))
);
CREATE INDEX search_entry_reading ON public.search_entry USING btree (cluster, source);
CREATE INDEX search_entry_value ON public.search_entry USING gin (lower(value) public.gin_trgm_ops);
GRANT DELETE ON TABLE public.search_entry TO app_poller;
GRANT SELECT(cluster),INSERT(cluster) ON TABLE public.search_entry TO app_poller;
GRANT SELECT(cluster) ON TABLE public.search_entry TO app_web;
GRANT SELECT(source),INSERT(source) ON TABLE public.search_entry TO app_poller;
GRANT SELECT(source) ON TABLE public.search_entry TO app_web;
GRANT SELECT(kind),INSERT(kind) ON TABLE public.search_entry TO app_poller;
GRANT SELECT(kind) ON TABLE public.search_entry TO app_web;
GRANT SELECT(title),INSERT(title) ON TABLE public.search_entry TO app_poller;
GRANT SELECT(title) ON TABLE public.search_entry TO app_web;
GRANT SELECT(label),INSERT(label) ON TABLE public.search_entry TO app_poller;
GRANT SELECT(label) ON TABLE public.search_entry TO app_web;
GRANT SELECT(value),INSERT(value) ON TABLE public.search_entry TO app_poller;
GRANT SELECT(value) ON TABLE public.search_entry TO app_web;
GRANT SELECT(href),INSERT(href) ON TABLE public.search_entry TO app_poller;
GRANT SELECT(href) ON TABLE public.search_entry TO app_web;
GRANT SELECT(admin_only),INSERT(admin_only) ON TABLE public.search_entry TO app_poller;
GRANT SELECT(admin_only) ON TABLE public.search_entry TO app_web;

CREATE TABLE public.update_check (
    only_row boolean DEFAULT true NOT NULL,
    latest_tag text,
    latest_url text,
    checked_at timestamp with time zone,
    attempted_at timestamp with time zone NOT NULL,
    failing_since timestamp with time zone,
    error text,
    CONSTRAINT update_check_answer_whole CHECK ((((latest_tag IS NULL) = (latest_url IS NULL)) AND ((latest_tag IS NULL) = (checked_at IS NULL)))),
    CONSTRAINT update_check_error_check CHECK ((char_length(error) <= 300)),
    CONSTRAINT update_check_latest_tag_check CHECK ((latest_tag ~ '^v[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$'::text)),
    CONSTRAINT update_check_latest_url_check CHECK ((latest_url ~ '^https://github\.com/haprion/haprion/releases/tag/v[0-9.]{5,14}$'::text)),
    CONSTRAINT update_check_only_row_check CHECK (only_row)
);
ALTER TABLE ONLY public.update_check
    ADD CONSTRAINT update_check_pkey PRIMARY KEY (only_row);
GRANT SELECT(only_row) ON TABLE public.update_check TO app_poller;
GRANT SELECT(latest_tag),INSERT(latest_tag),UPDATE(latest_tag) ON TABLE public.update_check TO app_poller;
GRANT SELECT(latest_tag) ON TABLE public.update_check TO app_web;
GRANT SELECT(latest_url),INSERT(latest_url),UPDATE(latest_url) ON TABLE public.update_check TO app_poller;
GRANT SELECT(latest_url) ON TABLE public.update_check TO app_web;
GRANT SELECT(checked_at),INSERT(checked_at),UPDATE(checked_at) ON TABLE public.update_check TO app_poller;
GRANT SELECT(checked_at) ON TABLE public.update_check TO app_web;
GRANT SELECT(attempted_at),INSERT(attempted_at),UPDATE(attempted_at) ON TABLE public.update_check TO app_poller;
GRANT SELECT(attempted_at) ON TABLE public.update_check TO app_web;
GRANT SELECT(failing_since),INSERT(failing_since),UPDATE(failing_since) ON TABLE public.update_check TO app_poller;
GRANT SELECT(failing_since) ON TABLE public.update_check TO app_web;
GRANT SELECT(error),INSERT(error),UPDATE(error) ON TABLE public.update_check TO app_poller;

CREATE TABLE public.package_waiting (
    name text NOT NULL,
    installed text NOT NULL,
    available text NOT NULL,
    read_at timestamp with time zone NOT NULL,
    CONSTRAINT package_waiting_available_check CHECK (((char_length(available) >= 1) AND (char_length(available) <= 128))),
    CONSTRAINT package_waiting_installed_check CHECK (((char_length(installed) >= 1) AND (char_length(installed) <= 128))),
    CONSTRAINT package_waiting_name_check CHECK ((name ~ '^haprion-[a-z0-9][a-z0-9.+-]{0,62}$'::text))
);
ALTER TABLE ONLY public.package_waiting
    ADD CONSTRAINT package_waiting_pkey PRIMARY KEY (name);
GRANT DELETE ON TABLE public.package_waiting TO app_poller;
GRANT SELECT(name),INSERT(name) ON TABLE public.package_waiting TO app_poller;
GRANT SELECT(name) ON TABLE public.package_waiting TO app_web;
GRANT SELECT(installed),INSERT(installed) ON TABLE public.package_waiting TO app_poller;
GRANT SELECT(installed) ON TABLE public.package_waiting TO app_web;
GRANT SELECT(available),INSERT(available) ON TABLE public.package_waiting TO app_poller;
GRANT SELECT(available) ON TABLE public.package_waiting TO app_web;
GRANT SELECT(read_at),INSERT(read_at) ON TABLE public.package_waiting TO app_poller;
GRANT SELECT(read_at) ON TABLE public.package_waiting TO app_web;
"""


#
# What somebody is changing and has not published.
#
# An object's draft is unfinished work and never part of a publish; a saved
# change is finished and goes out with the next one, so an object may have
# both (`stage`). A draft keeps the object as it was published when the draft
# was written (`base_document`), so the page can tell "the cluster moved" from
# "this object moved". `replaces` is the published name a renamed object takes
# the place of. A cluster's network description and settings have a saved state
# only, kept whole: the helper takes a whole document. Both tables are the
# web's own.
#
EDITING = r"""
CREATE FUNCTION public.proxy_draft_touch() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    begin
        new.revision := old.revision + 1;
        new.updated_at := statement_timestamp();
        return new;
    end;
    $$;

CREATE TABLE public.proxy_draft (
    cluster text NOT NULL,
    object_id text NOT NULL,
    yaml text NOT NULL,
    base_version integer,
    base_hash text NOT NULL,
    revision integer DEFAULT 1 NOT NULL,
    updated_by text NOT NULL,
    updated_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    deleted boolean DEFAULT false NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    stage text DEFAULT 'draft'::text NOT NULL,
    replaces text,
    base_document text,
    CONSTRAINT proxy_draft_base_document_size CHECK (((base_document IS NULL) OR (octet_length(base_document) <= 262144))),
    CONSTRAINT proxy_draft_base_hash_shape CHECK ((base_hash ~ '^[0-9a-f]{40}$'::text)),
    CONSTRAINT proxy_draft_base_version_positive CHECK (((base_version IS NULL) OR (base_version >= 1))),
    CONSTRAINT proxy_draft_cluster_shape CHECK ((cluster ~ '^[a-z][a-z0-9-]{0,62}$'::text)),
    CONSTRAINT proxy_draft_deleted_carries_no_document CHECK ((deleted OR (length(yaml) > 0))),
    CONSTRAINT proxy_draft_object_shape CHECK ((object_id ~ '^[a-z][a-z0-9_-]{0,39}$'::text)),
    CONSTRAINT proxy_draft_replaces_shape CHECK (((replaces IS NULL) OR ((replaces ~ '^[a-z][a-z0-9_-]{0,39}$'::text) AND (replaces <> object_id)))),
    CONSTRAINT proxy_draft_revision_positive CHECK ((revision >= 1)),
    CONSTRAINT proxy_draft_stage CHECK ((stage = ANY (ARRAY['draft'::text, 'saved'::text]))),
    CONSTRAINT proxy_draft_updated_by_shape CHECK (((length(updated_by) >= 1) AND (length(updated_by) <= 64))),
    CONSTRAINT proxy_draft_yaml_size CHECK ((octet_length(yaml) <= 262144))
);
ALTER TABLE ONLY public.proxy_draft
    ADD CONSTRAINT proxy_draft_pkey PRIMARY KEY (cluster, object_id, stage);
CREATE TRIGGER proxy_draft_touch BEFORE UPDATE ON public.proxy_draft FOR EACH ROW EXECUTE FUNCTION public.proxy_draft_touch();
GRANT DELETE ON TABLE public.proxy_draft TO app_web;
GRANT SELECT(cluster),INSERT(cluster) ON TABLE public.proxy_draft TO app_web;
GRANT SELECT(object_id),INSERT(object_id),UPDATE(object_id) ON TABLE public.proxy_draft TO app_web;
GRANT SELECT(yaml),INSERT(yaml),UPDATE(yaml) ON TABLE public.proxy_draft TO app_web;
GRANT SELECT(base_version),INSERT(base_version),UPDATE(base_version) ON TABLE public.proxy_draft TO app_web;
GRANT SELECT(base_hash),INSERT(base_hash),UPDATE(base_hash) ON TABLE public.proxy_draft TO app_web;
GRANT SELECT(revision) ON TABLE public.proxy_draft TO app_web;
GRANT SELECT(updated_by),INSERT(updated_by),UPDATE(updated_by) ON TABLE public.proxy_draft TO app_web;
GRANT SELECT(updated_at) ON TABLE public.proxy_draft TO app_web;
GRANT SELECT(deleted),INSERT(deleted),UPDATE(deleted) ON TABLE public.proxy_draft TO app_web;
GRANT SELECT(id) ON TABLE public.proxy_draft TO app_web;
GRANT SELECT(stage),INSERT(stage) ON TABLE public.proxy_draft TO app_web;
GRANT SELECT(replaces),INSERT(replaces),UPDATE(replaces) ON TABLE public.proxy_draft TO app_web;
GRANT SELECT(base_document),INSERT(base_document),UPDATE(base_document) ON TABLE public.proxy_draft TO app_web;

CREATE TABLE public.cluster_change (
    cluster text NOT NULL,
    kind text NOT NULL,
    document text NOT NULL,
    base_hash text NOT NULL,
    revision integer DEFAULT 1 NOT NULL,
    updated_by text NOT NULL,
    updated_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    CONSTRAINT cluster_change_base_hash_shape CHECK ((base_hash ~ '^[0-9a-f]{40}$'::text)),
    CONSTRAINT cluster_change_cluster_shape CHECK ((cluster ~ '^[a-z][a-z0-9-]{0,62}$'::text)),
    CONSTRAINT cluster_change_document_size CHECK (((octet_length(document) >= 1) AND (octet_length(document) <= 65536))),
    CONSTRAINT cluster_change_kind CHECK ((kind = ANY (ARRAY['network'::text, 'settings'::text]))),
    CONSTRAINT cluster_change_revision_positive CHECK ((revision >= 1)),
    CONSTRAINT cluster_change_updated_by_shape CHECK (((length(updated_by) >= 1) AND (length(updated_by) <= 64)))
);
ALTER TABLE ONLY public.cluster_change
    ADD CONSTRAINT cluster_change_pkey PRIMARY KEY (cluster, kind);
CREATE TRIGGER cluster_change_touch BEFORE UPDATE ON public.cluster_change FOR EACH ROW EXECUTE FUNCTION public.proxy_draft_touch();
GRANT DELETE ON TABLE public.cluster_change TO app_web;
GRANT SELECT(cluster),INSERT(cluster) ON TABLE public.cluster_change TO app_web;
GRANT SELECT(kind),INSERT(kind) ON TABLE public.cluster_change TO app_web;
GRANT SELECT(document),INSERT(document),UPDATE(document) ON TABLE public.cluster_change TO app_web;
GRANT SELECT(base_hash),INSERT(base_hash),UPDATE(base_hash) ON TABLE public.cluster_change TO app_web;
GRANT SELECT(revision) ON TABLE public.cluster_change TO app_web;
GRANT SELECT(updated_by),INSERT(updated_by),UPDATE(updated_by) ON TABLE public.cluster_change TO app_web;
GRANT SELECT(updated_at) ON TABLE public.cluster_change TO app_web;
GRANT SELECT(id) ON TABLE public.cluster_change TO app_web;
"""


#
# DNS and NDES provider profiles: sealed boxes the web writes and cannot open.
#
# The web seals a profile's secrets against the installation's public key in
# the request that receives them and stores the box; only the root helper the
# worker runs can open it. The worker reads a profile to apply it and removes
# one when it is taken away.
#
PROFILES = r"""
CREATE TABLE public.dns_provider_profile (
    id text NOT NULL,
    name text NOT NULL,
    provider_id text NOT NULL,
    schema_version integer NOT NULL,
    key_id text NOT NULL,
    revision integer DEFAULT 1 NOT NULL,
    ciphertext bytea NOT NULL,
    created_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    created_by text NOT NULL,
    updated_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    updated_by text NOT NULL,
    CONSTRAINT dns_provider_profile_ciphertext_size CHECK (((octet_length(ciphertext) >= 48) AND (octet_length(ciphertext) <= 65536))),
    CONSTRAINT dns_provider_profile_id_shape CHECK ((id ~ '^[a-z0-9][a-z0-9-]{0,31}$'::text)),
    CONSTRAINT dns_provider_profile_key_shape CHECK ((key_id ~ '^[0-9a-f]{16}$'::text)),
    CONSTRAINT dns_provider_profile_name_shape CHECK (((char_length(name) >= 1) AND (char_length(name) <= 80))),
    CONSTRAINT dns_provider_profile_provider_shape CHECK ((provider_id ~ '^[a-z][a-z0-9-]{0,31}$'::text)),
    CONSTRAINT dns_provider_profile_revision_range CHECK (((revision >= 1) AND (revision <= 1000000))),
    CONSTRAINT dns_provider_profile_schema_version CHECK ((schema_version = 1))
);
ALTER TABLE ONLY public.dns_provider_profile
    ADD CONSTRAINT dns_provider_profile_pkey PRIMARY KEY (id);
GRANT DELETE ON TABLE public.dns_provider_profile TO app_worker;
GRANT SELECT(id),INSERT(id) ON TABLE public.dns_provider_profile TO app_web;
GRANT SELECT(id) ON TABLE public.dns_provider_profile TO app_worker;
GRANT SELECT(name),INSERT(name),UPDATE(name) ON TABLE public.dns_provider_profile TO app_web;
GRANT SELECT(provider_id),INSERT(provider_id) ON TABLE public.dns_provider_profile TO app_web;
GRANT SELECT(provider_id) ON TABLE public.dns_provider_profile TO app_worker;
GRANT SELECT(schema_version),INSERT(schema_version),UPDATE(schema_version) ON TABLE public.dns_provider_profile TO app_web;
GRANT SELECT(schema_version) ON TABLE public.dns_provider_profile TO app_worker;
GRANT SELECT(key_id),INSERT(key_id),UPDATE(key_id) ON TABLE public.dns_provider_profile TO app_web;
GRANT SELECT(key_id) ON TABLE public.dns_provider_profile TO app_worker;
GRANT SELECT(revision),INSERT(revision),UPDATE(revision) ON TABLE public.dns_provider_profile TO app_web;
GRANT SELECT(revision) ON TABLE public.dns_provider_profile TO app_worker;
GRANT INSERT(ciphertext),UPDATE(ciphertext) ON TABLE public.dns_provider_profile TO app_web;
GRANT SELECT(ciphertext) ON TABLE public.dns_provider_profile TO app_worker;
GRANT SELECT(created_at) ON TABLE public.dns_provider_profile TO app_web;
GRANT SELECT(created_by),INSERT(created_by) ON TABLE public.dns_provider_profile TO app_web;
GRANT SELECT(updated_at),UPDATE(updated_at) ON TABLE public.dns_provider_profile TO app_web;
GRANT SELECT(updated_by),INSERT(updated_by),UPDATE(updated_by) ON TABLE public.dns_provider_profile TO app_web;

CREATE TABLE public.ndes_provider_profile (
    id text NOT NULL,
    name text NOT NULL,
    provider_id text NOT NULL,
    schema_version integer NOT NULL,
    key_id text NOT NULL,
    revision integer DEFAULT 1 NOT NULL,
    ciphertext bytea NOT NULL,
    created_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    created_by text NOT NULL,
    updated_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    updated_by text NOT NULL,
    endpoint text DEFAULT ''::text NOT NULL,
    CONSTRAINT ndes_provider_profile_ciphertext_size CHECK (((octet_length(ciphertext) >= 48) AND (octet_length(ciphertext) <= 16384))),
    CONSTRAINT ndes_provider_profile_endpoint_shape CHECK (((endpoint = ''::text) OR ((endpoint ~ '^https://'::text) AND (char_length(endpoint) <= 2048)))),
    CONSTRAINT ndes_provider_profile_id_shape CHECK ((id ~ '^[a-z0-9][a-z0-9-]{0,31}$'::text)),
    CONSTRAINT ndes_provider_profile_key_shape CHECK ((key_id ~ '^[0-9a-f]{16}$'::text)),
    CONSTRAINT ndes_provider_profile_name_shape CHECK (((char_length(name) >= 1) AND (char_length(name) <= 80))),
    CONSTRAINT ndes_provider_profile_provider_shape CHECK ((provider_id = 'ndes'::text)),
    CONSTRAINT ndes_provider_profile_revision_range CHECK (((revision >= 1) AND (revision <= 1000000))),
    CONSTRAINT ndes_provider_profile_schema_version CHECK ((schema_version = 1))
);
ALTER TABLE ONLY public.ndes_provider_profile
    ADD CONSTRAINT ndes_provider_profile_pkey PRIMARY KEY (id);
GRANT DELETE ON TABLE public.ndes_provider_profile TO app_worker;
GRANT SELECT(id),INSERT(id) ON TABLE public.ndes_provider_profile TO app_web;
GRANT SELECT(id) ON TABLE public.ndes_provider_profile TO app_worker;
GRANT SELECT(name),INSERT(name),UPDATE(name) ON TABLE public.ndes_provider_profile TO app_web;
GRANT SELECT(provider_id),INSERT(provider_id) ON TABLE public.ndes_provider_profile TO app_web;
GRANT SELECT(provider_id) ON TABLE public.ndes_provider_profile TO app_worker;
GRANT SELECT(schema_version),INSERT(schema_version),UPDATE(schema_version) ON TABLE public.ndes_provider_profile TO app_web;
GRANT SELECT(schema_version) ON TABLE public.ndes_provider_profile TO app_worker;
GRANT SELECT(key_id),INSERT(key_id),UPDATE(key_id) ON TABLE public.ndes_provider_profile TO app_web;
GRANT SELECT(key_id) ON TABLE public.ndes_provider_profile TO app_worker;
GRANT SELECT(revision),INSERT(revision),UPDATE(revision) ON TABLE public.ndes_provider_profile TO app_web;
GRANT SELECT(revision) ON TABLE public.ndes_provider_profile TO app_worker;
GRANT INSERT(ciphertext),UPDATE(ciphertext) ON TABLE public.ndes_provider_profile TO app_web;
GRANT SELECT(ciphertext) ON TABLE public.ndes_provider_profile TO app_worker;
GRANT SELECT(created_at) ON TABLE public.ndes_provider_profile TO app_web;
GRANT SELECT(created_by),INSERT(created_by) ON TABLE public.ndes_provider_profile TO app_web;
GRANT SELECT(updated_at),UPDATE(updated_at) ON TABLE public.ndes_provider_profile TO app_web;
GRANT SELECT(updated_by),INSERT(updated_by),UPDATE(updated_by) ON TABLE public.ndes_provider_profile TO app_web;
GRANT SELECT(endpoint),INSERT(endpoint),UPDATE(endpoint) ON TABLE public.ndes_provider_profile TO app_web;
"""


#
# The installation's own settings and bookkeeping.
#
# `feature_switch` holds the six switches - the web may flip them and cannot
# add, remove or rename one, and a trigger sets `updated_at`; the poller reads
# whether the update check is on. `getting_started` is present once an admin
# has hidden the dashboard's list. `status_access` is who may ask the
# monitoring endpoints; an empty list is the endpoints off. `retention_run` is
# when the nightly maintenance last finished, written by `haprion-retention`
# as the migration role and read by Needs attention.
#
SETTINGS = r"""
CREATE FUNCTION public.feature_switch_touch() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    begin
        new.updated_at := statement_timestamp();
        return new;
    end;
    $$;

CREATE TABLE public.feature_switch (
    name text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    remembered jsonb DEFAULT '{}'::jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    updated_by text,
    CONSTRAINT feature_switch_name CHECK ((name = ANY (ARRAY['cert_receivers'::text, 'node_backups'::text, 'cluster_colours'::text, 'advanced_config'::text, 'waf_engine'::text, 'update_check'::text]))),
    CONSTRAINT feature_switch_remembered_object CHECK ((jsonb_typeof(remembered) = 'object'::text)),
    CONSTRAINT feature_switch_updated_by_shape CHECK (((updated_by IS NULL) OR ((length(updated_by) >= 1) AND (length(updated_by) <= 64))))
);
ALTER TABLE ONLY public.feature_switch
    ADD CONSTRAINT feature_switch_pkey PRIMARY KEY (name);
CREATE TRIGGER feature_switch_touch BEFORE UPDATE ON public.feature_switch FOR EACH ROW EXECUTE FUNCTION public.feature_switch_touch();
GRANT SELECT(name) ON TABLE public.feature_switch TO app_web;
GRANT SELECT(name) ON TABLE public.feature_switch TO app_poller;
GRANT SELECT(enabled),UPDATE(enabled) ON TABLE public.feature_switch TO app_web;
GRANT SELECT(enabled) ON TABLE public.feature_switch TO app_poller;
GRANT SELECT(remembered),UPDATE(remembered) ON TABLE public.feature_switch TO app_web;
GRANT SELECT(updated_at) ON TABLE public.feature_switch TO app_web;
GRANT SELECT(updated_by),UPDATE(updated_by) ON TABLE public.feature_switch TO app_web;
INSERT INTO public.feature_switch (name, enabled) VALUES
    ('cert_receivers', false), ('node_backups', false), ('cluster_colours', true),
    ('advanced_config', false), ('waf_engine', false), ('update_check', false);

CREATE TABLE public.getting_started (
    hidden boolean DEFAULT true NOT NULL,
    hidden_by text NOT NULL,
    hidden_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    CONSTRAINT getting_started_hidden_by_check CHECK (((length(hidden_by) >= 1) AND (length(hidden_by) <= 64))),
    CONSTRAINT getting_started_hidden_check CHECK (hidden)
);
ALTER TABLE ONLY public.getting_started
    ADD CONSTRAINT getting_started_pkey PRIMARY KEY (hidden);
GRANT DELETE ON TABLE public.getting_started TO app_web;
GRANT SELECT(hidden) ON TABLE public.getting_started TO app_web;
GRANT SELECT(hidden_by),INSERT(hidden_by) ON TABLE public.getting_started TO app_web;
GRANT SELECT(hidden_at) ON TABLE public.getting_started TO app_web;

CREATE TABLE public.status_access (
    network cidr NOT NULL,
    added_by text NOT NULL,
    added_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL
);
ALTER TABLE ONLY public.status_access
    ADD CONSTRAINT status_access_pkey PRIMARY KEY (network);
GRANT DELETE ON TABLE public.status_access TO app_web;
GRANT SELECT(network),INSERT(network) ON TABLE public.status_access TO app_web;
GRANT SELECT(added_by),INSERT(added_by) ON TABLE public.status_access TO app_web;
GRANT SELECT(added_at) ON TABLE public.status_access TO app_web;

CREATE TABLE public.retention_run (
    singleton boolean DEFAULT true NOT NULL,
    completed_at timestamp with time zone NOT NULL,
    CONSTRAINT retention_run_singleton_check CHECK (singleton)
);
ALTER TABLE ONLY public.retention_run
    ADD CONSTRAINT retention_run_pkey PRIMARY KEY (singleton);
GRANT SELECT(completed_at) ON TABLE public.retention_run TO app_web;
INSERT INTO public.retention_run (completed_at) VALUES (now());
"""


#
# What HAProxy, dnsdist and IPVS counted: listeners in `metric_frontend`, pools
# and their servers in `metric_backend_member`, as the poller sampled them.
#
# The raw tables are partitioned by day, so retention drops a day whole
# (`metric_partition`, made ahead by `haprion-retention`); the hourly rollup by
# month (`metric_month_partition`). The poller writes the cumulative counters
# and nothing else: what changed since the sample before - `previous_at`,
# `restarted` and each `delta_*` - is set by a row trigger, so a figure on the
# page is the database's reading of what the node reported. A reload that kept
# HAProxy's counters (`counters_kept`) is not read as a restart. Statement
# triggers sum those changes per hour as the samples arrive, in tables that are
# not partitioned on purpose: a trigger that could meet a missing partition
# could fail the poller's insert.
#
# `metric_backend_alias` says that a renamed pool's earlier name belongs to its
# card, written by the worker once the publish that renamed it is done.
# `metric_rollup_state` is how far the hourly rollup has come.
#
METRICS = r"""
CREATE FUNCTION public.metric_partition(table_name text, day date) RETURNS text
    LANGUAGE plpgsql
    AS $$
    declare
        partition text;
    begin
        table_name := case table_name
            when 'metric_listener' then 'metric_frontend'
            when 'metric_pool_member' then 'metric_backend_member'
            else table_name
        end;
        if table_name not in ('metric_frontend', 'metric_backend_member') then
            raise exception 'not a metric table: %', table_name;
        end if;

        partition := format('%s_%s', table_name, to_char(day, 'YYYYMMDD'));

        execute format(
            'create table if not exists %I partition of %I for values from (%L) to (%L)',
            partition, table_name, day, day + 1
        );
        return partition;
    end;
    $$;

CREATE FUNCTION public.metric_month_partition(table_name text, month date) RETURNS text
    LANGUAGE plpgsql
    AS $$
    declare
        partition text;
        first     date;
    begin
        table_name := case table_name
            when 'metric_pool_hour' then 'metric_backend_hour'
            else table_name
        end;
        if table_name not in ('metric_backend_hour') then
            raise exception 'not a rollup table: %', table_name;
        end if;

        first := date_trunc('month', month)::date;
        partition := format('%s_%s', table_name, to_char(first, 'YYYYMM'));

        execute format(
            'create table if not exists %I partition of %I for values from (%L) to (%L)',
            partition, table_name, first, first + interval '1 month'
        );
        return partition;
    end;
    $$;

CREATE FUNCTION public.metric_frontend_delta() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'public'
    AS $$
    declare
        previous record;
    begin
        if new.owns_vip is not true then
            new.previous_at := null;
            new.restarted := null;
            return new;
        end if;
        select observed_at, uptime_sec, req_tot, hrsp_2xx, hrsp_3xx, hrsp_4xx, hrsp_5xx, econ, wretr, bin, bout
          into previous
          from metric_frontend
         where cluster = new.cluster and node = new.node and frontend = new.frontend
           and owns_vip
           and observed_at < new.observed_at
           and observed_at >= new.observed_at - interval '31 days'
         order by observed_at desc
         limit 1;
        if not found then
            new.previous_at := null;
            new.restarted := null;
            return new;
        end if;
        new.previous_at := previous.observed_at;
        new.restarted := coalesce(new.uptime_sec < previous.uptime_sec, false)
            and (not coalesce(new.counters_kept, false)
                 or coalesce(new.req_tot < previous.req_tot, false) or coalesce(new.hrsp_2xx < previous.hrsp_2xx, false) or coalesce(new.hrsp_3xx < previous.hrsp_3xx, false) or coalesce(new.hrsp_4xx < previous.hrsp_4xx, false) or coalesce(new.hrsp_5xx < previous.hrsp_5xx, false) or coalesce(new.econ < previous.econ, false) or coalesce(new.wretr < previous.wretr, false) or coalesce(new.bin < previous.bin, false) or coalesce(new.bout < previous.bout, false));
        new.delta_req_tot := case when previous.req_tot is null or new.req_tot is null then null when new.restarted then new.req_tot when new.req_tot < previous.req_tot then null else new.req_tot - previous.req_tot end;
        new.delta_hrsp_2xx := case when previous.hrsp_2xx is null or new.hrsp_2xx is null then null when new.restarted then new.hrsp_2xx when new.hrsp_2xx < previous.hrsp_2xx then null else new.hrsp_2xx - previous.hrsp_2xx end;
        new.delta_hrsp_3xx := case when previous.hrsp_3xx is null or new.hrsp_3xx is null then null when new.restarted then new.hrsp_3xx when new.hrsp_3xx < previous.hrsp_3xx then null else new.hrsp_3xx - previous.hrsp_3xx end;
        new.delta_hrsp_4xx := case when previous.hrsp_4xx is null or new.hrsp_4xx is null then null when new.restarted then new.hrsp_4xx when new.hrsp_4xx < previous.hrsp_4xx then null else new.hrsp_4xx - previous.hrsp_4xx end;
        new.delta_hrsp_5xx := case when previous.hrsp_5xx is null or new.hrsp_5xx is null then null when new.restarted then new.hrsp_5xx when new.hrsp_5xx < previous.hrsp_5xx then null else new.hrsp_5xx - previous.hrsp_5xx end;
        new.delta_econ := case when previous.econ is null or new.econ is null then null when new.restarted then new.econ when new.econ < previous.econ then null else new.econ - previous.econ end;
        new.delta_wretr := case when previous.wretr is null or new.wretr is null then null when new.restarted then new.wretr when new.wretr < previous.wretr then null else new.wretr - previous.wretr end;
        new.delta_bin := case when previous.bin is null or new.bin is null then null when new.restarted then new.bin when new.bin < previous.bin then null else new.bin - previous.bin end;
        new.delta_bout := case when previous.bout is null or new.bout is null then null when new.restarted then new.bout when new.bout < previous.bout then null else new.bout - previous.bout end;
        return new;
    end;
    $$;

CREATE FUNCTION public.metric_frontend_hour_delta_add() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
    begin
        
        insert into metric_frontend_hour_delta as kept (cluster, frontend, node, hour, crossing, first_previous_at, last_observed_at, restarted, samples, span_sec, span_clean_sec, delta_req_tot, span_req_tot_sec, delta_hrsp_2xx, span_hrsp_2xx_sec, delta_hrsp_3xx, span_hrsp_3xx_sec, delta_hrsp_4xx, span_hrsp_4xx_sec, delta_hrsp_5xx, span_hrsp_5xx_sec, delta_econ, span_econ_sec, delta_wretr, span_wretr_sec, delta_bin, span_bin_sec, delta_bout, span_bout_sec)
        select cluster, frontend, node, date_trunc('hour', observed_at, 'UTC'), previous_at < date_trunc('hour', observed_at, 'UTC'),
               min(previous_at),
           max(observed_at),
           bool_or(restarted),
           count(*),
           sum(extract(epoch from observed_at - previous_at)),
           coalesce(sum(extract(epoch from observed_at - previous_at)) filter (where not restarted), 0),
           sum(delta_req_tot), coalesce(sum(extract(epoch from observed_at - previous_at)) filter (where delta_req_tot is not null and not restarted), 0),
           sum(delta_hrsp_2xx), coalesce(sum(extract(epoch from observed_at - previous_at)) filter (where delta_hrsp_2xx is not null and not restarted), 0),
           sum(delta_hrsp_3xx), coalesce(sum(extract(epoch from observed_at - previous_at)) filter (where delta_hrsp_3xx is not null and not restarted), 0),
           sum(delta_hrsp_4xx), coalesce(sum(extract(epoch from observed_at - previous_at)) filter (where delta_hrsp_4xx is not null and not restarted), 0),
           sum(delta_hrsp_5xx), coalesce(sum(extract(epoch from observed_at - previous_at)) filter (where delta_hrsp_5xx is not null and not restarted), 0),
           sum(delta_econ), coalesce(sum(extract(epoch from observed_at - previous_at)) filter (where delta_econ is not null and not restarted), 0),
           sum(delta_wretr), coalesce(sum(extract(epoch from observed_at - previous_at)) filter (where delta_wretr is not null and not restarted), 0),
           sum(delta_bin), coalesce(sum(extract(epoch from observed_at - previous_at)) filter (where delta_bin is not null and not restarted), 0),
           sum(delta_bout), coalesce(sum(extract(epoch from observed_at - previous_at)) filter (where delta_bout is not null and not restarted), 0)
          from added
         where previous_at is not null 
         group by 1, 2, 3, 4, 5
        
        on conflict (cluster, frontend, node, hour, crossing) do update
           set first_previous_at = least(kept.first_previous_at, excluded.first_previous_at),
               last_observed_at = greatest(kept.last_observed_at, excluded.last_observed_at),
               restarted = kept.restarted or excluded.restarted,
               samples = kept.samples + excluded.samples,
               span_sec = kept.span_sec + excluded.span_sec,
               span_clean_sec = kept.span_clean_sec + excluded.span_clean_sec,
               delta_req_tot = case when kept.delta_req_tot is null then excluded.delta_req_tot when excluded.delta_req_tot is null then kept.delta_req_tot else kept.delta_req_tot + excluded.delta_req_tot end,
               span_req_tot_sec = kept.span_req_tot_sec + excluded.span_req_tot_sec,
               delta_hrsp_2xx = case when kept.delta_hrsp_2xx is null then excluded.delta_hrsp_2xx when excluded.delta_hrsp_2xx is null then kept.delta_hrsp_2xx else kept.delta_hrsp_2xx + excluded.delta_hrsp_2xx end,
               span_hrsp_2xx_sec = kept.span_hrsp_2xx_sec + excluded.span_hrsp_2xx_sec,
               delta_hrsp_3xx = case when kept.delta_hrsp_3xx is null then excluded.delta_hrsp_3xx when excluded.delta_hrsp_3xx is null then kept.delta_hrsp_3xx else kept.delta_hrsp_3xx + excluded.delta_hrsp_3xx end,
               span_hrsp_3xx_sec = kept.span_hrsp_3xx_sec + excluded.span_hrsp_3xx_sec,
               delta_hrsp_4xx = case when kept.delta_hrsp_4xx is null then excluded.delta_hrsp_4xx when excluded.delta_hrsp_4xx is null then kept.delta_hrsp_4xx else kept.delta_hrsp_4xx + excluded.delta_hrsp_4xx end,
               span_hrsp_4xx_sec = kept.span_hrsp_4xx_sec + excluded.span_hrsp_4xx_sec,
               delta_hrsp_5xx = case when kept.delta_hrsp_5xx is null then excluded.delta_hrsp_5xx when excluded.delta_hrsp_5xx is null then kept.delta_hrsp_5xx else kept.delta_hrsp_5xx + excluded.delta_hrsp_5xx end,
               span_hrsp_5xx_sec = kept.span_hrsp_5xx_sec + excluded.span_hrsp_5xx_sec,
               delta_econ = case when kept.delta_econ is null then excluded.delta_econ when excluded.delta_econ is null then kept.delta_econ else kept.delta_econ + excluded.delta_econ end,
               span_econ_sec = kept.span_econ_sec + excluded.span_econ_sec,
               delta_wretr = case when kept.delta_wretr is null then excluded.delta_wretr when excluded.delta_wretr is null then kept.delta_wretr else kept.delta_wretr + excluded.delta_wretr end,
               span_wretr_sec = kept.span_wretr_sec + excluded.span_wretr_sec,
               delta_bin = case when kept.delta_bin is null then excluded.delta_bin when excluded.delta_bin is null then kept.delta_bin else kept.delta_bin + excluded.delta_bin end,
               span_bin_sec = kept.span_bin_sec + excluded.span_bin_sec,
               delta_bout = case when kept.delta_bout is null then excluded.delta_bout when excluded.delta_bout is null then kept.delta_bout else kept.delta_bout + excluded.delta_bout end,
               span_bout_sec = kept.span_bout_sec + excluded.span_bout_sec;
        return null;
    end;
    $$;

REVOKE ALL ON FUNCTION public.metric_frontend_hour_delta_add() FROM PUBLIC;

CREATE FUNCTION public.metric_backend_member_delta() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path TO 'pg_catalog', 'public'
    AS $$
    declare
        previous record;
    begin
        select observed_at, uptime_sec, req_tot, hrsp_2xx, hrsp_3xx, hrsp_4xx, hrsp_5xx, econ, wretr, bin, bout, dns_queries, dns_tcp, dns_refused, dns_answered, syslog_messages, syslog_bytes
          into previous
          from metric_backend_member
         where cluster = new.cluster and node = new.node
           and backend = new.backend and member = new.member
           and observed_at < new.observed_at
           and observed_at >= new.observed_at - interval '31 days'
         order by observed_at desc
         limit 1;
        if not found then
            new.previous_at := null;
            new.restarted := null;
            return new;
        end if;
        new.previous_at := previous.observed_at;
        new.restarted := coalesce(new.uptime_sec < previous.uptime_sec, false)
            and (not coalesce(new.counters_kept, false)
                 or coalesce(new.req_tot < previous.req_tot, false) or coalesce(new.hrsp_2xx < previous.hrsp_2xx, false) or coalesce(new.hrsp_3xx < previous.hrsp_3xx, false) or coalesce(new.hrsp_4xx < previous.hrsp_4xx, false) or coalesce(new.hrsp_5xx < previous.hrsp_5xx, false) or coalesce(new.econ < previous.econ, false) or coalesce(new.wretr < previous.wretr, false) or coalesce(new.bin < previous.bin, false) or coalesce(new.bout < previous.bout, false) or coalesce(new.dns_queries < previous.dns_queries, false) or coalesce(new.dns_tcp < previous.dns_tcp, false) or coalesce(new.dns_refused < previous.dns_refused, false) or coalesce(new.dns_answered < previous.dns_answered, false) or coalesce(new.syslog_messages < previous.syslog_messages, false) or coalesce(new.syslog_bytes < previous.syslog_bytes, false));
        new.delta_req_tot := case when previous.req_tot is null or new.req_tot is null then null when new.restarted then new.req_tot when new.req_tot < previous.req_tot then null else new.req_tot - previous.req_tot end;
        new.delta_hrsp_2xx := case when previous.hrsp_2xx is null or new.hrsp_2xx is null then null when new.restarted then new.hrsp_2xx when new.hrsp_2xx < previous.hrsp_2xx then null else new.hrsp_2xx - previous.hrsp_2xx end;
        new.delta_hrsp_3xx := case when previous.hrsp_3xx is null or new.hrsp_3xx is null then null when new.restarted then new.hrsp_3xx when new.hrsp_3xx < previous.hrsp_3xx then null else new.hrsp_3xx - previous.hrsp_3xx end;
        new.delta_hrsp_4xx := case when previous.hrsp_4xx is null or new.hrsp_4xx is null then null when new.restarted then new.hrsp_4xx when new.hrsp_4xx < previous.hrsp_4xx then null else new.hrsp_4xx - previous.hrsp_4xx end;
        new.delta_hrsp_5xx := case when previous.hrsp_5xx is null or new.hrsp_5xx is null then null when new.restarted then new.hrsp_5xx when new.hrsp_5xx < previous.hrsp_5xx then null else new.hrsp_5xx - previous.hrsp_5xx end;
        new.delta_econ := case when previous.econ is null or new.econ is null then null when new.restarted then new.econ when new.econ < previous.econ then null else new.econ - previous.econ end;
        new.delta_wretr := case when previous.wretr is null or new.wretr is null then null when new.restarted then new.wretr when new.wretr < previous.wretr then null else new.wretr - previous.wretr end;
        new.delta_bin := case when previous.bin is null or new.bin is null then null when new.restarted then new.bin when new.bin < previous.bin then null else new.bin - previous.bin end;
        new.delta_bout := case when previous.bout is null or new.bout is null then null when new.restarted then new.bout when new.bout < previous.bout then null else new.bout - previous.bout end;
        new.delta_dns_queries := case when previous.dns_queries is null or new.dns_queries is null then null when new.restarted then new.dns_queries when new.dns_queries < previous.dns_queries then null else new.dns_queries - previous.dns_queries end;
        new.delta_dns_tcp := case when previous.dns_tcp is null or new.dns_tcp is null then null when new.restarted then new.dns_tcp when new.dns_tcp < previous.dns_tcp then null else new.dns_tcp - previous.dns_tcp end;
        new.delta_dns_refused := case when previous.dns_refused is null or new.dns_refused is null then null when new.restarted then new.dns_refused when new.dns_refused < previous.dns_refused then null else new.dns_refused - previous.dns_refused end;
        new.delta_dns_answered := case when previous.dns_answered is null or new.dns_answered is null then null when new.restarted then new.dns_answered when new.dns_answered < previous.dns_answered then null else new.dns_answered - previous.dns_answered end;
        new.delta_syslog_messages := case when previous.syslog_messages is null or new.syslog_messages is null then null when new.restarted then new.syslog_messages when new.syslog_messages < previous.syslog_messages then null else new.syslog_messages - previous.syslog_messages end;
        new.delta_syslog_bytes := case when previous.syslog_bytes is null or new.syslog_bytes is null then null when new.restarted then new.syslog_bytes when new.syslog_bytes < previous.syslog_bytes then null else new.syslog_bytes - previous.syslog_bytes end;
        return new;
    end;
    $$;

CREATE FUNCTION public.metric_backend_hour_delta_add() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
    begin
        insert into metric_backend_hour_delta as kept
               (cluster, backend, member, node, hour, crossing, first_previous_at, last_observed_at, restarted, samples, span_sec, span_clean_sec, delta_req_tot, span_req_tot_sec, delta_hrsp_2xx, span_hrsp_2xx_sec, delta_hrsp_3xx, span_hrsp_3xx_sec, delta_hrsp_4xx, span_hrsp_4xx_sec, delta_hrsp_5xx, span_hrsp_5xx_sec, delta_econ, span_econ_sec, delta_wretr, span_wretr_sec, delta_bin, span_bin_sec, delta_bout, span_bout_sec, delta_dns_queries, span_dns_queries_sec, delta_dns_tcp, span_dns_tcp_sec, delta_dns_refused, span_dns_refused_sec, delta_dns_answered, span_dns_answered_sec, delta_syslog_messages, span_syslog_messages_sec, delta_syslog_bytes, span_syslog_bytes_sec)
        select cluster, backend, member, node, date_trunc('hour', observed_at, 'UTC'), previous_at < date_trunc('hour', observed_at, 'UTC'),
               min(previous_at),
               max(observed_at),
               bool_or(restarted),
               count(*),
               sum(extract(epoch from observed_at - previous_at)),
               coalesce(sum(extract(epoch from observed_at - previous_at)) filter (where not restarted), 0),
               sum(delta_req_tot), coalesce(sum(extract(epoch from observed_at - previous_at)) filter (where delta_req_tot is not null and not restarted), 0),
               sum(delta_hrsp_2xx), coalesce(sum(extract(epoch from observed_at - previous_at)) filter (where delta_hrsp_2xx is not null and not restarted), 0),
               sum(delta_hrsp_3xx), coalesce(sum(extract(epoch from observed_at - previous_at)) filter (where delta_hrsp_3xx is not null and not restarted), 0),
               sum(delta_hrsp_4xx), coalesce(sum(extract(epoch from observed_at - previous_at)) filter (where delta_hrsp_4xx is not null and not restarted), 0),
               sum(delta_hrsp_5xx), coalesce(sum(extract(epoch from observed_at - previous_at)) filter (where delta_hrsp_5xx is not null and not restarted), 0),
               sum(delta_econ), coalesce(sum(extract(epoch from observed_at - previous_at)) filter (where delta_econ is not null and not restarted), 0),
               sum(delta_wretr), coalesce(sum(extract(epoch from observed_at - previous_at)) filter (where delta_wretr is not null and not restarted), 0),
               sum(delta_bin), coalesce(sum(extract(epoch from observed_at - previous_at)) filter (where delta_bin is not null and not restarted), 0),
               sum(delta_bout), coalesce(sum(extract(epoch from observed_at - previous_at)) filter (where delta_bout is not null and not restarted), 0),
               sum(delta_dns_queries), coalesce(sum(extract(epoch from observed_at - previous_at)) filter (where delta_dns_queries is not null and not restarted), 0),
               sum(delta_dns_tcp), coalesce(sum(extract(epoch from observed_at - previous_at)) filter (where delta_dns_tcp is not null and not restarted), 0),
               sum(delta_dns_refused), coalesce(sum(extract(epoch from observed_at - previous_at)) filter (where delta_dns_refused is not null and not restarted), 0),
               sum(delta_dns_answered), coalesce(sum(extract(epoch from observed_at - previous_at)) filter (where delta_dns_answered is not null and not restarted), 0),
               sum(delta_syslog_messages), coalesce(sum(extract(epoch from observed_at - previous_at)) filter (where delta_syslog_messages is not null and not restarted), 0),
               sum(delta_syslog_bytes), coalesce(sum(extract(epoch from observed_at - previous_at)) filter (where delta_syslog_bytes is not null and not restarted), 0)
          from added
         where previous_at is not null
         group by 1, 2, 3, 4, 5, 6
        
        on conflict (cluster, backend, member, node, hour, crossing) do update
           set first_previous_at = least(kept.first_previous_at, excluded.first_previous_at),
               last_observed_at = greatest(kept.last_observed_at, excluded.last_observed_at),
               restarted = kept.restarted or excluded.restarted,
               samples = kept.samples + excluded.samples,
               span_sec = kept.span_sec + excluded.span_sec,
               span_clean_sec = kept.span_clean_sec + excluded.span_clean_sec,
               delta_req_tot = case when kept.delta_req_tot is null then excluded.delta_req_tot when excluded.delta_req_tot is null then kept.delta_req_tot else kept.delta_req_tot + excluded.delta_req_tot end,
               span_req_tot_sec = kept.span_req_tot_sec + excluded.span_req_tot_sec,
               delta_hrsp_2xx = case when kept.delta_hrsp_2xx is null then excluded.delta_hrsp_2xx when excluded.delta_hrsp_2xx is null then kept.delta_hrsp_2xx else kept.delta_hrsp_2xx + excluded.delta_hrsp_2xx end,
               span_hrsp_2xx_sec = kept.span_hrsp_2xx_sec + excluded.span_hrsp_2xx_sec,
               delta_hrsp_3xx = case when kept.delta_hrsp_3xx is null then excluded.delta_hrsp_3xx when excluded.delta_hrsp_3xx is null then kept.delta_hrsp_3xx else kept.delta_hrsp_3xx + excluded.delta_hrsp_3xx end,
               span_hrsp_3xx_sec = kept.span_hrsp_3xx_sec + excluded.span_hrsp_3xx_sec,
               delta_hrsp_4xx = case when kept.delta_hrsp_4xx is null then excluded.delta_hrsp_4xx when excluded.delta_hrsp_4xx is null then kept.delta_hrsp_4xx else kept.delta_hrsp_4xx + excluded.delta_hrsp_4xx end,
               span_hrsp_4xx_sec = kept.span_hrsp_4xx_sec + excluded.span_hrsp_4xx_sec,
               delta_hrsp_5xx = case when kept.delta_hrsp_5xx is null then excluded.delta_hrsp_5xx when excluded.delta_hrsp_5xx is null then kept.delta_hrsp_5xx else kept.delta_hrsp_5xx + excluded.delta_hrsp_5xx end,
               span_hrsp_5xx_sec = kept.span_hrsp_5xx_sec + excluded.span_hrsp_5xx_sec,
               delta_econ = case when kept.delta_econ is null then excluded.delta_econ when excluded.delta_econ is null then kept.delta_econ else kept.delta_econ + excluded.delta_econ end,
               span_econ_sec = kept.span_econ_sec + excluded.span_econ_sec,
               delta_wretr = case when kept.delta_wretr is null then excluded.delta_wretr when excluded.delta_wretr is null then kept.delta_wretr else kept.delta_wretr + excluded.delta_wretr end,
               span_wretr_sec = kept.span_wretr_sec + excluded.span_wretr_sec,
               delta_bin = case when kept.delta_bin is null then excluded.delta_bin when excluded.delta_bin is null then kept.delta_bin else kept.delta_bin + excluded.delta_bin end,
               span_bin_sec = kept.span_bin_sec + excluded.span_bin_sec,
               delta_bout = case when kept.delta_bout is null then excluded.delta_bout when excluded.delta_bout is null then kept.delta_bout else kept.delta_bout + excluded.delta_bout end,
               span_bout_sec = kept.span_bout_sec + excluded.span_bout_sec,
               delta_dns_queries = case when kept.delta_dns_queries is null then excluded.delta_dns_queries when excluded.delta_dns_queries is null then kept.delta_dns_queries else kept.delta_dns_queries + excluded.delta_dns_queries end,
               span_dns_queries_sec = kept.span_dns_queries_sec + excluded.span_dns_queries_sec,
               delta_dns_tcp = case when kept.delta_dns_tcp is null then excluded.delta_dns_tcp when excluded.delta_dns_tcp is null then kept.delta_dns_tcp else kept.delta_dns_tcp + excluded.delta_dns_tcp end,
               span_dns_tcp_sec = kept.span_dns_tcp_sec + excluded.span_dns_tcp_sec,
               delta_dns_refused = case when kept.delta_dns_refused is null then excluded.delta_dns_refused when excluded.delta_dns_refused is null then kept.delta_dns_refused else kept.delta_dns_refused + excluded.delta_dns_refused end,
               span_dns_refused_sec = kept.span_dns_refused_sec + excluded.span_dns_refused_sec,
               delta_dns_answered = case when kept.delta_dns_answered is null then excluded.delta_dns_answered when excluded.delta_dns_answered is null then kept.delta_dns_answered else kept.delta_dns_answered + excluded.delta_dns_answered end,
               span_dns_answered_sec = kept.span_dns_answered_sec + excluded.span_dns_answered_sec,
               delta_syslog_messages = case when kept.delta_syslog_messages is null then excluded.delta_syslog_messages when excluded.delta_syslog_messages is null then kept.delta_syslog_messages else kept.delta_syslog_messages + excluded.delta_syslog_messages end,
               span_syslog_messages_sec = kept.span_syslog_messages_sec + excluded.span_syslog_messages_sec,
               delta_syslog_bytes = case when kept.delta_syslog_bytes is null then excluded.delta_syslog_bytes when excluded.delta_syslog_bytes is null then kept.delta_syslog_bytes else kept.delta_syslog_bytes + excluded.delta_syslog_bytes end,
               span_syslog_bytes_sec = kept.span_syslog_bytes_sec + excluded.span_syslog_bytes_sec;
        return null;
    end;
    $$;

REVOKE ALL ON FUNCTION public.metric_backend_hour_delta_add() FROM PUBLIC;

CREATE TABLE public.metric_frontend (
    cluster text NOT NULL,
    node text NOT NULL,
    frontend text NOT NULL,
    observed_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    owns_vip boolean,
    uptime_sec bigint,
    status text,
    scur bigint,
    stot bigint,
    bin bigint,
    bout bigint,
    req_tot bigint,
    qcur bigint,
    ereq bigint,
    econ bigint,
    eresp bigint,
    dreq bigint,
    dresp bigint,
    wretr bigint,
    wredis bigint,
    hrsp_2xx bigint,
    hrsp_3xx bigint,
    hrsp_4xx bigint,
    hrsp_5xx bigint,
    previous_at timestamp with time zone,
    restarted boolean,
    delta_req_tot bigint,
    delta_hrsp_2xx bigint,
    delta_hrsp_3xx bigint,
    delta_hrsp_4xx bigint,
    delta_hrsp_5xx bigint,
    delta_econ bigint,
    delta_wretr bigint,
    delta_bin bigint,
    delta_bout bigint,
    counters_kept boolean,
    CONSTRAINT metric_frontend_cluster_shape CHECK ((cluster ~ '^[a-z][a-z0-9-]{0,62}$'::text))
)
PARTITION BY RANGE (observed_at);
ALTER TABLE ONLY public.metric_frontend
    ADD CONSTRAINT metric_frontend_pkey PRIMARY KEY (cluster, node, frontend, observed_at);
CREATE INDEX metric_frontend_holder ON ONLY public.metric_frontend USING btree (cluster, node, frontend, observed_at) WHERE owns_vip;
CREATE INDEX metric_frontend_read ON ONLY public.metric_frontend USING btree (cluster, frontend, observed_at);
CREATE TRIGGER metric_frontend_delta BEFORE INSERT ON public.metric_frontend FOR EACH ROW EXECUTE FUNCTION public.metric_frontend_delta();
CREATE TRIGGER metric_frontend_hour_delta_add AFTER INSERT ON public.metric_frontend REFERENCING NEW TABLE AS added FOR EACH STATEMENT EXECUTE FUNCTION public.metric_frontend_hour_delta_add();
GRANT SELECT(cluster),INSERT(cluster) ON TABLE public.metric_frontend TO app_poller;
GRANT SELECT(cluster) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(node),INSERT(node) ON TABLE public.metric_frontend TO app_poller;
GRANT SELECT(node) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(frontend),INSERT(frontend) ON TABLE public.metric_frontend TO app_poller;
GRANT SELECT(frontend) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(observed_at) ON TABLE public.metric_frontend TO app_poller;
GRANT SELECT(observed_at) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(owns_vip),INSERT(owns_vip) ON TABLE public.metric_frontend TO app_poller;
GRANT SELECT(owns_vip) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(uptime_sec),INSERT(uptime_sec) ON TABLE public.metric_frontend TO app_poller;
GRANT SELECT(uptime_sec) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(status),INSERT(status) ON TABLE public.metric_frontend TO app_poller;
GRANT SELECT(status) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(scur),INSERT(scur) ON TABLE public.metric_frontend TO app_poller;
GRANT SELECT(scur) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(stot),INSERT(stot) ON TABLE public.metric_frontend TO app_poller;
GRANT SELECT(stot) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(bin),INSERT(bin) ON TABLE public.metric_frontend TO app_poller;
GRANT SELECT(bin) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(bout),INSERT(bout) ON TABLE public.metric_frontend TO app_poller;
GRANT SELECT(bout) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(req_tot),INSERT(req_tot) ON TABLE public.metric_frontend TO app_poller;
GRANT SELECT(req_tot) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(qcur),INSERT(qcur) ON TABLE public.metric_frontend TO app_poller;
GRANT SELECT(qcur) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(ereq),INSERT(ereq) ON TABLE public.metric_frontend TO app_poller;
GRANT SELECT(ereq) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(econ),INSERT(econ) ON TABLE public.metric_frontend TO app_poller;
GRANT SELECT(econ) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(eresp),INSERT(eresp) ON TABLE public.metric_frontend TO app_poller;
GRANT SELECT(eresp) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(dreq),INSERT(dreq) ON TABLE public.metric_frontend TO app_poller;
GRANT SELECT(dreq) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(dresp),INSERT(dresp) ON TABLE public.metric_frontend TO app_poller;
GRANT SELECT(dresp) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(wretr),INSERT(wretr) ON TABLE public.metric_frontend TO app_poller;
GRANT SELECT(wretr) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(wredis),INSERT(wredis) ON TABLE public.metric_frontend TO app_poller;
GRANT SELECT(wredis) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(hrsp_2xx),INSERT(hrsp_2xx) ON TABLE public.metric_frontend TO app_poller;
GRANT SELECT(hrsp_2xx) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(hrsp_3xx),INSERT(hrsp_3xx) ON TABLE public.metric_frontend TO app_poller;
GRANT SELECT(hrsp_3xx) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(hrsp_4xx),INSERT(hrsp_4xx) ON TABLE public.metric_frontend TO app_poller;
GRANT SELECT(hrsp_4xx) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(hrsp_5xx),INSERT(hrsp_5xx) ON TABLE public.metric_frontend TO app_poller;
GRANT SELECT(hrsp_5xx) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(previous_at) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(restarted) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(delta_req_tot) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(delta_hrsp_2xx) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(delta_hrsp_3xx) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(delta_hrsp_4xx) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(delta_hrsp_5xx) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(delta_econ) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(delta_wretr) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(delta_bin) ON TABLE public.metric_frontend TO app_web;
GRANT SELECT(delta_bout) ON TABLE public.metric_frontend TO app_web;
GRANT INSERT(counters_kept) ON TABLE public.metric_frontend TO app_poller;

CREATE TABLE public.metric_frontend_hour_delta (
    cluster text NOT NULL,
    frontend text NOT NULL,
    node text NOT NULL,
    hour timestamp with time zone NOT NULL,
    crossing boolean NOT NULL,
    first_previous_at timestamp with time zone NOT NULL,
    last_observed_at timestamp with time zone NOT NULL,
    restarted boolean NOT NULL,
    samples integer NOT NULL,
    span_sec numeric NOT NULL,
    span_clean_sec numeric NOT NULL,
    delta_req_tot bigint,
    span_req_tot_sec numeric NOT NULL,
    delta_hrsp_2xx bigint,
    span_hrsp_2xx_sec numeric NOT NULL,
    delta_hrsp_3xx bigint,
    span_hrsp_3xx_sec numeric NOT NULL,
    delta_hrsp_4xx bigint,
    span_hrsp_4xx_sec numeric NOT NULL,
    delta_hrsp_5xx bigint,
    span_hrsp_5xx_sec numeric NOT NULL,
    delta_econ bigint,
    span_econ_sec numeric NOT NULL,
    delta_wretr bigint,
    span_wretr_sec numeric NOT NULL,
    delta_bin bigint,
    span_bin_sec numeric NOT NULL,
    delta_bout bigint,
    span_bout_sec numeric NOT NULL
);
ALTER TABLE ONLY public.metric_frontend_hour_delta
    ADD CONSTRAINT metric_frontend_hour_delta_pkey PRIMARY KEY (cluster, frontend, node, hour, crossing);
CREATE INDEX metric_frontend_hour_delta_hour ON public.metric_frontend_hour_delta USING btree (hour);
GRANT SELECT(cluster) ON TABLE public.metric_frontend_hour_delta TO app_web;
GRANT SELECT(frontend) ON TABLE public.metric_frontend_hour_delta TO app_web;
GRANT SELECT(node) ON TABLE public.metric_frontend_hour_delta TO app_web;
GRANT SELECT(hour) ON TABLE public.metric_frontend_hour_delta TO app_web;
GRANT SELECT(crossing) ON TABLE public.metric_frontend_hour_delta TO app_web;
GRANT SELECT(first_previous_at) ON TABLE public.metric_frontend_hour_delta TO app_web;
GRANT SELECT(last_observed_at) ON TABLE public.metric_frontend_hour_delta TO app_web;
GRANT SELECT(restarted) ON TABLE public.metric_frontend_hour_delta TO app_web;
GRANT SELECT(samples) ON TABLE public.metric_frontend_hour_delta TO app_web;
GRANT SELECT(span_sec) ON TABLE public.metric_frontend_hour_delta TO app_web;
GRANT SELECT(span_clean_sec) ON TABLE public.metric_frontend_hour_delta TO app_web;
GRANT SELECT(delta_req_tot) ON TABLE public.metric_frontend_hour_delta TO app_web;
GRANT SELECT(span_req_tot_sec) ON TABLE public.metric_frontend_hour_delta TO app_web;
GRANT SELECT(delta_hrsp_2xx) ON TABLE public.metric_frontend_hour_delta TO app_web;
GRANT SELECT(span_hrsp_2xx_sec) ON TABLE public.metric_frontend_hour_delta TO app_web;
GRANT SELECT(delta_hrsp_3xx) ON TABLE public.metric_frontend_hour_delta TO app_web;
GRANT SELECT(span_hrsp_3xx_sec) ON TABLE public.metric_frontend_hour_delta TO app_web;
GRANT SELECT(delta_hrsp_4xx) ON TABLE public.metric_frontend_hour_delta TO app_web;
GRANT SELECT(span_hrsp_4xx_sec) ON TABLE public.metric_frontend_hour_delta TO app_web;
GRANT SELECT(delta_hrsp_5xx) ON TABLE public.metric_frontend_hour_delta TO app_web;
GRANT SELECT(span_hrsp_5xx_sec) ON TABLE public.metric_frontend_hour_delta TO app_web;
GRANT SELECT(delta_econ) ON TABLE public.metric_frontend_hour_delta TO app_web;
GRANT SELECT(span_econ_sec) ON TABLE public.metric_frontend_hour_delta TO app_web;
GRANT SELECT(delta_wretr) ON TABLE public.metric_frontend_hour_delta TO app_web;
GRANT SELECT(span_wretr_sec) ON TABLE public.metric_frontend_hour_delta TO app_web;
GRANT SELECT(delta_bin) ON TABLE public.metric_frontend_hour_delta TO app_web;
GRANT SELECT(span_bin_sec) ON TABLE public.metric_frontend_hour_delta TO app_web;
GRANT SELECT(delta_bout) ON TABLE public.metric_frontend_hour_delta TO app_web;
GRANT SELECT(span_bout_sec) ON TABLE public.metric_frontend_hour_delta TO app_web;

CREATE TABLE public.metric_backend_member (
    cluster text NOT NULL,
    node text NOT NULL,
    backend text NOT NULL,
    member text NOT NULL,
    observed_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    uptime_sec bigint,
    status text,
    check_status text,
    check_code text,
    scur bigint,
    stot bigint,
    bin bigint,
    bout bigint,
    req_tot bigint,
    qcur bigint,
    ereq bigint,
    econ bigint,
    eresp bigint,
    dreq bigint,
    dresp bigint,
    wretr bigint,
    wredis bigint,
    hrsp_2xx bigint,
    hrsp_3xx bigint,
    hrsp_4xx bigint,
    hrsp_5xx bigint,
    previous_at timestamp with time zone,
    restarted boolean,
    delta_req_tot bigint,
    delta_hrsp_2xx bigint,
    delta_hrsp_3xx bigint,
    delta_hrsp_4xx bigint,
    delta_hrsp_5xx bigint,
    delta_econ bigint,
    delta_wretr bigint,
    delta_bin bigint,
    delta_bout bigint,
    dns_queries bigint,
    dns_tcp bigint,
    dns_refused bigint,
    dns_answered bigint,
    delta_dns_queries bigint,
    delta_dns_tcp bigint,
    delta_dns_refused bigint,
    delta_dns_answered bigint,
    syslog_messages bigint,
    syslog_bytes bigint,
    delta_syslog_messages bigint,
    delta_syslog_bytes bigint,
    counters_kept boolean,
    CONSTRAINT metric_backend_member_cluster_shape CHECK ((cluster ~ '^[a-z][a-z0-9-]{0,62}$'::text))
)
PARTITION BY RANGE (observed_at);
ALTER TABLE ONLY public.metric_backend_member
    ADD CONSTRAINT metric_backend_member_pkey PRIMARY KEY (cluster, node, backend, member, observed_at);
CREATE INDEX metric_backend_member_read ON ONLY public.metric_backend_member USING btree (cluster, backend, member, observed_at);
CREATE TRIGGER metric_backend_hour_delta_add AFTER INSERT ON public.metric_backend_member REFERENCING NEW TABLE AS added FOR EACH STATEMENT EXECUTE FUNCTION public.metric_backend_hour_delta_add();
CREATE TRIGGER metric_backend_member_delta BEFORE INSERT ON public.metric_backend_member FOR EACH ROW EXECUTE FUNCTION public.metric_backend_member_delta();
GRANT SELECT(cluster),INSERT(cluster) ON TABLE public.metric_backend_member TO app_poller;
GRANT SELECT(cluster) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(node),INSERT(node) ON TABLE public.metric_backend_member TO app_poller;
GRANT SELECT(node) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(backend),INSERT(backend) ON TABLE public.metric_backend_member TO app_poller;
GRANT SELECT(backend) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(member),INSERT(member) ON TABLE public.metric_backend_member TO app_poller;
GRANT SELECT(member) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(observed_at) ON TABLE public.metric_backend_member TO app_poller;
GRANT SELECT(observed_at) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(uptime_sec),INSERT(uptime_sec) ON TABLE public.metric_backend_member TO app_poller;
GRANT SELECT(uptime_sec) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(status),INSERT(status) ON TABLE public.metric_backend_member TO app_poller;
GRANT SELECT(status) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(check_status),INSERT(check_status) ON TABLE public.metric_backend_member TO app_poller;
GRANT SELECT(check_status) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(check_code),INSERT(check_code) ON TABLE public.metric_backend_member TO app_poller;
GRANT SELECT(check_code) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(scur),INSERT(scur) ON TABLE public.metric_backend_member TO app_poller;
GRANT SELECT(scur) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(stot),INSERT(stot) ON TABLE public.metric_backend_member TO app_poller;
GRANT SELECT(stot) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(bin),INSERT(bin) ON TABLE public.metric_backend_member TO app_poller;
GRANT SELECT(bin) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(bout),INSERT(bout) ON TABLE public.metric_backend_member TO app_poller;
GRANT SELECT(bout) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(req_tot),INSERT(req_tot) ON TABLE public.metric_backend_member TO app_poller;
GRANT SELECT(req_tot) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(qcur),INSERT(qcur) ON TABLE public.metric_backend_member TO app_poller;
GRANT SELECT(qcur) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(ereq),INSERT(ereq) ON TABLE public.metric_backend_member TO app_poller;
GRANT SELECT(ereq) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(econ),INSERT(econ) ON TABLE public.metric_backend_member TO app_poller;
GRANT SELECT(econ) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(eresp),INSERT(eresp) ON TABLE public.metric_backend_member TO app_poller;
GRANT SELECT(eresp) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(dreq),INSERT(dreq) ON TABLE public.metric_backend_member TO app_poller;
GRANT SELECT(dreq) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(dresp),INSERT(dresp) ON TABLE public.metric_backend_member TO app_poller;
GRANT SELECT(dresp) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(wretr),INSERT(wretr) ON TABLE public.metric_backend_member TO app_poller;
GRANT SELECT(wretr) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(wredis),INSERT(wredis) ON TABLE public.metric_backend_member TO app_poller;
GRANT SELECT(wredis) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(hrsp_2xx),INSERT(hrsp_2xx) ON TABLE public.metric_backend_member TO app_poller;
GRANT SELECT(hrsp_2xx) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(hrsp_3xx),INSERT(hrsp_3xx) ON TABLE public.metric_backend_member TO app_poller;
GRANT SELECT(hrsp_3xx) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(hrsp_4xx),INSERT(hrsp_4xx) ON TABLE public.metric_backend_member TO app_poller;
GRANT SELECT(hrsp_4xx) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(hrsp_5xx),INSERT(hrsp_5xx) ON TABLE public.metric_backend_member TO app_poller;
GRANT SELECT(hrsp_5xx) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(previous_at) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(restarted) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(delta_req_tot) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(delta_hrsp_2xx) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(delta_hrsp_3xx) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(delta_hrsp_4xx) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(delta_hrsp_5xx) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(delta_econ) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(delta_wretr) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(delta_bin) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(delta_bout) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(dns_queries),INSERT(dns_queries) ON TABLE public.metric_backend_member TO app_poller;
GRANT SELECT(dns_queries) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(dns_tcp),INSERT(dns_tcp) ON TABLE public.metric_backend_member TO app_poller;
GRANT SELECT(dns_tcp) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(dns_refused),INSERT(dns_refused) ON TABLE public.metric_backend_member TO app_poller;
GRANT SELECT(dns_refused) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(dns_answered),INSERT(dns_answered) ON TABLE public.metric_backend_member TO app_poller;
GRANT SELECT(dns_answered) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(delta_dns_queries) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(delta_dns_tcp) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(delta_dns_refused) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(delta_dns_answered) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(syslog_messages),INSERT(syslog_messages) ON TABLE public.metric_backend_member TO app_poller;
GRANT SELECT(syslog_messages) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(syslog_bytes),INSERT(syslog_bytes) ON TABLE public.metric_backend_member TO app_poller;
GRANT SELECT(syslog_bytes) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(delta_syslog_messages) ON TABLE public.metric_backend_member TO app_web;
GRANT SELECT(delta_syslog_bytes) ON TABLE public.metric_backend_member TO app_web;
GRANT INSERT(counters_kept) ON TABLE public.metric_backend_member TO app_poller;

CREATE TABLE public.metric_backend_hour (
    cluster text NOT NULL,
    node text NOT NULL,
    backend text NOT NULL,
    member text NOT NULL,
    bucket_at timestamp with time zone NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    uptime_sec bigint,
    floor_uptime_sec bigint,
    status text,
    check_status text,
    check_code text,
    scur bigint,
    stot bigint,
    bin bigint,
    bout bigint,
    req_tot bigint,
    qcur bigint,
    ereq bigint,
    econ bigint,
    eresp bigint,
    dreq bigint,
    dresp bigint,
    wretr bigint,
    wredis bigint,
    hrsp_2xx bigint,
    hrsp_3xx bigint,
    hrsp_4xx bigint,
    hrsp_5xx bigint,
    CONSTRAINT metric_backend_hour_cluster_shape CHECK ((cluster ~ '^[a-z][a-z0-9-]{0,62}$'::text)),
    CONSTRAINT metric_backend_hour_on_the_hour CHECK ((bucket_at = date_trunc('hour'::text, bucket_at)))
)
PARTITION BY RANGE (bucket_at);
ALTER TABLE ONLY public.metric_backend_hour
    ADD CONSTRAINT metric_backend_hour_pkey PRIMARY KEY (cluster, node, backend, member, bucket_at);
GRANT SELECT(cluster) ON TABLE public.metric_backend_hour TO app_poller;
GRANT SELECT(cluster) ON TABLE public.metric_backend_hour TO app_web;
GRANT SELECT(node) ON TABLE public.metric_backend_hour TO app_poller;
GRANT SELECT(node) ON TABLE public.metric_backend_hour TO app_web;
GRANT SELECT(backend) ON TABLE public.metric_backend_hour TO app_poller;
GRANT SELECT(backend) ON TABLE public.metric_backend_hour TO app_web;
GRANT SELECT(member) ON TABLE public.metric_backend_hour TO app_poller;
GRANT SELECT(member) ON TABLE public.metric_backend_hour TO app_web;
GRANT SELECT(bucket_at) ON TABLE public.metric_backend_hour TO app_poller;
GRANT SELECT(bucket_at) ON TABLE public.metric_backend_hour TO app_web;
GRANT SELECT(observed_at) ON TABLE public.metric_backend_hour TO app_poller;
GRANT SELECT(observed_at) ON TABLE public.metric_backend_hour TO app_web;
GRANT SELECT(uptime_sec) ON TABLE public.metric_backend_hour TO app_poller;
GRANT SELECT(uptime_sec) ON TABLE public.metric_backend_hour TO app_web;
GRANT SELECT(floor_uptime_sec) ON TABLE public.metric_backend_hour TO app_poller;
GRANT SELECT(floor_uptime_sec) ON TABLE public.metric_backend_hour TO app_web;
GRANT SELECT(status) ON TABLE public.metric_backend_hour TO app_poller;
GRANT SELECT(status) ON TABLE public.metric_backend_hour TO app_web;
GRANT SELECT(check_status) ON TABLE public.metric_backend_hour TO app_poller;
GRANT SELECT(check_status) ON TABLE public.metric_backend_hour TO app_web;
GRANT SELECT(check_code) ON TABLE public.metric_backend_hour TO app_poller;
GRANT SELECT(check_code) ON TABLE public.metric_backend_hour TO app_web;
GRANT SELECT(scur) ON TABLE public.metric_backend_hour TO app_poller;
GRANT SELECT(scur) ON TABLE public.metric_backend_hour TO app_web;
GRANT SELECT(stot) ON TABLE public.metric_backend_hour TO app_poller;
GRANT SELECT(stot) ON TABLE public.metric_backend_hour TO app_web;
GRANT SELECT(bin) ON TABLE public.metric_backend_hour TO app_poller;
GRANT SELECT(bin) ON TABLE public.metric_backend_hour TO app_web;
GRANT SELECT(bout) ON TABLE public.metric_backend_hour TO app_poller;
GRANT SELECT(bout) ON TABLE public.metric_backend_hour TO app_web;
GRANT SELECT(req_tot) ON TABLE public.metric_backend_hour TO app_poller;
GRANT SELECT(req_tot) ON TABLE public.metric_backend_hour TO app_web;
GRANT SELECT(qcur) ON TABLE public.metric_backend_hour TO app_poller;
GRANT SELECT(qcur) ON TABLE public.metric_backend_hour TO app_web;
GRANT SELECT(ereq) ON TABLE public.metric_backend_hour TO app_poller;
GRANT SELECT(ereq) ON TABLE public.metric_backend_hour TO app_web;
GRANT SELECT(econ) ON TABLE public.metric_backend_hour TO app_poller;
GRANT SELECT(econ) ON TABLE public.metric_backend_hour TO app_web;
GRANT SELECT(eresp) ON TABLE public.metric_backend_hour TO app_poller;
GRANT SELECT(eresp) ON TABLE public.metric_backend_hour TO app_web;
GRANT SELECT(dreq) ON TABLE public.metric_backend_hour TO app_poller;
GRANT SELECT(dreq) ON TABLE public.metric_backend_hour TO app_web;
GRANT SELECT(dresp) ON TABLE public.metric_backend_hour TO app_poller;
GRANT SELECT(dresp) ON TABLE public.metric_backend_hour TO app_web;
GRANT SELECT(wretr) ON TABLE public.metric_backend_hour TO app_poller;
GRANT SELECT(wretr) ON TABLE public.metric_backend_hour TO app_web;
GRANT SELECT(wredis) ON TABLE public.metric_backend_hour TO app_poller;
GRANT SELECT(wredis) ON TABLE public.metric_backend_hour TO app_web;
GRANT SELECT(hrsp_2xx) ON TABLE public.metric_backend_hour TO app_poller;
GRANT SELECT(hrsp_2xx) ON TABLE public.metric_backend_hour TO app_web;
GRANT SELECT(hrsp_3xx) ON TABLE public.metric_backend_hour TO app_poller;
GRANT SELECT(hrsp_3xx) ON TABLE public.metric_backend_hour TO app_web;
GRANT SELECT(hrsp_4xx) ON TABLE public.metric_backend_hour TO app_poller;
GRANT SELECT(hrsp_4xx) ON TABLE public.metric_backend_hour TO app_web;
GRANT SELECT(hrsp_5xx) ON TABLE public.metric_backend_hour TO app_poller;
GRANT SELECT(hrsp_5xx) ON TABLE public.metric_backend_hour TO app_web;

CREATE TABLE public.metric_backend_hour_delta (
    cluster text NOT NULL,
    backend text NOT NULL,
    member text NOT NULL,
    node text NOT NULL,
    hour timestamp with time zone NOT NULL,
    crossing boolean NOT NULL,
    first_previous_at timestamp with time zone NOT NULL,
    last_observed_at timestamp with time zone NOT NULL,
    restarted boolean NOT NULL,
    samples integer NOT NULL,
    span_sec numeric NOT NULL,
    span_clean_sec numeric NOT NULL,
    delta_req_tot bigint,
    span_req_tot_sec numeric NOT NULL,
    delta_hrsp_2xx bigint,
    span_hrsp_2xx_sec numeric NOT NULL,
    delta_hrsp_3xx bigint,
    span_hrsp_3xx_sec numeric NOT NULL,
    delta_hrsp_4xx bigint,
    span_hrsp_4xx_sec numeric NOT NULL,
    delta_hrsp_5xx bigint,
    span_hrsp_5xx_sec numeric NOT NULL,
    delta_econ bigint,
    span_econ_sec numeric NOT NULL,
    delta_wretr bigint,
    span_wretr_sec numeric NOT NULL,
    delta_bin bigint,
    span_bin_sec numeric NOT NULL,
    delta_bout bigint,
    span_bout_sec numeric NOT NULL,
    delta_dns_queries bigint,
    span_dns_queries_sec numeric DEFAULT 0 NOT NULL,
    delta_dns_tcp bigint,
    span_dns_tcp_sec numeric DEFAULT 0 NOT NULL,
    delta_dns_refused bigint,
    span_dns_refused_sec numeric DEFAULT 0 NOT NULL,
    delta_dns_answered bigint,
    span_dns_answered_sec numeric DEFAULT 0 NOT NULL,
    delta_syslog_messages bigint,
    span_syslog_messages_sec numeric DEFAULT 0 NOT NULL,
    delta_syslog_bytes bigint,
    span_syslog_bytes_sec numeric DEFAULT 0 NOT NULL
);
ALTER TABLE ONLY public.metric_backend_hour_delta
    ADD CONSTRAINT metric_backend_hour_delta_pkey PRIMARY KEY (cluster, backend, member, node, hour, crossing);
CREATE INDEX metric_backend_hour_delta_hour ON public.metric_backend_hour_delta USING btree (hour);
GRANT SELECT(cluster) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(backend) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(member) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(node) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(hour) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(crossing) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(first_previous_at) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(last_observed_at) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(restarted) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(samples) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(span_sec) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(span_clean_sec) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(delta_req_tot) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(span_req_tot_sec) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(delta_hrsp_2xx) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(span_hrsp_2xx_sec) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(delta_hrsp_3xx) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(span_hrsp_3xx_sec) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(delta_hrsp_4xx) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(span_hrsp_4xx_sec) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(delta_hrsp_5xx) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(span_hrsp_5xx_sec) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(delta_econ) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(span_econ_sec) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(delta_wretr) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(span_wretr_sec) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(delta_bin) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(span_bin_sec) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(delta_bout) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(span_bout_sec) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(delta_dns_queries) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(span_dns_queries_sec) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(delta_dns_tcp) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(span_dns_tcp_sec) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(delta_dns_refused) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(span_dns_refused_sec) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(delta_dns_answered) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(span_dns_answered_sec) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(delta_syslog_messages) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(span_syslog_messages_sec) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(delta_syslog_bytes) ON TABLE public.metric_backend_hour_delta TO app_web;
GRANT SELECT(span_syslog_bytes_sec) ON TABLE public.metric_backend_hour_delta TO app_web;

CREATE TABLE public.metric_backend_alias (
    cluster text NOT NULL,
    old_name text NOT NULL,
    new_name text NOT NULL,
    renamed_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    reused_at timestamp with time zone,
    CONSTRAINT metric_backend_alias_cluster_shape CHECK ((cluster ~ '^[a-z][a-z0-9-]{0,62}$'::text)),
    CONSTRAINT metric_backend_alias_names CHECK ((((length(old_name) >= 1) AND (length(old_name) <= 128)) AND ((length(new_name) >= 1) AND (length(new_name) <= 128)) AND (old_name <> new_name)))
);
ALTER TABLE ONLY public.metric_backend_alias
    ADD CONSTRAINT metric_backend_alias_pkey PRIMARY KEY (cluster, old_name);
GRANT SELECT(cluster) ON TABLE public.metric_backend_alias TO app_web;
GRANT SELECT(cluster),INSERT(cluster) ON TABLE public.metric_backend_alias TO app_worker;
GRANT SELECT(old_name) ON TABLE public.metric_backend_alias TO app_web;
GRANT SELECT(old_name),INSERT(old_name) ON TABLE public.metric_backend_alias TO app_worker;
GRANT SELECT(new_name) ON TABLE public.metric_backend_alias TO app_web;
GRANT SELECT(new_name),INSERT(new_name),UPDATE(new_name) ON TABLE public.metric_backend_alias TO app_worker;
GRANT SELECT(renamed_at) ON TABLE public.metric_backend_alias TO app_web;
GRANT SELECT(renamed_at),UPDATE(renamed_at) ON TABLE public.metric_backend_alias TO app_worker;
GRANT SELECT(reused_at) ON TABLE public.metric_backend_alias TO app_web;
GRANT SELECT(reused_at),UPDATE(reused_at) ON TABLE public.metric_backend_alias TO app_worker;

CREATE TABLE public.metric_rollup_state (
    rollup_name text NOT NULL,
    complete_before timestamp with time zone NOT NULL,
    updated_at timestamp with time zone DEFAULT transaction_timestamp() NOT NULL,
    CONSTRAINT metric_rollup_state_boundary_on_the_hour CHECK ((complete_before = date_trunc('hour'::text, complete_before)))
);
ALTER TABLE ONLY public.metric_rollup_state
    ADD CONSTRAINT metric_rollup_state_pkey PRIMARY KEY (rollup_name);
GRANT SELECT(rollup_name) ON TABLE public.metric_rollup_state TO app_web;
GRANT SELECT(complete_before) ON TABLE public.metric_rollup_state TO app_web;
INSERT INTO public.metric_rollup_state (rollup_name, complete_before)
    VALUES ('backend_hour', date_trunc('hour', transaction_timestamp()) - interval '7 days');
"""


#
# The traffic log and what the WAF engine matched, written by the collector.
#
# Daily partitions, made ahead by `haprion-retention` and dropped whole when a
# day leaves the window; this migration makes the week before and after today.
# The collector inserts and reads nothing: it re-reads from a checkpoint, and
# a row whose `event_id` is already there is turned away by a trigger, so a
# repeat is harmless.
#
# The web reads the log through `traffic_log_read` and holds no grant on the
# table. With column grants alone PostgreSQL keeps the planner from the
# statistics of the trigram index the search uses, and a search that finds
# nothing read every row; a view's tables are checked as its owner. The view
# names what the web may see, and a test holds it to that.
#
# `waf_match` is one row per rule the engine matched on a request, with the
# matched value, read only by the trigger that counts it into
# `waf_finding_path` and `waf_finding_client` per hour - what the WAF page
# reads. Those two are not partitioned, for the reason the metric sums are not.
#
TRAFFIC = r"""
CREATE FUNCTION public.traffic_log_partition(day date) RETURNS text
    LANGUAGE plpgsql
    AS $$
    declare
        partition text := format('traffic_log_%s', to_char(day, 'YYYYMMDD'));
    begin
        execute format(
            'create table if not exists %I partition of traffic_log '
            'for values from (%L) to (%L)',
            partition, day, day + 1
        );
        execute format(
            'create index if not exists %I on %I using gin '
            '((host || '' '' || path || '' '' || backend) gin_trgm_ops)',
            partition || '_search', partition
        );
        execute format(
            'create index if not exists %I on %I (occurred_at) where rule <> ''''',
            partition || '_rule', partition
        );
        execute format(
            'create index if not exists %I on %I (cluster, occurred_at desc, request_number desc)',
            partition || '_cluster', partition
        );
        return partition;
    end;
    $$;

CREATE FUNCTION public.traffic_log_ignore_duplicate() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
    begin
        if exists (
            select 1 from traffic_log
             where occurred_at = new.occurred_at and event_id = new.event_id
        ) then
            return null;
        end if;
        return new;
    end;
    $$;

REVOKE ALL ON FUNCTION public.traffic_log_ignore_duplicate() FROM PUBLIC;

CREATE FUNCTION public.waf_match_partition(day date) RETURNS text
    LANGUAGE plpgsql
    AS $$
    declare
        partition text := format('waf_match_%s', to_char(day, 'YYYYMMDD'));
    begin
        execute format(
            'create table if not exists %I partition of waf_match '
            'for values from (%L) to (%L)',
            partition, day, day + 1
        );
        return partition;
    end;
    $$;

CREATE FUNCTION public.waf_match_ignore_duplicate() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$
    begin
        if exists (
            select 1 from waf_match
             where occurred_at = new.occurred_at and event_id = new.event_id
        ) then
            return null;
        end if;
        return new;
    end;
    $$;

REVOKE ALL ON FUNCTION public.waf_match_ignore_duplicate() FROM PUBLIC;

CREATE FUNCTION public.waf_finding_add() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog', 'public'
    AS $$ begin 
    insert into waf_finding_path as kept
           (cluster, object, rule_id, field, hour, path, requests, last_seen, matched)
    select cluster, object, rule_id, field, date_trunc('hour', occurred_at, 'UTC'), path,
           count(distinct request_id), max(occurred_at),
           (array_agg(matched order by occurred_at desc))[1]
      from added
     group by 1, 2, 3, 4, 5, 6
    on conflict (cluster, object, rule_id, field, hour, path) do update
       set requests = kept.requests + excluded.requests,
           matched = case when excluded.last_seen >= kept.last_seen
                          then excluded.matched else kept.matched end,
           last_seen = greatest(kept.last_seen, excluded.last_seen);

    insert into waf_finding_client (cluster, object, rule_id, field, hour, client, path)
    select distinct cluster, object, rule_id, field,
           date_trunc('hour', occurred_at, 'UTC'), client,
           case when rule_id < 900000 then path else '' end
      from added
    on conflict do nothing;
 return null; end; $$;

REVOKE ALL ON FUNCTION public.waf_finding_add() FROM PUBLIC;

CREATE TABLE public.traffic_log (
    event_id bytea NOT NULL,
    cluster text NOT NULL,
    node text NOT NULL,
    occurred_at timestamp with time zone NOT NULL,
    request_number bigint NOT NULL,
    client text NOT NULL,
    method text NOT NULL,
    host text NOT NULL,
    path text NOT NULL,
    frontend text NOT NULL,
    backend text NOT NULL,
    server text NOT NULL,
    status integer NOT NULL,
    request_time bigint NOT NULL,
    queue_time bigint NOT NULL,
    connect_time bigint NOT NULL,
    response_time bigint NOT NULL,
    total_time bigint NOT NULL,
    bytes bigint NOT NULL,
    inserted_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    rule text DEFAULT ''::text NOT NULL,
    waf_rules text DEFAULT ''::text NOT NULL,
    waf_score integer DEFAULT 0 NOT NULL,
    waf_id text DEFAULT ''::text NOT NULL,
    CONSTRAINT traffic_log_bytes_range CHECK ((bytes >= 0)),
    CONSTRAINT traffic_log_cluster_shape CHECK ((cluster ~ '^[a-z][a-z0-9-]{0,62}$'::text)),
    CONSTRAINT traffic_log_event_id_shape CHECK ((octet_length(event_id) = 32)),
    CONSTRAINT traffic_log_node_shape CHECK ((node ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$'::text)),
    CONSTRAINT traffic_log_rule_length CHECK ((char_length(rule) <= 160)),
    CONSTRAINT traffic_log_status_range CHECK (((status >= 0) AND (status <= 999))),
    CONSTRAINT traffic_log_waf_id_shape CHECK ((waf_id ~ '^([A-Za-z0-9_.-]{1,96})?$'::text)),
    CONSTRAINT traffic_log_waf_rules_form CHECK (((char_length(waf_rules) <= 1024) AND (waf_rules ~ '^([0-9]{6}(,[0-9]{6})*)?$'::text))),
    CONSTRAINT traffic_log_waf_score_range CHECK (((waf_score >= 0) AND (waf_score <= 100000)))
)
PARTITION BY RANGE (occurred_at);
ALTER TABLE ONLY public.traffic_log
    ADD CONSTRAINT traffic_log_pkey PRIMARY KEY (occurred_at, event_id);
CREATE TRIGGER traffic_log_duplicate BEFORE INSERT ON public.traffic_log FOR EACH ROW EXECUTE FUNCTION public.traffic_log_ignore_duplicate();
GRANT INSERT(event_id) ON TABLE public.traffic_log TO app_collector;
GRANT INSERT(cluster) ON TABLE public.traffic_log TO app_collector;
GRANT INSERT(node) ON TABLE public.traffic_log TO app_collector;
GRANT INSERT(occurred_at) ON TABLE public.traffic_log TO app_collector;
GRANT INSERT(request_number) ON TABLE public.traffic_log TO app_collector;
GRANT INSERT(client) ON TABLE public.traffic_log TO app_collector;
GRANT INSERT(method) ON TABLE public.traffic_log TO app_collector;
GRANT INSERT(host) ON TABLE public.traffic_log TO app_collector;
GRANT INSERT(path) ON TABLE public.traffic_log TO app_collector;
GRANT INSERT(frontend) ON TABLE public.traffic_log TO app_collector;
GRANT INSERT(backend) ON TABLE public.traffic_log TO app_collector;
GRANT INSERT(server) ON TABLE public.traffic_log TO app_collector;
GRANT INSERT(status) ON TABLE public.traffic_log TO app_collector;
GRANT INSERT(request_time) ON TABLE public.traffic_log TO app_collector;
GRANT INSERT(queue_time) ON TABLE public.traffic_log TO app_collector;
GRANT INSERT(connect_time) ON TABLE public.traffic_log TO app_collector;
GRANT INSERT(response_time) ON TABLE public.traffic_log TO app_collector;
GRANT INSERT(total_time) ON TABLE public.traffic_log TO app_collector;
GRANT INSERT(bytes) ON TABLE public.traffic_log TO app_collector;
GRANT INSERT(rule) ON TABLE public.traffic_log TO app_collector;
GRANT INSERT(waf_rules) ON TABLE public.traffic_log TO app_collector;
GRANT INSERT(waf_score) ON TABLE public.traffic_log TO app_collector;
GRANT INSERT(waf_id) ON TABLE public.traffic_log TO app_collector;
SELECT public.traffic_log_partition(day::date)
  FROM generate_series(current_date - 6, current_date + 7, interval '1 day') AS day;

CREATE VIEW public.traffic_log_read AS
 SELECT cluster,
    node,
    occurred_at,
    request_number,
    client,
    method,
    host,
    path,
    frontend,
    backend,
    server,
    status,
    request_time,
    queue_time,
    connect_time,
    response_time,
    total_time,
    bytes,
    rule,
    waf_rules,
    waf_score,
    waf_id
   FROM public.traffic_log;
GRANT SELECT ON TABLE public.traffic_log_read TO app_web;

CREATE TABLE public.waf_match (
    event_id bytea NOT NULL,
    cluster text NOT NULL,
    node text NOT NULL,
    occurred_at timestamp with time zone NOT NULL,
    request_id text NOT NULL,
    object text NOT NULL,
    rule_id integer NOT NULL,
    field text DEFAULT ''::text NOT NULL,
    matched text DEFAULT ''::text NOT NULL,
    path text DEFAULT ''::text NOT NULL,
    client text DEFAULT ''::text NOT NULL,
    inserted_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    CONSTRAINT waf_match_client_bound CHECK ((char_length(client) <= 64)),
    CONSTRAINT waf_match_cluster_shape CHECK ((cluster ~ '^[a-z][a-z0-9-]{0,62}$'::text)),
    CONSTRAINT waf_match_event_id_shape CHECK ((octet_length(event_id) = 32)),
    CONSTRAINT waf_match_field_form CHECK (((char_length(field) <= 256) AND (field !~ '[[:cntrl:]]'::text))),
    CONSTRAINT waf_match_matched_bound CHECK ((char_length(matched) <= 1024)),
    CONSTRAINT waf_match_node_shape CHECK ((node ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$'::text)),
    CONSTRAINT waf_match_object_shape CHECK ((object ~ '^[a-z][a-z0-9_-]{0,39}$'::text)),
    CONSTRAINT waf_match_path_bound CHECK ((char_length(path) <= 2048)),
    CONSTRAINT waf_match_request_id_shape CHECK ((request_id ~ '^[A-Za-z0-9_.-]{1,96}$'::text)),
    CONSTRAINT waf_match_rule_id_range CHECK (((rule_id >= 1) AND (rule_id <= 999999)))
)
PARTITION BY RANGE (occurred_at);
ALTER TABLE ONLY public.waf_match
    ADD CONSTRAINT waf_match_pkey PRIMARY KEY (occurred_at, event_id);
CREATE TRIGGER waf_finding_add AFTER INSERT ON public.waf_match REFERENCING NEW TABLE AS added FOR EACH STATEMENT EXECUTE FUNCTION public.waf_finding_add();
CREATE TRIGGER waf_match_duplicate BEFORE INSERT ON public.waf_match FOR EACH ROW EXECUTE FUNCTION public.waf_match_ignore_duplicate();
GRANT INSERT(event_id) ON TABLE public.waf_match TO app_collector;
GRANT INSERT(cluster) ON TABLE public.waf_match TO app_collector;
GRANT INSERT(node) ON TABLE public.waf_match TO app_collector;
GRANT INSERT(occurred_at) ON TABLE public.waf_match TO app_collector;
GRANT INSERT(request_id) ON TABLE public.waf_match TO app_collector;
GRANT INSERT(object) ON TABLE public.waf_match TO app_collector;
GRANT INSERT(rule_id) ON TABLE public.waf_match TO app_collector;
GRANT INSERT(field) ON TABLE public.waf_match TO app_collector;
GRANT INSERT(matched) ON TABLE public.waf_match TO app_collector;
GRANT INSERT(path) ON TABLE public.waf_match TO app_collector;
GRANT INSERT(client) ON TABLE public.waf_match TO app_collector;
SELECT public.waf_match_partition(day::date)
  FROM generate_series(current_date - 6, current_date + 7, interval '1 day') AS day;

CREATE TABLE public.waf_finding_path (
    cluster text NOT NULL,
    object text NOT NULL,
    rule_id integer NOT NULL,
    field text NOT NULL,
    hour timestamp with time zone NOT NULL,
    path text NOT NULL,
    requests integer NOT NULL,
    last_seen timestamp with time zone NOT NULL,
    matched text NOT NULL
);
ALTER TABLE ONLY public.waf_finding_path
    ADD CONSTRAINT waf_finding_path_pkey PRIMARY KEY (cluster, object, rule_id, field, hour, path);
CREATE INDEX waf_finding_path_hour ON public.waf_finding_path USING btree (hour);
GRANT SELECT(cluster) ON TABLE public.waf_finding_path TO app_web;
GRANT SELECT(object) ON TABLE public.waf_finding_path TO app_web;
GRANT SELECT(rule_id) ON TABLE public.waf_finding_path TO app_web;
GRANT SELECT(field) ON TABLE public.waf_finding_path TO app_web;
GRANT SELECT(hour) ON TABLE public.waf_finding_path TO app_web;
GRANT SELECT(path) ON TABLE public.waf_finding_path TO app_web;
GRANT SELECT(requests) ON TABLE public.waf_finding_path TO app_web;
GRANT SELECT(last_seen) ON TABLE public.waf_finding_path TO app_web;
GRANT SELECT(matched) ON TABLE public.waf_finding_path TO app_web;

CREATE TABLE public.waf_finding_client (
    cluster text NOT NULL,
    object text NOT NULL,
    rule_id integer NOT NULL,
    field text NOT NULL,
    hour timestamp with time zone NOT NULL,
    client text NOT NULL,
    path text DEFAULT ''::text NOT NULL
);
ALTER TABLE ONLY public.waf_finding_client
    ADD CONSTRAINT waf_finding_client_pkey PRIMARY KEY (cluster, object, rule_id, field, hour, client, path);
CREATE INDEX waf_finding_client_hour ON public.waf_finding_client USING btree (hour);
GRANT SELECT(cluster) ON TABLE public.waf_finding_client TO app_web;
GRANT SELECT(object) ON TABLE public.waf_finding_client TO app_web;
GRANT SELECT(rule_id) ON TABLE public.waf_finding_client TO app_web;
GRANT SELECT(field) ON TABLE public.waf_finding_client TO app_web;
GRANT SELECT(hour) ON TABLE public.waf_finding_client TO app_web;
GRANT SELECT(client) ON TABLE public.waf_finding_client TO app_web;
GRANT SELECT(path) ON TABLE public.waf_finding_client TO app_web;
"""


def upgrade() -> None:
    #
    # As pg_dump writes them: a function's body is checked when it runs, so a
    # function may name a table made further down.
    #
    op.execute("set local check_function_bodies = off")
    op.execute(REVISION)
    op.execute(ACCOUNTS)
    op.execute(JOBS)
    op.execute(READINGS)
    op.execute(EDITING)
    op.execute(PROFILES)
    op.execute(SETTINGS)
    op.execute(METRICS)
    op.execute(TRAFFIC)
