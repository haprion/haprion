# User manual

Using and administering an installed HAProxy Manager environment, through the web interface
and the authoritative command-line engine. For prerequisites, installation and environment
configuration, see the [installation guide](install.md).

Every name in this document is fictional. Substitute your own: the management host is `mgr`, the
clusters are `alpha` and `beta`, and each cluster has two nodes, `node-a` and `node-b`. Addresses
come from the documentation ranges in RFC 5737. Nothing here depends on those names — if a step
only works with the names used below, that is a bug in the software, not in this guide.

## Contents

- [Configuration and deployment](#configuration-and-deployment)
  - [Addresses, and what to call them](#addresses-and-what-to-call-them)
- [Accounts and signing in](#accounts-and-signing-in)
  - [What the two roles see](#what-the-two-roles-see)
  - [How a session works](#how-a-session-works)
  - [The throttle](#the-throttle)
  - [Signing in through an OpenID Connect provider](#signing-in-through-an-openid-connect-provider)
- [Features and advanced configuration](#features-and-advanced-configuration)
- [Certificates](#certificates)
  - [Publishing certificates](#publishing-certificates)
  - [Issuing a certificate](#issuing-a-certificate)
  - [The life of a profile](#the-life-of-a-profile)
  - [Deleting a certificate](#deleting-a-certificate)
  - [Importing a certificate](#importing-a-certificate)
  - [Enrolling and renewing through NDES](#enrolling-and-renewing-through-ndes)
  - [Registering a receiver](#registering-a-receiver)
- [Nodes and clusters](#nodes-and-clusters)
  - [Adding and removing a node](#adding-and-removing-a-node)
  - [Creating and removing a cluster](#creating-and-removing-a-cluster)
- [The interface certificate](#the-interface-certificate)
  - [Replacing it](#replacing-it)
  - [From the certificate registry](#from-the-certificate-registry)
- [Backups, and proving they restore](#backups-and-proving-they-restore)
- [Node backups](#node-backups)
- [Restoring a node onto an empty VM](#restoring-a-node-onto-an-empty-vm)
- [What a node keeps, and for how long](#what-a-node-keeps-and-for-how-long)
- [Keeping jobs, sessions and metric history bounded](#keeping-jobs-sessions-and-metric-history-bounded)
- [Traffic logs and metrics](#traffic-logs-and-metrics)
  - [A basic log viewer, on purpose](#a-basic-log-viewer-on-purpose)
  - [Sending the traffic log elsewhere, and metrics](#sending-the-traffic-log-elsewhere-and-metrics)
- [Jobs and status freshness](#jobs-and-status-freshness)
  - [How often status is refreshed](#how-often-status-is-refreshed)
  - [The worker](#the-worker)
- [Maintenance](#maintenance)
  - [Keeping HAProxy current](#keeping-haproxy-current)
  - [Releasing a change](#releasing-a-change)
  - [CLI rollback](#cli-rollback)
  - [Rolling a release back](#rolling-a-release-back)
- [Environment reference](#environment-reference)
  - [The shape of a deployment](#the-shape-of-a-deployment)
  - [Prerequisites](#prerequisites)
  - [Part 1 — the management host](#part-1--the-management-host)
  - [Part 2 — the nodes](#part-2--the-nodes)
  - [Part 3 — the versioned CLI release](#part-3--the-versioned-cli-release)
  - [Part 4 — the web platform](#part-4--the-web-platform)
  - [Verifying the installation](#verifying-the-installation)
  - [What is still missing](#what-is-still-missing)

## Configuration and deployment

Editing produces a draft; publishing produces an immutable release; deploying brings nodes
to that release. Publishing and deploying are separate operations. On the dashboard,
*Deploy certificates* installs the certificates and *Deploy configuration* installs the
published configuration. A rollout deploys the nodes that do not own the VIP first and
the owner last.

At the terminal, inspect the configuration and the nodes before deploying:

```bash
haproxy-config-status -c alpha
haproxy-status -c alpha
haproxy-objects -c alpha
haproxy-objects -c alpha --show <name>
haproxy-deploy -c alpha
```

A converged deploy skips nodes already current. See the installation guide for
[cluster and network configuration](#cluster-definitions).

### Addresses, and what to call them

If you arrive from a NetScaler or an F5, three addresses are worth naming before anything else,
because only one of the three has a word that every product agrees on.

| What it is | Here, and in HAProxy | In keepalived | NetScaler | F5 |
|---|---|---|---|---|
| the address clients connect to | `vip`, bound by a frontend | `virtual_ipaddress` | VIP | virtual server address |
| the address we connect out from | `source`, per backend | `virtual_ipaddress`, same block | SNIP | SNAT address / self IP |
| the node's own fixed address | not named; it is just the host | `unicast_src_ip` | NSIP | management address |

Two things follow from the middle row, and both matter more than the vocabulary.

**Keepalived has no separate concept for an outgoing address.** To it, both are entries in the same
`virtual_ipaddress` block - and they belong in the same block, because only the node currently
holding an address answers for it. A source address that does not move together with the VIP sends
its replies to a node that no longer carries the traffic, and that failure appears at failover
rather than at configuration time.

**HAProxy takes the source per backend, not per listener.** A site may therefore leave from a
different address than the one it arrived on. Each VIP still names a default source, so the normal
case needs no words; the [`sources` table](#optional-per-cluster-sections) exists for the exception.

`unicast_src_ip` is spelled out in full everywhere in this document. It is the node's own address,
it never moves, and confusing it with a source address produces a cluster that looks correct and
cannot fail over.

## Accounts and signing in

The installation creates the first break-glass administrator; see
[First administrator](#first-administrator).

Further accounts are a local root action too, or an admin's in the interface
(below):

```bash
sudo haproxy-ui-user -e prod add operator --role admin
```

The password is typed at the terminal, twice, and there is deliberately no flag
to pass it as an argument — that would put it in the shell history and the
process list.

An account name is at most 64 characters, with no line breaks, invisible
characters or spaces at either end. It is what a version records as who
published it, so the tool, the Users form and a first sign-in through the
provider all refuse a name that could not stand there.

The same tool is the break-glass path when the only administrator is locked
out, forgotten, or gone. An account it creates is a **break-glass** account
unless `--no-break-glass` is given: one that signs in with its password even
while sign-in goes through an OIDC provider (schema `0041`).

| Command | What it does |
|---|---|
| `add <user> --role admin\|reader [--no-break-glass]` | create an account |
| `init-admin` | create `admin`, a break-glass admin, if there is no account at all |
| `delete <user> --yes` | remove an account and its sessions for good; without `--yes` it only says what it would do |
| `break-glass <user> [--off]` | mark a local account break-glass, or unmark it |
| `reset <user>` | set a new password **and end every session that account has** |
| `disable <user>` | block sign-in and end every session |
| `enable <user>` | allow sign-in again |
| `unlock <user>` | clear the sign-in throttle |
| `revoke <user>` | end every session without changing the password |
| `list` | accounts, roles, kind (`local`, `break-glass`, `sso`), and how many live sessions each has |

Reset and disable revoke sessions on purpose. An account that cannot sign in
again while its existing cookie keeps working has not actually been taken back
from whoever had it, which is usually why either command is being run.

Anyone signed in, reader or admin, can also change their own password from the
account menu (**Change password**). It asks for the current password, and a
wrong one counts as a failed sign-in for that name and address, under the same
throttle, so a session someone else is holding cannot be used to guess it. The
change ends the account's other sessions and keeps the one it was made from; it
is recorded as `password_changed` with `via: web`.

An admin manages the other accounts under **Settings → Users**, on
installations with `management_writes` on: add, change role, disable and
enable, set a new password, mark break-glass, end sessions, unlock and delete —
the same verbs as the table above, recorded under the same audit names plus
`role_changed`, `break_glass_changed` and `account_deleted`, with the admin as
actor and `via: web`. The signed-in admin session is the proof; no second
password is asked. A new role, a new password and the break-glass mark are saved
together, in one transaction. Delete asks first, on its own page. The admin's
own account is not changed there.

The database refuses to leave no active admin, from either path: the last one
cannot be demoted, disabled or deleted. Since `0041` the web role holds `delete`
on the account table — the one table where an application role does. Sessions
go with a deleted account; jobs and the audit trail name it as text and keep
it. An account that signs in through an OIDC provider has no password here, and
its role comes from the provider.

`-e` names the environment, and each one is a root-owned file written by
`02-platform-database`: `/etc/haproxy-manager/ui-admin-<environment>.conf`,
holding the database name and the role to connect as. Prod and dev therefore
cannot be confused by an environment variable or a working directory.

**Root connects as the migration role**, the one that owns the schema, so the
tool works when nobody can sign in. The web role may write accounts too (schema
`0039`): name, hash and role on a new one; role, `disabled` and hash on an
existing one — never `created_at` or `updated_at`, which the database
sets, and never a delete. **The database refuses to leave no active admin**,
from either path: demoting or disabling the last one fails, under a lock, so two
admins disabling each other at once cannot both succeed. The break-glass answer
to a lost last admin is `add`.

### What the two roles see

A **reader** sees every page and can press nothing. An **admin** can queue the
operations the interface offers, and sees two things a reader does not.

- **The error code** of an operation that did not end cleanly — the stable,
  environment-independent string the engine blamed, such as
  `cluster_not_converged` or `ssh_unreachable`. It is shown verbatim rather than
  translated, and it is the same string the command line prints beside its
  message and the audit trail records, so what a terminal said and what the page
  says can be compared without guessing.
- **The operation's diagnostics** — its redacted stderr, folded away under the
  job until asked for. Private keys, `token`/`password`/`secret` assignments and
  sensitive paths are masked before the text is ever stored, and it is capped at
  64 KiB.

The diagnostics contain **real host names, node names and the proxy's own
output**, which is what makes them worth showing. Masking covers secrets, not
the identity of the environment. So: a screenshot of that panel does not belong
in an issue, a README, a support ticket or anywhere else outside the
installation.

Withholding raw diagnostics from a *reader* is what the contract requires;
withholding them from an administrator as well was a habit that cost the one
person who had to open an SSH session at every failure, and bought nobody
anything in an installation where the reader and the administrator are the same
person.

### How a session works

- **Passwords are Argon2id**, with parameters stated in the code rather than
  taken from library defaults, and a database CHECK refuses any hash that is not
  Argon2id. Changing algorithm has to be a migration, not a dependency upgrade.
- **The session token is opaque and lives only in the cookie.** The database
  stores its SHA-256 hash, so `app_session` read by anything — a dump, a backup,
  a mistake — cannot be replayed as a login. There are no claims in the token and
  no signing key to leak.
- **Cookies are `Secure`, `HttpOnly` and `SameSite=Lax`.** Lax rather than
  Strict, so arriving from a link in a mail or a dashboard still works, which is
  a normal way to reach an operations interface.
- **Two clocks, not one.** Roughly ten hours of inactivity ends a session, and an
  absolute lifetime caps one kept warm by a forgotten browser tab. The web role
  holds no `update` on `expires_at`, so use can move the first clock forward and
  nothing can move the second.
- **CSRF tokens are derived from the session token**, not stored. Producing one
  requires the cookie, which a cross-site form post can make a browser send but
  cannot read. The login form itself is protected the same way, by a short-lived
  cookie scoped to `/login`.
- **A new token on every login**, so nothing a browser held before signing in is
  still valid after.

### The throttle

Failed sign-ins are counted per normalised username **and** client IP together.
Per username alone would let one attacker lock every real user out; per IP alone
would let one address work through a list of names.

The attempts table is **append-only by grant** — the web role can add a row and
read rows, and holds no update or delete. A counter the web process could reset
would be a lock whose key is kept behind the door. An unlock therefore deletes
nothing: `haproxy-ui-user unlock` (and, for an admin, the interface) adds a row
to `login_unlock`, and the throttle counts failures since the latest success or
unlock for that name. The failed attempts stay in the record.

The client address is taken from `X-Forwarded-For`, which the nginx site
*overwrites* rather than appends to, so a request cannot contribute its own. An
address that will not parse falls back to loopback rather than becoming an
unthrottled bucket of its own.

Every sign-in, failure, sign-out and account change is written to the audit
trail, in the same transaction as the thing it describes. What the login page
says, on the other hand, is one sentence for every kind of failure — unknown
account, wrong password, disabled account and throttled address are
indistinguishable from outside, and the same amount of time is spent on each.

### Signing in through an OpenID Connect provider

Sign-in through a provider — authentik, Keycloak, Entra ID, ADFS, Authelia,
Okta, Zitadel, or any other that follows OpenID Connect Core and Discovery —
arrives in parts (schema `0041`). What is installed first is the path to the
provider, and it does not go through the web service.

The web service reaches localhost and nothing else (`IPAddressDeny=any`), and
keeps doing so. Every request to the provider goes through
`/run/haproxy-mgmt/oidc.sock` to `haproxy-oidc-helper`, installed by platform
step 17. It runs as an account of its own (`OIDC_USER`, the identity policy's
`roles.oidc`), not root, and is the one part that may reach the network. It
takes no URL from the web: the issuer comes from the settings, every other
address from that issuer's own discovery document, over verified TLS — the
system's authorities plus, when set, a CA certificate pasted into the
settings. It follows no redirect, uses no proxy from the environment, and
bounds every answer to ten seconds and one megabyte.

The client secret is sealed by the web against the public key step 17 made,
and only the helper opens it. The sealed text names the issuer and the client
it was saved for, and the helper refuses to open it for any other: changing
the issuer means typing the secret again, so a session that changes where
sign-in goes cannot also send the old secret there.

The helper verifies the id_token as OpenID Connect Core lays out for the authorization code flow (section 3.1.3, step 7) —
signature (RSA, RSA-PSS or ECDSA against the provider's key set; HMAC with the
client secret, which authentik uses when no signing key is chosen; never
`none`), issuer, audience, `azp`, expiry with one minute's leeway, and the
sign-in's own nonce. Userinfo is added when it names the same subject and
ignored otherwise; it is never a reason to refuse. Names and groups are read
from the claims the settings name, as a dotted path (`realm_access.roles`); a
claim that is an object counts as its keys. A provider that sends a pointer to
the groups instead of the groups (Entra's overage, above 200 groups) is refused
with a sentence that says to use app roles.

The role is read from the groups at every sign-in through the provider, and
not between two of them. A session made that way therefore ends after at most
`oidc_absolute_hours` (under `[session]` in `ui.toml`, default 10), whatever
the activity, so a group taken away at the provider stops counting here by
then. The provider's own token lifetime is not used for this; to end someone's
access sooner, **Revoke sessions** on the account does it at once.

An account made through the provider is bound to the issuer and the subject it
first signed in with, not to its name. Changing the issuer — another provider,
or the same provider's application under a new name — therefore leaves every
such account bound to the old one, and sign-in says so. Remove those accounts
under **Settings → Users**; each is made again at its next sign-in.

#### Examples: three providers

In every case the provider gets a confidential client (one with a secret),
the authorization code flow, and exactly one redirect URI: the one the
settings page shows, `https://<SERVER_NAME>/login/oidc/callback`. The issuer
must be typed exactly as the provider states it — **Verify** says so when it is
not, and quotes the provider's own value. Menu names change between provider
versions; what matters is what ends up in the id_token, which **Test sign-in**
shows.

**authentik** (checked against 2026.8)

- Applications → New Application, provider type OAuth2/OIDC, client type
  confidential, redirect URI in strict mode, a signing key chosen (RS256).
- Issuer: `https://id.example.com/application/o/<application slug>/`, with the
  trailing slash. The provider's page shows the discovery URL ending in
  `/.well-known/openid-configuration`; the issuer is what comes before it.
- Scopes, claims: the defaults here (`openid profile email`,
  `preferred_username`, `groups`). authentik's `profile` scope carries the
  groups by name.
- Groups: authentik's own, or those an LDAP source synchronises from Active
  Directory; the claim carries the group's name as authentik shows it.
- Binding the application to the two groups keeps everyone else out at the
  provider as well.

**Keycloak**

- Clients → Create client, OpenID Connect, client authentication on, standard
  flow on, the redirect URI under valid redirect URIs.
- Issuer: `https://id.example.com/realms/<realm>`.
- Groups: add a *Group Membership* mapper to the client's dedicated scope with
  token claim name `groups`, added to the ID token. With *Full group path* on,
  which is the default, groups arrive as paths — type the admin group as
  `/haproxy-admins` here, or turn the option off and type `haproxy-admins`.
- Username claim: `preferred_username` (the default here).

**Microsoft Entra ID**

- App registrations → New registration, platform *Web*, the redirect URI, and
  a client secret under Certificates & secrets.
- Issuer: `https://login.microsoftonline.com/<tenant ID>/v2.0`.
- Groups: Token configuration → Add groups claim. By default the claim carries
  group **object IDs**, not names; type the IDs as the admin and reader
  groups, or, for groups synchronised from on-premises AD, choose
  `sAMAccountName` for the ID token. Someone in more than 200 groups gets a
  pointer instead of the groups, which is refused; choose *Groups assigned to
  the application*, or use app roles with the groups claim set to `roles`.
- Username claim: `preferred_username` (the user's UPN).

The settings are an admin's, under **Settings → Users → OIDC configuration**,
on installations with `management_writes` on: issuer, client ID and secret,
client authentication (`client_secret_basic` or `client_secret_post`),
scopes, the claims for the name and the groups, the admin and reader groups,
the button text, sign-out (this interface only, or also at the provider),
local sign-in (break-glass accounts only, or all), an optional CA
certificate, whether accounts are created at first sign-in, and whether the
provider is always asked to sign in again. The redirect URI to register at the
provider is shown there, to copy. The web's `ui.toml` names the public key
step 17 made (`[oidc] public_key`); without it the page says the helper is not
installed.

**Verify** asks the helper: discovery against the issuer, the key set, the
client's method, the signing algorithm, and whether the provider accepts the
client and its secret — by sending a code that was never issued, which a
provider answers with `invalid_grant` when it accepted the client and
`invalid_client` when it did not. Each check is listed. The database records
the revision that passed, and every change to the settings raises the
revision, so sign-in through the provider can be turned on only at settings
that passed Verify, and only while an active admin is break-glass. Saving
while it is on runs Verify first and saves as verified, or saves nothing.
Each change is audited (`oidc_configured`, `oidc_verified`, `oidc_enabled`,
`oidc_disabled`); the secret never is.

## Features and advanced configuration

Two capabilities can be turned off under **Settings → Features** (schema
`0040`), by an admin on an installation with `management_writes` on. Off hides
the capability's tab, pages and operations; a kept URL answers 404. Both are
off on a new installation, which enables no backup timer either; an
installation opts in.

- **Certificate receivers** off hides the receivers page, the receiver choices
  in the certificate forms and in *Publish to…*/*Remove from…*, and the
  certificates page's second view. Receivers already registered go on getting
  renewed certificates, and a certificate's *Used by* still names them.
- **Node backups** off also stops every cluster's backup timer: one
  `backup_schedule` job per running timer, with its schedule unchanged and
  `enabled: false`. The schedules it stopped are remembered, and turning it on
  starts exactly those again. Archives already taken are kept. It is refused
  while a cluster has a job running, while a restore is running or waiting,
  and for a cluster whose schedule the form cannot write back.

`haproxy-state-backup` and the restore commands on the manager work either way.

A third switch, **Cluster colours** (schema `0042`), is on from the start and
hides nothing: it draws the rule down each cluster card's left edge, one of six
colours handed out in the order `clusters` lists them in `ui.toml` — the order
the dashboard draws the cards in, so reordering that list reorders both. With
more than six clusters it is off and cannot be turned on; the name stands
beside every card either way.

A fourth, **Advanced config** (schema `0049`), is off from the start. On, an
object's page has an *Advanced config* button between *Edit* and *Remove* that
opens a dialog for HAProxy configuration pasted as a layer on top of the
object; the object stores it as `advanced` in its YAML. Off hides the button
and the dialog only: an object that has text keeps it, its page says so, and
the generator writes it on every publish, because what a cluster runs must not
depend on an interface setting.

What the layer does, line by line (`haproxy-objects -c alpha --advanced <name>`
prints the same answer as the dialog's *Check*):

- Lines outside a section, and under the text's own `frontend` or `listen`, are
  the object's: an http object's go to every pool it has, a tcp object's to its
  frontend where HAProxy takes the keyword there and to its pool otherwise.
  They are written **after** the generated lines of the same section, so the
  cluster's abuse brake and the object's rate limit run first.
- `backend`, `cache`, `http-errors`, `userlist` and `ring` sections are written
  as they stand, under a name that must begin with `<object>-`. A section named
  otherwise is refused, not renamed: other files may refer to it.
- Refused outright: `global`, `defaults`, `program`, `peers`, `resolvers` and
  `mailers` sections; `use_backend`/`default_backend`, `bind`, `guid`, and
  `source`/`usesrc` (also as a server parameter) — routing, listening and the
  outgoing address are the form's; a keyword HAProxy would ignore in that place;
  `track-sc0` (the cluster's counter), `track-sc1` while the object's rate limit
  is on (the limit's counter); a `stick-table` on the object's own lines (its
  pool already carries the rate limit's). The text counts on `sc2`, with tables
  in a backend of its own: `track-sc2 src table <object>-logins`. Reading `sc0`
  and `sc1` is allowed.
- `mode` is skipped (the form sets the protocol), and so are lines that set what
  the form owns for the pool — servers, balancing, health checks, cookie, and
  the connect, server, queue, tunnel and check timeouts — while the form writes
  the pool. Ticking
  *The text writes the pool* hands the object's one pool to the text instead:
  the YAML keeps `servers: []` and nothing else, the form shows no pool fields,
  and the text must carry at least one `server` line. Unticking gives the pool
  back with the text's `server name host:port` lines as its servers.

Stick tables in the text have no `peers`: their counts start again when HAProxy
reloads and when the address moves to the other node. A `haproxy -c` error in a
generated file is reported as the object and the line of its text, and a
publish is refused when HAProxy warns about a pasted line: a warning there means
the line would be ignored, which `-c` alone lets pass. Beyond what
is refused here and what `haproxy -c` checks, what the text does is the author's
responsibility: a valid line can still mean something else than intended, and
the dialog's list of where each line went is the review before a publish.

## Certificates

Certificate tools, provider keys and trust are configured during installation. See
[The certificate registry](#the-certificate-registry),
[ACME configuration and challenge routing](#acme-configuration-and-challenge-routing)
and [Preparing Microsoft AD CS / NDES for CSR enrollment](#preparing-microsoft-ad-cs--ndes-for-csr-enrollment).

### Publishing certificates

`haproxy-cert-publish` is the one path from a certificate's source to every place it is read.
It runs as root, takes no file, directory or account on its command line, and reads the registry
for all three: which certificates exist, where each comes from, and where each goes.

| Source | Read from |
|---|---|
| `acme` | `/etc/letsencrypt/live/<lineage>/` - `fullchain.pem` and `privkey.pem` |
| `import` | `/etc/haproxy-manager/certificates/<id>/` - the same two files, written by the import helper |

| Target | Written as | Owner and mode |
|---|---|---|
| a cluster | `<certificate_root>/<id>.pem`, the private key followed by the full chain - HAProxy's own format | `root`, the group that owns `certificate_root`, `640` |
| a receiver, `layout: flat` | `<path>/fullchain.pem` and `<path>/privkey.pem` | the receiver's `owner`, `600`; the directory itself belongs to root or to the owner and is writable by nobody else |
| a receiver, `layout: per-certificate` | `<path>/<id>/fullchain.pem` and `<path>/<id>/privkey.pem` | the same, and the per-certificate directory is `root` with the account's group, `750`, made by the publisher |
| a receiver, `format: pkcs12` | `<path>/<id>/<id>.pfx` and `<path>/<id>/<id>.password` | the receiver's `owner`, `600` |

Every certificate is checked before its first file is written - it parses, its private key
belongs to it, and it has at least seven days left - and all of its targets are resolved first, so
a certificate that cannot be published leaves nothing half-done. Each file is written as a
temporary in its own directory, fsynced and renamed over the previous version: a reader sees the
old file or the new one, never a partial one. A file whose bytes already match is not touched,
which is what lets the command run after every renewal, or by hand at any time, without cost.
The run holds one lock and waits for a concurrent run rather than refusing: the publisher is
idempotent, so the second run does exactly the right thing after the first.

A PKCS#12 bundle is compared by the certificate inside it rather than by its bytes, which are
salted and differ every time the same material is exported. The password is made once per pair and
kept across renewals - the receiver imported the bundle into a certificate store with the password
it fetched, and a new one at every renewal would make every renewal a manual re-import.

An `import` entry whose directory does not exist yet is reported as skipped, not failed, and its
published copy is left as it is. That is what a certificate published by hand before the import
store existed looks like.

With `--deploy`, every cluster that received a new version is rolled out afterwards with
`haproxy-cert-deploy`, once each, after every file is written. Two clusters that carry the same
certificate read the same file; it is written once and both are rolled out.

So is every cluster an earlier run published to without a rollout that succeeded. The files alone
cannot say that - a cluster's PEM is the same whether its nodes took it or not - so the publisher
keeps a note beside the registry, `certificates.pending-deploy.json` (owned and moded like the
registry): a cluster is marked before its material is written and cleared only when
`haproxy-cert-deploy` answered 0 for it. Running the same command again after a failed rollout
therefore finishes it, with nothing issued or rewritten, instead of finding the files in place and
answering `done`. Adding a cluster to a certificate (*Publish to…*, `haproxy-cert-target-helper`) marks it
the same way. A note that cannot be read counts every cluster as due: each is rolled out once, its
current nodes are skipped, and the file is written whole again. A cluster removed from the
configuration is dropped from it.

```bash
haproxy-cert-publish                 # publish what changed, report per certificate
haproxy-cert-publish --json          # the same, as a result envelope
haproxy-cert-publish --deploy        # ... and roll out the clusters that changed or are still due
haproxy-cert-publish --certificate example.com   # one registered certificate only
```

### Issuing a certificate

`haproxy-cert-issue` obtains one ACME certificate and takes it all the way to its targets: certbot,
then the registry entry, then the publish and the rollout of the clusters named. Root only. The
whole run is timed and the time is part of its result, because the point of the command is the
number: a certificate on its targets in minutes, from one line.

```bash
sudo haproxy-cert-issue --domain www.example.com --method dns-01 --cluster alpha
sudo haproxy-cert-issue --domain '*.example.net' --method dns-01 --dns-profile cf-main \
  --cluster alpha --receiver lb-01.example.net
sudo haproxy-cert-issue --domain intranet.example.com --method dns-01 --dns-profile cf-main \
  --receiver certserver1.example.net --format certserver1.example.net=pkcs12
```

The ACME policy and challenge routes must already be configured; see
[ACME configuration and challenge routing](#acme-configuration-and-challenge-routing).

The web interface asks for the same thing from **Certificates → New certificate**: a domain, a
method, an in-effect DNS profile for DNS-01, and boxes for the clusters and the registered receivers. It queues one `cert_issue` job
through `haproxy-cert-issue-helper` ([worker helper configuration](#what-the-worker-may-run)) and reports on the Jobs page, certbot's output included.
The form cannot register a receiver - one is a directory, an account and a key, made on the host as
in [Registering a receiver](#registering-a-receiver) - and it refuses a wildcard over `http-01` before the job is queued.

The account is the one certbot already has on this host; the command registers none. The
certificate becomes an ordinary certbot lineage, renewed by certbot's timer and published by the
hook in [Publishing certificates](#publishing-certificates) like every other.

The registry is rewritten as a whole, with its ownership and mode kept and the result loaded back
through the engine before it replaces the previous file. Comments in it do not survive the first
machine write; the file's header says so.

### The life of a profile

Profiles are made and retired at **Certificates → DNS providers** (`/dns-profiles`), by an
administrator, and never from a file. A profile is one provider's credentials under a short ID the
operator chooses (`cloudflare-main`: lowercase letters, digits and hyphens, at most 32). The ID is
the profile's name everywhere - the certificate form's choice list, the credentials file, and
`--dns-profile` on the command line - so pick one that reads well typed from memory.

Saving or replacing a profile seals the values in the browser's request against the public key and
queues `dns_profile_apply`. The no-argument root helper opens the sealed row, verifies
profile/provider/key/revision bindings, validates it against the provider catalogue, and atomically
writes a `0600 root:root` credentials file plus root-only metadata under the policy's directory.
The page waits a few seconds for that job before it redraws, so an idle queue shows the new row as
**In effect** straight away; if a certificate job holds the queue, the row says **Applying** and
the page refreshes itself until the file is written. Only a profile whose current revision has a
completed apply job is offered during certificate issuance. The status column reads:

| Status | Meaning |
|---|---|
| In effect | the file certbot reads is the box the row holds; the certificate form offers it |
| Applying / Removing | its job is queued or running |
| Apply failed | the helper refused it - the Jobs page carries its account, without the values |
| Replaced; not applied | a newer revision was saved and its job has not finished |
| Not applied | no apply job for the row was found at all |

The values themselves are never shown again. To change one, **Replace** re-enters every value; the
new box becomes the next revision and is applied by a job of its own. **Remove** uses the same helper
and is refused while either the certificate registry or a Certbot `renewal/*.conf` file still names
the profile; the database row is deleted only after the helper's successful, revision-fenced result.

A lineage issued through a profile renews through it: certbot writes the profile's credentials path
and the catalogue's propagation wait into the lineage's renewal configuration, and [The certbot environment](#the-certbot-environment)'s
`haproxy-cert-renew` restores what a plugin cannot persist. Removing a profile a lineage still
renews through would break that renewal, which is why the registry and the renewal files are
checked first.

### Deleting a certificate

Nothing else in this project removes certificate material, and the helpers say so in their
headers: a deletion can erase a certificate a cluster is serving. The cleanup exists anyway,
because a registry that only ever grows is not caution — after a few years it holds hundreds of
certificates that expired or stopped mattering, and for those the missing path is what makes the
registry unusable.

**Where it is.** The registry view at `/certificates?view=registry` has a box on every row and one
button, grey until something is ticked. The button leads to a confirmation page that says, per
certificate, what deleting it means; confirming queues one `cert_delete` job for the whole
selection (at most 32 at a time). One job, not one per certificate: a cleanup of seventy rows must
not become seventy jobs.

**What one deletion is.** Four layers, in this order, for each certificate in the job:

| Layer | What goes | Why this order |
|---|---|---|
| the material | `<certificate_root>/<id>.pem` and the two files in every receiver directory the entry named | |
| the source | `certbot delete --cert-name <lineage>` for `acme`; `/etc/haproxy-manager/certificates/<id>/` for `import` | a dead certificate would otherwise renew forever |
| the registry entry | the certificate stops being published | only once the two above are gone: an entry that outlives its material is a certificate the next run can finish, an entry gone before its material is one nothing can find again |
| the node copies | each node of every cluster the entry named is asked `cert-remove <id>` over the trigger identity | last, and the one layer that may lawfully be left behind; a node is asked by name, so it needs no entry |

The whole job holds the publisher's lock (`/run/haproxy-mgmt/locks/cert-publish.lock`), like
issue, publish and target changes do. The renewal timer publishes outside the job queue, and a
renewal that ran between the layers would put a still-registered certificate's material back
and leave a deleted one's node copies behind; under the lock the layers are one step to it.

**A deletion can be run again.** Every layer is idempotent and reports `absent` where there was
nothing to remove. A layer that fails — certbot refuses, a file cannot be unlinked, a node is
unreachable or does not know the verb — is reported on the certificate's row, the entry stays
where the failure was above it, and the same selection deleted again picks up where it stopped.
A certificate that is no longer registered is still looked for by name: its PEM, a lineage of
the same name, its import directory and the copy on every node of every cluster. So the row a
job reports as left is finished by ticking the certificate again, not by hand; only a
certificate nothing holds anywhere is refused as `not_registered`.

**The guards are the operation, not a warning.** A certificate is refused, with nothing touched,
when a proxy object in a cluster's committed configuration still names it, when it is a cluster's
`default_certificate`, when it is the only certificate a cluster has (the engine refuses to load a
cluster no certificate names), when another registry entry names the same certbot lineage or the
same receiver directory (the lineage and the receiver's pair are removed whole, so they have to
be the entry's alone), or when a draft in the interface's database still names it. The
draft check is the web's, made on the confirmation page and again as the job is queued; the worker
holds no grant on drafts and does not look, so a draft written after queueing is the one window
left open - its publish then fails on a missing file, which is recoverable. A draft written
between the confirmation page and the confirm is a refusal at the confirm: the question is asked
again with the draft on the row, and nothing is queued until it is confirmed as it now stands. A
refused certificate stops nothing else in the batch: it is reported on its own row and the others
go through. The job's outcome is `done` when every row went, `partial` when any was refused or
left a layer behind, `blocked` when every row was refused, and `failed` when nothing at all went.

**What is left behind, and said.** A node whose trigger does not know the verb yet answers
"unknown request", and the copy is reported as kept, by node. The file is inert there: bind lines
name certificates through crt-lists, and a PEM nothing lists is never loaded. So an installation
can run deletions before its nodes carry the current bundle, and read on the job which node still
holds what. The node's own script refuses an ID that any installed crt-list, `haproxy.cfg` or
`conf.d` fragment names — the same guard as the manager's, measured against what is actually
served rather than what is committed — and it does not reload, because nothing changed for HAProxy.

**The worker's sandbox opens the import store for it.** `07-platform-services` creates
`/etc/haproxy-manager/certificates` (root, `700`) before it writes the worker unit, because the unit
names the directory in `ReadWritePaths` without the optional dash: a missing path stops the worker
from starting rather than being skipped in silence. An installation upgraded to this operation
reruns step 7 before releasing the interface that queues it.

**Nothing here can be undone.** A deleted lineage has to be issued again, and a deleted import has
to be imported again. The confirmation page says so, and the job's rows say what went.

#### Publishing to another target, and withdrawing from one

The same boxes carry two more buttons, *Publish to…* and *Remove from…*, for the two questions
short of a deletion: a certificate that should also go to the other cluster, and one that was
sent to a cluster (or a receiver) it should not be on. Each leads to a page that offers the
targets the change would touch — for a publish, what some chosen certificate is not on yet; for
a removal, what some chosen certificate is on — and confirming queues one `cert_target` job for
the selection and one delta. The job applies the delta per certificate to whatever the registry
holds when it runs, so thirty certificates sent to the wrong cluster are one job, and a
certificate somebody else changed in between is not overwritten with a stale target set.

**Publishing** registers the certificate for the target, publishes its material there, and rolls
each added cluster out once — a `haproxy-cert-deploy` for the cluster, so its nodes pull and
**reload HAProxy**. A receiver fetches on its own schedule. A certificate already on a chosen
target is reported `unchanged`.

**Removing** takes the target off the registry entry and removes the copy that target held: each
node of a removed cluster is asked `cert-remove <id>` over the trigger identity (no reload — a
file nothing names is not loaded), and a removed receiver's pair on the manager is unlinked.
What the receiver host already fetched stays there; the manager cannot reach into it. A receiver
another certificate also publishes to keeps its pair. Nothing else is touched: not the material
for the remaining targets, not the lineage, not the entry.

**The guards are the deletion's, scoped to the removed cluster.** A certificate is refused, with
nothing touched, when a proxy object in *that* cluster's committed configuration still names it,
when it is that cluster's `default_certificate`, when it is the only certificate that cluster
has, or when a draft in that cluster names it (the web's check, as for a deletion). An object in
another cluster does not hold it. A refused certificate stops nothing else in the batch; the
job's outcome follows the rows the way a deletion's does, and a node that kept its copy makes the
row `incomplete` — the registry has changed, and running the removal again asks the node again.

### Importing a certificate

`haproxy-cert-import` is the other way a certificate reaches the registry: one issued elsewhere -
an internal CA, a purchased certificate, a wildcard exported from a Windows CA - whose key the
maintainer already holds. Root only. Like `haproxy-cert-issue` it goes all the way: the import
store, the registry entry, the publish and the rollout of the clusters named.

```bash
sudo haproxy-cert-import --id intranet.example --certificate intranet.example.crt --key intranet.example.key \
  --chain issuing-ca.pem --cluster alpha
sudo haproxy-cert-import --id intranet.example --pkcs12 intranet.example.pfx --password-file /root/intranet.example.pw \
  --cluster alpha
```

**What is read.** PEM files, or one PKCS#12 (`.pfx`/`.p12`) holding everything. The password for
a PKCS#12 comes from the first line of a file, never from the command line, where every user on
the host can read it (`ps`). An encrypted PEM key is refused - decrypt it first with
`openssl pkey` - because a passphrase the publisher would have to know is a secret in a second
place. Bag attributes and comments between blocks are dropped; a Windows export is read as it is.

**What is checked before anything is written.** The material is taken apart into blocks; the
leaf is the one certificate whose public key is the key's, so a chain handed in the wrong order,
or a PKCS#12 with the CA certificates first, comes out right. A key that belongs to no
certificate is refused (`key_mismatch`). The chain is then followed by issuer from the leaf
upward, and a self-signed root is left out: clients hold it already, and serving it is noise. A
certificate that has already expired is refused (`expired`). An ID certbot has a lineage for
(`already_exists`), an ID registered as `acme` (`not_import`), and an unknown cluster or
receiver are refused too. None of these leave anything behind.

**What is written.** `/etc/haproxy-manager/certificates/<id>/` with `privkey.pem`, `cert.pem`,
`chain.pem` and `fullchain.pem`, root-only, in one rename - the same four files certbot's `live/`
holds, so the publisher and the listing read both sources the same way. Then the registry entry,
`source.kind: import`, with the targets named. Then the publish for that one certificate and the
rollout of its clusters, exactly as after an issue.

**Importing again.** The same ID imported a second time replaces the material - a rotated key, a
renewed certificate from the same CA - and keeps every target the entry has; targets named on the
second import are added to them, never a replacement (taking a target away is *Remove from…*, [Deleting a certificate](#deleting-a-certificate)).
The manager does not renew an imported certificate; its expiry is on the registry view,
and a new import before that date is the maintainer's job. A certificate registered as `import`
before this command existed, with its material placed by hand, is replaced the same way.

**From the interface.** *Certificates → Import certificate* takes the same material as a file:
PEM (certificate, key and chain in any order), PKCS#12 with its password, a DER certificate or a
PKCS#7 bundle, at most 32 kB, plus the name and the targets. The web process seals the file
against the installation's public key - the pair step 15 creates for DNS provider profiles -
inside the request that carries it, and queues a `cert_import` job whose payload is the
ciphertext. `haproxy-cert-import-helper`, run by the worker through its sudoers rule, opens the
box with the private key and imports the material exactly as the command does. So the key is in
clear in the web process for the length of one request and in the root helper; it is never in
the database, the job row, the audit or the snapshot to a development platform, none of which
the private key can reach. That is a narrower promise than *the web never sees a key*, and it is
stated here because until this feature the interface refused a key on purpose; the command-line
import remains the way in for whoever wants the key to stay off the web entirely.

A file without a key is accepted for a name whose key the manager already holds: an imported
certificate's renewal on the same key, or the certificate a CA returned for a request made here.
*Renew…* under the list, with the imported certificate's row ticked, takes exactly that - only the
certificate; a file holding a key is refused there and pointed at the import page, where replacing
the key is the stated intent. Enrollment from a Microsoft CA needs no file at all ([Preparing Microsoft AD CS / NDES for CSR enrollment](#preparing-microsoft-ad-cs--ndes-for-csr-enrollment)).

**Renew…** is one button for every source: ticked on a certbot certificate it runs the daily
timer's `certbot renew --cert-name <lineage>` now with `--force-renewal` (`haproxy-cert-renew
--acme-now <id>` from the terminal; Let's Encrypt allows five identical certificates a week), on an
NDES certificate it enrolls again from the same profile with the same names and targets ([Preparing Microsoft AD CS / NDES for CSR enrollment](#preparing-microsoft-ad-cs--ndes-for-csr-enrollment)),
and on an imported one or a waiting signing request it is the page with the file field.

**A signing request made here.** For a CA the manager cannot talk to - a purchase, an internal
PKI without SCEP, whoever signs things - the key can be made on the manager instead of imported:

```bash
sudo haproxy-cert-request --id intranet.example --domain intranet.example --domain '*.intranet.example' \
  --cluster alpha [--key-type ec-p256|rsa-2048|rsa-4096]
```

writes `/etc/haproxy-manager/certificates/<id>/privkey.pem` (root-only, never printed) beside
`request.csr`, `request.json` and `targets.json`, and prints the CSR. The base name is the CN and
the certificate's ID, a wildcard a SAN beside it. EC P-256 is the default; RSA for the CA that
requires it. The request is *not* in the registry - an entry without material would refuse every
rollout to its clusters - and the listing shows it from the store as **Signing request pending**,
with the CSR to download from the row. The name is refused while anything else holds it: a
registry entry, a certbot lineage, imported material, an NDES request in flight.

When the CA has signed, the certificate comes back without a key - `haproxy-cert-import --id <id>
--certificate <file> [--chain <file>]` with no `--key`, or *Renew…* with the row ticked - and is
matched against the stored key, imported and published to the targets the request named plus any
named now. A certificate for another key is refused and the request kept. Deleting the row ([Deleting a certificate](#deleting-a-certificate))
removes the key with it; a request nobody signs is otherwise harmless, and stays until it is
deleted. On the interface the same thing is the fourth choice on *New certificate*, **CSR**, with
the key type where the other methods have their profile; it queues a `cert_request` job that
`haproxy-cert-request-helper` runs, the fourteenth worker helper (its sudoers rule and step 07 are
part of the release).

### Enrolling and renewing through NDES

After installation, root policy configuration and provider application, the pilot root CLI is:

```sh
haproxy-cert-scep --id example-cert --profile internal-ca --domain example.test --domain '*.example.test' --json
```

A CA approval wait returns `state: pending` and envelope outcome `partial`. The certificate is
**not** registered yet: the registry names only certificates that exist, because the cluster's
certificate list and the deploy preflight are built from it and an entry without material would
refuse every rollout to the clusters it names. The request's root-only state holds the key, the
profile, the names and the chosen targets, and the listing helper reads it there, so the row shows
as **Request pending** all the same. Resume with `haproxy-cert-scep --id <id> --resume` - the
original key is retained, the targets are the ones the request was made with, and a resume that
disagrees with the record is refused. Returned certificates must pass chain, names, usages and key
validation before the existing import/publication path is called; only then is the certificate
registered and published.

A request the CA rejects, or one Certmonger never took, removes its own state so the same ID can
be asked for again. A request that is neither answered nor rejected - the approval is not coming,
or the process died on it - is given up with `haproxy-cert-scep --id <id> --abandon`, which
discards the key; deleting the certificate removes its request state too.

**Scheduled renewal.** `haproxy-cert-renew` - the command the daily `haproxy-certbot-renew.timer`
runs - makes an NDES pass after certbot's: every registered certificate whose source names an
NDES profile and whose `not_after`, read at its source, is less than `ndes.renew_days` away is
enrolled again under the same ID, with the same profile, the names the current certificate
carries (CN first) and the targets the registry holds. It is the same request as a first
enrollment: a fresh key, and the published material replaced only once the new certificate has
been validated; a request the CA holds is **Renewal pending** on the row, with the same *Resume
enrollment* button, and the next day's pass resumes that request rather than asking anew. One record per certificate under `<state_root>/renewals/` says what the last
attempt did, and the listing shows a failure as **Renewal failed** with the CA's sentence rather
than an expiry creeping closer. `haproxy-cert-renew --ndes-now <id>` renews one certificate at
once, threshold or not, and skips certbot's pass: the way to prove the path on a template whose
validity cannot be shortened per request, and to rotate a key. `--acme-now <id>` is the same for
a certbot lineage, forced; the interface's *Renew…* runs both. `--dry-run` says who would renew.


From the interface, *Certificates → New certificate* offers *Microsoft AD CS · NDES* beside
the two Let's Encrypt challenges whenever an NDES profile is in effect; a wildcard becomes the
base name as CN with the wildcard as a SAN. The submission is one `cert_scep` job run by
`haproxy-cert-scep-helper` (the twelfth worker helper; a sudoers rule and step 07 are part of
its installation). A pending request shows **Resume enrollment** in its registry row, which
queues the same job with only the ID. Migration `0027` adds provider storage and apply jobs,
`0028` the profile's plain endpoint column and worker deletion, `0029` the `cert_scep` job.
A compatible UI bridge is required before each migration.

A certificate the CLI enrolls is registered as `source.kind: import` with
`source.ndes_profile` naming the profile whose challenge enrolled it; the interface shows
such a certificate as **NDES** rather than **Imported**. Removing a profile (Certificates →
NDES providers → Remove) runs one job that deletes the root-only record and then the row;
it is refused while the registry still names the profile or an enrollment request under
`state_root` is still bound to it. A refused removal leaves the profile in effect.

### Registering a receiver

A receiver is a machine outside this installation that fetches certificates from the manager. It
is four things at once - an account, a directory only that account may read, a lock binding its key
to that directory, and the registry entry - and `haproxy-cert-receiver` makes all four, or none:

```bash
# The receiver makes its own key pair and sends you the public half.
sudo haproxy-cert-receiver add lb-02.example.net --transport rsync \
  --public-key /tmp/lb-02.pub

sudo haproxy-cert-receiver add lb-03.example.net --transport sftp \
  --public-key /tmp/lb-03.pub --owner crx-lb-03

sudo haproxy-cert-receiver add 192.0.2.40 --transport https --allow 192.0.2.0/24

sudo haproxy-cert-receiver list
sudo haproxy-cert-receiver remove lb-02.example.net
```

**The account is `crx-` and the ID** with its dots turned into dashes (`crx-lb-02-example-net`):
*crx* for *certificate receiver*, a prefix nothing else on the machine uses, so `ls -l` under the
receiver root names the receiver. Linux holds an account name to 32 characters; an ID that would
not fit is refused rather than cut, and `--owner` names the account instead - two long IDs must
never quietly become one account. An `https` receiver has no account of its own: nginx serves it.

**The ID is the fetching host**: its DNS name or its IPv4 address, and nothing else. That is what the
lock binds to - `from=` in `authorized_keys`, `allow <id>` in nginx. **The key line carries the
name and its addresses both**, `from="lb-02.example.net,192.0.2.10"`: sshd's `UseDNS` is off by
default, and then `from=` matches addresses only - a lock naming the host alone refuses the very
host it was issued for, and the log says *correct key but not from a permitted host*. The
address is what sshd always has; the name is what an operator reads, and what `UseDNS yes` would
match. The addresses are resolved once, at registration, so a host that changes address is
`remove` and `add` again. A name that does not resolve is refused, because there would be
nothing to write into the lock; its PTR record is not looked at. One address commonly carries
several names in a zone - the host's own and one per service it serves - and whichever of them
the reverse lookup answers with, the address half of the lock admits the host. An IPv6 address
is not accepted as an ID (the ID is also a directory name and a URL path segment, and `:` is
neither); a host that fetches over IPv6 is registered under its DNS name, and its IPv6 address
goes into `from=` with the rest.

**Where the directory goes** is `receiver_root` in the runtime policy: a new receiver's
directory is `<receiver_root>/<id>` unless `--path` names another, and a migration's record
lives there too. The registry, not the root, says where each receiver actually is - one
registered before this command existed may be elsewhere - so the root is optional until the
first `add` or `migrate`, which refuse with `dependency_unavailable` until it is declared.

**The private key is never given to the manager.** The pair is made on the receiver
(`ssh-keygen -t ed25519`), and `--public-key` takes the `.pub` file. A private key that passed
through the manager has passed through one machine too many.

| Transport | How it fetches | What holds it there |
|---|---|---|
| `rsync` | `rsync` over ssh | `restrict,from="<id>,<addresses>",command="/usr/bin/rrsync -ro <path>"` - one directory, read-only, no shell |
| `sftp` | `sftp`, read-only | the same key line without the forced command, plus a `Match User` block with `ChrootDirectory <path>` and `ForceCommand internal-sftp -R` |
| `https` | plain `GET`, no key at all | an address whitelist in nginx, and nothing else |

The rsync account has `/bin/sh` as its login shell because OpenSSH runs an
`authorized_keys command="..."` through that shell with `-c`. The shell does not grant an
interactive login: the key still carries `restrict`, `from=` and the fixed `rrsync -ro` command,
and no unrestricted key is installed. An SFTP account keeps `/usr/sbin/nologin` because
`internal-sftp` is sshd's in-process server and does not need a shell.

`https` is a deliberate lowering of the trust level: an address list is not a key, and what such a
receiver holds - a wildcard, a certificate the clusters serve - is the operator's call, not the
program's. It reaches nothing but its own directory. It is served from the interface's own server block, on 443 under the
interface's certificate and hostname, at `https://<server name>/certdist/<id>/<certificate>/`.
The `location` blocks live in `/etc/nginx/snippets/haproxy-manager-receivers.conf`, which only this
command writes and which the interface's site pulls in with one `include` line; the interface's
block itself is never edited by a receiver. Not a server block of its own beside the interface's:
nginx serves the first server block for a name and port and silently ignores a second one, so that
block would test clean and never answer. **An installation set up before this line existed must
rerun `install/platform/05-platform-nginx`**, which adds the include and creates the empty
snippet; until then `add --transport https` refuses with `dependency_unavailable` rather than
registering a receiver nothing serves.

**What the receiver trusts.** The interface's certificate is what the receiver's `curl` must
verify, and it is served as a file for that purpose at `https://<server name>/certdist/manager-ui.pem`
(a copy under `/srv/certdist/`, written by `haproxy-ui-tls` at every replacement and by
`haproxy-ui-tls publish`; the TLS directory itself is root-only, which nginx's workers are not).
The receiver saves it once - `curl -k -o manager-ui.pem …` on that first contact, or with
`openssl s_client` where openssl exists - and passes it as `--cacert` to every fetch after, so it
trusts exactly that certificate. A receiver whose host already trusts the CA that issued the
interface's certificate needs neither the file nor `--cacert`. An installation whose site
predates the `manager-ui.pem` location reruns `05-platform-nginx`, which also publishes the copy.

Every change to sshd's drop-in or nginx's site is followed by `sshd -t` or `nginx -t`, and a
refusal puts the previous file back before reporting: a broken sshd locks out everyone, not only
the receiver being registered.

The account's home is the receiver's directory - one directory per receiver, root-owned, with the
lock in a root-owned `.ssh` inside it. An `sftp` receiver therefore sees `.ssh` in its chroot beside
its certificates: its own public key, readable and not writable, and nothing else.

**Removing** is refused while any certificate still names the receiver - `Remove from...` in the
interface ([Deleting a certificate](#deleting-a-certificate)) is what lets a certificate go of a target, and it is the operation that also
says what that costs. There is no operator command for that step: the interface queues a
`cert_target` job and the worker runs `haproxy-cert-target-helper`, which takes its request on
stdin and is not meant to be typed. Once nothing names it, the registry entry, the lock, the
directory and the account go in that order; an account another receiver still fetches as (the
`legacy` ones share one) is kept, and only the key line naming this directory is taken out.

**Migrating the receivers registered before this command** (the ones `list` shows as `legacy`,
sharing one account and a `flat` directory) is two steps with the receiver's own change in between:

```bash
sudo haproxy-cert-receiver migrate pve-01.example.net --public-key /tmp/pve-01.pub
# ... the host changes account, path and key, and fetches once ...
sudo haproxy-cert-receiver migrate pve-01.example.net --finish
```

The first builds the new account, directory and lock **beside** the old ones and points the
registry at the new path; nothing is taken away, so the host goes on fetching as before until it is
changed. `--finish` removes the old layer, and keeps the old account if another receiver still
fetches as it. A migration is refused while any certificate on that receiver has less than seven
days left: the new directory is empty until the next publish, and the publisher will not write a
certificate that close to expiry.

Reference fetch scripts for each transport are in
[`../examples/receivers/`](../examples/receivers/). They are what a receiver's own operator
adapts; the manager never pushes.

**The worker's sandbox must be able to look into a receiver's directory.** A receiver's files
belong to its fetch account (`0600`), and a directory made before this command existed may belong
to that account outright. Root inside the worker's unit is only uid 0 - the mode bits are the law
there unless the bounding set says otherwise - so the worker unit carries `CAP_DAC_READ_SEARCH`,
the read-and-traverse capability the poller already has. Without it a target change from the
interface ends `target_missing` on a directory that `haproxy-cert-publish` run as root from a
terminal publishes to without complaint. An installation whose worker unit predates this line
reruns `install/platform/07-platform-services`, which rewrites and restarts the unit.

**From the interface**, *Certificates → Receivers* lists every registered receiver - transport,
account, what it holds - and registers or removes one. The form takes the receiver's name, the
transport, and the public key pasted as text (or, for https, the allowed addresses); the job is
one `cert_receiver` run by `haproxy-cert-receiver-helper` - not through `sudo` but on a socket,
`/run/haproxy-mgmt/cert-receiver.sock`, from a unit of its own that step 07 installs (see *The
worker's way to the receiver helper* in the installation guide; migration `0032` lets the queue accept the job). The
helper takes the key as text and never as a path, so the interface cannot point it at a file. What the page adds over the command is the other half of the contract: under each
receiver it writes out the exact commands that host runs to fetch - the account, the manager's
name and each certificate it holds filled in, for Linux and for Windows where the transport
allows both - together with the `ssh-keygen` line the host runs first. Removal from the page is
refused while any certificate names the receiver, as at the terminal; a `legacy` receiver is
migrated from the terminal and not removed from the page.

The receivers page reads its rows from `registry.receiver_records` and the manager's name from
`registry.manager` in the `cert_list` answer (the interface's `SERVER_NAME`); an installation
whose CLI release predates those fields shows the page without rows until the CLI is updated.

## Nodes and clusters

### Adding and removing a node

A node is known to the management host in six root-owned places: its entry in `clusters.yaml`, its
host key in root's `known_hosts`, its two fetch keys in the pull accounts' `authorized_keys`, and -
where the traffic-log collector is installed - its entry in the collector's node list and its host
key in the collector's own `known_hosts`. `haproxy-node` and the Nodes card under Settings change
all six as one, through the same root helper:

```bash
# On the node: step 4 prints an enrollment block - one line starting with haproxy-node-v1:
sudo ./04-node-prepare answers.env alpha

# On the management host, the block on stdin:
sudo haproxy-node add -c alpha --host node-c.example.com < block
sudo haproxy-node remove -c alpha node-c
```

The block carries the node's name, its cluster, a suggested host name, its ed25519 host key and the
public halves of its two fetch keys. Copying it from the node's console is the trust - the manager
takes the host key from the block, never from the network - and the fingerprint the command and the
page print is the one to compare with what step 4 printed. `--host` is the name the manager reaches
the node at; the block's suggestion is the node's own `hostname -f` and may not be.

After writing, the manager asks the node for its status as the status identity, with strict host
key checking. The node reports its own host name and cluster, so an answer proves the host key, that
the node already has the manager's key lines from step 3, and that the block described the node that
answered. Anything short of that puts every file back and says why. The node has no certificates
and no release until `haproxy-cert-deploy -c <cluster>` and then `haproxy-deploy -c <cluster>` run
(*Deploy certificates* and *Deploy configuration* on the dashboard); a deploy before the
certificates stops and says so, since the node has none.

A removal takes the node's lines out of all six files, so it can no longer fetch configuration or
certificates. It is refused for the node that reports holding the VIP and below two nodes; the node
itself is not touched and keeps serving until it is shut down. A cluster has two to eight nodes
([Cluster definitions](#cluster-definitions)). Each node's `keepalived.conf` is not written by this project.

Once written by step 2, `clusters.yaml` is the record: a second run of step 2 keeps it unless
`REWRITE_CLUSTER_FILE=yes` asks for the answers file's version, and step 13 reads the collector's
nodes from it rather than from the answers file.

### Creating and removing a cluster

Steps 1 and 2 make the clusters of a new installation from the answers file. A cluster added later
is made by `haproxy-cluster`, or the Nodes card under Settings, through the same root helper as a
node:

```bash
# On each of the two nodes: step 4 prints its enrollment block for the new cluster.
sudo ./04-node-prepare answers.env beta

# On the management host, both blocks on stdin in the order of the --host options:
sudo haproxy-cluster add -c beta --display-name Beta --vip 203.0.113.10 \
    --node-path beta --certificate example.com \
    --host node-c.example.com --host node-d.example.com [--prefix 24] [--interface eth0] < blocks

sudo haproxy-cluster remove -c beta
```

A creation writes, as one change: the cluster's entry in `clusters.yaml`; the default certificate's
entry in the certificate registry, which gains the cluster as a target; a configuration repository
(the bare history and the worktree, seeded with the same `core/haproxy.cfg`, `manual/` and
`managed/network.yaml` step 1 makes, and owned like the others); an empty release directory; a
`sudoedit` rule per handwritten file in the operator editing policy, checked with `visudo -cqf`
before it is installed; the two repositories in root's git `safe.directory`; and both nodes in the
six places of [Adding and removing a node](#adding-and-removing-a-node). Then both nodes are asked for their
status, as a single added node is. Anything short of that removes the repository and release
directory again and puts every file back. The ID, the node path and the nodes' names and hosts
must all be free; the certificate must already be in the registry.

The new cluster is polled and drawn from the poller's next pass ([Which clusters get
polled](#which-clusters-get-polled)). It has no release until its network description and objects
are published and `haproxy-cert-deploy -c <cluster>` and then `haproxy-deploy -c <cluster>` run, and no backup schedule until one is set on
the Backups page; its retention is the default until then. Each node's `keepalived.conf` is not
written by this project.

A removal is refused for the last cluster. It takes the cluster out of `clusters.yaml`, out of every
certificate's targets, out of the editing policy and `safe.directory`, and takes its nodes out of the
six places; it stops `haproxy-state-backup@<cluster>.timer`. Nothing is deleted: the configuration
repository and its history, the release directory, the nodes' backup archives and the retention
file are moved to `.removed/<cluster>-<time>/` under their own roots - the same file system, so a
rename, and whatever protects the root protects the archive. The ID cannot be used again while its
archive is there; deleting an archive is a separate, deliberate step. The nodes are not touched and
keep serving the VIP until they are shut down - the manager only stops managing them. Jobs and
versions in the interface's database stay as history.

## The interface certificate

### Replacing it

Not by rerunning the installer. The command that owns the certificate is
installed by step 5:

```bash
sudo haproxy-ui-tls show
sudo haproxy-ui-tls install --cert /path/to/ui.crt --key /path/to/ui.key
```

`install` checks that the certificate and key actually belong together by
comparing public halves, refuses an expired certificate, warns under 30 days,
installs the pair root-owned `0600`, runs `nginx -t`, and **puts the previous
pair back if nginx refuses the new one**. A management host whose UI stopped
answering is a worse outcome than a rejected replacement.

The site config has HSTS present but commented out, with the reason next to it:
HSTS makes a certificate warning unclickable, so enabling it while the
certificate is still self-signed locks every operator out of the UI — including
whoever would fix it. Enable it after installing a trusted pair.

### From the certificate registry

The pair can instead come from the certificate registry ([The certificate registry](#the-certificate-registry)): an entry marked
`interface: true`, issued over ACME or NDES or imported like any other certificate, and renewed by
the same timer. Publishing that entry runs `haproxy-ui-tls install` with it - the same checks and
the same rollback as above - after two refusals the command does not make itself: the certificate
must name this host's `SERVER_NAME` (a wildcard covers one label), and a certificate nginx already
serves is not installed again, so a renewal of some other certificate costs no reload.

Who runs it depends on where the publish runs. `haproxy-cert-publish` and the renewal timer are
root outside any sandbox and install directly. The certificate helpers the worker starts through
`sudo` run inside the worker's `ProtectSystem=strict` namespace, where `/etc/haproxy-manager` is
read-only; they name the entry by ID to `haproxy-ui-tls-helper` on
`/run/haproxy-mgmt/ui-tls.sock`, a root unit step 07 installs, which reads the registry and the
material itself and refuses any entry not marked `interface: true`. The key never passes through
the web process: the interface names a certificate, never bytes, never a path.

At the terminal the mark is `--interface` on `haproxy-cert-issue`, `haproxy-cert-scep`,
`haproxy-cert-request` and `haproxy-cert-import`, with no `--cluster` or `--receiver` beside it; a
signing request or an NDES enrollment the CA is still holding remembers it until the certificate
arrives. A rotated or renewed interface certificate keeps the mark. A new one under another ID takes
it: the registry moves the mark, publishing installs the new certificate, and only once nginx
serves it is the previous entry deleted, through the ordinary deletion. If the install is refused
the previous pair keeps serving, and its entry stays in the listing without the mark and without
targets. The entry that serves the interface cannot be deleted (`serves_interface`).

`haproxy-ui-tls install` and `self-signed` stay the way back: running either replaces the served
pair whatever the registry says, and the next publish of the marked entry puts it back.

## Backups, and proving they restore

```bash
sudo haproxy-ui-backup dump            # what the daily timer runs
sudo haproxy-ui-backup verify-restore  # what the weekly timer runs
sudo haproxy-ui-backup list
```

**Dumps are root-owned `0600` in a `0700` directory**, and step 6 verifies that
none of the three application identities can read one. This is not tidiness: a
dump contains every Argon2id password hash and every session hash in the
installation, so it sits behind the same boundary as nginx's private key.

That constraint shapes the restore test. `pg_restore` there runs as the
`postgres` superuser — the only identity that may create and drop a database —
which must not be able to open the dump. So root opens the file and hands the
descriptor over: the archive is read without ever becoming readable to another
account.

#### What the dump does

- `pg_dump --format=custom`, written to a `.partial` name and renamed into
  place, so anything reading the directory sees a complete dump or none — never
  a file still being written that looks finished.
- Read back with `pg_restore --list` **before it is kept**. A zero exit from
  `pg_dump` says the command ran; this says the archive can be opened and its
  contents parsed, which is what a truncated or corrupt dump fails.
- One dump per day — today's replaces today's — and the seven newest are kept.
  Retention counts files rather than calendar days, so a week with the machine
  switched off does not delete the last dump that exists.
- Warns when the filesystem holding the dumps is over 85% full, and dumps
  anyway. A backup that refuses to run because a disk is filling is a backup
  that stops precisely when things are going wrong.

#### What the restore check does

It restores the newest dump into a scratch database that it creates and drops
itself — never a database named in configuration, because a restore test that
can be pointed at the wrong database will eventually overwrite something real.
Then it compares the result with what the archive holds:

- row counts for `app_user`, `app_session`, `audit_event`, `login_attempt` and
  `job`, named explicitly so an empty restore cannot pass by matching zero
  against zero. The expected count is read from the archive's own data section,
  not from the live database: live moves on after the dump — a sign-in adds a
  session, retention removes old jobs — and a check measured against it fails
  on a perfect restore. The live count is printed beside each table as
  information about how far the installation has moved since;
- a hard requirement that the restored `app_user` table is **not empty**, since
  an installation nobody can sign into is not a backup worth verifying;
- one row read back in full — the first account's hash must still be a valid
  Argon2id hash, because counts can match while the contents are unusable.

Any mismatch fails the unit, and the scratch database is dropped either way.

#### What is not covered

This is a database backup, and the database is not the whole installation. It
does not hold the HAProxy configuration — that lives in Git — nor the cluster
definitions, the keys, or the release tree. The DNS profiles it holds are
ciphertext: without the private key in `secrets/dns-profile-keys/` ([The DNS profile key pair](#the-dns-profile-key-pair)) a
restored dump lists every profile and can apply none of them, and the recovery
is to re-enter them. **Nothing here survives losing the
host**, and nor does anything else on it — the release tree, the runtime policy,
the keys, the sudoers rules. **Backing up the management host itself is a very
good idea**, and how that is done is entirely up to whoever runs it. If it is
backed up whole, these dumps are along for the ride.

That does not make them redundant. An image of a running database is
crash-consistent rather than transactionally clean, and restoring a single table
out of a machine image is not something anyone does under pressure. The dump is
what makes "put that one table back" an ordinary afternoon.

#### After restoring the database on its own: replay the traffic log

Restoring the whole host puts the database and the collector's staging back together, and nothing
more is needed. Restoring **only the database** from a dump does not: the collector keeps, per day
file in staging, how far it has imported, and that position is newer than the dump. Its next run
would go on from there and leave every request between the dump and the restore missing from the
log page, although the records are still in staging ([Mirroring node traffic logs](#mirroring-node-traffic-logs)). After such a restore, run once, as the
collector account (`COLLECTOR_USER`):

```bash
sudo -u <collector> /opt/haproxy-mgmt/current/bin/haproxy-ui-traffic-collector \
  --replay-database /etc/haproxy-manager/traffic-collector.json
```

It waits for a run in progress, drops the import positions and nothing else — the day files and
how far each node has been fetched stay — and the next run imports every staged day again. A
record the database already holds is passed over by the table's own duplicate check, so nothing is
counted twice. What staging no longer holds (older than the retention window plus one day) cannot
be replayed.

## Node backups

On the Backups page, an administrator can set each cluster's schedule on the manager's
clock, enable or disable it, choose how many archives to retain (1–365), and run a backup
immediately. Schedules may run every day, on chosen weekdays, or on one day of the month
(1–28). The terminal path is:

```bash
sudo haproxy-state-backup -c alpha
haproxy-list-backups -c alpha
```

Archives are root-only and belong to a specific node. For backup identities, storage and
timers, see [Runtime policy](#runtime-policy).

## Restoring a node onto an empty VM

A node that is lost is rebuilt from its state archive: install an empty VM, run
`haproxy-node-restore`, and the VM becomes that node - its hostname, address, SSH host keys,
accounts, node scripts and keepalived role - and then fetches its configuration and certificates
the way a deploy does. Nothing is installed on the VM beforehand.

**What counts as an empty VM.** Ubuntu 26.04 or Debian 13, installed from its cloud image - whichever
the node ran before does not matter; both write their network as Netplan, which is what the restore
writes. One network
interface with the same name as the node's, a temporary address the management host can reach,
an administrator account with `sudo`, and neither `haproxy` nor `keepalived` installed - the
restore installs them itself, with their services held off until their configuration is in place. The node's own address must not answer: a restore onto
it while the old node is still up would put two machines on one address, and the preview stops.

The same command also repairs a node that still runs, over itself - see *Repairing the node
itself* below.

**Three steps, each its own command**, run as root on the management host:

```bash
# 1. Choose the node, the archive (by its version, from haproxy-list-backups) and the VM.
sudo haproxy-node-restore prepare -c alpha --node node-a \
    --archive 2026-01-01_04-00-00 --target 192.0.2.120

# It prints one line. Paste it on the VM, as its administrator. It adds this run's
# one-time key to root's authorized_keys - restricted, and accepted only from the
# management host's address - shows the line that landed, and prints the VM's
# host key fingerprint.

# 2. Compare: the fingerprint it printed is the one the preview is given.
sudo haproxy-node-restore preview --run <run> --fingerprint SHA256:...

# 3. Carry out exactly what the preview showed, confirmed with the node's name.
sudo haproxy-node-restore run --run <run> --confirm node-a

# To abandon a run: remove its directory and one-time key.
sudo haproxy-node-restore discard --run <run>

# How a run stands: running, finished (and how), stopped mid-run, or not started.
sudo haproxy-node-restore status --run <run>
```

**The same three steps from the interface.** An administrator with management writes gets
*Restore…* on each archive row of the backup page. The form takes the temporary address and the
mode (the node itself, or a test with its hostname, address and VIP); the run's own page,
`/backups/restore/<run>`, then shows the line to paste, takes the fingerprint, shows the plan and
takes the node's name as confirmation. Each step is one job - `node_restore_prepare`,
`node_restore_preview`, `node_restore` - run by the worker through the root helper on
`node-restore.sock`, the same engine as the command. The page is drawn from those jobs alone;
nothing else is stored. While a job runs it holds the cluster's job slot, so a deploy to that
cluster waits. *Discard* on the run's page is the fourth job, `node_restore_discard`.

**When the run's job loses its answer.** The job ends `unknown` - the helper may have gone on as
root and changed the node - and the page says *Outcome unknown* rather than failed. *Ask for the
outcome* queues the fifth job, `node_restore_status`, which reads the run's directory and changes
nothing. A finished run is then drawn as its own answer; otherwise the page says what was found:
still running, stopped mid-run (look at the target), or never started. The helper's socket takes
one connection at a time, so while a restore still holds it the question is answered *ask again
when it has finished*.

**A run has an hour.** From *prepare* to the start of *run*: past it the run has expired, the
backup page stops listing it, its page takes nothing more, and the command and the helper refuse
it and remove its directory - prepare a new one. Every call to either puts away the runs past
their hour that no step is working in. A run that never began writing to the target goes whole;
one that did loses its one-time key, `known_hosts` and preview at the hour and keeps
`request.json`, `prepared.json`, `started.json` and `result.json` for seven days - as long as the
web keeps its jobs - so its outcome can still be read with `status`. The pasted line
carries `expiry-time` two hours after *prepare*, so the VM itself stops accepting the one-time key
even when nothing on the management host ever runs again.

**What the preview shows and what stops it.** The target's OS, interface and MAC address; the
host key fingerprint; the name and address the VM will have; every file written, and every archived
file that is not - the VM's own in a directory it shares with the image, the archive's APT sources,
and old `.replaced-` copies (kept on the node, 30 days - see
[What a node keeps and for how long](#what-a-node-keeps-and-for-how-long)); the node bundle that will prepare the node; every account with its IDs
and groups; and, in test mode, every rewritten field with its old and new value. It stops on: this
manager's CLI release carrying no node bundle, or one that does not verify (see
[Part 3](#part-3--the-versioned-cli-release)); a `node.conf` in the archive that cannot be read back
into answers; a fingerprint that is not the one
given (nothing is sent at all); an archive that is not of the chosen node; a target that is not
Ubuntu 26.04 or Debian 13; `haproxy` or `keepalived` already installed (unless an earlier restore run left
them there - a run that rolled back can be tried again); the final address, or the node's own,
already answering; and an account whose primary group the archive does not
carry. A number the VM already uses stops nothing: an account or group is its name. One the VM
already has keeps the VM's number, a new one gets the archive's number where it is free and a free
one of the same kind (system or ordinary) where it is not, and the preview lists every such
change; the restored files are owned by name, so they follow. `run` asks the VM again and refuses unless the
archive, the VM and the plan are exactly what the preview saw - so what was approved is what is
written.

**What `run` does, in order.** Three SSH sessions with the one-time key:

1. On the temporary address: the archive's groups and accounts, numbered as above (before any
   package can take a number), password hashes only for accounts that have no password on the VM, the
   HAProxy repository for the VM's own distribution and release on the branch the node ran (the
   archive's APT sources name the release it was taken on and are not written; the VM keeps its
   own; the repository's signing key ships with the product and is used only when its fingerprint
   is the one pinned in the code - it is never fetched at restore time), then `haproxy keepalived rsyslog openssh-server rsync python3 netplan.io` with
   service starts held off until their configuration is in place, then the files. Only paths the
   export copied get the archive's ownership and mode; a directory it created only to hold one is
   made if missing and otherwise left alone. What the product shares with the OS image is restored
   file by file, not directory by directory: in `sudoers.d` and `sysctl.d` only the file
   `04-node-prepare` writes comes back, and `sshd_config` and its drop-ins stay the VM's own. An
   operator's own file there comes back when the node names it in `EXTRA_BACKUP_PATHS`. Then the
   HAProxy release layout, the services, the hostname, and sshd is reloaded. Last, the node
   bundle of the manager's own CLI release runs its `04-node-prepare` on the VM, with an answers
   file read back out of the archive's `node.conf` (and the manager's publish root): it writes the
   node scripts and `node-installation.json` of the running release, not the archive's, the sudo
   rules, the traffic-log directory, and re-renders `node.conf` - to the same bytes, which the
   preview's answers are tested against. If the archive shows the traffic log was on, the bundle's
   `haproxy-traffic-log-enable` turns it on again, prune timer included.
2. Still there: the archive's Netplan, bound to the VM's MAC address, applied three seconds after
   the session ends - under a timer that puts the VM's own Netplan back after 180 seconds.
3. On the node's own address, with the archive's host key: the timer is cancelled, HAProxy starts
   on a placeholder release whose only listener is a root-only unix socket, the node's
   `haproxy-cert-pull` fetches the cluster's certificates and its `haproxy-pull-deploy` the
   published configuration - the same scripts a deploy triggers - keepalived starts as `BACKUP`,
   and **last** root's `authorized_keys` is replaced by the archive's, which removes the one-time
   key.

If the node never answers on its own address, the timer returns the VM to its temporary address
and the run reports `failed` with the network rolled back. A session that breaks or times out
once writing has begun is a `failed` run in that session, never a refusal. The run's result is
kept in `/var/lib/haproxy-mgmt/restore/<run>/result.json`, root-only `0600` in a `0700`
directory, with `started.json` written just before the first write to the target. A restore takes about a minute; the longest part is the package installation.

**Test mode proves a restore before it is needed.** Add `--test --test-hostname <name>
--test-address <address/prefix> --test-vip <address/prefix>` to `prepare`. The node is restored as
above, except that the hostname, the node address in Netplan, keepalived's own address and its
virtual addresses are rewritten to the test values - the preview lists every one - the `include`
of the published address list is removed, keepalived is masked so it can never join the
production pair's VRRP, and the VM keeps its own SSH host keys. The test address must be in the
node's network, because the node's routes come with the archive. `--confirm` takes the test
hostname.

**Repairing the node itself.** The same restore, with the node's own address as `--target`, puts
the archive back over the node - for a node left in a bad state by hand. Nothing is chosen for
this: the preview tells the two cases apart by the host key the target offers. The archived one
means the node itself; any other means an empty VM in its place, with the rules above. The paste
and the three steps are the same; over the node itself, what differs:

- the node must be reached at the address its archive gives it;
- the preview takes a state backup of the cluster and reads the pair: whether this node holds the
  VIP and whether its neighbour is healthy (answering, HAProxy and keepalived active). It lists
  every file whose contents differ from the node's, how many are already equal, what goes to
  quarantine, and whether the network differs;
- `run` refuses when that backup failed, unless `--backup-failed-ok`, and when the node may hold
  the VIP while its neighbour is not healthy, unless `--break-traffic` - which is what it says;
- before its first write the run copies every path it or the node bundle may change to
  `/var/lib/haproxy-restore/<run>/before/` on the node, then stops keepalived, so the VIP moves to
  the neighbour before anything changes. The copy stays 30 days (see
  [What a node keeps and for how long](#what-a-node-keeps-and-for-how-long));
- the node's software is its own: no repository file is written, and only a product package the
  node lacks is installed (`apt-get install --no-upgrade`, from the node's own sources). The HAProxy
  releases and `current` are not touched;
- what `/etc/haproxy-manager` and `/etc/systemd/system/haproxy.service.d` hold beyond the archive
  and the node bundle goes to quarantine on the node - not deleted by the run, and removed with the
  run's directory after 30 days ([What a node keeps and for how long](#what-a-node-keeps-and-for-how-long)); the directories the product
  shares with the OS image keep the image's files, as for a new VM;
- Netplan is written only when the node's differs from the archive's; otherwise the network
  session is skipped and nothing is applied;
- if a session fails, the node is put back from its copy in the same session - or, after a
  network change that never came up, by the timer and then from the management host once the node
  answers again - keepalived is started again, and the run is `failed` with `rolled_back`. The
  one-time key stays in root's `authorized_keys` until its `expiry-time` when the run was put back.

**What it does not do.** Restore onto an OS other
than Ubuntu 26.04 or Debian 13; configure what is the environment's rather than the product's - a
configuration-management baseline, monitoring agents, an operator's own sudo rules - which runs
afterwards as it would on any new machine.

The restore is one piece of a recovery plan; the rest - where the VM comes from, how the management
host survives, who fails over - is yours to decide. [`DISASTER-RECOVERY.md`](DISASTER-RECOVERY.md)
lists the questions.

## What a node keeps, and for how long

Two kinds of copies build up on a node. Both are removed automatically after **30 days**, and
only at the moment a new copy of the same kind is made. Nothing runs on the node on a schedule
for this. A node that is never reinstalled or restored keeps its copies until it is.

| What | Where | Made by | Removed |
|---|---|---|---|
| rollback copy of a file an installer replaced | `<file>.replaced-<yyyymmdd-hhmmss>` beside the file, e.g. `/etc/haproxy-manager/node.conf.replaced-20260924-200115`, `/usr/local/sbin/haproxy-pull-deploy.replaced-…` | `04-node-prepare` (and so every node bundle installation and every restore) | when the same file is next installed, if the time in its name is more than 30 days old. **The newest copy of each file always stays, however old.** |
| a restore run's directory: the `before/` copy an overwrite took, its `quarantine/`, and the node bundle it installed | `/var/lib/haproxy-restore/<run>/` | `haproxy-node-restore` (the terminal or the web page) | when a later restore run begins writing to the same node, if the run is more than 30 days old (by the date in its ID, `r<yymmdd>-…`). The current run is never removed. |

Why 30 days: a copy is for the days after a change, until the change has proved itself. After
that, the nightly state backup on the management host is the node's history and a node bundle
rollback is done with the previous bundle (see [node bundle rollback](#rollback)), not with these copies. The
age of a `.replaced-` copy is the time in its name, not its modification time: `cp -a` keeps the
original's.

To keep something for longer, move it out of those names before the next installation or restore:
anything not named `<file>.replaced-<yyyymmdd-hhmmss>`, and any directory under
`/var/lib/haproxy-restore` that is not a run ID, is left alone. The periods are
`REPLACED_KEEP_DAYS` in `install/lib.sh` and `RUN_KEPT_DAYS` in `haproxy_mgmt/restore_agent.py`.
Each removal is printed: `pruned <path>` in the installer's output, and an `old-runs` step in the
restore's `apply` session.

The manager's own installers use the same `install_file` and so the same rule for the files they
write; the manager is backed up as a whole machine and needs no older copies than that.

## Keeping jobs, sessions and metric history bounded

```bash
sudo haproxy-ui-retention report              # how many rows, how many removable
sudo haproxy-ui-retention prune --dry-run     # the same, deleting nothing
sudo haproxy-ui-retention prune               # what the daily timer runs
```

**It is a root command because no application role holds `delete` on any table,
and none is going to.** That is the same boundary as the audit trail and the
login attempts: a compromised web or worker process must not be able to remove
the record of what it did. The migration role owns the table and may therefore
delete from it, and the ident map lets root — and only root — be that role for
this database. The step verifies that last part rather than describing it: if an
application identity could connect as the owning role, nothing about `delete`
being ungranted would matter.

#### What it removes, and what it will not

- **Finished jobs older than seven days.** A management request older than that
  has been acted on or superseded, and *what it did* is in the audit trail,
  which this never touches.
- **Never a `pending` or `running` job**, however old. Those are the states the
  single-active-job index is built on, and removing one would let a second
  operation start against a cluster that is still being changed. Every other
  state carries a `finished_at` by the table's own constraint, so the age test
  cannot match a row that has no timestamp.
- **Never the twenty most recent rows**, whatever their age. Without that floor
  a quiet fortnight empties the jobs page completely, which reads as the
  interface having lost its history rather than as nothing having happened.
  Twenty is the number the page itself lists, **ordered the way the page orders
  them**, so the floor is exactly the set a reader can see. Ordered any other
  way it would select a different twenty rows and quietly stop promising
  anything.
- **OIDC sign-ins in progress older than a day** (schema `0041`). Each sign-in
  through the provider leaves one row, usable for ten minutes and once; a day
  is kept so a failed sign-in can still be looked at the next morning.
- **Sessions that ended more than thirty days ago**, expired or signed out. A
  live session is never touched.
- **Sign-in attempts older than ninety days**, far outside any throttle window
  (at most a day) — **except each name's newest successful attempt**, which is
  what *Last sign-in* on the Users page reads. A break-glass account may go
  unused for longer than ninety days and must not then read as never used.
- **Diffs of versions no longer listed** (schema `0046`). The poller keeps what
  each version changed and may only add; after a history reset, or once a
  version is older than the listing reaches, its diff is removed here. A cluster
  whose last listing failed is left alone.
- **Never the audit trail.** It is the record of what every identity did and
  is kept for the life of the installation.

The timer runs daily, after the daily dump rather than before it, so the newest
dump still contains the rows the prune removes.

The same command creates the metric tables' future partitions, writes the pool's
hourly rollup and removes expired partitions. It performs those actions in that
order. The rollup and its `metric_rollup_state` completion boundary are written
by one SQL statement; a failed statement advances neither. Only then may raw
pool partitions be dropped, and only when their complete day is at least one
further day behind that boundary. Listener metrics have no rollup and keep their
fixed seven-day raw retention.

The interface normally changes from raw pool samples to the hourly rollup at
seven days. If maintenance has fallen behind, it moves that boundary back to the
last continuously completed hour and reads the still-retained raw samples from
there. An hour with no samples still advances the boundary: the marker says the
interval was considered, whereas the newest rollup row cannot distinguish an
empty hour from an unprocessed one. `report` prints the boundary so lag is
visible without changing the database.

The timer is daily because that normally keeps the completed edge six days
ahead of the preferred reader boundary. The explicit boundary is what keeps a
longer outage correct; the schedule is no longer treated as proof that work
finished. The installed command also remains usable against revision `0020`
during a staged upgrade. There it rolls up before age-based pruning but cannot
publish a completion boundary until migration `0021` exists.

Unlike the backup step, this one is meant to be run for development too — a
development platform's job table grows exactly as production's does, and
rehearsal traffic fills it fastest. Its units are therefore named after the
environment, since a machine carrying both platforms would otherwise have two
timers pruning each other's database.

## Traffic logs and metrics

### A basic log viewer, on purpose

The page answers one question: what did the recent requests look like. A filter —
cluster, status class, search, a from/to time — searches every day the database
holds, and the page shows the newest matches, at most `max_lines` of them (500 by
default, at most 10 000). A column heading reorders **those rows**; it does not ask
the database for another order, so sorting on *Bytes* shows the largest of the
newest matches, not the largest of the week. Each row shows the time, cluster and
node, client, request, status, destination and size, and nothing more.

That is deliberate. Aggregation over time, dashboards, alerting, long retention
and correlation with other systems are what dedicated log platforms such as Loki
or Elasticsearch do well, and rebuilding them here would be a second, weaker copy.
An installation that needs them should send the logs to such a platform, and
the nodes can do that themselves: see [Sending the traffic log elsewhere and metrics](#sending-the-traffic-log-elsewhere-and-metrics).

### Sending the traffic log elsewhere, and metrics

Each cluster can send its traffic log to up to four external receivers and
expose HAProxy's own Prometheus exporter. Both are settings of the cluster's
HAProxy configuration, kept in `managed/cluster.yaml` in its repository and
published as a version like any other change - a lock, a validated candidate,
*Published by*, and a revert that takes them back. Nothing is installed on the
nodes and nothing is relayed through the management host: after `haproxy-deploy`
the nodes send and listen themselves.

```yaml
# managed/cluster.yaml
log_targets:
  graylog:
    address: 192.0.2.20      # an IP address, never a name
    port: 6514
    buffer_kib: 4096         # optional; 64 to 65536
    tls: false               # optional
metrics:
  port: 8405
  sources:
    - 192.0.2.0/24           # who may scrape; everyone else gets 403
```

An admin edits it under **Settings → Logs & metrics**, one row per cluster and a
page for each (installations with `management_writes` on); saving publishes a
version, and deploying it is what reaches the nodes. Or read and set it at the
terminal - `--set` publishes through the same privileged helper the interface
uses, against the version it has just read, so a change
somebody else published in between is refused rather than overwritten. It runs
under `sudo`, and the version records the person who typed it:

```bash
sudo haproxy-cluster-settings -c alpha
sudo haproxy-cluster-settings -c alpha --set cluster.yaml -m "Send the traffic log to graylog"
haproxy-deploy -c alpha
```

**The log** is the same structured record the node's own file gets ([Mirroring node traffic logs](#mirroring-node-traffic-logs)),
plus `node`, the host name of the node that wrote it, sent as syslog over TCP
(RFC 5424, octet-counted) whether or not the local stream is on. The syslog
header's host name field is `-`: HAProxy sets it only globally, and doing so
would change the node's own classic log lines too. One transport reaches the common platforms through their usual
receivers: Graylog takes it directly, Loki through a syslog receiver such as
Grafana Alloy's `loki.source.syslog`, Elasticsearch or OpenSearch through
Logstash or Vector with a syslog input. `tls: true` verifies the receiver
against the node's system trust store.

A receiver is named by **address, never by host name.** HAProxy resolves a log
server when it reads the configuration, whatever the server's `init-addr`
says, so a name that fails to resolve at a reload fails the whole
configuration and the deploy with it. An address fails nothing.

Each receiver has a buffer of its own, and the buffer is what an outage is
survived with. While a receiver is away, HAProxy keeps what fits and drops the
rest; the traffic itself is not held up. Measured on 3.4.4: with a receiver
that accepted and then stopped reading, nine thousand requests were served
without an error and without a change in response time, HAProxy disconnected
the receiver once its server timeout ran out (10 s in the generated ring),
reconnected once it answered again, and
delivered the buffer and everything after it. A receiver that has been away
longer than its buffer lasts has lost the difference, and nothing in the
traffic shows it; watch the receiving side.

**The exporter** answers `GET /metrics` on the port given, on every IPv4
address of both nodes - the configuration is shared by the pair, and scraping
each node is what shows the passive one as well. Only the listed sources get
an answer; anything else gets 403, and any other path 404. The port is taken on
every address, so a publish refuses one that an object already listens on or
that `manual/reservations.yaml` reserves. Letting the scraper through the
nodes' firewall, and letting the nodes reach the log receivers, is part of the
installation, not of this setting.

## Jobs and status freshness

### How often status is refreshed

`poller.interval_seconds` in `ui.toml`, 20 by default, bounded to 10-3600. It is
a sleep *after* a pass rather than a fixed period, so the real cadence is the
interval plus however long a pass takes - measured at 2-3 seconds for two
clusters on the reference machine, where one pass is fourteen helper
invocations and two of them reach the nodes.

**A finished job wakes it as well as the clock.** Publishing or deploying
through the interface queues a job, and the poller reads the clusters again as
soon as that job ends - so those changes appear without waiting. What waits is a
change made *outside* the interface: `haproxy-publish` or `haproxy-deploy` run
on the command line queues no job, nothing is notified, and until the next tick
the pages show the reading taken before the change. An object deployed from the
command line therefore keeps its `Inactive - deploy to add` badge for up to one
interval, which is the interface being careful rather than wrong.

The same holds for what a version changed. `haproxy-list -c <cluster> --diff <version>`
prints one version against the version before it, file by file; the poller asks the
helper for the same thing (`diffs`, at most ten commit hashes per request) for each
version it has no diff for yet and keeps the answer, since a version's diff never
changes. Both read it through one function, bounded at 200 files and 256 KiB of
patch text, and a diff past that bound says it was cut.

Two failure kinds are kept apart in the table. `poll_error` means the poller
could not get an answer — sudo refused, the helper is missing, the output was
not JSON. An `outcome` of `failed` or `partial` means the cluster answered and
the answer is bad news. Collapsing them would send somebody to read sudoers when
a node is down, or the reverse.

### The worker

It starts, connects and reports which database role it is actually running as.
With `management_writes` off it claims nothing: that is the state a rollback of
the write path returns to, so it has to be a state that runs.

With writes on it runs each job through an exact privileged helper, over `sudo`
for most and over a root-owned socket for the few that write under `/etc`. Its
unit therefore allows `sudo` to raise privilege (`NoNewPrivileges=no` and a
short, named capability set); every capability is explained in the unit file
beside it. The real limit is not the sandbox but
`/etc/sudoers.d/haproxy-ui-worker`, which names each helper and permits no
arguments: widening the unit does not widen what may be run, only that file
does.

Once writes are on, each pass first settles jobs whose worker died. An expired
lease says only that the process holding a job stopped renewing its authority,
so the job is judged by what can be read rather than retried on assumption: a
publish, a revert or a managed-network publish by whether a version carrying that request exists and
whether its release was published, a deploy or a certificate deploy by nothing
at all, because those read the cluster before they act and repeating one is how
they work. Evidence older than the expired lease is not weak evidence but none —
it describes a world in which the operation could still have been running — and
such a job waits rather than being decided. A job is handed to a worker at most
twice; one that has been taken twice and answered neither time ends as
`unknown`, which is the outcome reserved for "nobody can say whether this took
effect" and is never retried automatically.

This too is below the writes check. With writes off nothing moves at all,
including a job somebody would rather see moved — which is what makes the flag a
rollback rather than a pause.

**The worker may not touch `proxy_draft`.** Only the web role holds grants on it. The worker
publishes from the job payload, never from the table, which is why a draft that has been published
is cleared by the interface on its next read rather than by the worker as it finishes. The clearing
matches on the publish's idempotency key, which carries the draft revision — so a draft edited after
the publish was asked for has a different key and is left alone.

## Maintenance

### Keeping HAProxy current

Which HAProxy version runs, and when it is upgraded, stays with you. That is a boundary in the
design rather than an omission, and it is worth knowing why before it matters.

Upgrading the package restarts the data plane. The whole privilege model here exists so that this
tool cannot do that on its own: every management identity is a forced command that can ask a node
to *pull* something, and nothing else. There is no push path, and a tool that could silently
restart HAProxy on a live node would need one. Package upkeep belongs to whatever already patches
these hosts — unattended upgrades, a configuration-management run, your own maintenance window —
on a schedule you choose and can pause.

Two things this project does depend on:

**The branch you run should still be receiving fixes.** HAProxy publishes maintenance status per
branch at [haproxy.org](https://www.haproxy.org/), and the binary states it too:

```console
$ haproxy -v
HAProxy version 3.4.4 2026/08/28 - https://haproxy.org/
Status: long-term supported branch - will stop receiving fixes around Q2 2031.
```

Distribution packages are often frozen at an early point release of a branch and carry backported
security fixes only, which is a different thing from running the branch's current release. Both are
defensible; they are worth telling apart deliberately rather than by default.

**The management host and the nodes should run the same branch.** The management host validates a
candidate configuration with its own `haproxy -c` before any node is asked to pull it. That check
is only meaningful while it is at least as strict as the nodes are. A validator on a *newer* branch
can accept a directive the nodes then reject — the deploy fails on the first node and rolls back,
so nothing breaks, but the check stopped doing its job. When you upgrade, do the nodes first and
the management host last, and the validator is never the newer of the two.

Package sources and pinning are described under
[Where the package comes from](#where-the-package-comes-from).

### Releasing a change

Three things install independently — the CLI engine, the web platform, and the
node scripts — and a release ships only the ones a change actually touched.
Which of them a change touched is a question with a measurable answer, so
measure it rather than deciding by feel:

```bash
git show --stat <commit>
```

| What the commit touched | What to release |
|---|---|
| `src/haproxy_mgmt/`, `tools/`, `install/` | the CLI wheel — [Part 3](#part-3--the-versioned-cli-release) |
| `ui/` | the platform, `update-platform-release`, development then production |
| `install/node/`, node scripts | the node bundle, per [Part 2](#part-2--the-nodes) |
| more than one of those | **the CLI wheel first**, then the platform, then the nodes |

**The CLI wheel goes first when both move**, and the order is not a preference.
The platform check deliberately compares the independently installed CLI before
it activates a UI candidate, so releasing the UI first stops its own update —
correctly, but after it has already prepared and migrated.

**Development before production**, for the same reason both exist: production
is where the real configuration lives, so it is the environment where a bad
release costs something.

A CLI-only change does not need a UI release, and forcing one would be the
mistake the compatibility check was built to avoid. It compares engine API
levels and helper names, never release hashes, precisely so an engine
correction does not drag an unrelated UI rollout along with it. What decides
whether the running UI still fits the new engine is:

- `src/haproxy_mgmt/compatibility.json` — the engine API the wheel carries. A
  UI release declares the minimum it needs.
- the console scripts in `pyproject.toml` — the check requires every helper the
  UI names by name.

Unchanged in both means the running UI keeps working, whatever the new release
is called. Changed in either means the UI release moves with it, in that order.

**Prove it afterwards rather than assuming it.** The install steps each prove
their own result; the whole-installation check answers the different question of
whether the independently installed pieces still work together:

```bash
sudo install/platform/check-compatibility /path/to/answers.env
```

Run it against the production answers file after any of the three. Development
installs no CLI, no worker, no poller and no nodes — that is its isolation
boundary, not a skipped check — so its own check cannot say anything about an
engine release.

**Every release is a commit.** Both installers refuse a source tree with
uncommitted changes, because a release built from an edited tree is one nobody
can reproduce, and the moment it runs, "what is in it" has no answer. Run the
full repository gate before building; a release is not the place to find out
that a test fails.

### CLI rollback

Re-run the same installer with the retained previous wheel and its recorded digest - and its node
bundle, if it was installed with one. An already installed matching release is verified and
`current` is atomically switched back.

**Ten releases stay on disk; older ones go when a new one activates.** The installer prunes after
a successful activation and never before it - a failed activation is exactly when nothing may be
removed - and it always keeps the release it just activated and the one that was current before,
whatever their age, so the rollback path is never the one pruned. Ten is enough because a release
is reproducible from its commit: the wheel is built from `git archive <commit>`, so removing an
old directory loses nothing Git holds. `--keep N` changes the number (at least two).

### Rolling a release back

```bash
sudo haproxy-ui-rollback --list
sudo haproxy-ui-rollback                       # the previous release
sudo haproxy-ui-rollback --to <release-id>     # a named one
```

"Point `current` back and restart" is the shape of the rollback, but doing only
that took the interface down when it was measured. Two reasons, neither visible
from the symlink:

- **Configuration is validated strictly.** Unknown keys are refused, which is
  what makes a typo an error rather than a setting that silently does nothing —
  and it means a configuration written for release N makes release N−1 refuse to
  start. **Configuration follows the same expand/contract rule as the schema:** a
  key added for a newer release has to be removed before rolling back past the
  release that introduced it.
- **Units name programs.** A unit installed for a newer release starts a program
  an older release does not contain. The poller and the worker did not exist in
  every release still on disk.

So the command checks both against the target *before* switching — asking the
target's own validator, because the answer is whatever that release says rather
than what the script believes — and verifies the interface answers afterwards,
**rolling forward by itself if it does not**. Somebody running this is already
having a bad day; leaving them on a release that does not answer, with the
rollback reported as done, is the worst outcome available.

Releases are offered oldest-last by build time rather than by name: an id ends
in a commit hash, which sorts alphabetically and says nothing about when it was
built.

How far back that list reaches is bounded: `update-platform-release` keeps the
ten newest releases on a production platform and three on a development one,
pruning the rest only after the update has been proved, and always keeping the
release just activated and the one it replaced. A release is reproducible from
its commit, so nothing older is lost with the directory. `RELEASES_KEPT` in the
answers file changes the number (at least two).


## Environment reference

Deployment layout, prerequisites, configuration files, service identities, node preparation
and implementation details are collected here for administration and troubleshooting.
For the steps to install the application, use the [installation guide](install.md).

### The shape of a deployment

```text
                 mgr  (management host)
                  |
     authoritative config, published releases,
     the CLI, the privileged helpers, the keys
                  |
        +---------+---------+
        |                   |
     node-a              node-b        cluster alpha
     node-a              node-b        cluster beta
```

Three properties drive the whole design, and every step below follows from one of them:

1. **The management host never pushes.** It asks a node to pull, and nothing else. Every management
   SSH identity is a forced command; none of them can copy a file or run a shell on a node. A node
   fetches its own configuration from the management host over a separate, restricted account.
   The one exception is deliberate and does not stand: restoring a node onto an empty VM
   ([Restoring a node onto an empty vm](#restoring-a-node-onto-an-empty-vm)) writes as root through a key the operator pastes
   into that VM's console for one run, limited to the management host's address, and removed by
   the run itself as its last step.
2. **Configuration is versioned before it is deployed.** Editing produces a draft; publishing
   produces an immutable release; deploying brings nodes to a published release. Each stage is a
   separate command with its own privilege.
3. **The application never holds privilege.** Privileged work happens in small root-owned helpers
   with no caller-supplied paths, reached through exact sudo rules. See
   [`PRIVILEGE.md`](PRIVILEGE.md) for the contract these rules implement.

### Prerequisites

HAProxy Manager manages HAProxy's configuration; it does not install, patch or upgrade
HAProxy itself. Before starting, you need:

**On the management host**

- a current Linux distribution with `systemd`
- Python 3.12 or newer at `/usr/bin/python3`
- the operating-system PyYAML package (`python3-yaml`), major version 6
- the operating-system PyNaCl package (`python3-nacl`), major version 1 - the CLI release's
  installer refuses a host without it, as it does without PyYAML
- the operating-system psycopg package (`python3-psycopg`), major version 3 - the collector uses
  it for transactional PostgreSQL COPY and the CLI installer refuses a host without it
- `git`, `rsync`, `openssh-client`
- `sudo` new enough to support the no-argument sudoers form (`command ""`)

**On the management host, only for the web platform (Part 4)**

- PostgreSQL 16 or newer. 16 is the floor rather than a preference: role
  membership carries its own `INHERIT` setting from that version, and the
  installation states it explicitly instead of depending on a role attribute as
  it happened to be when a grant was made
- nginx
- `uv`, for building a release environment from the committed lockfile

**On every node**

- HAProxy, installed and managed by `systemd`, from the source you choose ([Where the package comes
  from](#where-the-package-comes-from))
- `keepalived`, if the cluster uses a virtual address
- `rsync` and `openssh-server`
- `sudo`

**Names and addresses you decide before you start**

| Thing | Example | Notes |
|---|---|---|
| management host | `mgr` | reachable by name from every node |
| cluster IDs | `alpha`, `beta` | lowercase, used in every command as `-c <cluster>` |
| node names | `node-a`, `node-b` | two per cluster in the reference layout |
| virtual address | `192.0.2.10` | per cluster, if keepalived is used |
| management network | `192.0.2.0/24` | how the host and nodes reach each other |

#### Where the package comes from

To run a branch's current release rather than the distribution's frozen one, take HAProxy from the
repositories [haproxy.org](https://www.haproxy.org/) links to, maintained per branch: the
`vbernat/haproxy-<branch>` PPA on Ubuntu, and [haproxy.debian.net](https://haproxy.debian.net/) on
Debian. They follow upstream closely but not instantly - a point release has reached them a day or
two after haproxy.org announced it - so `apt` offers a new release only after its next list update
following the repository's.

Pin the package to that repository, on the management host and on every node alike, so that an
upgrade never quietly falls back to the distribution's older branch:

```text
# /etc/apt/preferences.d/haproxy
Package: haproxy haproxy-doc vim-haproxy
Pin: release o=<origin of the HAProxy repository>
Pin-Priority: 1001

Package: haproxy haproxy-doc vim-haproxy
Pin: release o=Ubuntu
Pin-Priority: -1
```

`1001` takes the repository's package even where that would be a downgrade; `-1` never installs the
distribution's, so a repository that stops answering becomes an error at the next upgrade rather
than a silent change of branch. On Debian the second stanza names `o=Debian`. Read the origin from
the repository's own `Release` file, or from `apt-cache policy` once the source is added
(`release ...,o=LP-PPA-vbernat-haproxy-3.4,...` for the Ubuntu 3.4 PPA) - an origin that is
mistyped matches nothing, and the pin then silently does nothing. `apt-cache policy haproxy` shows
the pin working: the repository's version at priority 1001, the distribution's at -1.

The installation steps do not set this up. The dashboard's *Runtime* column shows the version each
node's HAProxy process is running, read from its runtime socket - after an upgrade, the new version
appears there once the service has restarted.

### Part 1 — the management host

#### Service accounts and the config group

The web, worker, and poller processes run as three distinct, locked, no-login accounts, and only
the worker joins the read-only configuration group. Account names are deployment data, so they are
supplied in a policy file rather than compiled in:

```bash
haproxy-render-sysusers --policy /etc/haproxy-manager/identity-policy.yaml
```

The command validates the policy and renders a `sysusers.d` fragment. It does not modify the
system — review the fragment, install it, and let `systemd-sysusers` apply it.

Human operators are deliberately absent from the fragment. Adding an administrator to the config
group is a separate action against an already existing account.

#### Directory layout

```text
/srv/haproxy-manager/config/alpha.git/            authoritative history, bare
/srv/haproxy-manager/config/alpha/                linked draft worktree - what you edit
/srv/haproxy-manager/config/alpha/{core,managed,manual}

/srv/haproxy-manager/published/alpha/releases/    immutable published releases
/srv/haproxy-manager/published/alpha/current      symlink to the current release

/srv/haproxy-manager/validation/certs/            validation-only certificate material
/srv/haproxy-manager/clusters.yaml                cluster definitions
/etc/haproxy-manager/runtime-policy.yaml          the outer path boundary
```

**Read your handwritten layers before adding `default-path config`.** It changes how every relative
path in the configuration resolves, and a `crt`, `map` or `errorfile` written relatively would start
resolving somewhere else. Generated configuration writes absolute paths throughout, so only
`manual/` and `core/conf.d` need looking at.

`manual/reservations.yaml` is what the handwritten half of the configuration declares about itself:

```yaml
# Hostnames a handwritten frontend already answers for, and ports it already
# binds. A generated object claiming one is refused before anything is
# committed. Both lists are optional; `{}` reserves nothing, which is what a
# cluster that has never needed one carries.
hostnames:
  - legacy.example.com
tcp_ports:
  - 8443                 # every address this cluster has
  - 192.0.2.10:8443      # only that one
reviewed:
  # Each handwritten fragment, with the SHA-256 of the bytes you read.
  core/conf.d/0010-stats.cfg: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
```

A bare port and a port written `:8443` mean the same thing: claimed on every
address. That is what a `bind` line without an address does, so a handwritten
listener written that way really has taken the port everywhere. Give the address
when the claim belongs to one VIP — otherwise a cluster with several of them
cannot reserve anything without blocking every managed object on all the others.
An IPv6 address is bracketed, `[2001:db8::1]:8443`, exactly as a bind line
requires.

`reviewed:` is what keeps the promise current. A reservation written once and
never revisited looks exactly like a complete one, so a listener added to a
fragment afterwards would be invisible. Naming each fragment together with the
digest of what you read closes that: when the file changes, the digest stops
matching and the next publish asks you to look again. Get the digest with
`sha256sum core/conf.d/0010-stats.cfg`.

Which files it covers is fixed, not a selection: everything under
`core/conf.d/` and `manual/conf.d/`. Listing a fragment that reserves nothing is
how you say you read it and it claims no listener — that confirmation is the
point, not the reservations it did or did not produce. A confirmation for a file
outside those directories, or a digest that is not SHA-256 hex, is refused
rather than quietly ignored.

It proves currency and that somebody looked. It does not prove the promise is
complete — only reading the fragments could, and nothing here interprets
handwritten HAProxy configuration.

The file is seeded empty by step 1 and named in the operator editing policy by
step 2. Empty is correct while nothing handwritten defines a listener; a publish
says so when the cluster carries handwritten fragments this file does not
account for, and when a fragment has changed since it was confirmed.

`core/haproxy.cfg` is the handwritten `global` and `defaults` for the cluster — the file every
generated fragment is assembled behind. It must declare the TLS defaults every listener falls back
to when it names no policy of its own:

```haproxy
global
    # ... your own log, chroot, socket and user lines ...

    # Relative paths in the configuration resolve against the directory of the
    # file they are written in. A generated bind line reaches its certificate
    # list that way, and the node validates a copy of a release at one path
    # before installing it at another - one line, both places, nothing rewritten.
    default-path config

    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets
```

**A publish is refused while these disagree with the manager's own lists**, and the refusal prints
the exact line to write. The reason is that both halves are true at once: a generated bind line that
names a TLS policy carries the manager's list, and every listener naming no policy inherits this
one. While the two differ, what protects a given listener depends on which line HAProxy read last —
and each file looks entirely correct read on its own. That is how one such pair came to be a cipher
apart without anything reporting it.

The list is Mozilla's intermediate recommendation, guideline v5.7; the
manager holds it in `haproxy_mgmt/tls_policy.py` with the date it was last checked. Nothing fetches
it at run time. If you deliberately change it, change it there first and in every cluster's `core/`
after — the refusal will tell you which clusters are still behind.

A **revert** is never refused for this. Going back to a release that was good before must not depend
on a file being current.

An HTTPS object may override its VIP's TLS policy. The generated certificate list then contains an
explicit SNI-filtered row for every object, so several names may use the same wildcard certificate
with different policies. The first, unfiltered row is an intentional fallback: a client with no or
unknown SNI inherits the VIP/bind policy. When one listener carries several effective policies,
HAProxy also returns `421 Misdirected Request` if the HTTP Host belongs to a different policy group
than the connection's SNI; HTTP/2 connection reuse remains possible between names in the same group.

Nothing derives this file — `manual/` is read, never interpreted, and a promise a person writes is
the only thing available. It exists because both collisions are silent: two frontends binding one
port both bind it under `SO_REUSEPORT` and the kernel splits new connections between them at random,
so the publish reports success and the node answers correctly for about half the traffic, and a
hostname claimed twice is answered by whichever frontend HAProxy reached first.

Only two of these paths are fixed by the software: `/etc/haproxy-manager/runtime-policy.yaml`, which
is where the code looks unless told otherwise, and `/opt/haproxy-mgmt`, where releases are installed.
Everything else above is a deployment choice — put the trees wherever your environment keeps them,
and name them in the runtime policy.

Repeat the first two blocks per cluster.

Config repositories and published releases are **root-owned and never group-writable**. The config
group reads; it does not write. Publishing is a write into root-owned history and therefore happens
through a helper, not directly.

The split between `alpha.git/` and `alpha/` is a bare repository plus a linked worktree. They are
held together by a path reference in each direction. Restoring only one of them breaks the link;
`git worktree repair` fixes it without touching configuration.

#### Runtime policy

`runtime-policy.yaml` is the outer security boundary, not a convenience file. It names the roots
that every path in `clusters.yaml` must stay inside, and the code refuses any cluster path that
escapes its root.

```yaml
schema_version: 1

cluster_file: /srv/haproxy-manager/clusters.yaml
config_root: /srv/haproxy-manager/config
publish_root: /srv/haproxy-manager/published
validation_certs_root: /srv/haproxy-manager/validation

deploy_identity:
  user: "svc-trigger"
  key: "/root/.ssh/id_ed25519_config_deploy"

certificate_root: /srv/certificates/haproxy
cert_deploy_identity:
  user: "svc-trigger"
  key: "/root/.ssh/id_ed25519_cert_deploy"

status_identity:
  user: "svc-status"
  key: "/root/.ssh/id_ed25519_status"

probe_identity:
  user: "svc-status"
  key: "/root/.ssh/id_ed25519_probe"

backup_root: /srv/state-backups
backup_identity:
  user: "svc-backup"
  key: "/root/.ssh/id_ed25519_node_backup"
backup_timer: haproxy-state-backup.timer

interface_account: "svc-app"
pull_account: "svc-pull"
cert_pull_account: "svc-cert-pull"
```

`certificate_root` is also what a publish reads to check that each site's certificate answers for
its hostnames. HAProxy loads a certificate; it does not check it against the objects using it, so a
name the certificate cannot answer for reaches visitors as a browser error while every layer here
reports success. **Leave the root unconfigured and that check does not run** - the publish succeeds
and nothing says the question went unasked. Choosing a certificate that does not cover the name on
purpose stays possible with the certificate mismatch override, which is asked for per publish rather
than written into the object.

`backup_root` is where the state backup engine writes one directory per node, and it is what
`haproxy-list-backups` reads. Called with no cluster, that command lists every configured cluster
in turn - it reads `clusters.yaml` as the calling user, the same way `haproxy-cluster-config` does,
only to learn which clusters exist. Each listing is still resolved inside the privilege boundary by
one helper call per cluster. Only metadata is ever reported from it - archive name, size and
modification time. The archives themselves hold password hashes and private SSH keys, so the root
stays root-owned and only one command opens one - `haproxy-node-restore`, as root, to restore it
([Restoring a node onto an empty vm](#restoring-a-node-onto-an-empty-vm)); the helper exists precisely so that an unprivileged
caller can learn a backup exists without being able to read it.

`backup_identity` is the separate forced-command SSH identity that fetches the state-export stream
from a node. It must not reuse the deploy or status key: unlike those responses, this stream holds
password hashes and private SSH keys. Step 3 creates the key and prints the exact line to install
for the node's backup account; the private half remains root-only on the manager.

Step 2 installs `haproxy-state-backup@.service`. Each instance takes both nodes in exactly one
configured cluster and keeps a bounded number of root-only archives per node — 14 unless the
Backups page set another count, which the root socket helper records in
`/etc/haproxy-manager/backup-retention/<cluster>.json` (root-only, 1–365). Every run
reads that file, including the terminal `haproxy-state-backup`, so a manual run prunes to the
same count the schedule promised; a file that is present but unreadable stops the run rather
than falling back to 14. The ordinary list and the backup UI show every retained archive per node
and identify the source node because hostnames, network state and SSH identities are not
interchangeable between the pair.

`backup_timer` names the legacy fleet-wide timer during migration. With `backup_identity`
configured, listings instead read the derived `haproxy-state-backup@<cluster>.timer`. An admin can
set its schedule on the manager's clock — every day, chosen weekdays, or one day of the month
(1–28, so no month is skipped) at a given time — enable or disable it, set the retention, and run
an immediate cluster backup on the Backups page. The browser supplies no unit name or systemd
expression: the root socket helper derives both from the configured cluster and the bounded
request (`Mon,Wed,Fri *-*-* 05:00:00`, `*-*-07 05:00:00`), writes them as a drop-in on the
timer instance, and reads the effective state back before reporting success. A calendar edited
by hand on the manager is shown verbatim on the page and is not translated into the form's
shapes. The terminal break-glass path remains `sudo haproxy-state-backup [-c <cluster>]`.

`interface_account` names the web interface's worker account. It is the one caller a version
believes about who published it: a publish or revert from the browser records the signed-in person
as *Published by*, beside the worker account that actually ran it. Anyone else who may run those
helpers - an operator at the terminal - is recorded as the account sudo proves, whatever the request
says, so the column can be trusted. Leave it out and every version names the account that ran the
helper, the worker's own name for everything done in the browser.

`pull_account` and `cert_pull_account` name the accounts the nodes fetch as - the `rrsync -ro`
accounts whose `authorized_keys` carry one line per node ([Ssh identities](#ssh-identities)). They are what
lets a node be added or removed with `haproxy-node` or the interface's Nodes card
([Adding and removing a node](#adding-and-removing-a-node)): the names exist nowhere else a command reads. Leave
them out and nodes are added by hand, as before.

`status_identity` is the account `haproxy-status` becomes to read a node, and `haproxy-deploy`
uses it too: a rollout reads the pair before and after every step, and it reads with the identity
that cannot change a node rather than the one it triggers with. Both commands refuse to run
without it instead of falling back to the deploy identity. It is deliberately not
the deploy identity: reading status is the one thing the manager asks a node to do that cannot
change it, so it is the identity that can be granted most widely, and keeping it separate is what
preserves that difference. Without it, `haproxy-status` says exactly which field is missing.

`probe_identity` is what the interface uses to ask a node to *try* a health check - open a
connection to the servers an object names, from the address that object leaves from, and report
whether they answered. It logs in as the same account status does and still carries its own key,
because it is a different thing to grant: status reads what a node already knows, while this makes
the node open a connection to an address the caller chose. The forced command behind it needs no
sudo, returns a status and never a response body, and refuses anything that is not a bounded list
of targets. Leave it out and the button in the editor says the probe is unavailable; nothing else
changes.

The file must be root-owned, a regular file (not a symlink), not group- or world-writable, and at
most 1 MiB. The reader rejects unknown fields, so **install a release that understands a new field
before adding it** — otherwise every command that reads the policy fails, not only the new one.

#### Cluster definitions

```yaml
schema_version: 1

clusters:
  alpha:
    display_name: Alpha
    vip: 192.0.2.10
    config_path: /srv/haproxy-manager/config/alpha
    publish_path: /srv/haproxy-manager/published/alpha
    node_path: a
    nodes:
      - name: node-a
        mgmt_host: node-a.example.com
      - name: node-b
        mgmt_host: node-b.example.com
    validation_certs: /srv/haproxy-manager/validation/certs
    certificate_ids:
      - example.com
    default_certificate: example.com

    # Opt in to the separate structured stream used by the traffic-log
    # collector.  The setting reaches the nodes when an object is next
    # published; changing this file alone does not deploy a configuration.
    traffic_logging: true
```

`node_path` is the subdirectory a node fetches from on the management host. It is the only
per-cluster value the node side needs.

A cluster has **between two and eight nodes**. keepalived sets no limit - one VRRP instance shares
its addresses between any number of nodes by priority, so a third node adds a standby, not capacity -
and eight is a ceiling nobody is meant to reach rather than a size to aim for: the pages were measured
to draw eight nodes per cluster without scrolling sideways, and every node costs the poller a read
(below). Two is the floor, because a cluster of one has nothing to fail over to. Each node's own
`keepalived.conf` (its priority and its `unicast_peer` list) is not written by this project.

There is **no hard limit on the number of clusters** in the engine, interface configuration or
database schema. Two is the recommended starting shape - commonly one internal and one external
trust zone - not a maximum.

**It has been run with two clusters of two nodes each, and is built for up to about ten clusters
and twenty nodes.** Nothing enforces that figure; it is where the manager's reads, which run one
after another, stop being comfortable:

- The poller reads cluster by cluster and node by node. At two clusters of two nodes a pass takes
  about two and a half seconds against a default `interval_seconds` of 20: the status read costs
  about 0.3 s per node, and the cluster's other readings about 0.7 s whatever its size. A node that is
  switched off adds five seconds to every pass (the SSH connect timeout); one that connects and
  then never answers adds up to sixty (the status read's own limit). Either delays every
  cluster's reading, not only its own.
- The traffic-log collector runs once a minute and fetches node by node - about a second for four
  nodes, so a healthy fleet of a couple of hundred still fits. A node that does not answer costs it
  ten to thirty seconds, so five or six at once make a run outlast its minute.
- The worker runs one job at a time for the whole installation: a deploy or backup on one cluster
  queues every other cluster's jobs behind it.

An installation growing past that should time a complete poller pass and a collector run against
their intervals before it adds more.

Each cluster card carries a colour rule, one of six ([Accounts and signing in](#accounts-and-signing-in)). With more
than six clusters the colours are off and the name alone marks the card; that limits the colours,
not the clusters.

A release directory holds that subdirectory and, beside it, `MANIFEST.json` - the manager's own
record of what each object in that release amounts to. It is written outside `node_path`
deliberately: a node fetches that subdirectory whole with `--delete`, and HAProxy loads everything
in `conf.d` with `-f`, so a file the manager keeps for itself has no business being inside either.
Nothing on the node side reads it, and a release published before this existed simply has none -
the status then reports each object as unknown rather than guessing.

`address_prefix` and `address_interface` are optional and describe how this pair's nodes write an
address they carry:

```yaml
    address_prefix: 24          # from the nodes' own virtual_ipaddress block
    address_interface: ens192   # likewise; names differ between installations
```

They are used for one thing: rendering the keepalived address list a release carries. **Read both
values off the nodes rather than choosing them**: whatever stands in their `virtual_ipaddress`
block today is what the generated list has to reproduce. A line reading `<address>/24 dev ens192`
means `address_prefix: 24` and `address_interface: ens192`. Nothing here requires a particular
interface name - the field exists precisely because it differs between installations - and a
cluster whose nodes name no interface should leave `address_interface` out, so that keepalived
keeps using the `vrrp_instance`'s own. Omitted, an address is written bare, which
keepalived reads as `/32` on the `vrrp_instance`'s own interface. **A bare address is not the same
address:** a `/32` carries no subnet route and is not chosen as a source address for the segment,
so a cluster whose nodes use a prefix must say so or moving the list into the generated file would
change the network rather than only where the list is written.

They live here rather than in `managed/network.yaml` because a prefix length is a statement about
the network the pair sits on, not about which addresses the cluster serves - and `clusters.yaml` is
root-owned, so the interface cannot change them.

##### Optional per-cluster sections

Four sections may be added. All of them are optional, and a cluster that omits every one of them
behaves exactly as the example above.

```yaml
    # Named addresses the generated frontends bind, each with the source
    # address it connects to backends from - what an ADC calls a SNIP. A
    # proxy object names the VIP it sits on; it never names an address.
    # Omitted, the cluster has one VIP called `main`, taken from `vip` above.
    vips:
      internal:
        address: 192.0.2.10
        source: 192.0.2.15
      dmz:
        address: 198.51.100.10
        # Which TLS versions and ciphers this listener accepts: `intermediate`
        # for TLS 1.2 and 1.3, `modern` for 1.3 alone. Optional, and left out
        # the listener takes what core/ sets through ssl-default-bind-*, which
        # is what every cluster does today. Read that file before naming a
        # policy here: the bind line overrides those defaults in both
        # directions, so a policy can loosen a stricter cluster as well as
        # tighten a looser one.
        tls: modern
    default_vip: internal

    # The resolvers section in core/ that generated server lines point at.
    # Without it, a backend named by hostname is resolved once at startup and
    # not again until the next reload.
    resolvers: cluster-dns

    # Named source addresses an object may connect out from instead of the one
    # its VIP pairs with. HAProxy takes the source per backend, so the pairing
    # in `vips` is a default rather than a rule.
    sources:
      outbound: 192.0.2.15

    # Named address groups an object may restrict itself to with `allow_from`.
    # An object may also write an address or range directly, for what belongs
    # to one site alone.
    networks:
      office:
        - 198.51.100.0/24

    # What a request for a hostname no object claims is answered with. Without
    # it, HAProxy answers 503. Set exactly one of `status` or `redirect`.
    unknown_host:
      status: 404
```

`vip` keeps its original meaning and is unchanged: it is the address whose ownership `deploy`
checks before it acts. One node holds every virtual address at a time, so that single check answers
for all of them.

**Three of those tables have a second, preferred home.** `vips`, `sources` and `networks` may
instead live in `managed/network.yaml` inside the cluster repository, and that is where a new
installation puts them:

```yaml
# /configs/haproxy/<cluster>/managed/network.yaml
vips:
  internal:
    address: 192.0.2.10
    source: 192.0.2.15
default_vip: internal
sources:
  outbound: 192.0.2.35
networks:
  office:
    - 198.51.100.0/24
```

The file wins where it exists; a cluster without one keeps answering from `clusters.yaml`, and
nothing has to be migrated. The reason for the move is that these three describe *what gets
published*, while everything left in `clusters.yaml` describes *how the system itself runs* -
paths, identities, keys, the resolvers section, the certificate allowlist, and the `vip` line
above. The repository is owned by the application, which means these tables can be edited in the
interface through the same publish path as a proxy object, with the same lock, the same history and
the same revert, and without the web identities gaining any access to the engine's configuration.

`vip` deliberately did not move. It is what `deploy` checks node ownership against, and a control
the interface can rewrite is not a control. `managed/network.yaml` is refused outright if it names
it.

**Adding a VIP here does half the job by default.** The other half is keepalived on the nodes: no
node carries the address until it is in the `virtual_ipaddress` block, and until then no traffic
reaches the frontend however correct the generated configuration is. The same applies to a source
address, which additionally must sit in the *same* block as the VIP - see [Addresses, and what to
call them](#addresses-and-what-to-call-them).

**The other half can be handed to the deploy.** A published release carries
`keepalived/addresses.conf`, derived from `managed/network.yaml`: every VIP and every source
address, one per line, with a comment saying which is which. `haproxy-pull-deploy` installs it at
`/etc/keepalived/addresses.conf` on each node, and a node whose `keepalived.conf` includes that
path gets a `keepalived --config-test` and a reload - **only** on exit 0, because keepalived skips
an address it cannot parse at runtime and carries on, which would turn a mistyped address into a
VIP that never appears and never says why. A failed test restores the previous list and reports
the deploy as failed with the HAProxy configuration already live.

**That failure leaves the node half-way, and the status says which half.** The configuration is
live on the new release while the address list is the old one, so the release hash alone would
report the node as up to date and a second deploy would pass over the node that still needs the
work. `haproxy-node-status` therefore reports three measurements about the list - the digest the
release publishes, the digest the node installed, and whether `keepalived.conf` includes it - and
both `haproxy-status` and `haproxy-deploy` call a node current only when every component the
release owns is where it should be. Re-running the deploy after fixing the cause finishes the half
that was left; the node script syncs the addresses even on a release it already runs.

The include is reported and never compared. Putting that line into `keepalived.conf` is a person's
step, taken one node at a time (below), and a deploy that treated it as a target would try forever
to reach a state only a human can put the node in.

The application writes the address list and nothing else. `priority`, `virtual_router_id`,
`authentication`, `unicast_src_ip`, `unicast_peer` and the `notify_` lines stay in a file a person
edits. Those decide who owns an address, and getting one wrong gives two masters or none - neither
of which `--config-test` catches, because both are runtime behaviour rather than syntax. An extra
line in `virtual_ipaddress` cannot cause either, which is what makes this half safe to generate.

**Switching a node over, in this order:**

1. Deploy once, so `/etc/keepalived/addresses.conf` exists. Until a node's `keepalived.conf`
   mentions that path the file is installed and inert, and the deploy says so.
2. Compare it against the addresses in the node's own `virtual_ipaddress` block. They must already
   agree; this step changes where the list is written, not what is in it.
3. On **one node at a time, the address owner last**, with a backup of `keepalived.conf`: replace
   the addresses in the block with `include /etc/keepalived/addresses.conf`, run
   `keepalived --config-test -f /etc/keepalived/keepalived.conf`, and reload only if it passes.
4. Prove it from another host - the address still answers ARP from the same node - before touching
   the second node.

An `include` naming a file that does not exist yet is a keepalived that will not start. That is the
whole reason step 1 comes first.

**The node's status helper has to be able to follow that include.** `haproxy-node-status` reports
whether this node currently carries the address by reading the `virtual_ipaddress` block and
looking the address up on the interface. Once the block holds nothing but the include, a helper
that reads only the block finds no address and answers that ownership is unknown - on both nodes.
That is not a cosmetic answer: a deploy refuses to run without a known owner, so the whole cluster's
deployment path stops. Install the node scripts from the same release as the manager before
switching a node over, and confirm afterwards with `haproxy-status -c <cluster>` that the owner is
named and the state is `single_owner`.

**A cluster that sets `resolvers` must provide the section itself in `core/`**, since nameserver
addresses are environment values the generator never invents:

```text
resolvers cluster-dns
    nameserver ns1 192.0.2.53:53
    resolve_retries 3
    timeout resolve 1s
    timeout retry 1s
    hold valid 10s
```

#### The certificate registry

`certificate_ids` above is the allowlist form: the cluster names the certificates it may carry,
by hand, in a root-owned file. It is what an installation starts with, and it is being replaced by
a registry - one root-owned file beside `clusters.yaml` that says, for every certificate, where it
comes from and where it goes:

```yaml
schema_version: 1

receivers:
  lb-01.example.net:
    path: /srv/certificates/receivers/lb-01.example.net
    owner: svc-app
    transport: sftp            # rsync | sftp | https; left out, rsync
    layout: per-certificate    # flat | per-certificate; left out, flat
    allow:                     # https only, and required there
      - 192.0.2.0/24

certificates:
  example.com:
    source:
      kind: acme
      lineage: example.com-wildcard
    clusters:
      - alpha
  lb-01.example.net:
    source:
      kind: import
    receivers:
      - lb-01.example.net
```

Name it in the runtime policy as `certificate_registry`. From that moment a cluster's certificates
are the ones that name it under `clusters`, and a `certificate_ids` list left in `clusters.yaml` is
refused - the two would otherwise be two answers to one question, free to drift apart without
anything noticing. Declaring the registry and moving the lists out of `clusters.yaml` is therefore
one edit. `default_certificate` stays in `clusters.yaml` and must still be one the cluster carries.

A **receiver** is somewhere other than a cluster that certificates are published to: a directory
under the distribution root and the account whose fetch key is locked to it. A receiver is
registered with `haproxy-cert-receiver` ([Registering a receiver](#registering-a-receiver)), not by hand, because an account, a key and a
directory are what let anyone fetch key material at all and none of the three is safe without the
others. Which certificate goes to which already-registered receiver is the part the interface is
allowed to change, and it does so through a helper that accepts only targets registered in this
file.

One entry may carry `interface: true`: the certificate the management host's own interface is
served with ([HTTPS and the certificate](#https-and-the-certificate)). It is issued, imported and renewed like every other entry, names no cluster and
no receiver - the loader refuses either, and refuses a second such entry - and is published to
nginx instead of to targets.

`transport` says how the receiver fetches, `layout` how its directory is arranged, and `allow` -
`https` only - which addresses may fetch at all. Both defaults describe the receivers registered
before this command existed, so an older file means exactly what it meant before: `rsync` and
`flat`. `flat` puts `fullchain.pem` and `privkey.pem` straight into the directory, which is why
such a receiver holds **one** certificate at a time and a second is refused; `per-certificate`
gives each certificate a directory of its own, and is the only form a new receiver is registered
in. Neither field is edited afterwards: a receiver finds out about a moved path or a changed
transport at its next fetch, which is a renewal away, so a change is `remove` and `add` again.

A certificate's `receivers` list may name a receiver as `{id: <id>, format: pkcs12}` instead of as
a bare ID, and then that pair - this certificate, this receiver - is published as a PKCS#12 bundle
with a password beside it rather than as a PEM pair. A bare ID means `pem`. The choice belongs to
the pair, because one host can want PEM for HAProxy and a `.pfx` for IIS.

The choice is made where the receiver is chosen: `--format <receiver>=pkcs12` beside `--receiver`
on `haproxy-cert-issue`, `haproxy-cert-import` and `haproxy-cert-scep`, and a select beside the
receiver's box on the interface's certificate form and in *Publish to…*. A receiver kept at a
target change keeps its format unless a new one is stated; stating a different one rewrites that
receiver's files in the new format at once.

The bundle's password is not a protection. It is published beside the bundle, in the same
directory with the same owner and mode, so whoever can read the one can read the other; it exists
because a PKCS#12 import asks for one, and it is made once per pair and kept across renewals so
the receiver's import script need not change. What protects the key is the same thing that
protects a PEM pair: the receiver's account, its directory and the transport's lock. Publishing
a `.pfx` to a receiver is exactly as sensitive as publishing `privkey.pem` to it.

`source.kind` is `acme` for a certificate certbot renews and `import` for one signed elsewhere. An
ACME certificate's `lineage` is its certbot lineage name; left out, it is the certificate ID, which
is what a certificate issued from the interface gets. State it only where an existing lineage was
named before that convention - renaming a lineage moves certbot's archive, and is not worth it.

Every command that changes the file - issue, import, delete, a target change, a receiver's
registration or removal, the scheduled renewal - reads it, changes it and writes it back under one
lock, the publisher's (`/run/haproxy-mgmt/locks/cert-publish.lock`). The interface queues one
certificate job at a time, but the renewal timer and an operator's command run outside that queue,
and two writers in the same second would otherwise be a lost update the loader cannot see: the
file that wins is valid, it just lacks what the other one wrote. A command that finds the lock held
for longer than two minutes refuses with `operation_locked` rather than waiting on.

`haproxy-cert-list` reports `source` and `targets` for every certificate the registry names, and
`null` for both on a file in the distribution directory that no entry names: that is what a
certificate published before the registry existed looks like, and it is listed so it can be
registered rather than hidden.

#### Certificate publication hook

**The certbot hook** is one file, [`../install/certbot-deploy-hook`](../install/certbot-deploy-hook),
installed as `/etc/letsencrypt/renewal-hooks/deploy/50-haproxy-manager`:

```bash
sudo install -o root -g root -m 755 install/certbot-deploy-hook \
  /etc/letsencrypt/renewal-hooks/deploy/50-haproxy-manager
sudo certbot renew --dry-run --run-deploy-hooks
```

It runs `haproxy-cert-publish --deploy` and nothing else. certbot runs every hook in that directory
after every successful renewal, whichever lineage renewed, and the publisher finds the changed one
by comparing bytes - so there is no per-lineage logic in the hook to go stale when a certificate is
added. A hook that filtered on a hardcoded lineage, and a second one that walked a list file, are
what this replaces; remove them when this one is installed, or every renewal publishes twice.

Nothing here renews anything. certbot stays authoritative for renewal, on its own timer; the
publisher is what runs after it has.

#### ACME configuration and challenge routing

What the caller supplies is a domain, a method and target names the registry already knows.
Everything certbot is told beyond that is fixed - `certonly`, the lineage name (which is the
certificate ID), `--key-type ecdsa`, non-interactive, directory hooks off for this one run - or read
from the runtime policy:

```yaml
acme:
  dns_cloudflare_credentials: /etc/letsencrypt/cloudflare/example.ini
  webroot: /var/www/acme
  certbot: /opt/haproxy-certbot/current/venv/bin/certbot
  dns_profiles:
    directory: /etc/haproxy-manager/dns-profiles
    private_keys:
      - /srv/platform/secrets/dns-profile-keys/0123456789abcdef.key
```

`certbot` names the binary the helper runs: the locked environment's, once [The certbot environment](#the-certbot-environment) has installed it.
Left out, the helper runs the distribution's `/usr/bin/certbot`, with the distribution's plugins.
`dns_profiles` is where the DNS provider credentials entered through the web interface end up,
and which private keys may open them; [The DNS profile key pair](#the-dns-profile-key-pair) makes the keys.

| Method | certbot | What the installation is responsible for |
|---|---|---|
| `dns-01` | the plugin and root-only file selected by `--dns-profile`; without it, legacy `--dns-cloudflare` with the policy file above | the profile may edit that zone |
| `http-01` | `--webroot -w <webroot>` | `http://<name>/.well-known/acme-challenge/` reaches that directory |

A method whose setting is missing is refused by name before certbot runs. A wildcard
(`*.example.net`, which also covers `example.net`) needs `dns-01` and is refused with `http-01`.
The command does not create routes, touch the published configuration or check that the name
resolves.

`http-01` needs more than the webroot setting, because port 80 for a proxied name terminates at the
cluster VIP, not at the manager. Three things have to be in place, all of them the installation's
to make: the webroot directory named in the policy; something on the manager serving that directory
over plain HTTP - a port-80 `server` block in nginx that exposes only `/.well-known/acme-challenge/`
from the webroot; and a rule in each cluster that sends that path to the manager, written once into
`core/` or `manual/`, never generated:

```text
# core/ or manual/ - hand the ACME HTTP-01 challenge to the manager
backend acme_challenge
    server mgr 192.0.2.10:80

# in the HTTP frontend, before any host routing
acl acme_challenge path_beg /.well-known/acme-challenge/
use_backend acme_challenge if acme_challenge
```

Without all three, an `http-01` request fails at the challenge with certbot's own account of it.
A wildcard cannot use `http-01` at all. When certbot fails, its output is printed after the error line at a terminal and carried
whole under `error.details.diagnostics` in the JSON envelope, so the account of a failed challenge
reaches whoever asked, in certbot's own words.

#### The certbot environment

The distribution's certbot runs on the system Python, which accepts no packages beyond the
distribution's own - and the DNS plugins the distribution packages are a dozen. The product
offers many more, so it carries its own certbot: [`../certbot/pyproject.toml`](../certbot/pyproject.toml)
names certbot and every DNS plugin the web interface can offer, and `certbot/uv.lock` pins the
whole set, with hashes, as resolved together. What the interface can offer is what that lock
resolved. Nothing installs a plugin at runtime.

Platform step 14 builds it:

```bash
sudo UV_BIN=/path/to/uv ./install/platform/14-platform-certbot answers.env /path/to/source-tree
```

The step hands the lock to [`../tools/install-certbot-env.py`](../tools/install-certbot-env.py),
which lets uv install exactly the locked set into `/opt/haproxy-certbot/releases/<certbot
version>-<lock hash>/venv` and proves that every plugin in it loads. It then runs
`certbot/verify-integrations.py` with the new environment's interpreter. Those checks feed the
catalogue's rendered credentials through every offered plugin's own credential setup, exercise
Azure through its SDK with the network mocked, and run with sockets disabled so a plugin that
reaches out fails instead of passing quietly; a missing, empty or failed report refuses the
release. The catalogue states per provider what has been proved (`packaged`, `loaded`,
`integration-tested`, `live-verified`) and the verifier refuses a catalogue that claims more than
the run showed. The passed check names are recorded in `INSTALLATION.json`. The installer freezes the tree root-owned and read-only and
points `/opt/haproxy-certbot/current` at it. Then the platform step runs
`haproxy-cert-renew --certbot <new binary> --dry-run --run-deploy-hooks` against every lineage on the host: the
one gate a certbot upgrade has, and a failure puts the previous release back before the step
stops. Only after that does renewal move: the distribution's `certbot.timer` is masked and
`haproxy-certbot-renew.timer` - the same schedule, the release's binary, the same
`/etc/letsencrypt` - takes over. Its bounded wrapper invokes Certbot once per lineage. Most plugins
persist their credentials-file flag in the renewal configuration; Route53 has no such flag, so the
wrapper restores `AWS_SHARED_CREDENTIALS_FILE` from the registry's `source.dns_profile` binding.
One certbot owns the lineages; renewal walks all of them and fails
on one whose plugin it cannot load, which is why the distribution's timer is masked rather than
left disabled.

The step also checks that the worker's unit opens certbot's directories (`/etc/letsencrypt`,
`/var/lib/letsencrypt`, `/var/log/letsencrypt`), the publisher's target (`/srv/certdist`), the
registry's directory (`/configs/haproxy-mgmt`) and the DNS profile directory
(`/etc/haproxy-manager/dns-profiles`). The issue helper runs certbot inside the worker's sandbox,
and without those paths every issuance from the web interface fails on a write such as certbot's
log lock. Step 07 installs the unit; rerun it with a source tree that has them before running step
14.

Point the runtime policy at the release afterwards - `acme.certbot` in [ACME configuration and challenge routing](#acme-configuration-and-challenge-routing) - and the issue
helper runs it too. Upgrading is the same step with a newer lock, a few times a year: bump
`certbot/uv.lock` in the source tree (`uv lock --upgrade` in `certbot/`), run the step, read its
gate. A plugin that no longer resolves against the newer certbot falls out of the lock, and so out
of what the interface offers; a release that fails the dry run is never made current. Rolling back
by hand is one symlink, which the step prints, followed by the same dry run.

#### The DNS profile key pair

A DNS provider's credentials are entered once, in the web interface, and stored sealed: the web
process encrypts them against the installation's public key and keeps only the ciphertext, and the
root helper that runs certbot holds the one private key that opens them (libsodium's sealed box,
through PyNaCl). A compromised web process can therefore add or replace a profile but never read
one back, and a database dump carries nothing a reader can use without root's key file.

Platform step 15 makes the pair, under the platform root of the answers file it is given:

```bash
sudo ./install/platform/15-platform-dns-keys answers.env /path/to/source-tree
```

The private key lands in `secrets/dns-profile-keys/<key id>.key`, root-only; the public key in
`config/dns-profile-keys/<key id>.pub`, readable by the platform group. The key id is a digest of
the public key, so it is read off either file rather than assigned, and a stored profile names the
id it was sealed against. Both files are one tagged line, and a private key placed where a public
one belongs is refused by its tag. The step proves the pair by sealing and opening a message
through the files it wrote, and never overwrites an existing key.

Then tell both readers about it. The runtime policy ([ACME configuration and challenge routing](#acme-configuration-and-challenge-routing)) names the private key and the
directory the helper materialises credential files into:

```yaml
acme:
  dns_profiles:
    directory: /etc/haproxy-manager/dns-profiles
    private_keys:
      - /srv/platform/secrets/dns-profile-keys/0123456789abcdef.key
```

and the web interface's `config/ui.toml` names the public key:

```toml
[dns_profiles]
public_key = "/srv/platform/config/dns-profile-keys/0123456789abcdef.pub"
```

A new runtime policy key costs a CLI release before the policy is edited, and a platform release
after it, in that order: `check-compatibility` reads the policy through the platform's own copy of
the engine, and the installed engine refuses a key it does not know.

**Replacing the key.** Run the step with `ROTATE=1`: it adds a second pair beside the first. List
both private keys in the policy, point `ui.toml` at the new public key, and re-enter each profile
so it is sealed against the new key; a profile sealed against a key the policy no longer lists
cannot be applied until it is. Remove the old pair last. The private key file is part of the host's
disaster-recovery material like the SSH identities in [SSH identities](#ssh-identities): without it every stored profile is
unreadable, and the recovery is to re-enter them, not to restore a dump.

A development platform gets its own pair from the same step with its own answers file, and no
runtime policy entry, because it has no helper.

#### Preparing Microsoft AD CS / NDES for CSR enrollment

**Status:** enrollment from the manager is complete: encrypted NDES provider profiles, the
retained Certmonger client, the root enrollment CLI and its job helper, and the certificate
form's third choice, *Microsoft AD CS · NDES*. Two live enrollments (a DNS name; a wildcard
with its base name) were verified end to end.

**Other SCEP servers.** NDES is Microsoft's SCEP implementation; the client speaks plain SCEP
and the manager makes two choices that NDES needs and other servers accept - a signature-and-
encryption request, and a PrintableString challenge. Only NDES has been verified. Another SCEP
CA (step-ca is the quickest to stand up; EJBCA, OpenXPKI and network appliances also serve
SCEP) should work and is untested; the profile and policy fields keep their NDES names.

**Selected client:** [Certmonger](https://codeberg.org/freeipa/certmonger/) will provide the
SCEP protocol support through a temporary process and private socket, with Certmonger's own
renewal disabled - the manager schedules renewal itself; see the
[user manual](#enrolling-and-renewing-through-ndes). Its installation and runtime dependencies will be included in the manager installation.
Release materials must retain the selected package, corresponding source, license and build
instructions so the selected version remains available independently of its upstream hosting.
The packaging tools are described below. Root installation has not yet been verified.

The intended flow creates an RSA key and a PKCS#10 CSR locally on the manager, sends an enrollment
request through SCEP over verified HTTPS, validates the returned certificate and uses the existing
publication and distribution path. The private key stays on the manager. The manager needs no
domain membership or AD account and does not visit `mscep_admin` during normal operation.

**Manager configuration and packaging (source implementation).** The optional root policy
`ndes` object has the fields `endpoint`, `tls_ca`, `issuing_ca`, `client_root`, `state_root`,
`profiles` and the optional `renew_days` (1–3650, default 30). Paths are absolute. `profiles` contains `directory` and `private_keys`,
a non-empty list of absolute private-key file paths using the existing profile sealing keys. The endpoint must use HTTPS and
match the encrypted provider profile exactly. TLS trust and certificate issuing trust are
configured separately. Suggested roots are `/opt/haproxy-scep/current`,
`/etc/haproxy-manager/ndes-requests` and `/etc/haproxy-manager/ndes-profiles`.
The latter directories are root-owned, mode `0700`; records and keys are mode `0600`.

Build the native bundle with `tools/build-scep-client.py`: supply `--package`, its independently
verified `--package-sha256`, the matching signed `--source-description` and verified
`--source-sha256`, plus `--distribution`, `--distribution-release` and `--output`.
Keep both source archives beside the source description. The bundle retains the package,
complete corresponding source, license and rebuild instructions; a bit-for-bit rebuild has
not been demonstrated. Only matching Debian-family distribution packages are supported.
Install the reviewed bundle as root with
`install/platform/16-platform-scep <bundle.zip> <verified-bundle-sha256>`.
The installer checks hashes, archive paths, OS release and architecture, installs runtime
library dependencies and activates the three client programs under an immutable release.
It does not install a standing Certmonger service.

**Server prerequisites.** Install and configure the AD CS Network Device Enrollment Service role
with IIS, an issuing CA and valid NDES signing/encryption RA certificates. NDES and the CA may
share a server; co-location is not a product requirement. Microsoft's
[NDES overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/network-device-enrollment-service-overview)
describes the role and its IIS applications. For a dedicated domain service identity, follow
[Microsoft's service-account instructions](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/create-domain-user-account-ndes-service-account).
The identity needs local `IIS_IUSRS` membership, effective CA `Request Certificates` permission
and `Read` + `Enroll` on the dedicated certificate template. It need not be a domain or local
administrator. Ensure the IIS `Default Web Site` exists before NDES configuration; a missing site
caused setup error `0x80070003` in the technical trial. The working SCEP application pool used
`Load User Profile = True`.

**One dedicated, published template.** Set the following values in the certificate template and
publish it on the issuing CA:

| Setting | Required value |
|---|---|
| Request Handling / Purpose | Signature and encryption |
| Cryptography | RSA, minimum 2048 bits |
| Subject Name | Supply in the request |
| Application Policies / EKU | Server Authentication |
| Key Usage | Digital Signature, Key Encipherment |
| CA certificate manager approval | Disabled for immediate unattended issuance |
| Allow private key to be exported | Disabled; the manager generates its own key |
| Template security | Read and Enroll for the NDES service identity |

`Supply in the request` allows the enrolling identity to request names supplied by the client;
restrict template rights and endpoint access according to your PKI policy. SANs are CSR
extensions. The integration does not require enabling the global CA flag
`EDITF_ATTRIBUTESUBJECTALTNAME2`.

Map `GeneralPurposeTemplate` under
`HKLM\SOFTWARE\Microsoft\Cryptography\MSCEP` to the template's **internal name**, rather
than its display name. For example, an installation may name its dedicated template
`HAProxyWebServer`. The signature-and-encryption request selects this mapping; no template is
selected in the manager's interface. The other two mappings need not change for this request type.

**HTTPS and trust.** Expose the SCEP endpoint at
`https://<ndes-fqdn>/certsrv/mscep/mscep.dll` with a server certificate matching the endpoint's DNS
name. The manager must trust its TLS chain and separately validate the certificate issued by the
CA. Provision the trust anchor explicitly: SCEP `GetCACert` retrieves protocol CA/RA material but
does not itself establish trust. Serve the issued leaf plus any intermediate certificates to
HAProxy; omit the root from the served fullchain.

**Reusable challenge.** The intended unattended integration requires these DWORD settings:

| Registry subkey under `HKLM\SOFTWARE\Microsoft\Cryptography\MSCEP` | Value name | Value |
|---|---|---|
| `EnforcePassword` | `EnforcePassword` | `1` |
| `UseSinglePassword` | `UseSinglePassword` | `1` |

An administrator retrieves the master challenge once from
`https://<ndes-fqdn>/certsrv/mscep_admin/` and enters it in the NDES provider profile under Certificates → NDES providers.
As with DNS provider credentials, the web application seals it using the installation public
key, and the database stores only ciphertext. Only the root helper can decrypt it and create
the root-owned, mode `0600` challenge file that Certmonger reads. The profile offers replacement
of the challenge, never plaintext retrieval. NDES uses a separate profile type with validated
identity and revision binding. The helper atomically writes a root-only profile record, then
enrollment creates a temporary challenge file and removes that file when its process ends.
Protected request state can still contain the challenge in its CSR. Normal enrollment uses only
`mscep.dll` and this secret.
Microsoft's historical
[single-password article](https://support.microsoft.com/en-au/topic/two-improvements-are-available-that-shorten-the-time-that-is-required-to-manage-scep-certificates-by-using-the-network-device-enrollment-service-in-windows-server-2008-c497db37-9c87-0cd0-30dc-845eeb8ba9f5)
documents the reusable, non-expiring password and registry setting for Windows Server 2008;
it is a historical reference, not an instruction to install that hotfix on a modern server.
The technical trial verified this mode on Windows Server 2022. In that trial the NDES service
identity needed Full Control on the MSCEP registry subtree for single-password operation;
review the necessary registry permissions in your installation.

The master challenge is a long-lived credential. Endpoint access and NDES protection remain
operator responsibilities. Keep its plaintext out of command arguments, job payloads, logs,
job results and the database; only the sealed ciphertext may be stored in the database. A CSR contains this credential as `challengePassword`, so protect CSRs and any temporary
OpenSSL request configuration as secret material too. Rotate a challenge exposed during testing
before using it in production.

**Interoperability and verification.** The tested NDES installation accepted `challengePassword`
as ASN.1 PrintableString. A missing attribute caused NDES Event ID 28; the trial's initial encoding
caused Event ID 29. OpenSSL `string_mask = nombstr` produced a working PrintableString. This is a
technical trial finding, not a general encoding rule established by the Microsoft links above.
The tested client, `scepclient 2.3.0`, needed a pre-created CSR for multiple SANs and a PKCS#1 RSA
key representation; those are client constraints, not general SCEP requirements or a selected
product dependency.

Verify enrollment from Linux with both a single DNS name and a wildcard plus its base name,
using the same challenge twice. Check the exact SAN set, Subject, Server Authentication EKU,
Key Usage, validity, key match and certificate chain. A responsive landing page or `GetCACaps`
alone does not prove enrollment. Application acceptance will also cover verified TLS,
`GetCACert`, SCEP response correlation, pending/failure handling and diagnostics without secrets.

The integration automates issuance requested through CLI/UI and renews on schedule ([user manual](#enrolling-and-renewing-through-ndes)).
CEP/CES/WSTEP, template discovery and automatic password retrieval from `mscep_admin` are outside
this integration.

#### Validation certificate

Candidate validation runs a real `haproxy -c` against the candidate. Any configuration that
references a certificate therefore needs certificate material present during validation — but the
real private key must never be readable by the validating path.

A dedicated, self-signed certificate under `validation_certs_root` solves this. It is readable only
by root, is copied into the private candidate for the duration of validation, and is removed before
the helper returns. It never leaves the management host and is never deployed.

#### SSH identities

Four key pairs, each with exactly one job:

| Key on the management host | Connects as | Purpose |
|---|---|---|
| `id_ed25519_config_deploy` | `svc-trigger` on the node | trigger a configuration pull |
| `id_ed25519_cert_deploy` | `svc-trigger` on the node | trigger a certificate pull |
| `id_ed25519_node_status` | `svc-status` on the node | read node status |
| the node's own config pull key | `svc-pull` on the management host | read the published tree |
| the node's own cert pull key | `svc-cert-pull` on the management host | read the certificate tree |

A key that can push configuration must not be able to push certificates, and neither may read
status. Private keys are root-owned; no application identity can read any of them.

**The node's keys are generated on the node, by step 4, and never leave it.** A private key a node
authenticates with has no reason to exist on the management host; copying one there would make the
management host able to impersonate a node. Step 4 prints the public halves and the exact
`authorized_keys` lines for the management host, which is the mirror image of step 3.

One line per node, not one per cluster. Each node has its own key, so a node that is rebuilt or
compromised is revoked on its own.

The pull direction is the mirror image: an account on the management host, restricted to an
`rrsync`-style read-only export of the published tree, which the node authenticates to with its own
key.

`rrsync` is what makes that restriction real: the forced command is
`rrsync -ro <tree>`, which allows a read-only rsync of exactly one directory and nothing else.
Without it a forced `rsync` command is a shell in all but name.

**The published tree belongs to the pull account, not to the config group.** Giving it to the
config group looks reasonable and locks the nodes out of the only tree they are supposed to read —
deploys then fail while every permission still looks deliberate.

#### Sudo rules

Two separate policies, which must not be merged:

- **Application rules.** Exact helper paths, invoked with no arguments (`command ""`), so the
  helper reads its request as one bounded JSON line on stdin. A caller that runs an operation it may
  later need to stop keeps that stream open as a lifeline; see `PRIVILEGE.md`. No rule grants a shell, an interpreter, an
  editor, a wildcard path, environment preservation, or unrestricted arguments. The web identity
  has no sudo rule at all.
- **Operator rules.** A `sudoedit` policy listing the configuration files an administrator may
  edit, by exact path. `sudoedit` is what makes editing possible without making the repositories
  group-writable.

  **Remove the rule in the same change that removes the file.** `sudoedit` creates a file it does
  not find, so a rule naming a path that no longer exists is not merely stale - it is a standing
  way to place a new root-owned file at that path, in a directory the configuration is loaded from,
  outside the set anyone reviewed. Rewrite the whole alias rather than deleting the line: the last
  entry carries no trailing comma, so removing a line can move that position and leave the file
  syntactically broken. Validate with `visudo -cqf` before installing, and keep the backup outside
  `/etc/sudoers.d/` - a superseded policy file inside the directory the privilege system reads is
  protected only by the convention that names containing a dot are skipped.

Every sudoers file is root-owned and read-only (`0440` or stricter). See [`PRIVILEGE.md`](PRIVILEGE.md)
for the full contract and the negative tests that prove it.

### Part 2 — the nodes

The scripts are in [`install/node/`](../install/node/) and are installed by
[`04-node-prepare`](../install/04-node-prepare), which also creates the accounts, the release
layout and the sudo rules.

Later updates use the [versioned node bundle](#installing-and-changing-node-scripts). The bundle runs the same idempotent
step, but do not mistake that for a script-only copy: the step also reconciles service accounts,
directory ownership and modes, `node.conf`, sudoers, the HAProxy baseline and the complete script
attestation. Read every reported `created`, `fixed`, `written` and `installed` line on the pilot
before another node is touched.

This section explains what they do and why; run the script rather than following it by hand.


#### HAProxy and keepalived baseline

This project does not install HAProxy or keepalived, but it does **assume things about how they are
configured**. Get these wrong and nothing fails loudly — deploys just stop being safe, because the
ordering that protects live traffic quietly stops meaning anything.

**Both nodes must be able to bind the virtual address, whether or not they own it.**

```text
# /etc/sysctl.d/60-haproxy.conf
net.ipv4.ip_nonlocal_bind = 1
```

Without it, HAProxy on the node that does *not* hold the address fails to start: it is asked to
bind an address the kernel says is not there. With it, both nodes run continuously and the virtual
address decides which one traffic reaches. `04-node-prepare` sets this and reports it.

**The unit must load `conf.d`, and must load it exactly once.**

A node's configuration is a main file plus a directory of fragments, and systemd has to be told
about both:

```text
ExecStart=/usr/sbin/haproxy -Ws -f $CONFIG -f $CFGDIR -p $PIDFILE $EXTRAOPTS
```

Upstream's packaging does this and sets `CFGDIR=/etc/haproxy/conf.d`. Some distribution packages
ship a unit with only `-f $CONFIG`, and installations working around that have historically
smuggled the directory in through the variable itself:

```text
# Don't. This breaks the moment the unit gains -f $CFGDIR of its own.
Environment="CONFIG=/etc/haproxy/haproxy.cfg -f /etc/haproxy/conf.d"
```

Against a unit that already loads `CFGDIR`, that reads the directory **twice**, every proxy is
declared twice, and HAProxy refuses to start — duplicate proxy names are an error as of 3.3, where
they were a warning before. Check the effective invocation rather than the unit file, since
drop-ins and `/etc/default/haproxy` both feed into it:

```console
$ systemctl cat haproxy
$ grep -vE '^\s*#|^\s*$' /etc/default/haproxy
```

`systemctl show haproxy -p Environment` is not a substitute: it reports only the unit's own
`Environment=` lines. `EnvironmentFile=` is read when the service starts, never appears there, and
overrides them.

This matters beyond startup. `haproxy-pull-deploy` validates with its own explicit arguments —
each file named once — so a configuration can validate cleanly while the service will not start.
The two paths only agree if the unit names each path once too.

**Both nodes run keepalived as `BACKUP`, with `nopreempt`.**

```text
vrrp_instance alpha {
    state           BACKUP        # both nodes - not MASTER on either
    interface       eth0          # whatever carries the VIP on your nodes
    virtual_router_id 51          # unique per VRRP domain on the segment
    priority        100           # 100 on one node, 90 on the other
    nopreempt
    advert_int      1

    unicast_src_ip  192.0.2.11    # this node
    unicast_peer {
        192.0.2.12                # the other node
    }

    authentication {
        auth_type PASS
        auth_pass <shared secret>
    }

    virtual_ipaddress {
        192.0.2.10                # the VIP
    }

    notify_master "/usr/local/sbin/haproxy-keepalived-state MASTER"
    notify_backup "/usr/local/sbin/haproxy-keepalived-state BACKUP"
    notify_fault  "/usr/local/sbin/haproxy-keepalived-state FAULT"
}
```

Three details carry weight:

- **`state BACKUP` on both, plus `nopreempt`.** A node that comes back after a failure does not take
  the address back, even with the higher priority. Preemption would move live traffic for no reason
  — during a rebuild, exactly when you least want it. The priorities still decide who takes it on a
  cold start, when neither holds it.
- **Unicast, not multicast.** `unicast_peer` names the other node explicitly. Multicast VRRP works
  until something on the path quietly stops forwarding it, and then two nodes both believe they are
  master.
- **The `notify_` lines are not optional here.** They are how the management host learns who owns
  the address. Without them the state file is never written, node status cannot report an owner, and
  a deploy has no way to order the nodes.

**Why the ordering matters.** A rollout deploys the non-owner first and the address owner last. If
the new configuration breaks, it breaks on the node not carrying traffic, and the run stops before
reaching the other one. That protection is only real if the owner is actually known — which is why
the three points above are part of the installation and not an operational detail.

**One more assumption, in the cluster's own configuration rather than the node's.** Status and
metrics are read from a local HAProxy stats socket, so the published configuration is expected to
contain a line like:

```text
stats socket /run/haproxy/ui-status.sock mode 660 level user
```

`level user` is read-only — enough for status and metrics, not enough to change anything. It is a
local socket and must not be exposed on the network. An existing admin socket is separate and is not
replaced by it.

A copy-paste starting point for the keepalived side is in
[`install/examples/keepalived.conf.example`](../install/examples/keepalived.conf.example).

**One thing to expect after first provisioning.** A clean keepalived config reload does not
necessarily produce a VRRP state transition, so the state file may be empty until the first real
transition. Force one — stop keepalived on one node and start it again — or write the file once by
hand.

#### Node accounts

Four service accounts, identical on every node. They are system accounts with no password, a home
directory for `authorized_keys`, and — deliberately — a real login shell:

| Account | Reached by | May run |
|---|---|---|
| `svc-trigger` | the management host's deploy and cert-deploy keys | the pull scripts, through forced commands |
| `svc-backup` | the management host's backup path | the state export |
| `svc-status` | the management host's status key | the node status reporter, read-only |
| `svc-logread` | the production collector's traffic-log key | the bounded traffic-log reader, read-only and without sudo |

**The shell looks like a mistake and is not.** sshd runs a forced command through the account's
login shell, so `nologin` here does not harden anything — it stops every forced command from
working, and the only symptom is a nologin message where output was expected.

What constrains these accounts is that each key carries `restrict` and its own forced command, so a
session cannot run anything else. Where sudo is needed, its rules name exact absolute commands;
`svc-logread` needs and receives no sudo rule. None of this depends on the shell.

Each key in the account's `authorized_keys` carries its **own** forced command and the `restrict`
option. One key, one command: a shared forced command would make the keys interchangeable and
defeat the separation.

**The account owns nothing in its own home.** `/home/<account>`, `.ssh/` and `authorized_keys`
are `root:root` (`755`, `755`, `644`); sshd accepts a root-owned key file as readily as one owned
by the account. A key file the account could write would let a session rewrite its own forced
command, and a home directory it owned would let it replace `.ssh` wholesale. The shell's dotfiles
are covered by the same rule: Debian's bash sources `~/.bashrc` for a command it runs on behalf of
sshd, before the forced command, so no dotfiles are created and any left by an earlier installation
are made root's on the next run of step 4. Edit `authorized_keys` with `sudo`.

#### Node scripts

All root-owned under `/usr/local/sbin`, not group-writable:

| Script | What it does |
|---|---|
| `haproxy-pull-deploy` | fetches the published release, validates it, installs it, reloads once |
| `haproxy-cert-trigger` | unprivileged wrapper: validates the verb (`cert-pull` or `cert-remove`) and the certificate IDs, then escalates |
| `haproxy-cert-pull` | fetches the requested certificates, validates them, installs, reloads; a run stopped between installing and reloading leaves `/run/haproxy-cert-pull.pending`, the node's status leaves those certificates out until the next run reloads |
| `haproxy-cert-remove` | removes the requested certificates from `/etc/haproxy/certs`, refusing any the installed configuration still names; no reload |
| `haproxy-node-status` | reports version, health, carried certificates, keepalived state and the address list |
| `haproxy-keepalived-state` | records the keepalived transition to a state file |
| `haproxy-state-export` | writes this node's permanent state to stdout as a gzipped tar |
| `haproxy-health-probe` | opens one connection per named target and reports the status line |
| `haproxy-traffic-log-read` | returns whole records after a validated UTC day/cursor, capped at 8 MiB |
| `haproxy-traffic-log-enable` | installs or removes this node's rsyslog route and retention timer |
| `haproxy-traffic-log-prune` | deletes traffic day files past the 14-day window, whole and never renamed |

Step 4 also writes `/etc/haproxy-manager/node-installation.json`. It records the
node compatibility API and a SHA-256 digest for each of these eleven scripts.
`haproxy-node-status` recomputes the digests on every reading, so copied metadata
cannot hide a script changed after installation. The report contains code
digests only, never node configuration or key material.

**Your own files in the state backup.** The export carries the product's state
by name. Files that are yours rather than the product's — a local kernel option,
a site drop-in — are listed in `EXTRA_BACKUP_PATHS` in the answers file, which
step 4 renders into `node.conf`. Absolute paths, space-separated, letters, digits
and `. _ @ + - /` only; step 4 refuses anything else, because `node.conf` is
sourced as root. The export copies each one into the archive at its own path and
lists them in `meta/extra-paths.txt`, so a restore can tell them apart. A listed
path that does not exist on the node, or a directory holding a socket, pipe or
device, **fails that node's backup** instead of being skipped — the management
host only shows an export's messages when it fails, and an archive that quietly
lacks a file you asked for is the drift a backup is there to rule out. Every
node that gets the answers file must therefore have every listed path.

Two of these deserve attention:

**`haproxy-cert-trigger` exists because sudoers cannot express a list.** The certificate IDs arrive
as SSH command arguments, and no wildcard rule can safely constrain them. So validation happens
twice: unprivileged in the wrapper, and again in the root helper. The wrapper escalates with
`sudo -n` and an exact `NOPASSWD` rule, so a policy mismatch fails immediately instead of falling
back to an interactive password prompt. Since the cleanup operation ([Deleting a certificate](#deleting-a-certificate)) the wrapper knows two
verbs, `cert-pull` and `cert-remove`, each with its own root helper and its own sudoers rule; a
node installed before that answers `cert-remove` with "unknown request", which the manager reports
as a kept copy rather than as a failure. Rerun step 4 on such a node to give it the verb.

**`haproxy-health-probe` is held to the same TLS floor as the configuration.** A pool whose object
names a `legacy` policy is reached by HAProxy over TLS [Service accounts and the config group](#service-accounts-and-the-config-group), so a probe that kept a floor of its own
would refuse a backend HAProxy accepts and report a healthy pool as down. Each target therefore
carries a `min_version` — `TLSv1.1`, `TLSv1.2` or `TLSv1.3` — and the script refuses anything else.

A target that names none means `TLSv1.2`, which is what a manager older than the field sends. The
degradation runs the other way too and is worth knowing: a **node** older than the field ignores it
and probes at TLS [Directory layout](#directory-layout) regardless, so a `legacy` pool reads as unreachable until that node's script
is updated. The configuration is unaffected — only the answer the card gives.

**`haproxy-pull-deploy` is generic except for its publication path.** Everything else — validation,
release creation, the atomic symlink swap, the rollback on failure — is identical on every node.

#### Node filesystem layout

```text
/etc/haproxy/current -> /etc/haproxy/releases/<timestamp>
/etc/haproxy/haproxy.cfg -> current/haproxy.cfg
/etc/haproxy/conf.d      -> current/conf.d
/etc/haproxy/maps        -> current/maps
/etc/haproxy/certs/          local certificate directory
/run/lock/haproxy-deploy.lock
```

The releases root is `root:root 0750`. HAProxy, deployment, status and backup operations read it as
root; no forced-command service account needs to traverse it. Files inside an immutable release
may remain `0644` without thereby exposing the active configuration to those accounts.

A deploy never edits the running configuration. It builds a new immutable release directory, swaps
the `current` symlink atomically, validates again through exactly the paths `systemd` uses, and only
then reloads. If either validation or the reload fails, the symlink is swapped back.

`/run/lock` itself belongs to the operating system and is commonly mode `1777`. The node installer
requires it to exist but never changes its owner or permissions; HAProxy Manager owns only its
root-created lock files inside the directory.

#### Installing and changing node scripts

There is no unattended management-identity path for this, by design. Every management identity is
a forced command; none of them can copy a file. Installing or changing a node script crosses an
administrator's own interactive SSH login and escalates with `sudo` on the node.

The repository does automate everything around that interactive boundary. A node release is a
minimal tar archive containing only `04-node-prepare`, `lib.sh`, the ten attested node scripts and
an internal manifest. Platform installers, examples, caches and the source tree do not belong in
it. Environment answers remain a separate root-owned input; putting them in the code artifact
would make two installations of the same commit produce different releases.

##### Build and verify the bundle

Use a clean, committed source tree that has passed the complete repository gate. Build into a
protected staging directory outside the repository:

```bash
commit="$(git rev-parse --short=12 HEAD)"
bundle="/path/to/protected/staging/haproxy-manager-node-${commit}.tar.gz"

tools/node-bundle.py build \
  --source "$(pwd)" \
  --output "$bundle"
```

The builder refuses a dirty tree, an existing output file, a missing payload file, a symlink and an
unexpected Git file mode. It reads payload bytes and modes from the commit rather than the working
tree, then prints the full source commit, release name and SHA-256. Record the digest beside the
artifact; do not derive trust from a digest received with an untrusted copy.

The archive is deterministic: building the same commit twice produces identical bytes. Its
`MANIFEST.json` binds every path, mode and content digest to the full commit. Verify a retained or
transferred copy without extracting it:

```bash
tools/node-bundle.py verify \
  --bundle "$bundle" \
  --sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Verification rejects an external digest mismatch, an unsafe or duplicate path, a symlink, a
special file, an unmanifested member, changed bytes or modes, and files or archives over their hard
size limits.

##### Preflight and install one node

Measure the pair immediately before an update and select the node that does not own the virtual
address:

```bash
haproxy-status -c alpha
```

Run the transport as your administrator account, never as root. All paths must be absolute. The dry
run verifies the bundle locally, opens the operator's normal host-key-checked SSH path, checks the
node's cluster and prerequisites, and writes neither a backup nor a staging file:

```bash
tools/install-node-bundle --dry-run \
  --bundle /path/to/protected/staging/haproxy-manager-node-0123456789ab.tar.gz \
  --sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --answers /path/to/answers.env \
  --node node-b \
  --cluster alpha
```

Remove `--dry-run` to install. Rolling one bundle across a cluster's pair, give the first node
`--skip-backup-after` and the second `--skip-backup-before`: the state backup
(`haproxy-state-backup -c <cluster>` from the installed release) archives both nodes of that
cluster, and one before the first write and one after the last is the rule, not one pair per
node. Another cluster's roll-out is its own pair of backups. The tool:

1. verifies the external digest and complete internal manifest before contacting the node;
2. takes a state backup of the cluster before the first remote write;
3. uses one multiplexed, strictly host-key-checked SSH session for staging and installation;
4. copies only the bundle and the separate answers file to a random mode-700 directory under
   `/tmp`, then verifies the bundle digest again on the node;
5. runs the bundle's own `04-node-prepare` through the operator's interactive `sudo` path;
6. takes another state backup and runs `haproxy-status` for the cluster; and
7. removes its remote and local staging automatically. A cleanup failure is a visible warning that
   names the exact directory; remove only that named directory after inspecting it.

The SSH login and the node's sudo authentication are deliberately interactive. The shared SSH
session means each is requested once per node, not once per file. The management identities remain
forced commands and gain no file-copy ability.

Stop after the first node and read both the install report and `haproxy-status`. A successful copy
proves bytes, modes and ownership; run the command that uses a changed script before proceeding.
Remeasure VIP ownership before every subsequent node — never assume it stayed where the previous
status reading found it.

`haproxy-traffic-log-enable` and its `--disable` path restart rsyslog because rsyslog does not load
a changed rule on HUP. HAProxy does not buffer while its local log socket is unavailable, so a
request during that sub-second restart can be absent from both the structured day file and the
classic log. Run the command on the node that does not own the VIP first, remeasure ownership, and
then run it on the owner. The command repeats this loss window in its final output; a successful
restart cannot recover a line emitted while rsyslog was down.

##### Rollback

Keep the previous node bundle and its recorded SHA-256. A code rollback is the same verified
installation command with that retained bundle; there is no special path that bypasses manifest or
hash checks. Re-run the functional command and `haproxy-status` afterwards.

State backups are taken on both sides of every update so account, policy and configuration changes
also have a recovery point. They are not restored automatically: an automatic whole-node restore
after a partial failure could overwrite unrelated state that changed during the window. Stop on a
failure, preserve the reported backup, note any cleanup warning and determine which reported
operation completed before restoring state.

Optional features have their own symmetric rollback. For traffic logging, disable the node route
with `sudo haproxy-traffic-log-enable --disable`, remove only that collector key's forced-command
line from `svc-logread` and disable the manager collector. Traffic files are deliberately retained;
rollback never deletes evidence.

### Part 3 — the versioned CLI release

The management CLI is installed independently of the application data filesystem. Source and
development environments may live anywhere, but an installed release lives under
`/opt/haproxy-mgmt` so recovery and diagnostics remain available if application storage is not.

Application code is installed from a wheel. It is never imported from a checkout, an editable
environment, a developer-owned virtual environment, or any development path.

#### Build and install

Run the complete repository gate before producing the wheel. Build into a protected staging
directory outside the repository and record its SHA-256 digest:

```bash
python -m build --wheel --outdir /path/to/protected/staging
sha256sum /path/to/protected/staging/haproxy_manager-*.whl
```

Build the node bundle from the same commit, as in [Installing and changing node scripts](#installing-and-changing-node-scripts),
and record its digest too. The release carries it: a node restore installs exactly the bundle of
the release that runs it, and a rollback of the CLI takes the bundle back with it.

Install the absolute wheel and bundle paths with the digests printed by the previous commands:

```bash
sudo /usr/bin/python3 tools/install-release.py \
  --wheel /path/to/protected/staging/haproxy_manager-0.1.0-py3-none-any.whl \
  --sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --node-bundle /path/to/protected/staging/haproxy-manager-node-0123456789ab.tar.gz \
  --node-bundle-sha256 fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
```

The bundle is verified by the new release's own verifier before anything is activated, copied
into the release as `node-bundle.tar.gz` and recorded in `INSTALLATION.json` with its commit and
digest. The two bundle arguments are optional so a wheel from before them stays installable for
rollback; a release without a bundle refuses to restore a node and says why. A release is not
changed in place: installing an already installed wheel with another bundle, or without the one it
has, is refused.

The installer fails closed unless it runs as root and the supplied digest matches. It also rejects
unsafe wheel members and entry points, verifies the runtime baseline (including the distribution's
PyYAML, PyNaCl and psycopg packages) and imports, then installs:

```text
/opt/haproxy-mgmt/
├── current -> releases/<version>-<wheel-hash-prefix>
└── releases/
    └── <version>-<wheel-hash-prefix>/
        ├── INSTALLATION.json
        ├── node-bundle.tar.gz
        ├── bin/
        └── lib/
```

Release directories are `root:root`, directories and launchers are mode `555`, and other files are
mode `444`. The `current` link is replaced atomically only after the new release passes validation.
Short stable wrappers and exact sudoers rules may point into `current/bin`; they must never point
into a source checkout.

**`current/bin` is not on `sudo`'s path.** `sudo` resets `PATH` to its `secure_path`, which does
not include `/opt/haproxy-mgmt/current/bin`, so `sudo haproxy-cert-receiver ...` answers
`command not found` on a fresh installation even though the command is installed. The examples
in the user manual assume one short wrapper per operator command in `/usr/local/bin`, each of the
shape

```bash
#!/usr/bin/env bash
exec /opt/haproxy-mgmt/current/bin/haproxy-cert-receiver "$@"
```

so that a release switch moves every command at once and nothing points at a release
directory by name. The installer does not write them - which commands an operator types is
the installation's choice, and a helper the worker runs through an exact sudoers rule must
**not** get one. Until a wrapper exists, the full path works the same:
`sudo /opt/haproxy-mgmt/current/bin/haproxy-cert-receiver ...`.

`INSTALLATION.json` also records the engine compatibility API carried by the
wheel. A wheel from before that metadata existed remains installable for
rollback and is recorded as API zero; the whole-installation check will not
silently treat an unknown old engine as compatible with a newer UI.

#### Order of operations

Install the release **before** adding runtime-policy fields that a new release introduces. The
policy reader rejects unknown fields, so the reverse order breaks every command that reads the
policy, not only the new one.

### Part 4 — the web platform

Optional, and separate on purpose. The command line is the authoritative engine
and installs and runs without any of this; a management host that only ever uses
the CLI never needs the platform at all. [`../install/platform/`](../install/platform/)
is what you follow; this section explains the shape.

#### What is installed where

```text
/apps/haproxy-manager/
├── current -> releases/<version>-<commit>/
├── releases/<version>-<commit>/venv/
├── releases/<version>-<commit>/migration/
├── config/          ui.toml, root-owned, readable by the platform group
├── secrets/         root-only, granted one file at a time
└── data/
    ├── dumps/       database backups, root-only
    └── logs/
```

Config, secrets and data sit **beside** the releases rather than inside one. A
release is replaced wholesale and rolled back by pointing `current` elsewhere,
so anything that has to survive that cannot live within it.

A release is a commit, and the installer refuses to build one from a source tree
with uncommitted changes. It is built at its final path against the system
interpreter — a virtual environment is not relocatable, and an interpreter under
someone's home directory is invisible to a service running with `ProtectHome`.
Both are checked before `current` is switched.

The release is also compared with its source tree before activation. The check
covers Python, templates, CSS, JavaScript and the complete Alembic environment;
a build that reused an older local wheel or omitted a frontend asset is removed rather than activated. This keeps
the visible interface under the same “a release is a commit” rule as its server
code.

#### Identities

Three service accounts, one per service, each with its own database role. A
shared account for all three would make a web intrusion equal to worker access,
which is deploy rights. They share one group, and that group grants exactly one
thing: reading the configuration file.

Nothing authenticates to the database with a password. Connections use the local
socket with peer authentication, where the kernel states which operating-system
user is on the other end, and each account is named after its role — so there is
no password to leak, rotate, or find in a process listing.

#### The database

The migration role owns every object and has no operating-system account. That
is what makes "a service process cannot run DDL" true by construction rather
than by a grant somebody could add later: you cannot drop a table you do not
own. Running a migration is a deliberate root action, mapped explicitly in
`pg_ident.conf`.

Table grants live in the migration that creates the table, so a column's
permissions are versioned with the column. They name contract roles —
`app_web`, `app_worker`, `app_poller`, `app_collector` — and never an account; the installation
connects whatever the accounts are called to those roles. Columns are listed one
at a time, because a grant written as a whole table widens itself the next time
somebody adds one.

The web role may state what it wants done. It holds `insert` on three columns of
the job table and no `update` at all, so a queued job is immutable to the role
that queued it and there is no path from "I asked for this" to "this is what
happened". State, request ID and timestamps come from column defaults.

The poller writes cached readings and never removes one, with a single exception: the search
index, `search_entry`. Each reading the poller makes is turned into the values the header's search
looks for, and the poller replaces that reading's rows in one transaction, so it holds `delete` on
that table and on no other. The rows are derived and rebuilt every pass; the web only reads them.

##### Where the data lives

Put the cluster's storage on the volume that holds the platform, and keep the
package's path. The reference host mounts the platform volume at `/apps`, and
`/var/lib/postgresql` is a bind mount onto a directory there — not a cluster
reconfigured with a different `data_directory`:

```text
# /etc/fstab
/apps/postgresql  /var/lib/postgresql  none  bind,x-systemd.requires-mounts-for=/apps  0 0

# /etc/systemd/system/postgresql@.service.d/10-apps-mount.conf
[Unit]
RequiresMountsFor=/var/lib/postgresql
```

The directory behind the mount is owned by `postgres` (`755`), because a bind
mount shows the target's top level as the mount point. The drop-in is what makes
the arrangement safe rather than merely working: without it a boot on which the
platform volume comes up late would start the server on an empty directory,
and it would run — initdb-fresh, with no databases — until somebody noticed.

Two things sit behind this shape. The traffic-log table ([Mirroring node traffic logs](#mirroring-node-traffic-logs)) is the one part
of the installation whose growth is set by the nodes' visitors rather than by
the administrator, so it belongs on the volume that was given room for exactly
that, next to the dumps and the mirror; the root filesystem stays predictable.
And the path stays the package's because a cluster at its own path turns every
distribution upgrade into a special case for years, while a mount point leaves
`pg_upgradecluster` and the package tooling looking at the layout they expect.
The price is one ordering condition, proved once at installation:

```bash
findmnt /var/lib/postgresql        # SOURCE must name the platform volume
sudo systemctl restart postgresql  # and the cluster must come back on it
```

Moving an existing cluster is a stop, an `rsync -aHAX --numeric-ids`, a second
dry run that finds nothing left to copy, the mount, and the start — with a
verified dump ([Backups, and proving they restore](#backups-and-proving-they-restore)) taken first, and the old tree kept beside the mount until the
new one has served a day. The backup step's 85 % warning watches the filesystem
holding the dumps, which is now also the one holding the database.

#### Verifying it

`install/platform/03-verify` is read-only and can be run at any time. It is
deliberately a **second description** of the privilege surface, compared against
what the running database reports, and it checks both directions.

Both directions matters more than it sounds. A suite that only asks what a role
must *not* do passes completely when a role has no privileges at all — which is
a broken system reading as a perfectly secured one. Ask what must work too.

`install/platform/check-compatibility` is the read-only check above that local
database proof. Run it after the independently released pieces have been
installed:

```bash
sudo ./check-compatibility /path/to/answers.env
```

The running UI release supplies the accepted database revisions and minimum CLI
and node APIs. The command reports both release IDs, queries `alembic_version`,
checks that worker, poller and web really execute from `current`, compares the
active sudo rules with the helpers the UI requires, and reads each node bundle
through the existing status helper. It ends in one `COMPATIBLE` or `INCOMPATIBLE`
verdict and changes no file, row, service or HAProxy release.

For the development platform described below, the command follows its smaller
installed boundary: UI release, database revision and web process, plus the
absence of a sudo rule for the web account. Development deliberately has no
worker, poller or node access, so an empty `clusters` list and those absent
components are required isolation rather than missing production pieces.

For an update, first run `install-ui-release --prepare`. The candidate is built
and verified but `current` stays on the old release. Run `check-compatibility
--release <release-id> --before-migration` to prove its CLI, helper and node
requirements, then `migrate --release <release-id>`, `03-verify`, and the candidate
check again without `--before-migration`. Only after those pass is the same
prepared release activated by rerunning `install-ui-release` without `--prepare`.
The final ordinary compatibility check proves the processes after the switch.

The first bridge may encounter a running release from before compatibility
metadata existed. It can be activated only when its database head is exactly the
revision already running, so the operation makes no schema change. A candidate
that would migrate from such a release is refused because rollback safety cannot
be inferred without metadata.

`update-platform-release` owns that complete order for normal updates:

```bash
sudo ./update-platform-release /path/to/answers.env /path/to/source-tree
```

The CLI and node scripts remain independent installations; the command checks
them and stops before migration when either is too old. It also requires the
currently running UI to accept the candidate's declared database head. When a
new revision would not be safe for the old process and for rollback, first ship
a bridge UI release whose compatibility metadata accepts both revisions, then
ship the migration release. A failure after activation runs the installed UI
rollback command and checks the restored processes before returning failure.

#### HTTPS and the certificate

`install/platform/05-platform-nginx` puts nginx in front of the web service and
terminates HTTPS there. The web service itself listens only on
`127.0.0.1:8080`, in plain HTTP, and that leg stays plain deliberately: it never
leaves the host. The rendered site also includes
`/etc/nginx/snippets/haproxy-manager-receivers.conf`, created empty by this
step and written afterwards only by `haproxy-cert-receiver` ([Registering a receiver](#registering-a-receiver)); a rerun of
the step leaves an existing snippet alone.

**This is the direct address, and it does not go through the HAProxy pair.**
That is the whole point of it. The UI is the tool used to repair that pair, so
putting the UI behind it means a broken publish locks you out of the only thing
that could revert it. A reverse proxy elsewhere — anything from another nginx to
a Proxy Manager on a container host — may be added in front as an *additional*
path, terminating with its own certificate. It must never become the only path.

**The certificate is what a browser meets at login**, not something internal. It
cannot come from the certbot chain the rest of this project uses: that chain is
ACME with DNS-01 against a public domain, and a management host named on an
internal domain cannot be validated that way. So the pair is either self-signed
or issued by your own PKI.

Four answers-file keys control it:

| Key | Meaning |
|---|---|
| `SERVER_NAME` | the name the UI is reached on directly. Required |
| `TLS_CERT` | defaults to `/etc/haproxy-manager/tls/ui.crt` |
| `TLS_KEY` | defaults to `/etc/haproxy-manager/tls/ui.key` |
| `TRUSTED_PROXIES` | addresses or networks of a reverse proxy in front, space-separated; empty by default. See [Behind another reverse proxy](#behind-another-reverse-proxy) |

If no pair exists at those paths, step 5 generates a self-signed one so the UI
is encrypted from the first login. Point the keys at a pair your clients already
trust and that step never runs.

**Plain HTTP is not a lesser option here, it is a non-working one.** The session
cookie is `Secure`, and a `Secure` cookie is never sent over HTTP, so login
simply stops working. Removing `Secure` to get around that would put the session
for a tool with deploy rights in clear text on the network. A self-signed
certificate gives a browser warning but real encryption, which is the better
trade while a proper pair is being arranged.

##### Behind another reverse proxy

A proxy in front - another nginx, a Proxy Manager, a load balancer - is an additional path; the
direct one stays. Without being told about it, the management host knows every user by the proxy's
address, and three things go wrong:

- the sign-in throttle (`[throttle]` in `ui.toml`, failed sign-ins per address) is shared by everyone, so one
  person, or an attacker, locks every user out; the audit log names the proxy for every action;
- a certificate receiver's `/certdist/<receiver>/` location allows only the receiver's address, so a
  receiver fetching through the proxy is refused - and naming the proxy in its place would open
  certificates, and sometimes keys, to everyone who can reach the proxy;
- the sign-in provider (SSO) sends the browser back to the name the request arrived with.

**Name the proxy** in the answers file and run step 5 again:

```bash
TRUSTED_PROXIES="192.0.2.10"        # one or more addresses or networks, space-separated
sudo ./05-platform-nginx answers.env
```

Step 5 writes `/etc/nginx/snippets/haproxy-manager-real-ip.conf` on every run - `set_real_ip_from`
per entry, `real_ip_header X-Forwarded-For` and `real_ip_recursive on` - and the site includes it.
From then on nginx believes `X-Forwarded-For` only on connections from those addresses, and takes
the client to be the last address in it that is not one of them: a value a client wrote into the
header before it reached the proxy is skipped. A client that reaches the manager directly and sends
the header is still known by its own address. Throttle, audit log, receivers' `allow` and the access
log then all see the client. Host names and "every address" (`0.0.0.0/0`, `::/0`) are refused.
Emptying the key and running step 5 again stops believing the proxy.

**What the proxy must do:**

- **Use the manager's `SERVER_NAME`** as the name users reach it by, and send that name upstream as
  `Host`. The management host picks its site by that name, and the SSO provider sends the browser
  back to it; a different public name is not supported.
- **Forward to `https://<manager>:443`**, not to the application port, which listens on loopback only.
- **Append to `X-Forwarded-For`** rather than replace it. Other forwarded headers are optional - the
  manager's nginx sets its own.
- Leave receivers fetching directly where they can; through the proxy they work too, once it is
  named here, because the receiver's own address is then what `allow` sees.

A complete nginx block for the proxy, with made-up names (`ui.example.com` is the manager's
`SERVER_NAME`, `192.0.2.20` its address):

```nginx
server {
    listen 443 ssl;
    server_name ui.example.com;
    ssl_certificate     /etc/ssl/ui.example.com.crt;
    ssl_certificate_key /etc/ssl/ui.example.com.key;
    client_max_body_size 1m;

    location / {
        proxy_pass https://192.0.2.20:443;
        proxy_ssl_server_name on;
        proxy_ssl_name ui.example.com;
        # The manager's certificate, from https://ui.example.com/certdist/manager-ui.pem:
        # proxy_ssl_trusted_certificate /etc/ssl/manager-ui.pem;
        # proxy_ssl_verify on;
        proxy_set_header Host            $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_http_version 1.1;
        proxy_read_timeout 60s;
    }
}
```

In a Proxy Manager, the same thing is a proxy host for the manager's name with scheme `https`,
the manager's address and port 443, and `client_max_body_size 1m;` in its advanced field. Check in
its generated configuration that `Host` is passed unchanged and `X-Forwarded-For` is appended.

#### First administrator

There is no default password and no first-run setup page. Both are holes that
exist for the whole life of an installation in order to be useful for its first
thirty seconds: a shipped password survives in the field, and an
unauthenticated page that creates an administrator is exactly what it sounds
like.

So the first account is made by the installation itself, on the terminal of
whoever installs it: when `install-ui-release` activates a release on an
installation that has **no account at all**, it runs `haproxy-ui-user init-admin`,
which creates `admin` as a break-glass admin and asks for its password, twice,
as `add` does. It is never printed and stored nowhere but as a hash. Every later
release finds accounts and does nothing, and asks nothing. Without a terminal —
the installer run with its input redirected — no account is made and the
installer says to run `init-admin` by hand. Nothing about it is the same on two
installations, and nothing answers on the network before it exists.

For account administration and password recovery, see
[Accounts and signing in](#accounts-and-signing-in).

#### Platform backup installation

`install/platform/06-platform-backup` installs `haproxy-ui-backup`, a daily
timer, and a weekly restore check — then takes a dump and restores it
immediately, because the moment to discover that a backup does not work is
during installation rather than during an incident.

For manual dumps, restore checks and recovery, see
[Backups, and proving they restore](#backups-and-proving-they-restore).

#### Retention installation

`install/platform/11-platform-retention` installs `haproxy-ui-retention` and a
daily timer. It is optional, and it is separate from the backup step because
it is the only thing here that removes rows from a live table. **The step itself
deletes nothing** — it reports what the first run would remove and leaves the
deciding to the timer or to an operator.

For reports, pruning and retention rules, see
[Keeping jobs, sessions and metric history bounded](#keeping-jobs-sessions-and-metric-history-bounded).

#### Mirroring node traffic logs

`install/platform/13-platform-traffic-collector` installs a fourth, deliberately
small identity and a timer that asks each node for its own traffic log. Optional,
production only, and last: nothing else on the platform depends on it.

```text
${PLATFORM_ROOT}/logs/mirror     collector writes freshness metadata, the interface reads
${PLATFORM_ROOT}/logs/staging    the collector's alone
/etc/haproxy-manager/traffic-collector/{id_ed25519,known_hosts}
/etc/haproxy-manager/traffic-collector.json
```

The collector program itself is installed with the CLI engine under
`/opt/haproxy-mgmt/current`, not inside the web release. This is a privilege boundary rather than
packaging trivia: web releases are traversable only by the platform group, while the collector
deliberately does not join that group and therefore cannot read `ui.toml`. The engine release is
root-owned, immutable and executable without granting access to the platform configuration.

**The direction is manager to node, and that is the whole design.** The first
attempt had each node forward its log to the management host over TLS, and a DMZ
node correctly could not open that connection. Nothing here asks for a new
network path in any topology: the management host already reaches every node
over SSH for configuration, certificates and status, so this adds one key to a
path the product already requires. An installation whose firewall differs still
needs nothing new.

**A fourth account with one narrow database direction.** The collector is not a member of the
configuration group and has no sudoers rule. Its `app_collector` contract role can only insert
traffic rows; it cannot select, update or delete them. It owns one
SSH key, and the far end of that key is a forced command that can return one
validated day of one node's traffic log and nothing else. The step checks that
boundary rather than describing it, and checks it by traversal: `ls` on a
directory fails whether or not an account can reach through it, so listing is not
evidence.

**Host keys are copied from what this host already trusts, never scanned.**
`ssh-keyscan` asks a node who it is and believes the answer. If a node has no
pinned key yet, the step refuses and says so; accept that one deliberately,
once, through the path that already exists.

**The mirror is a sibling of `data/`.** Reaching a mirror under `data/logs`
would mean opening `data/` for traversal by the web account, and `data/dumps`
holds every session and every audit record in one file. The mirror directory is
set-group-id, because the collector is deliberately outside the web account's
group and could not otherwise create a file the interface can read.

**No collector on a development platform.** The step refuses unless
`ENVIRONMENT` is `prod`. A development platform is built not to reach the real
nodes, and giving it a key and an inventory would undo exactly that.

The step fetches nothing on its own. It prints one `authorized_keys` line to add
to `svc-logread` on each node, and each node also needs its own log route
switched on with `sudo haproxy-traffic-log-enable`.

Enabling or disabling that node route restarts rsyslog; a reload does not apply
the rule. HAProxy does not buffer log lines during the brief restart, so apply
the change to the node that does not own the VIP first, verify it, remeasure VIP
ownership and only then change the owner. A request landing in the restart
window can be absent from both the structured and classic local logs.

The stream is also opt-in per cluster. Set `traffic_logging: true` in that
cluster's entry in `clusters.yaml`, then publish an actual object change so the
generator's log profile reaches the nodes. Rerun platform step 13 whenever a
node is added to or removed from `clusters.yaml`; `check-compatibility` refuses
a running traffic-log view while the collector's installed node list differs.

Only the structured stream removes query strings, and only that stream is
mirrored to the manager and shown in the interface. HAProxy's ordinary
`haproxy.log` remains byte-for-byte unchanged and its traditional HTTP log line
contains the complete request target, including any query string. Treat that
local file accordingly when choosing retention, backup and access controls.

The collector imports complete records with PostgreSQL `COPY` and advances an atomic local
checkpoint only after the database transaction commits. Repeating a batch is safe because each
record has a deterministic identity. The interface reads indexed database rows once
`[traffic_logs]` is enabled in `ui.toml`; the mirror metadata still reports collection freshness.
With the database configured the collector keeps the day files in staging and one metadata file
per node in the mirror directory, and does not join the days into one log file per node: nothing
reads that file, and writing it meant rewriting the whole retained history once a minute. A joined
file left from a configuration without the database is removed on the next run.
`retention_days` defaults to seven (range 1–90). The privileged retention timer creates daily
partitions ahead and removes expired data by dropping whole partitions; application identities
have no `CREATE` or `DELETE`. PostgreSQL's `pg_trgm` extension is installed once by platform step
2 so host, path and backend substring searches use per-day GIN indexes.

**The manager's mirror follows that setting rather than carrying a window of its own.** Each run
takes the days the database still holds, keeps one more as the margin it would replay from after a
restore, and lets the rest go. Nothing is configured twice: a mirrored day the database has no
partition for can be neither read in the interface nor imported, so keeping it would cost disk on
the volume the mirror sits on and buy nothing. A run that cannot reach the database keeps the wider
fallback window instead of pruning — fetching is the part that cannot be caught up later, because
each node drops its own day files on its own schedule. **The nodes keep fourteen days regardless.**
Those cost the node's disk rather than the manager's, and they are what makes raising
`retention_days` a setting rather than a hole in the history.
It never asks a node anything, so an unreachable node cannot make a page slow — it can only make
its own mirror old. The page therefore names every
node and how old its mirror is **before** the records, because a node that
stopped answering renders an empty table that otherwise reads as calm. Log text
is written by whoever made the request and is escaped as text, never as markup.

##### Sizing the traffic table

The numbers below were measured, not estimated, on a management host at the
reference size — 2 vCPU, 4 GiB, PostgreSQL with stock `shared_buffers` of
128 MB, the production services running beside the test. A throwaway cluster on
the platform volume took the real migrations, was filled through the collector's
own `COPY` path with realistic cardinality (twenty hostnames, three hundred
paths, ten proxies, weighted methods and status codes, seven days of
time-ordered records as the collector writes them), and was read through the
page's own query. Three checkpoints, `analyze` before each:

| Rows | Table | Indexes | Per row | Newest 500 | Substring, one word | Substring, two words | Status 5xx | One day | One cluster, one day |
|---|---|---|---|---|---|---|---|---|---|
| 1 M | 230 MiB | 161 MiB | 411 B | 3 ms | 3 ms | 10 ms | 3 ms | 2 ms | 2 ms |
| 10 M | 2 299 MiB | 1 678 MiB | 417 B | 3 ms | 4 ms | 11 ms | 4 ms | 2 ms | 3 ms |
| 30 M | 6 897 MiB | 4 562 MiB | 401 B | 3 ms | 3 ms | 13 ms | 4 ms | 2 ms | 2 ms |

**Plan on 410 bytes per record, indexes included**, and on the page staying
fast: every query form the interface issues answered in about ten milliseconds
or less at thirty million rows, with the trigram indexes carrying the
substring searches. The write side is not the limit either — the collector's
path sustained about 30 000 records per second throughout the load, flat with
table size, and a run imports a minute's worth of traffic.

So the disk a retention window needs is `records per day × retention_days ×
410 bytes`, plus the collector's day files in staging for the same days (one
more, the replay margin), plus WAL. At the default seven days that is close to **3 GB per
million records a day**. A pair of nodes serving ten thousand requests a day
uses tens of megabytes; an installation nearing a million a day should have that
volume sized for it and the 85 % backup warning ([user manual](#what-the-dump-does)) heeded. The number that grows
without the administrator's say-so is this one, which is why the database sits
on the platform volume ([The database](#the-database)) rather than on the root filesystem.

#### The worker and the poller

`install/platform/07-platform-services` installs both, each as its own operating
system account. That separation is the reason the interface can be safe at all:
a single application user would have made a web intrusion equivalent to deploy
rights.

| Identity | May | May not |
|---|---|---|
| web | authenticate, audit, queue a strictly validated job | no sudo rule, no management group, no key, cannot claim a job |
| worker | call the engine's exact helpers, claim and complete jobs | read key files, run DDL |
| poller | run exact read-only metadata helpers, write the status, inventory and history caches | read private trees directly, write a job, call any write operation |

##### The poller

It never reaches a node itself. The engine's configuration, the status account's
key and the published release tree are all outside this account's reach by
design, so the poller runs the same privileged helper the command line runs,
through exact sudoers rules:

```
<poller> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-status-helper ""
<poller> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-inventory-helper ""
<poller> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-list-helper ""
<poller> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-list-backups-helper ""
<poller> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-cert-list-helper ""
<poller> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-network-helper ""
<poller> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-objects-helper ""
```

For the polling interval and refresh behaviour, see
[Jobs and status freshness](#jobs-and-status-freshness).

The configuration file is written by `01-platform-prepare` **only when it is
absent**, so an edit here survives every later release. Changing the value takes
effect when the poller is restarted; it reads its configuration once, at start.

**A rule under `/etc/sudoers.d/` does not travel with a release.** Adding a helper here means
installing its line separately, `visudo`-checked; a release that carries a helper nobody may run
fails at the first call with sudo's refusal in the diagnostics rather than at install time.

The rule is exact because the helper **takes no arguments at all** — the cluster
arrives as a bounded JSON request on one line of stdin. `PRIVILEGE.md` forbids wildcards in
sudoers argument matching, and without the no-argument form a rule naming a
cluster would need one. The helpers read their target inside the boundary. In
particular, inventory reads the exact commit named by the published RELEASE
stamp rather than the repository work tree, so an unpublished change cannot be
presented as live. The list helper reads saved commit metadata — version number,
timestamp and comment — and no file content at all. The backup helper reads
directory metadata under the state backup root and never opens an archive,
which is what lets an account that must not read password hashes and private
SSH keys still report that a backup exists. The certificate helper reports
metadata about the distribution root, and about which certificates certbot is
renewing on this host; private key material never reaches its output, because
what it parses is the leaf certificate alone. The network helper reads one
cluster's `managed/network.yaml` — a file whose directory is group-readable by
the engine's own group and by nobody else, which is why the interface cannot
simply open it — and reports the three address tables plus which of the two
possible sources they came from. None takes a lock, so these
reads stay answerable while a deploy runs.

`haproxy-list` itself does not use that helper: a person running it can already
read the cluster repository, so the command reads it directly and requiring
`sudo` for machine-readable output would be privilege for formatting. Both paths
build their result with the same function, so the two cannot come to describe
the same history differently.

The request itself is built by the engine's own code, not by a copy of it in the
interface. Two constructions of the same request are two things to keep in step,
and each looks correct on its own — which is the hardest kind of divergence to
find.

Results go to `cluster_status`, `cluster_inventory` and `cluster_history`, each
with one row per cluster, and every page shows how old the answer it uses is. `observed_at` is
set by the database — by default on insert and by trigger on update — and the
poller holds no `update` on that column: a poller that could write it could
report a cluster it never reached as freshly observed.

##### The sandbox, and the three ways it failed quietly

The poller's unit is hardened like the others, with three deliberate exceptions
that are written in the file with their reasons: `NoNewPrivileges=no`, because
sudo is setuid and the whole point of this service is to run one helper through
it; a capability set that permits changing uid, for the same reason; and network
address families, because the helper reaches nodes from inside this sandbox.

One more is worth stating separately, because it was found by running it rather
than by reasoning about it. The status identity's key is root-owned and lives
under `/root`, so the unit needs a hole in `ProtectHome` — and:

- `ProtectHome=yes` **masks** a `BindReadOnlyPaths` under `/root`. The file
  stays invisible and the service starts perfectly. `ProtectHome=tmpfs` is what
  works, because the bind then lands on top of the empty filesystem.
- A bind mount written with a leading dash is *optional*, and systemd skips it
  in silence when it cannot be satisfied. The service starts, and every cluster
  reports as unreachable — a failure that reads as a broken environment rather
  than as a missing file. The dash is deliberately not used.
- Both of those present identically: SSH exits 255 in under a tenth of a second
  and every node is `ssh_unreachable`. If that is what the cache shows, run the
  helper by hand outside the unit before suspecting the nodes:

```bash
printf '{"schema_version":1,"operation":"status","cluster":"<id>",'\
'"request_id":"'"$(uuidgen)"'","parameters":{}}' \
  | sudo -u <poller> sudo -n /opt/haproxy-mgmt/current/bin/haproxy-status-helper
```

If that answers `done`, the sandbox is the problem and not the environment.

If that answers `done`, the sandbox is the problem and not the environment.

**One poller, enforced by the database.** It holds a session-scoped advisory
lock for its whole life; a second one finds the lock taken and exits rather than
doubling the load on every node. The lock is released by the server when the
connection dies, including when the process is killed without cleanup — which is
exactly the case a lock file gets wrong.

##### What the worker may run

Thirteen helpers, each with no arguments, in `/etc/sudoers.d/<worker>`:

```
<worker> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-deploy-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-cert-deploy-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-revert-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-network-publish-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-objects-publish-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-cert-issue-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-cert-publish-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-cert-target-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-dns-profile-apply-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-cert-delete-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-ndes-profile-apply-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-cert-scep-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-cert-import-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haproxy-mgmt/current/bin/haproxy-cert-request-helper ""
```

The last nine are the certificate jobs ([Issuing a certificate](#issuing-a-certificate), [The DNS profile key pair](#the-dns-profile-key-pair), [Deleting a certificate](#deleting-a-certificate), [Importing a certificate](#importing-a-certificate)): they belong to no cluster, and
the queue runs one of them at a time. `cert-delete` is the only rule in the file that removes
key material; [Deleting a certificate](#deleting-a-certificate) says what bounds it. The receiver helper ([Registering a receiver](#registering-a-receiver)), which makes accounts and
edits sshd's and nginx's own configuration, is deliberately not in this file: it is reached over
a socket instead, for the reason given under *The worker's way to the receiver helper*.

Publishing was deliberately absent from that list until the editor existed, on the reasoning that
it was an operator's decision made at a terminal. What changed is that the interface became where
those decisions are made: an editor that can only save a draft is an editor whose work has to be
finished somewhere else, and asking somebody to leave the screen and log in to a shell to complete
a change is how a change gets left unfinished. Publishing still writes nothing to a node — that is
deploy, a separate helper and a separate decision.

**`07-platform-services` installs this file**, `visudo`-checked, since 2026-09-03. Before that it
was installed by hand, and it fell behind exactly as this document warns: the file predated the
objects-publish helper, so the publish button would have met sudo's refusal on its first use. If you
are upgrading an installation that was built earlier, rerun that step.

##### The web service, and why it has no sudoers rule at all

The web service asks the nodes exactly one thing: try this health check. Nothing
else it does reaches outside the database.

That one thing needs root, because the probe identity's key is root-owned — no
application account may hold a key that reaches a node. The obvious way to grant
it would be a sudoers rule, one exact no-argument helper, the way the poller's
seven are granted. **That does not work here, and it is worth knowing why before
somebody writes the rule again.**

The web unit carries `NoNewPrivileges=yes`, an empty `CapabilityBoundingSet=`
and `RestrictSUIDSGID=yes`. Under `NoNewPrivileges` the kernel ignores the setuid
bit, so `sudo` fails *before it reads `/etc/sudoers.d/`* — it fails however the
rule is written, and the rule then sits on disk saying this account may become
root while granting nothing at all. The poller solves the same problem by
relaxing its own sandbox (`NoNewPrivileges=no`, a capability set that permits
changing uid); doing that to the web service would trade the one boundary most
worth keeping for a button.

So the privilege stays still and the request travels instead:

```
/run/haproxy-mgmt/probe.sock   root:<web> 0660, created by haproxy-probe-helper.socket
haproxy-probe-helper@.service  runs the helper as root, one instance per connection
```

The web service opens the socket, writes one JSON request, closes its write side,
and reads one JSON answer. The far end takes no arguments and does exactly one
thing, so reaching it is worth no more than the sudo rule would have been — and
the web account keeps a sandbox in which nothing it runs can gain privilege.

`haproxy-probe` on the command line still goes through `sudo`, because a person
running it has a terminal and a `%sudo` rule. Both build the request with the
same function, so the two paths cannot come to describe the same probe
differently.

**A development platform must not get this socket.** It reaches the real nodes.
`PROBE_SOCKET=no` in its answers file is the default, and its interface then says
the probe is unavailable rather than showing an empty result.

##### The worker's way to the receiver helper

The worker *can* `sudo` - thirteen of its helpers go that way. The receiver helper
does not, for a reason on the other side of the boundary: a helper the worker
starts inherits the worker unit's mount namespace, and that unit has
`ProtectSystem=strict` with a short `ReadWritePaths` list. Registering a
receiver writes `/etc` - `useradd` rewrites `/etc/passwd` and its neighbours
through a rename, so the whole directory has to be writable, and the helper
rewrites `/etc/ssh/sshd_config.d/` and `/etc/nginx/snippets/` besides. A
`ReadWritePaths=/etc` on the job runner would end the sandbox for every helper
in order to serve one; a rule that stays fails at the first write.

So this helper, too, sits still and the request travels:

```
/run/haproxy-mgmt/cert-receiver.sock    root:<worker> 0660, created by haproxy-cert-receiver-helper.socket
haproxy-cert-receiver-helper@.service   runs the helper as root, one instance per connection
```

The worker runs `haproxy-cert-receiver-ask` from its own environment, as
itself: no arguments, the request on stdin, the answer on stdout - the same
shape every other helper is run in, so the queue, the lease and the output cap
are unchanged. The client connects to the socket, writes the request, closes its
write side and passes the answer through untouched. When nothing listens, the
answer is an envelope that says so (`dependency_unavailable`), never `unknown`;
a helper that was asked and went quiet leaves the job `unknown` (see the backup
and restore helpers below).
The helper's own stderr goes to the journal (`journalctl -u
'haproxy-cert-receiver-helper@*'`), not to the job.

The service's sandbox is `ProtectSystem=yes` - `/usr`, `/boot` and `/efi`
read-only, `/etc` writable - because writing `/etc` is the job. `full` and
`strict` would both take `/etc` away, which is the failure this unit ends.
`haproxy-cert-receiver` at the terminal does not go this way; root runs it
directly.

Step 07 installs the socket wherever it installs a worker. It reaches no node.

##### The way to the interface certificate

The same boundary once more, with a different caller. The helpers that issue, enroll and import
certificates run through `sudo` inside the worker's namespace, and publishing the entry marked
`interface: true` ([HTTPS and the certificate](#https-and-the-certificate)) ends in `haproxy-ui-tls install`, which writes `/etc/haproxy-manager/tls`
and a rollback directory beside it. So those helpers name the entry by ID on a socket:

```
/run/haproxy-mgmt/ui-tls.sock      root:<worker> 0660, created by haproxy-ui-tls-helper.socket
haproxy-ui-tls-helper@.service     runs the helper as root, one instance per connection
```

The request carries the certificate ID and nothing else; the helper reads the registry and the
material itself and refuses an entry without the mark. The socket takes one connection at a time,
and the helper takes no lock: its callers hold the publisher's lock while they wait for it. The
sandbox is `ProtectSystem=yes`, as for the receiver helper. The renewal timer and
`haproxy-cert-publish` do not go this way; root runs them directly. Step 07 installs the socket
wherever it installs a worker.

##### The worker's way to the backup and restore helpers

Node backups from the interface and node restores go the same way as receivers,
for the same reason from the other direction: both read root-only state archives
under `backup_root`, a restore keeps its run and one-time key under
`/var/lib/haproxy-mgmt/restore`, and both reach nodes over SSH as root. A sudoed
child of the worker would inherit its read-only mount namespace.

```
/run/haproxy-mgmt/backup-job.sock       root:<worker> 0660, created by haproxy-backup-job-helper.socket
haproxy-backup-job-helper@.service      backup_run and backup_schedule, as root, one instance per connection
/run/haproxy-mgmt/node-restore.sock     root:<worker> 0660, created by haproxy-node-restore-helper.socket
haproxy-node-restore-helper@.service    node_restore_prepare, _preview, node_restore and _discard, as root
```

The worker runs `haproxy-backup-job-ask` and `haproxy-node-restore-ask` from its
own environment, exactly as it runs the receiver client. Two answers differ from
a helper that ran and refused. Nothing listening is an envelope that says so
(`dependency_unavailable`, `failed`): nothing ran. A helper that was asked and
then went quiet - the client's time ran out, or the connection dropped - is
**no** envelope, and the job ends `unknown`: the root service carries on without
the client and may have finished. The client's sentence is in the job's stderr
excerpt; the helper's own lines are in the journal (`journalctl -u
'haproxy-node-restore-helper@*'`).

The restore service needs `AF_NETLINK` besides the usual families: `ip route
get` names the address the target will see the manager come from, which is what
the one-time key's `from=` is limited to. `update-platform-release` refuses to
run while a restore or backup job holds a live lease, because activation
restarts the worker. Step 07 installs both sockets wherever it installs a
worker; `haproxy-node-restore` and `haproxy-state-backup` at the terminal do not
go this way, root runs them directly.

##### The worker's way to the node helper

Adding or removing a node writes root's `known_hosts`, the pull accounts' `authorized_keys`, the
cluster file and the collector's files - none of which a helper the worker starts through sudo may
write. Creating or removing a cluster writes those and the editing policy under `/etc/sudoers.d`,
a new repository under the configuration root, and moves directories into `.removed/`. So
`haproxy-node-helper` answers both on `/run/haproxy-mgmt/cluster-node.sock` (root, group the
worker's account, `0660`) from `haproxy-node-helper@.service`, installed by step 07; the worker's
`haproxy-node-ask` carries the request there, and `haproxy-node` and `haproxy-cluster` from a
terminal run the helper directly as root.

##### Which clusters get polled

The clusters `clusters.yaml` lists, in its order. The poller asks
`haproxy-cluster-list-helper` on every pass - through one sudoers rule, because the application
accounts cannot read the engine's configuration and must not - and keeps the answer in one row that
the pages read. A cluster created or removed from Settings is therefore polled and drawn from the
next pass on, and its colour follows its place in the file.

`clusters` in `ui.toml` is the fallback: the list before the poller has read one, and the list
while the helper cannot be read. A pass that cannot read the list polls the clusters it knew
rather than none. An empty `ui.toml` list with no readable cluster file leaves the poller nothing
to do, and it says so instead of starting.

#### A development platform beside production

The same steps install it, with a second answers file. Nothing is shared: its
own accounts, its own database and roles, its own release tree, its own port.

```bash
sudo ./01-platform-prepare   answers-dev.env
sudo ./02-platform-database  answers-dev.env
sudo ./install-ui-release   answers-dev.env <source-tree>
sudo ./migrate               answers-dev.env
sudo ./04-platform-service   answers-dev.env
sudo ./15-platform-dns-keys  answers-dev.env <source-tree>
```

Steps 5, 6 and 7 are deliberately **not** run for development. It does not need
backups, and it must not have the poller's sudoers rule, because a development
platform has no business reaching production's nodes.

By default development has no nginx site and is reached over an SSH tunnel to
its loopback port. If browser review needs a direct development address, add a
distinct `SERVER_NAME` to the dev answers file, provision DNS for it, and run:

```bash
sudo ./09-dev-nginx answers-dev.env
```

Step 9 is deliberately separate from production's step 5: it makes a second
nginx virtual host to the dev loopback port, with a separate certificate path
and `haproxy-ui-dev-tls` command. It neither exposes the development port
directly nor changes the production vhost or certificate. A self-signed pair is
generated when no development pair has been supplied; an internal-PKI pair can
later replace it through the dev-specific command.

`ENVIRONMENT=dev` in the answers file also keeps the root commands in
`/usr/local/sbin` pointing at production. A development install would otherwise
aim the operator's rollback command at the development release, which is the one
moment a wrong answer is expensive.

##### Proving the two cannot reach each other

```bash
sudo ./08-verify-isolation answers.env answers-dev.env
```

Read-only and runnable at any time. It is every check that only exists in the
gap between the two installations, so nothing else finds it: each platform's own
privilege suite is green while asking only about its own accounts.

It asks in **both** directions. The asymmetry people expect — development is the
dangerous one — is not the only way this goes wrong: a production poller that
could write to the development database would be reporting into a void.

The first run failed on the database checks, in both directions, and the reason
is worth knowing before building anything similar. Grants in the migrations name
generic contract roles, `app_web` and friends, so that they never name a real
service account. Generic means **shared**, and two platforms on one PostgreSQL
cluster are both members of the same `app_web` — so `grant connect ... to
app_web` had given every development account a route into production.

`CONNECT` is not a column privilege, and it now goes to the environment's three
**login** roles instead, granted by the installer that knows which environment
it is installing. Column privileges stay in the migrations where they are
versioned with the column. Who may enter a database is the installation's
business; what they may do inside it is the schema's.

### Verifying the installation

Work outward, and stop at the first step that fails:

1. **Configuration status** — `haproxy-config-status -c alpha` reports the published version and a
   clean draft.
2. **Node status** — `haproxy-status -c alpha` reaches both nodes and reports the address owner,
   the release each node runs, and whether that is the published one. This proves the status key,
   its forced command, and the node reporter.
3. **The stored objects** — `haproxy-objects -c alpha` lists the proxy objects as they are written,
   at the commit the repository is on, and `--show <name>` prints one document exactly as stored;
   `--advanced <name>` prints where each line of its advanced config goes.
   Where `haproxy-inventory` parses what a node is serving, this reads the source that produced it -
   so an object the generator refuses is listed with the refusal rather than left out. The listing
   also names the VIP each object is served on, worked out by the generator's own rule against the
   network description, which is what the interface lists and searches by.
4. **A converged deploy** — `haproxy-deploy -c alpha` with nodes already current should skip both
   nodes and change nothing. A run that correctly does nothing is a real test. Step 2 should
   already have said the cluster was converged; if the two disagree, believe neither and find out
   why before deploying anything.
5. **A deploy that does something** — publish a harmless change and deploy it. Confirm the non-owner
   is deployed first, the owner last, and that the address does not move.
6. **The negative tests** in [`PRIVILEGE.md`](PRIVILEGE.md), run as the real installed identities
   rather than through mocks.

Do the last two on a cluster that carries no traffic if you have one.

### What is still missing

This guide is honest about its gaps rather than complete on paper:

- **Certificate renewal** is deliberately out of scope and belongs to the ACME client:
  certificates issued through Certbot renew on Certbot's own timer, and those enrolled from a
  Microsoft CA over NDES/SCEP renew through the same daily run. Issuance, import and
  distribution are described in the [user manual](#certificates).
- **A rebuild from this repository alone** has not yet been re-verified end to end since the
  latest phases; that is the last step before 1.0.

The acceptance criterion for closing them is mechanical: a new management host and a new pair of nodes, with names of your own choosing, built
from this repository alone by someone who has never seen the maintainer's environment.

