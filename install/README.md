# Installing Haprion

Five steps. Three run on the management host, one on each node, and the last one
checks your work.

Everything that can be scripted is scripted. What is left for you is the part
that genuinely cannot be automated — pasting public keys onto machines the
management host is not allowed to write to — and step 3 prints those lines ready
to paste.

[`../docs/user-manual.md`](../docs/user-manual.md) explains *why* each step
looks the way it does. This file is what you follow.

**This is a first installation.** Shipping a later change is a different
question — which of the CLI engine, the web platform and the node scripts it
touches, and in what order — and it is answered once in
[Releasing a change](../docs/user-manual.md#releasing-a-change).

## Before you start

You need HAProxy and, if your clusters use a virtual address, keepalived already
installed on the nodes. This project manages HAProxy; it does not install it.

**But it does assume things about how they are configured**, and getting those
wrong does not fail loudly — it quietly makes deploys unsafe. Read
[the keepalived baseline in the manual](../docs/user-manual.md#haproxy-and-keepalived-baseline)
before step 4: both nodes binding the virtual address, both keepalived instances
as `BACKUP` with `nopreempt`, and the `notify_` lines that tell the management
host who owns the address. There is a working starting point in
[`examples/keepalived.conf.example`](examples/keepalived.conf.example), and step
4 checks all three and says so if one is missing.

The
management host needs Python 3.12+, the OS PyYAML, PyNaCl and psycopg 3 packages, `git`, `rsync`,
`openssh-client` and a `sudo` new enough for no-argument rules.

The answers file is optional. Without one every step uses the defaults in
[`defaults.sh`](defaults.sh) - standard places, no cluster - and the clusters are
created in the web interface. To choose differently, copy the example and keep
the lines you change; it is the only place you make decisions:

```bash
cp answers.example.env answers.env
$EDITOR answers.env
```

Pass it to each step below, or leave the argument out. `haprion-setup` runs the
manager's steps here and the platform's under `platform/` in order, checks what
it can before it changes anything, and reports a step that fails in words -
what went wrong, why, what to do - with its whole output in
`/var/log/haprion/setup.log` ([docs/install.md](../docs/install.md#1-choose-the-answers-or-keep-the-defaults)).

## Step 1 — prepare the management host

```bash
sudo ./01-manager-prepare answers.env
```

Creates the configuration group, the directory trees, and one Git repository per
cluster with the standard layout committed. Writes no configuration and contacts
no node.

## Step 2 — write the configuration

```bash
sudo ./02-manager-config answers.env
```

Renders `clusters.yaml` and `runtime-policy.yaml` from your answers - with no
cluster, an empty cluster file - creates the empty certificate registry the
policy names, and creates the validation-only certificate. Rendering them rather than hand-editing is the
point: what the code reads and what you reviewed cannot drift apart.

When `BACKUP_ROOT` is set it also installs the hardened
`haprion-state-backup@.service` template. A timer or *Back up now* starts one
validated cluster instance; the service itself never accepts a path or node.

It also installs the operator editing policy — the `sudoedit` rules that let the
accounts in `CONFIG_EDITORS` edit `core/haproxy.cfg` and `manual/reservations.yaml`
without a root shell, checked by `visudo` before anything is written. Leave
`CONFIG_EDITORS` empty and the step says it skipped it. The paths are written
once: after that *Create cluster* and *Remove cluster* keep them, and a rerun
changes only the editors.

## Step 3 — keys, and the lines for the nodes

```bash
sudo ./03-manager-keys answers.env | tee keys.txt
```

Generates the management key pairs and prints, per node, the exact
`authorized_keys` lines to install. Keep the output — step 4 does not print them
again.

**This is the manual part.** The management host cannot write to a node: every
management identity is a forced command that can ask a node to pull and nothing
else. So you log in to each node yourself and paste. That restriction is the
security model, not an oversight.

## Step 4 — each node

The node's software is one package, `haprion-node`, built from a commit on the
management host:

```bash
tools/node-package.py build --source . --output-dir /path/to/protected/staging
```

It prints the package's path, version and SHA-256. Install it on a node, and
configure the node with this step, from the management host as yourself:

```bash
tools/install-node-package --node-package /path/to/haprion-node_<version>_all.deb \
  --sha256 <digest> --answers /path/to/answers.env --node node-a --cluster alpha
```

The tool verifies the package, takes a state backup, copies the package and the
answers over one SSH session, installs the package with apt and runs
`/usr/share/haprion-node/install/04-node-prepare answers.env alpha` on the node -
the step the package put there. That step creates the service accounts, the
`/etc/haproxy` release layout and the sudo rules; the node scripts are the
package's, in `/usr/sbin`.

Then paste the `authorized_keys` lines for this node from step 3, and add the
keepalived notify lines if the script asked for them. The server state key's line
is the exception: with `SERVER_STATE_PUBKEY` in the answers file, this step writes
it. Drain, maintenance and ready also need the admin socket line in each cluster's
`core/haproxy.cfg` (`docs/user-manual.md`, 'Node scripts').

Repeat for every node. A later update is the same command with a newer package;
see `docs/user-manual.md`, 'Installing and changing node scripts'.

## Step 5 — check

Back on the management host, as yourself:

```bash
./05-verify answers.env
```

Read-only. It checks file ownership and modes, that each cluster resolves, and —
the one that matters — that every node answers a status request through its own
key and forced command.

## Then prove it

`05-verify` passing means the installation answers. It does not mean it works.
Two more things, in this order, on a cluster that carries no traffic if you have
one:

1. `haprion-deploy -c alpha` with the nodes already current. It should skip both
   nodes and change nothing. A run that correctly does nothing tests the ordering
   logic for real.
2. Publish a harmless change and deploy it. Confirm the non-owner is deployed
   first, the owner last, and that the virtual address does not move.

## If a step fails

Every script is safe to run again. A failed installation is resumed by fixing
what it complained about and re-running the same step — nothing needs unpicking
first. The scripts check before they change, and say `ok`, `fixed`, `created` or
`written` per item so a second run tells you what was already right.

## Installing the CLI itself

Steps 1–3 assume the management CLI is installed. It is a separate, versioned,
hash-verified installation under `/opt/haprion`, described in
[`../docs/user-manual.md`](../docs/user-manual.md#part-3--the-versioned-cli-release).

One ordering rule from that section is worth repeating, because getting it
backwards breaks every command rather than one: **install a release before adding
runtime-policy fields that the release introduces.** The policy reader rejects
fields it does not know.
