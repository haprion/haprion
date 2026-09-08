# Installing HAProxy Manager

Five steps. Three run on the management host, one on each node, and the last one
checks your work.

Everything that can be scripted is scripted. What is left for you is the part
that genuinely cannot be automated — pasting public keys onto machines the
management host is not allowed to write to — and step 3 prints those lines ready
to paste.

[`../docs/INSTALLATION.md`](../docs/INSTALLATION.md) explains *why* each step
looks the way it does. This file is what you follow.

**This is a first installation.** Shipping a later change is a different
question — which of the CLI engine, the web platform and the node scripts it
touches, and in what order — and it is answered once in
[Releasing a change](../docs/INSTALLATION.md#releasing-a-change).

## Before you start

You need HAProxy and, if your clusters use a virtual address, keepalived already
installed on the nodes. This project manages HAProxy; it does not install it.

**But it does assume things about how they are configured**, and getting those
wrong does not fail loudly — it quietly makes deploys unsafe. Read
[section 2.1 of the guide](../docs/INSTALLATION.md#21-haproxy-and-keepalived-baseline)
before step 4: both nodes binding the virtual address, both keepalived instances
as `BACKUP` with `nopreempt`, and the `notify_` lines that tell the management
host who owns the address. There is a working starting point in
[`examples/keepalived.conf.example`](examples/keepalived.conf.example), and step
4 checks all three and says so if one is missing.

The management host needs Python 3.12+, the OS PyYAML package, `git`, `rsync`,
`openssh-client` and a `sudo` new enough for no-argument rules. The optional
traffic-log view additionally needs rsyslog's GnuTLS driver on the manager and
nodes (`rsyslog-gnutls` on Debian/Ubuntu).

Copy the answers file and fill it in. It is the only place you make decisions:

```bash
cp answers.example.env answers.env
$EDITOR answers.env
```

Every value in it is an example, including the names. Nothing in this project
depends on what you call things.

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

Renders `clusters.yaml` and `runtime-policy.yaml` from your answers, and creates
the validation-only certificate. Rendering them rather than hand-editing is the
point: what the code reads and what you reviewed cannot drift apart.

It also installs the operator editing policy — the `sudoedit` rules that let the
accounts in `CONFIG_EDITORS` edit `core/haproxy.cfg` and `manual/reservations.yaml`
without a root shell, checked by `visudo` before anything is written. Leave
`CONFIG_EDITORS` empty and the step says it skipped it.

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

Copy this `install` directory to the node and run, on the node:

```bash
sudo ./04-node-prepare answers.env alpha
```

The second argument is the cluster this node belongs to. It creates the service
accounts, the `/etc/haproxy` release layout, the sudo rules, and installs the
node scripts.

Then paste the `authorized_keys` lines for this node from step 3, and add the
keepalived notify lines if the script asked for them.

Repeat for every node.

Traffic logging is installed after the web platform exists. Run platform step
13 on the manager, update the node bundle with this step, then run
`sudo haproxy-traffic-log-trust` on each node. The CA private key stays on the
manager; the node fetches only public trust through its existing read-only
configuration identity.

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

1. `haproxy-deploy -c alpha` with the nodes already current. It should skip both
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
hash-verified installation under `/opt/haproxy-mgmt`, described in
[`../docs/INSTALLATION.md`](../docs/INSTALLATION.md#part-3--the-versioned-cli-release).

One ordering rule from that section is worth repeating, because getting it
backwards breaks every command rather than one: **install a release before adding
runtime-policy fields that the release introduces.** The policy reader rejects
fields it does not know.
