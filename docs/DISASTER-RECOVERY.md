# Disaster recovery

> **This is a template, not a procedure that works as shipped.** HAProxy Manager can back up a
> node and restore it onto a machine you provide. Everything around that - where the machine
> comes from, how the management host itself survives, who fails over and when, what runs on a
> node after it is back - belongs to your environment, and only you can decide it. Work through
> this document, write down your answers, and rehearse them before you need them. Using the
> restore at all is optional; a site that rebuilds nodes another way loses nothing by ignoring it.

Names follow the rest of the documentation: the management host is `mgr`, the cluster is `alpha`,
its nodes are `node-a` and `node-b`, and addresses come from RFC 5737. Replace every `<...>` with
your own answer.

## What the product gives you

| Piece | What it does | Reference |
|---|---|---|
| State backup | Archives each node of a cluster, validated before it gets its permanent name, root-only. On a schedule per cluster or on demand, from the terminal or the *Node backups* page. | [INSTALLATION.md 1.3](INSTALLATION.md#13-runtime-policy) |
| Node restore | Puts an archive back as that node - onto an empty VM, or over the node itself - with a preview of every change before anything is written, and a test mode that never touches production addresses. | [INSTALLATION.md 2.6](INSTALLATION.md#26-restoring-a-node-onto-an-empty-vm) |
| Platform backup | A daily dump of the interface's database and a weekly proof that it restores. | [INSTALLATION.md 4.7](INSTALLATION.md#47-backups-and-proving-they-restore) |

What a node archive holds: hostname and hosts, Netplan, keepalived and its address list,
`node.conf`, the node's SSH host keys and pull keys, its accounts and password hashes, the service
accounts' `authorized_keys`, package and service state, and any path you list in
`EXTRA_BACKUP_PATHS`. What it does not hold: the HAProxy configuration and the certificates - a
restored node fetches both from the management host, exactly as a deploy does.

What the product does **not** do: create virtual machines, back up the management host, copy
archives off it, decide when to fail over, or configure what is yours on a node (configuration
management, monitoring agents, your own sudo rules).

## What keeps working without the management host

Nodes pull; nothing is pushed to them. A node serves its installed release on its own, and
keepalived moves the VIP between the pair without asking anyone. Losing the management host is not
a traffic outage. What stops:

| Stops | Consequence | How long you have |
|---|---|---|
| Deploys and publishing | no configuration change reaches a node | until a change is needed |
| Certificate renewal | certificates on the nodes and receivers keep working until they expire | the earliest expiry among them - check it, it is your deadline |
| State backups | the newest archive grows older | until a node needs restoring |
| The interface | no one can see or change anything through it | - |

A node that fails while the management host is down cannot be restored until the management host
is back: the restore runs from it. Restore the management host first.

## When the restore is the wrong tool

**A node you suspect is compromised.** The archive carries the node's SSH host keys and its pull
keys, and a restore always puts them back - there is no option for fresh ones. A restore would hand
the attacker's knowledge of those keys to the new machine. Instead:

1. Remove the node's lines from the management host's pull accounts (one line per node, see
   [INSTALLATION.md 1.6](INSTALLATION.md#16-ssh-identities)), so its keys fetch nothing.
2. Install the replacement as a new node ([Part 2](INSTALLATION.md#part-2--the-nodes)): new keys,
   generated on it, and their public halves added on the management host.
3. Replace the certificates the node carried. It held their private keys.
4. Change the passwords of accounts that had one on the node; the archive and the node held their
   hashes.

**No usable archive.** Archives are kept for a bounded number of runs per node (14 unless the
*Node backups* page sets another count), and every one may postdate the fault you are recovering
from. Without an archive from before it, install a new node as above.

## Your answers

### 1. Where a replacement node comes from

The restore needs an empty Ubuntu 26.04 or Debian 13 machine installed from its cloud image, one
network interface named like the node's, a temporary address the management host can reach, and
an administrator account with `sudo`.

- Hypervisor or platform: `<...>`
- Image or template, and who keeps it current: `<...>`
- How a VM is created - by hand, by your own automation, by an API: `<...>`
- Temporary address for a new VM, per network (DHCP or static): `<...>`
- Can you snapshot the empty VM before the restore, so a failed attempt is a rollback: `<...>`

The old node and the restored one must never run at the same time: they would carry the same
address and host keys. Decide how the old one is taken out of service: `<...>`

The restore also needs, and these are firewall and mirror questions rather than product ones:

- SSH from the management host to the temporary address: `<...>`
- SSH from the node's own address to the management host, for its pulls: `<...>`
- Package repositories reachable from the new VM - the distribution's and HAProxy's; a site without
  internet access needs a mirror: `<...>`

### 2. How the management host survives

Everything the nodes fetch comes from the management host. A node can be rebuilt from its archive;
the management host cannot be rebuilt from anything the product keeps.

- How the management host is backed up (VM image, file backup, ...): `<...>`
- How often, and how long it is kept: `<...>`
- Where the node archives (`backup_root` in the runtime policy) are copied off the host: `<...>`
- How that copy is protected. An archive holds password hashes and private SSH keys; a copy needs
  the same protection as the management host itself: `<...>`
- How old may the newest backup of the management host be, and of each node - and how long may a
  cluster run on one node before the second is back: `<...>`
- Where this document is kept. Not only on the management host: it is needed when that host is
  gone: `<...>`

These exist only on the management host. Losing them is not recoverable from the nodes:

| What | Where (defaults) | Without it |
|---|---|---|
| Cluster configuration history and drafts | the configuration repositories (1.2) | every change since the last copy is gone |
| ACME account key | `/etc/letsencrypt/accounts` | certificates can be issued again, as new certificates, under a new account |
| The DNS profile private key | `secrets/dns-profile-keys/` under the platform root (1.4.5) | every stored DNS and NDES profile is unreadable and must be registered again |
| Imported and NDES-enrolled keys | `/etc/haproxy-manager/certificates/<id>/` | those certificates must be replaced, and every receiver fetches the new ones |
| The management host's SSH identities | the root-owned keys the runtime policy names (1.6) | every node's `authorized_keys` must be rewritten by hand |
| The interface's database dumps | the platform backup directory (4.7) | accounts, history and job records are gone |

After restoring the management host, before restoring any node:

- Check the configuration repositories. A restore that put the history and the draft on different
  paths leaves a link pointing at the old one; `haproxy-config-status -c <cluster>` reports it, and
  `git worktree repair` fixes it.
- Check the CLI release. A node restore prepares the node with the node bundle of the management
  host's own release, and a host restored from an older backup would give the restored node older
  scripts than its neighbour. `/opt/haproxy-mgmt/current/INSTALLATION.json` names the release's
  bundle (`node_bundle.commit`); it must be the one the nodes were last prepared with, so note that
  at every node roll-out: `<...>`. Node status cannot tell you: it compares a node's scripts with
  that node's own record. After a restore, `sha256sum /usr/local/sbin/haproxy-*` on both nodes
  should match.

### 3. Failing over

- Who may fail a cluster over, and how they are reached: `<...>`
- How traffic is moved off a node before it is replaced (stopping keepalived on it moves the VIP to
  its neighbour): `<...>`
- How you confirm the neighbour carries the traffic before anything is torn down: `<...>`

Both nodes run keepalived as `BACKUP` with `nopreempt`, so a restored node does not take the VIP
back. That is the intended result, not a fault.

**Both nodes lost.** Restore one at a time. The first has no neighbour: once keepalived starts and
hears no one, it takes the VIP, and traffic returns with it. Confirm that before restoring the
second, which then comes up as `BACKUP`.

### 4. After a node is back

- Configuration management run: `<...>`
- Monitoring agent and its registration: `<...>`
- Anything else a new machine gets in your environment: `<...>`
- Take a state backup of the cluster, so the next restore starts from the restored node.

### 5. Rehearsal

A plan that has not been run is a guess. The restore's test mode (`--test`) brings a copy of a node
up under a test hostname, address and VIP, with keepalived masked, next to the production pair.

- How often you rehearse, and on which cluster: `<...>`
- Where the result is written down: `<...>`

## Checklist for a real recovery

- [ ] The management host works, or has been restored first, and its CLI release is the one the
      nodes run (section 2).
- [ ] The node is not suspected compromised ([When the restore is the wrong tool](#when-the-restore-is-the-wrong-tool)).
- [ ] Traffic is on the neighbour, and the neighbour is healthy (`haproxy-status -c <cluster>`).
- [ ] A recent archive of the lost node exists (`haproxy-list-backups --node <node>`), and you have
      chosen which one.
- [ ] The old node is off and cannot come back by itself.
- [ ] An empty VM with a temporary address is running (section 1).
- [ ] `haproxy-node-restore prepare`, paste the line on the VM, `preview`: read every line of the plan.
- [ ] `run`, confirmed with the node's name.
- [ ] `haproxy-status -c <cluster>`: the node is `BACKUP` and runs the published version.
- [ ] Your own steps from section 4.
- [ ] A state backup of the cluster.
