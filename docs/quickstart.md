# Haprion quickstart

The short way through Haprion: from empty machines to a site served by your HAProxy nodes. After the
installation, everything here is done in the web interface. The [user manual](user-manual.md) explains each
step in full: why it works the way it does, every option, and what to do when something fails.

## What you need

- **A manager**: one machine with Ubuntu 26.04 or Debian 13, 2 vCPU and 4 GB of memory. It holds
  the configuration, the certificates and the history, and runs the web interface. It is not in
  the traffic path.
- **Two nodes** with Ubuntu 26.04 or Debian 13, 1 vCPU and 1 GB of memory each - 2 GB with the
  WAF - on one network segment, and a free address on that segment for the virtual address (VIP)
  your sites will answer on. One node holds the VIP at a time; if it fails, the other takes it
  over. One node works too, without failover; a cluster has up to eight.
- A DNS name for the manager that resolves to it, and SSH from the manager to the nodes.

The packages come from the project's apt repository. On the manager and on each node, add its key
and source (`sudo apt install curl` first if the machine has no curl):

On **Ubuntu 26.04**:

```bash
sudo curl -fsSLo /usr/share/keyrings/haprion-archive-keyring.asc \
  https://haprion.github.io/haprion/haprion-archive-keyring.asc
sudo tee /etc/apt/sources.list.d/haprion.sources >/dev/null <<'EOF'
Types: deb
URIs: https://haprion.github.io/haprion/
Suites: ubuntu26.04
Components: main
Signed-By: /usr/share/keyrings/haprion-archive-keyring.asc
EOF
sudo apt update
```

On **Debian 13**:

```bash
sudo curl -fsSLo /usr/share/keyrings/haprion-archive-keyring.asc \
  https://haprion.github.io/haprion/haprion-archive-keyring.asc
sudo tee /etc/apt/sources.list.d/haprion.sources >/dev/null <<'EOF'
Types: deb
URIs: https://haprion.github.io/haprion/
Suites: deb13
Components: main
Signed-By: /usr/share/keyrings/haprion-archive-keyring.asc
EOF
sudo apt update
```

[Installing](install.md#the-packages) has the key's fingerprint and how apt trusts it.
(The same packages are files in each [release](https://github.com/haprion/haprion/releases/latest)
for a machine that cannot reach the repository.)

## 1. Install the manager

On the manager, install the web interface - it brings the rest of the manager with it - and run
the setup:

```bash
sudo apt install haprion-ui
sudo haprion-setup
```

`haprion-setup` first checks what it can before it changes anything – the distribution, the database
server, that the manager's name points to it, that ports 80 and 443 are free – and lists every problem it
finds. Then it installs the manager step by step, one line each, and last asks for a password for the first
administrator, `admin`. If it stops, run it again: it continues where it was.

It uses sensible defaults: a local PostgreSQL database, the machine's own name (`hostname -f`) and
a self-signed certificate for the web interface until you replace it
([step 10](#10-replace-the-interfaces-certificate)). To choose differently, see
[Installing](install.md#1-choose-the-answers-or-keep-the-defaults).

## 2. Install the nodes

On each node:

```bash
sudo apt install haprion-node
```

The node package prepares the machine and prints an **enrollment block**: a line starting with
`haprion-node-v2:`. Keep it at hand; the manager joins the node with it. The node package can also
be downloaded from the manager, on the page the next step opens.

## 3. Set up the first cluster

Open `https://<your manager>` and sign in as `admin`. Your browser may ask you to accept the
interface's certificate until you replace it.

A new installation's **Dashboard** opens with *Getting started*. Its first line, *Nodes and a cluster*,
has **Set up**: it opens *Set up your first cluster*, in five steps:

1. **Name and address**: a cluster ID (for example `edge`) and the VIP; the display name is optional. Press
   **Continue**.
2. **First node**: paste the first node's block and press **Read block**. Compare the host key the
   page shows with the one the node printed, then press the button with the node's name, for
   example **Add node-a**. The cluster is created with it.
3. **Second node**: the same with the second node's block, or **Skip** for a cluster of one.
4. **Deploy**: starts keepalived on the nodes, and the VIP lands on one of them.
5. **Done** says which node holds the VIP and which stands by.

The manager checks that it can reach each node before it keeps anything, and every step is a job
you can follow on *Events → Jobs*. A guide left half-way continues where it was.

## How changes go out

A change to what the nodes serve - proxies, the network, a cluster's logging - goes **edit → save →
publish → deploy**. Saving keeps your work; publishing turns everything saved into a numbered
version; deploying brings the nodes to that version, one node at a time, the VIP holder last.
The rest takes effect at once: users and settings, and what is done to a running server
(drain, maintenance, unblock).

The **Dashboard** shows each cluster: its nodes, who holds the VIP, which version they run, and
whether anything is waiting to go out. Come back here after every change.

## 4. Describe the network

*Network* holds each cluster's virtual addresses: the VIPs your proxies listen on, and any source
addresses the nodes use towards the servers. Add what you need and press **Save**. Like a
proxy, the network is saved first and goes out with the next publish.

## 5. Get a certificate

An HTTPS site needs a certificate. Open *Certificates*.

**From Let's Encrypt:** first open **DNS profiles** and add your DNS host's API credentials with
**New DNS profile**. They are encrypted so that only the manager's root helper can read them. Then
**New certificate**: enter the domain (for example `www.example.com`, or `*.example.com` for a wildcard),
choose the DNS profile, tick the cluster under **Targets**, and press **Request the certificate**.
HTTP-01 is offered only when the runtime policy names a webroot
([ACME configuration](user-manual.md#acme-configuration-and-challenge-routing)); otherwise it is greyed.

**From your own CA:** **Import certificate** takes a PEM or PKCS#12 file, with or without its key.
**New certificate** can also make the key on the manager and give you a signing request
(**Download CSR**) to have signed. A Microsoft CA can be used directly through **NDES providers**.

The certificate is published to the clusters you ticked. Renewal is automatic for Let's Encrypt
and NDES certificates.

## 6. Create a proxy

A proxy is one site or service: what listens, and where the traffic goes. *Proxies →
New proxy*.

**Frontend**

| Field | What to enter |
|---|---|
| Name | a short name, for example `shop` |
| Protocol | `HTTPS`, `HTTP`, `TCP`, `DNS` or `Syslog (UDP)` |
| Hostnames | the names the site answers to, for example `shop.example.com` |
| Port | usually 443 for HTTPS |
| VIP | the address it listens on; the default VIP unless you chose another |
| Certificate | the certificate from step 5 |

**Backend**

| Field | What to enter |
|---|---|
| Servers | `address:port` for each server, for example `192.0.2.10:8080` |
| Balancing | how requests are spread; the default suits most sites |
| Backend TLS | `Plain HTTP`, or HTTPS to the servers |
| Health check | how the nodes decide a server is up |

**Test health check** asks a node to try the check right now, before anything is published.
**Validate the proxy** checks the whole proxy. **Save** stores it; the proxy list shows it as
*New · not published*. **Save as draft** keeps unfinished work that will not be published.

## 7. Publish and deploy

On the **Dashboard**, the cluster's card now offers **Publish & deploy 1 change**. Press it,
read the list of changes, write a short comment, and confirm. One job publishes a new version
and rolls it out: the nodes without the VIP first, the VIP holder last.

Follow the job on *Events → Jobs*. When it ends, the card says every node runs the published version.
Your site now answers on the VIP.

## 8. Day-to-day

**Change something.** Edit the proxy in *Proxies*, **Save**, then **Publish & deploy** on the
Dashboard. Several saved changes go out together as one version.

**Take a server out for maintenance.** Open the proxy in *Proxies*, select the server and press
**Drain** (no new connections) or **Maintenance** (out of service). This takes effect at once,
without a deploy, and lasts until you press **Ready**.

**Go back to an earlier version.** *Versions* lists every published version, with a **Diff** of
what each one changed. **Publish this version** on an older one makes it the newest version again;
then **Deploy configuration**. Nothing in the history is lost.

**Add or remove a node.** *Settings → Nodes & clusters*, then the cluster: under **Add a node**, paste the
new node's block and press **Read block**. The page shows its host key; confirm, and the node is added and
gets its configuration and certificates in the same job. **Remove node** takes one out the same way. A new cluster is made with **Create cluster**
under *Settings*.

**See what is happening.** *Metrics* shows traffic per site and server, *Traffic logs* the recent
requests, and *WAF logs* what the web application firewall matched, if you use it.

## 9. Back up the nodes

Node backups are **off on a new installation**, and the *Node backups* page is not in the menu
until they are turned on. Turn them on under *Settings → Features → Node backups*. Then, on the
*Node backups* page:

1. set a schedule per cluster - for example every day at 04:00 - and how many backups each node
   keeps, and press **Save schedule**;
2. press **Back up now** once, and check that each node shows a new backup.

A backup holds what makes a node that node: its addresses, keys, accounts and keepalived setup.
**Restore** puts it back onto an empty VM or over the node itself, with a preview of every change
first ([restoring a node](user-manual.md#restoring-a-node-onto-an-empty-vm)).

The manager itself is not backed up by Haprion. Back it up like any other server; the web
interface's database is also dumped daily under `/var/lib/haprion-ui/dumps/`.

## 10. Replace the interface's certificate

*Settings → Interface certificate*: **Import** a certificate you have, or **New certificate** to
make one from the certificate registry.

## 11. Add people

*Settings → Users → Add user*. A **Reader** sees everything and changes nothing; an **Admin**
can make changes. To sign in through your organisation's identity provider instead, see
*Settings → Users → OIDC configuration* ([OpenID Connect](user-manual.md#signing-in-through-an-openid-connect-provider)).
Keep the local `admin` account: it is the way in when the provider is down.

## When something goes wrong

Start on the **Dashboard** and on *Events → Jobs*: every operation is a job, and a job that did not end
cleanly says why. An admin also sees the error code, which is what to search the manual for.

| You see | Look at |
|---|---|
| a deploy stopped, or a node is behind | [Configuration and deployment](user-manual.md#configuration-and-deployment) |
| *VIP state: split brain* or *unknown* | [Addresses, and what to call them](user-manual.md#addresses-and-what-to-call-them) |
| a certificate did not issue or renew | [Certificates](user-manual.md#certificates) |
| a server shows as down | [A pool's servers](user-manual.md#a-pools-servers) |
| status looks old | [Jobs and status freshness](user-manual.md#jobs-and-status-freshness) |
| a node is lost | [Restoring a node onto an empty VM](user-manual.md#restoring-a-node-onto-an-empty-vm) |

Everything the interface sets is also a command on the management host (`haprion-status`,
`haprion-objects apply`, `haprion-deploy`, ...), the way to look closer or to script, and
`haprion-export` writes what is set now as the files those commands take.
[Automation from the terminal](user-manual.md#automation-from-the-terminal) shows each command
beside the page it matches.
