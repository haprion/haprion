# Haprion quickstart

The short way through Haprion: from an installed manager to a site served by your HAProxy pair.
Everything here is done in the web interface. The [user manual](user-manual.md) is the reference
for each step: why it works the way it does, every option, and what to do when something fails.

## What you have

- **A management host** with Haprion installed ([installation](install.md)). It holds the
  configuration, the certificates and the history, and runs the web interface.
- **One or more clusters.** A cluster is two to eight HAProxy nodes sharing one or more virtual
  addresses (VIPs) through keepalived. One node holds a VIP at a time; if it fails, another takes
  it over.
- **Nodes** with the `haprion-node` package installed. The manager never pushes to a node: it
  asks the node to fetch, and the node fetches what has been published for its cluster.

The flow of every change is the same: **edit → save → publish → deploy**. Saving keeps your work;
publishing turns everything saved into a numbered version; deploying brings the nodes to that
version, one node at a time, the VIP holder last.

## 1. Sign in

Open `https://<your manager>` and sign in as `admin` with the password set during installation.
Your browser may ask you to accept the interface's certificate until you replace it
([step 9](#9-replace-the-interfaces-certificate)).

The **Dashboard** shows each cluster: its nodes, who holds the VIP, which version they run, and
whether anything is waiting to go out. Come back here after every change.

## 2. Add your nodes

*Settings → Nodes* lists each cluster's nodes.

1. On the new node, install the node package and run its preparation step
   ([installation, step 4](../install/README.md#step-4--each-node)). It prints an **enrollment
   block**: a few lines starting with `haproxy-node-v1`.
2. In *Settings → Nodes*, choose **Add node** on the cluster, paste the block and press
   **Read block**.
3. Compare the fingerprint the page shows with the one the node printed, enter the name the
   manager reaches the node at, and add it.

The manager checks that it can reach the node before it keeps anything. A new node has no
certificates and no configuration yet; step 6 gives it both.

A new cluster is made the same way, with **Create cluster** under *Settings*.

## 3. Describe the network

*Network* holds each cluster's virtual addresses: the VIPs your sites listen on, and any source
addresses the nodes use towards the servers. Add what you need and press **Save**. Like an
object, the network is saved first and goes out with the next publish.

## 4. Get a certificate

An HTTPS site needs a certificate. Open *Certificates*.

**From Let's Encrypt:** first add a **DNS provider** (your DNS host's API credentials, sealed so
that only the manager's root helper can read them). Then **New certificate**: enter the domain
(for example `www.example.com`, or `*.example.com` for a wildcard), choose the provider, tick
the cluster under **Targets**, and press **Request the certificate**.

**From your own CA:** **Import certificate** takes a PEM or PKCS#12 file, with or without its key.
**New certificate** can also make the key on the manager and give you a signing request
(**Download CSR**) to have signed. A Microsoft CA can be used directly through **NDES providers**.

The certificate is published to the clusters you ticked. Renewal is automatic for Let's Encrypt
and NDES certificates.

## 5. Create a proxy object

An object is one site or service: what listens, and where the traffic goes. *Proxies →
New object*.

**Frontend**

| Field | What to enter |
|---|---|
| Name | a short name, for example `shop` |
| Protocol | `HTTPS`, `HTTP`, `TCP`, `DNS` or `Syslog (UDP)` |
| Hostnames | the names the site answers to, for example `shop.example.com` |
| Port | usually 443 for HTTPS |
| VIP | the address it listens on; the default VIP unless you chose another |
| Certificate | the certificate from step 4 |

**Backend**

| Field | What to enter |
|---|---|
| Servers | `address:port` for each server, for example `192.0.2.10:8080` |
| Balancing | how requests are spread; the default suits most sites |
| Backend TLS | `Plain HTTP`, or HTTPS to the servers |
| Health check | how the nodes decide a server is up |

**Test health check** asks a node to try the check right now, before anything is published.
**Validate the object** checks the whole object. **Save** stores it; the object list shows it as
*New · not published*. **Save as draft** keeps unfinished work that will not be published.

## 6. Publish and deploy

On the **Dashboard**, the cluster's card now offers **Publish & deploy 1 change**. Press it,
read the list of changes, write a short comment, and confirm. One job publishes a new version
and rolls it out: the nodes without the VIP first, the VIP holder last.

A brand-new node needs its certificates before its first configuration: press
**Deploy certificates**, then **Deploy configuration**, on the cluster's card.

Follow the job on *Jobs*. When it ends, the card says every node runs the published version.
Your site now answers on the VIP.

## 7. Day-to-day

**Change something.** Edit the object in *Proxies*, **Save**, then **Publish & deploy** on the
Dashboard. Several saved changes go out together as one version.

**Take a server out for maintenance.** Open the object in *Proxies*, select the server and press
**Drain** (no new connections) or **Maintenance** (out of service). This takes effect at once,
without a deploy, and lasts until you press **Ready**.

**Go back to an earlier version.** *Versions* lists every published version, with a **Diff** of
what each one changed. **Publish this version** on an older one makes it the newest version again;
then **Deploy configuration**. Nothing in the history is lost.

**See what is happening.** *Metrics* shows traffic per site and server, *Traffic logs* the recent
requests, and *WAF logs* what the web application firewall matched, if you use it.

## 8. Back up the nodes

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

## 9. Replace the interface's certificate

*Settings → Interface certificate*: **Upload certificate…**, or **New certificate** to make one
from the certificate registry.

## 10. Add people

*Settings → Users → Add user*. A **Reader** sees everything and changes nothing; an **Admin**
can make changes. To sign in through your organisation's identity provider instead, see
*Settings → OIDC configuration* ([OpenID Connect](user-manual.md#signing-in-through-an-openid-connect-provider)).
Keep the local `admin` account: it is the way in when the provider is down.

## When something goes wrong

Start on the **Dashboard** and on *Jobs*: every operation is a job, and a job that did not end
cleanly says why. An admin also sees the error code, which is what to search the manual for.

| You see | Look at |
|---|---|
| a deploy stopped, or a node is behind | [Configuration and deployment](user-manual.md#configuration-and-deployment) |
| *VIP state: split brain* or *unknown* | [Addresses, and what to call them](user-manual.md#addresses-and-what-to-call-them) |
| a certificate did not issue or renew | [Certificates](user-manual.md#certificates) |
| a server shows as down | [A pool's servers](user-manual.md#a-pools-servers) |
| status looks old | [Jobs and status freshness](user-manual.md#jobs-and-status-freshness) |
| a node is lost | [Restoring a node onto an empty VM](user-manual.md#restoring-a-node-onto-an-empty-vm) |

Status, deploys, versions, certificates, nodes, drain and backups are also commands on the
management host (`haprion-status`, `haprion-deploy`, ...), the way to look closer or to script.
Proxy objects and the network are edited in the interface only. The manual shows each command
beside the page it matches.
