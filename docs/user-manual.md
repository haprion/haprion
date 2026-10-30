# User manual

This manual is about using and running an installed Haprion environment, through the web interface and
through the command-line engine, which has the final say. For prerequisites, installation and environment
configuration, see the [installation guide](install.md).

Every name in this document is made up. Substitute your own: the management host is `mgr`, the clusters
are `alpha` and `beta`, and each cluster has two nodes, `node-a` and `node-b`. Addresses come from the
documentation ranges in RFC 5737. Nothing here depends on those names. If a step only works with the
names used below, that is a bug in the software, not in this guide.

## Contents

- [Configuration and deployment](#configuration-and-deployment)
  - [Words used here](#words-used-here)
  - [An http or https object, field by field](#an-http-or-https-object-field-by-field)
  - [A whole subdomain](#a-whole-subdomain)
  - [A pool's servers](#a-pools-servers)
  - [A pool over HTTPS](#a-pool-over-https)
  - [The client's address on a tcp pool](#the-clients-address-on-a-tcp-pool)
  - [A slow server](#a-slow-server)
  - [Drain and maintenance](#drain-and-maintenance)
  - [Addresses, and what to call them](#addresses-and-what-to-call-them)
  - [Ports the cluster takes itself](#ports-the-cluster-takes-itself)
  - [HTTP/3](#http3)
  - [DNS objects](#dns-objects)
  - [Syslog objects](#syslog-objects)
- [Accounts and signing in](#accounts-and-signing-in)
  - [What the two roles see](#what-the-two-roles-see)
  - [How a session works](#how-a-session-works)
  - [The throttle](#the-throttle)
  - [Signing in through an OpenID Connect provider](#signing-in-through-an-openid-connect-provider)
- [Features and advanced configuration](#features-and-advanced-configuration)
  - [What the advanced layer does, line by line](#what-the-advanced-layer-does-line-by-line)
- [Access rules](#access-rules)
- [Dynamic blocking](#dynamic-blocking)
- [The WAF engine](#the-waf-engine)
- [Certificates](#certificates)
  - [Publishing certificates](#publishing-certificates)
  - [Issuing a certificate](#issuing-a-certificate)
  - [The life of a profile](#the-life-of-a-profile)
  - [Deleting a certificate](#deleting-a-certificate)
  - [Importing a certificate](#importing-a-certificate)
  - [Enrolling and renewing through NDES](#enrolling-and-renewing-through-ndes)
  - [Certificates installed by hand](#certificates-installed-by-hand)
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
  - [Getting started](#getting-started)
  - [Needs attention, and external monitoring](#needs-attention-and-external-monitoring)
  - [Events: jobs, the nodes and the audit record](#events-jobs-the-nodes-and-the-audit-record)
  - [How often status is refreshed](#how-often-status-is-refreshed)
  - [The worker](#the-worker)
- [Automation from the terminal](#automation-from-the-terminal)
  - [Automating with Ansible](#automating-with-ansible)
- [Maintenance](#maintenance)
  - [Keeping HAProxy current](#keeping-haproxy-current)
  - [Updating Haprion](#updating-haprion)
  - [CLI rollback](#cli-rollback)
  - [Rolling a release back](#rolling-a-release-back)
- [What it does not do](#what-it-does-not-do)
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

A change goes through four stages before visitors see it:

1. **Draft.** You edit an object in the editor. A draft is unfinished work and is never published.
2. **Saved change.** You save it. The change is stored and goes out with the next publish.
3. **Version.** You publish. Publishing makes a numbered release of the cluster's configuration that
   never changes afterwards.
4. **Deployed.** You deploy. The nodes are brought to that release.

Publishing and deploying are separate steps. The dashboard's *Publish & deploy* button runs both in one
job (below).

**Drafts and saved changes.** The editor has two buttons for this. *Save as draft* keeps the work and
stays in the editor. *Save* stores the change and returns to the proxy list, where the row says *New*,
*Changed*, *Renamed* or *Removal* · *not published* until the change is published. You may start a draft
on top of a saved change; the saved change stays in.

Three actions save directly, without a draft: the advanced config dialog, a WAF exception and *Remove*.
They are refused while the object has a draft.

A saved rename remembers the published name it replaces, so the publish that carries it also removes the
old name.

The network description and a cluster's logs and metrics settings are saved the same way, as one document
per cluster each. The page shows the saved document, and *Discard the changes* drops it. The object editor
checks objects against the saved network, so an object may name a VIP that the same unpublished change
adds. The confirmation for the default VIP is asked when the network is saved.

**Publishing.** Saved changes are published from *Versions*. Each cluster lists what is saved there and by
whom. One publish takes all of it, with one comment, as one version - up to 64 objects (the job is called
`changes_publish`).

Sometimes a publish changes an object after your change to it was saved. Your change then holds back the
cluster's whole list: its row says *Changed since it was saved*. *Open* takes you to the editor, which
lists what the publish changed, field by field - before and now. Choose *Save over them* to keep your
version, or *Discard the changes* (*Discard the draft* for a draft) to drop it. A publish that changed
other objects does not hold anything back.

**Going back.** *Publish this version* on an older version makes its configuration the newest version
again. The cluster keeps the nodes it has now. Their keepalived settings, shared counters and exporter
addresses are made again for today's nodes, so a node added since stays in service. The version's WAF
rule set and country networks come back as it ran them, not as installed today.

**Publish & deploy.** When a cluster has saved changes, its dashboard card offers *Publish & deploy N
changes* instead of *Deploy configuration*. A dialog lists the changes and takes the comment. One job then
publishes and deploys: the worker deploys the version the publish recorded. The job ends when the deploy
ends, and keeps the publish's answer beside it.

**Deploying.** On the dashboard, *Deploy certificates* installs the certificates and *Deploy configuration*
installs the published configuration. A deploy skips nodes that already run the release.

A rollout deploys the nodes in an order that protects the VIP:

- First the nodes that do not own the VIP, and the owner last. This holds even when another node cannot be
  read.
- A node whose ownership is unknown goes between the two.
- A node whose keepalived is not running - one just added or added back - goes after the owner. By then
  every other node has it as a peer, so it starts as a standby instead of taking the VIP because it hears
  nobody.
- If two nodes both report the VIP, the rollout stops before anything is changed, whatever else could not
  be read. No override lets it past.

A node counts as running a release once HAProxy has reloaded with it, not once the files are in place.
Until the reload, the node marks the switch in `/run/haprion-pull-deploy.pending`, and its status reports
the release HAProxy still runs. If a run is stopped in between, the next deploy finishes the reload. Each
node gets five minutes to answer a deploy. A node that does not answer is a failed step, and its status
decides which release it runs.

At the terminal, inspect the configuration and the nodes before deploying:

```bash
haprion-config-status -c alpha
haprion-status -c alpha
haprion-objects -c alpha
haprion-objects -c alpha --show <name>
haprion-deploy -c alpha
```

As in the interface, a deploy skips nodes that are already current. A node that answered its deploy and
then cannot be read is waited for, up to 30 seconds by the clock; one that stays silent stops the rollout before the
next node is touched (`partial`, `node_lost_after_deploy`). Cluster and network configuration is
described under [Cluster definitions](#cluster-definitions) in the environment reference.

**Objects from files**, for automation. You can keep objects as files and apply them from the command line.
Each file holds one object's document, in the form the interface stores
(`haprion-objects -c alpha --show <name>` prints one). The file name is the object name: `shop.yaml` is
the object `shop`.

- `apply` publishes whatever differs from what is stored, as one version, and says what it did. It works
  against the version it read. Applying the same files again changes nothing.
- An object that no file names is left alone, unless `--prune` is given.
- A directory with no object files changes nothing. With `--prune` it is refused, since it would remove
  every object.
- `--check` shows the difference and publishes nothing.
- `--json` answers with `changed`.
- Deploying stays a step of its own.

```bash
sudo haprion-objects apply -c alpha objects/ --check
sudo haprion-objects apply -c alpha objects/ -m "Add the shop"
sudo haprion-objects remove -c alpha staging
haprion-deploy -c alpha
```

More than 64 changed objects are published in batches of 64, each its own version. Every file is checked
by the same model the publish uses before anything is asked of the manager, so a mistake is reported with
the name of its file.

**Say what an object is for.** *Description*, in the form's *Frontend* part, is one line of at most 200
characters: what the service is and who to ask about it. The object's page shows it in the *Stored proxy*
card as *Description:*, and the search finds it. In YAML it is `description:`, beside `name:`. Nothing in
the generated HAProxy configuration reads it, so a publish that changes only the description deploys the
same configuration.

### Words used here

One word per thing, the same on every page:

| Word | Means | Where |
|---|---|---|
| proxy | one site or service: what listens, and where the traffic goes; the command line and YAML call it an *object* (`haprion-objects`) | *Proxies* |
| draft | unfinished work, never published | the editor |
| saved | a change stored here and not yet published | *Versions*, the proxy list (*· not published*) |
| version | a numbered, unchangeable configuration made by a publish | *Versions*, the dashboard's *Published version* |
| Behind | a cluster or node that does not run the published version; *Deploy configuration* is green there | the dashboard, *Network* |
| Unknown version | a node on a version past the published one, which this manager has no record of - as after the manager was restored from older state. A deploy puts the published, older version on it; `haprion-status` says *AHEAD* | the dashboard, *Needs attention* |
| Older package | a node whose packages are older than another node's | the dashboard's *Runtime* cell |
| Older node package | a node whose `haprion-node` is older than the one the manager's release carries | the dashboard's *Runtime* cell, *Needs attention* |
| Newer node package | a node whose `haprion-node` is newer than the one the manager's release carries | the dashboard's *Runtime* cell, *Needs attention* |
| Node package not configured | a node whose `haprion-node` install script failed, or whose unpacking stopped; `sudo dpkg --configure -a` on the node finishes it, or `sudo apt install --reinstall haprion-node` | the dashboard's *Runtime* cell, *Needs attention* |
| Reconfigured · deploy to activate | a published change to a proxy the nodes do not serve yet | *Proxies*, *Network* |
| Waiting for deploy | how far a proxy's newest version has come | the proxy's page |
| DNS profile, NDES profile | the credentials a certificate is requested with; *provider* is the company | *Certificates* |
| receiver | a host outside the clusters that fetches its certificates from here | *Certificates → Receivers* |
| Installed by hand | a certificate exported with its key, for a device no receiver reaches | *New certificate*, *Certificates* |

### An http or https object, field by field

The editor's form has three parts: *Frontend*, *Backend* and *Health check*. It shows only the fields that
mean something for the chosen *Protocol*. *Certificate* and *TLS and HSTS* appear for https only, and the
fields of other protocols are hidden.

What an object cannot do without is always on screen. The rest sits in folded groups, closed when the page
opens. Each group has one line that sums up what it holds. When you change a group's fields, its line says
*Changed — validate to see the result* until *Validate the proxy* writes the line anew.

Below are the fields in the order the form shows them.

**Frontend.**

- *Name* is lowercase letters, digits, hyphens and underscores, starting with a letter. It is at most 40
  characters and unique in the cluster.
- *Hostnames* takes several names separated by commas. One of them may be a whole subdomain
  ([A whole subdomain](#a-whole-subdomain)).
- *VIP* is the cluster's default VIP unless you choose another. http and https are served on the cluster's
  own ports, so a site names no port.
- *Description* is the one line described above.

*Certificate* lists the certificates the cluster carries ([Certificates](#certificates)). An https object
is refused without one. When the management host can read the certificate, a publish refuses a hostname
the certificate does not cover.

**TLS and HSTS** (https only):

- *Specific TLS for this proxy only* is *Use VIP settings* unless the site needs its own TLS versions:
  *TLS 1.2 only*, *TLS 1.2 and 1.3* or *TLS 1.3 only*. The versions are chosen by the name the client asks
  for in the TLS handshake (SNI), so the site can still share its VIP with sites that use other versions.
- *Redirect plain HTTP to HTTPS (301)* also puts the site on the VIP's http port. Every plain request there
  is answered with a 301 to the same address over https.
- *Send HSTS* adds the `Strict-Transport-Security` header to every answer for the site's names over
  https - also the answers HAProxy makes itself: a refusal, a 429 from a rate limit, the maintenance page,
  a redirect, a 503 when no server answers. *HSTS lifetime, seconds* is one year
  (31536000) unless changed, and at most two years. *…including subdomains* extends it to every name under
  the site's.

  HSTS cannot be taken back by changing the configuration. For its whole lifetime, a browser that has seen
  it refuses plain http to the name and offers no way past a certificate warning.

**Access**, **Dynamic blocking** and **WAF** decide who is served.

- *Reachable from* takes groups from the *Network* page, and addresses, ranges or countries. Anyone else
  is refused.
- *Rate limit* is the number of requests one source address may make within *Rate window* (`10s` when
  empty). Requests over the limit are answered 429; the rest are served.
- *Denied*, *Max request body* and *Deny rules* are described in [Access rules](#access-rules).
- Blocking is described in [Dynamic blocking](#dynamic-blocking).
- The WAF group is shown where the engine is offered or already in use. It is described in
  [The WAF engine](#the-waf-engine).

**Maintenance page.** *Out of service for maintenance* takes the whole site out on purpose. Every request
for its hostnames is answered 503 with the text in *What visitors are told instead*, which is required
while the box is ticked. The answer is not cached.

The object, its routing and its pool stay as they are, and its servers go on being health-checked. Publish
it with the box unticked, and the site is back with nothing to rebuild. This is the site's own switch,
published and deployed like any other field. To take one server out of its pool instead, use the
*Maintenance* button on the object's *Servers* card ([Drain and maintenance](#drain-and-maintenance)).

*What visitors are told when no server answers* replaces HAProxy's own text on a 502, 503 or 504. These are
the answers a site's own error page cannot give, because they arise when nothing behind the proxy answers.
Empty keeps HAProxy's text.

Both messages are one line of at most 200 characters. They may contain the letters A-Z and a-z, digits,
spaces and the characters `% # . , : ; ! ? ( ) ' / @ + $ -`, and nothing else - so no double quotes, no
backslashes and no letters such as å, ä or é. `%URL%` becomes the site's first exact hostname. No other
`%...%` is accepted.

**Backend.** *Backend name* is the object's name when empty. It must be unique in the cluster, and it is
the name metrics use. *Servers* is one server per line, with weights and backup servers as described in
[A pool's servers](#a-pools-servers).

*Balancing* decides which server gets each new connection. It is `roundrobin` unless changed:

- `roundrobin` takes the servers in turn, by weight. `static-rr` does the same, but weights cannot be
  changed while it runs.
- `leastconn` picks the server with the fewest connections. It suits long-lived sessions rather than short
  requests.
- `first` fills one server before using the next. It ignores weights, so a pool with weights refuses it.
  It only means something together with *Connections per server*.
- `source` hashes the client's address and `uri` the request path, so one client or one URL keeps one
  server. `random` picks at random.
- `hdr` and `url_param` hash the value of one request header or one query parameter, named in *Balancing
  key*. The key is required with these two and refused with the others.

**Connections.**

- *Source address* is the address the pool is reached from. It is the VIP's own unless another is named
  ([Addresses, and what to call them](#addresses-and-what-to-call-them)).
- *Backend TLS* and *CA* are described in [A pool over HTTPS](#a-pool-over-https). With HTTPS chosen,
  *Specific TLS for this backend only* is *Use default settings (TLS 1.2 and 1.3)*, *TLS 1.3 only*, or
  *TLS 1.1 and up — for old equipment*.
- *Session cookie* keeps one visitor on one server. HAProxy adds the cookie to its answers and takes it off
  each request before the server sees it. It also marks the answer so that a shared cache does not hand one
  visitor's cookie to another. Empty means no persistence. The field suggests `hap_<name>`; a name is
  letters, digits, `_` and `-`, at most 32 characters. Unlike `source` balancing, the cookie follows the
  session rather than the address, so visitors behind one NAT address are still spread over the servers.
- *Connections per server*, 1 to 65535, is how many connections one server is given at once. The rest wait
  in the pool's queue for up to 5 seconds, instead of making every server slow at once.
- *Server timeout* is described in [A slow server](#a-slow-server).
- *Slow start* is for a server that comes back after it was seen as failed. Over the time given, such as
  `30s`, its share of the traffic is raised step by step to the full share, so a cold server is not knocked
  over again. It never applies when HAProxy starts. It needs a health check, and must be longer than the
  check interval, since the ramp moves one step per check. The hint under the field shows the current
  interval.

**Redirect.** *Path*, *Match*, *To* and *Status* make one redirect. A request for *Path* is answered with
*To* and never reaches the backend.

- *To* is an absolute `http://` or `https://` URL. It replaces the whole address.
- *Match* is `prefix` (the path and everything under it) or `exact`. A redirect of `/` itself must be
  `exact`, so the backend keeps the rest of the site.
- *Status* is 301 unless changed; 302, 303, 307 and 308 are the others. On a 301 or 302 a browser may turn a
  redirected POST into a GET; on a 307 or 308 it does not.
- *Path* and *To* go together. *Status* is greyed out until both are written.

**Headers.** *Request headers* are changed on the way to the servers, and *Response headers* on the way
back. Write one per line:

- `Name: value` sets a header, replacing any with that name.
- `+Name: value` adds one more header with that name, beside any the traffic already carries.
- `-Name` removes every header with that name.

One name cannot appear in two of these three forms, or twice in one of them. A value is at most 200 characters, without a single
quote. `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Host` belong to the cluster, which writes
them from what the connection actually was. They are refused here.

**Health check.** *Type* `disabled` means no check. HAProxy then treats every server as always up, sends a
server that has gone its share of the traffic all the same, and the object has no status lamp.

A new object's form arrives with an `http` check of `/` that accepts `200-499`. That proves the web server
answers, without a 401 or 404 on `/` marking the pool down at its first deploy. The form adjusts this
suggestion as you go, as long as *Type* is still `disabled` or still the suggestion:

- Changing *Protocol* makes the suggestion again for the new protocol: `https` when *Backend TLS* is HTTPS,
  `tcp` for a tcp object.
- Changing *Backend TLS* switches an untouched suggestion between `http` and `https`.

A type somebody chose stays. The types:

- `http` and `https` send a GET for *Path* and expect *Expected status*: one status or a range, such as
  `204` or `200-299`. When empty, any 2xx or 3xx counts. Point the check at the application's health page
  and narrow the range if it has one: a 302 to a login page is also what a broken application answers.
  `https` speaks TLS to the check even on a plain pool, and `http` speaks plain to a pool reached over
  HTTPS - for a plaintext management port. A check over TLS does not judge the certificate.
- `tcp` opens a connection, and `tcp, TLS handshake` completes a TLS handshake. *Send* and *Expect* turn
  either into a short exchange: *Send* is written once the connection is up, and the answer must contain
  *Expect*. The two belong together. Each is one short word of at most 64 characters - letters, digits and
  `. _ : / + = @ -` - with `\r` and `\n` as the only escapes. This suits a line protocol that answers once a
  line has ended, such as `PING\r\n` to a Redis server.

*Check details* holds three fields:

- *Port* is the server's own port when empty. Set it for a health endpoint on a management port.
- *Host header* is for a backend that serves several names. Without it, such a backend may answer the check
  with a 404 or a redirect and look dead.
- *Expected body* is text the answer must contain as well as the status. It is written the same way as
  *Expect*.

*Timing* holds:

- *Check interval* (`2s`).
- *Checks to rise*: 2 good answers before a server is used again.
- *Checks to fall*: 3 failures before it is taken out.
- *Fast interval* and *Down interval* (`1s` each): the interval while a server is going up or down, and
  while it is down.

Rise and fall are 1 to 10. Intervals are written as `500ms`, `5s` or `1m`.

*Test health check*, in the editor, asks the node holding the object's address to try the check as it
stands on screen, once, now. *What the nodes report* lists each node's verdict on each server. The rows
the test tried are marked *tested*, and pointing at *Last check* shows HAProxy's own code.

### A whole subdomain

One hostname may be `*.apps.example.com`. It covers every name exactly one label under `apps.example.com`,
as a wildcard certificate does: `shop.apps.example.com`, but not `apps.example.com` and not
`a.b.apps.example.com`.

- Each object may have one such name, beside exact names if wanted. Two objects cannot claim the same one.
- A name that another object claims exactly belongs wholly to that object. Its requests go there and meet
  only that object's rules. The subdomain object's page lists the name under *Answered elsewhere*.
- A name reserved in `manual/reservations.yaml` under the subdomain is refused at publish.
- Over https, the certificate must name the subdomain itself (`*.apps.example.com` in its SAN). ACME issues
  one over DNS-01; NDES and an import work as for any name.

### A pool's servers

The *Servers* field takes one `address:port` or `hostname:port` per line. Up to two words may follow it, in
either order:

```
198.51.100.10:8080 weight 50
198.51.100.11:8080
198.51.100.12:8080 backup
```

- **`weight N`**, 1 to 256, is the server's share of the pool's traffic compared with the others.
  HAProxy's default is 1, so a pool written without weights shares evenly. A pool balanced with `first`
  refuses weights, since that algorithm ignores them. DNS and syslog pools refuse them too, because their
  engines have none. A weight of 0 is refused: that is a drain, something done to a server for a while, not
  a setting that should outlive the reason for it ([Drain and maintenance](#drain-and-maintenance)).
  Changing a weight keeps the server's counters. Changing its address or port starts it as a new server.
- **`backup`** makes it a backup server: it gets no traffic while any other server is up, and all of it
  when none is. A pool cannot consist of backup servers only.

The stored object spells both out under the server (`weight: 50`, `backup: true`).

**Host names.** HAProxy on each node resolves a host name, and a name a node cannot resolve stops the
deploy on that node. The editor and the publish therefore look each name up with the management host's
resolver. When it gives no address they warn - *app.example.com cannot be resolved from the manager* - but
never refuse, since the nodes may resolve names the manager cannot. After such a warning, *Save* stays in
the editor so the warning is seen, and `haprion-objects apply` prints it as a `WARNING:` line.

### A pool over HTTPS

*Backend TLS* says how the pool is reached:

- **HTTPS, verify the certificate** checks the server's certificate against the node's own trust store,
  the one the operating system keeps (`ca-file @system-ca`). Use it for a certificate from a public CA.
- **HTTPS, verify against a CA** checks it against a CA certificate that was imported under *Certificates*
  and sent to the cluster ([Importing a certificate](#importing-a-certificate)). Use it for a service whose
  certificate your organisation's own CA issued. The node's trust store is not touched: the CA file is read
  by the pools that name it and by nothing else.
- **HTTPS, do not verify** encrypts and checks nothing.

The form's server test trusts the same CA as the node's check does. The test runs on the node without
access to the node's certificate directory, so the manager sends its copy of the CA along with the test.
On the command line, `haprion-probe ... --tls --verify --ca <id>` does the same.

Both verifying choices need the servers named by hostname rather than address. The name is sent as SNI,
and the certificate is checked against it. A pool that names a CA its cluster does not carry is refused at
publish, with the CA's name. In the stored object:

```yaml
backends:
  app:
    tls:
      verify: ca
      ca: corp-root
```

### The client's address on a tcp pool

An http pool learns who the client is from the `X-Forwarded-For` header. A tcp pool sees only the node's
address, unless it is sent a PROXY protocol header - a short preamble that carries the client's address.

To send it, tick *Send the client address (PROXY protocol v2)* in the pool's group. The stored object then
says `proxy_protocol: v2`, and every server line gets `send-proxy-v2`. The health check sends the header
too (`check-send-proxy`), because a server that expects one closes a connection that opens without it.

The servers must be set up to read the header first - a mail server, a database proxy, another HAProxy with
`accept-proxy`. Otherwise every connection is refused.

### A slow server

HAProxy waits 50 seconds for a server to answer, and then gives the visitor a 504. The wait is for silence,
not for the whole answer. A download that streams for an hour is never cut. A report that takes two minutes
to compute before its first byte is.

*Server timeout*, in the pool's group, gives one object a longer wait, up to 99 minutes. In the stored
object it is `server_timeout: 5m`; in the generated configuration, `timeout server` in the object's own
backend. Empty means the 50 seconds. Nothing shared changes: the visitor's own timeout on the VIP does not
run while the visitor is waiting for the server.

A longer wait is also how long a server that has hung keeps its connections. Set it on the object that
needs it rather than on all of them.

### Drain and maintenance

Taking a server out for a while - to patch or replace it - is not a change to the object. It is set
directly on the nodes, on every node of the cluster at once.

On the object's page, the **Servers** card lists each server with its state on each node, its open
sessions and its weight. Tick the servers and press **Drain**, **Maintenance** or **Ready**. The same from
the command line - the command runs its helper through sudo itself, so no `sudo` is typed in front:

```
haprion-server-state -c alpha -o shop drain 198.51.100.10:8080
haprion-server-state -c alpha -o shop ready 198.51.100.10:8080
```

- **`drain`** takes the server out of load balancing. A visitor whose session cookie names it still reaches
  it, and it is still health-checked.
- **`maint`** sends it nothing new at all, and stops its health checks.
- **`ready`** puts it back.

Requests already in flight finish in both cases; nothing is cut off.

Write a server as on its line in the editor, `address:port`. If one object has the same server in two
pools, name the pool first: `api/198.51.100.10:8080`. Every server is looked up in the object's newest
version before any node is asked, so a request with one wrong server in it changes nothing.

**How long the state lasts.** Each node keeps the state through deploys, certificate rollouts and restarts,
until the server is set to `ready` again. A deploy does not quietly put a drained server back. A server
that has been given a new address or port is a new server, and starts ready.

**When a node does not answer.** That node is named, and the result is `PARTIAL`: the other node holds the
state, and running the same command again finishes the job. A node that does not run the server yet -
published but not deployed - says so.

**What the card shows.** Each node's own answer: `DRAIN` or `MAINT` for a server somebody took out,
otherwise `UP` or `DOWN` from the health check.

- An object that leaves from a source address is checked only by the node holding the VIP, since only that
  node has the address. The other node reads `STANDBY`, as the dashboard calls it.
- While the nodes are not yet on the object's newest version, the states are not shown. A pool edited
  since the deploy may have its servers in another order.
- A node may fail to put back a drain or maintenance after a reload or a start - its HAProxy did not
  answer in time, or the admin socket is missing. It reports this, and the card reads `DRAIN LOST` or
  `MAINT LOST` in red on that node: the server takes traffic there. Press the button again; the deploy
  itself is not undone.

A drained server is not a fault. The *Proxies* list does not turn amber for it; point at the lamp to see
how many servers are drained or in maintenance. Each cluster's dashboard card says how many servers are in
drain or maintenance, so one left that way is not forgotten. An admin's *Operations* row names the objects
- three of them, then how many more - each linked to its *Servers* card. A state the node keeps but HAProxy
does not hold is not counted there, since that server takes traffic; the card says it in red.

### Addresses, and what to call them

If you come from a NetScaler or an F5, three addresses are worth naming first, because only one of them
has a word that every product agrees on.

| What it is | Here, and in HAProxy | In keepalived | NetScaler | F5 |
|---|---|---|---|---|
| the address clients connect to | `vip`, bound by a frontend | `virtual_ipaddress` | VIP | virtual server address |
| the address we connect out from | `source`, per backend | `virtual_ipaddress`, same block | SNIP | SNAT address / self IP |
| the node's own fixed address | not named; it is just the host | `unicast_src_ip` | NSIP | management address |

Two things follow from the middle row, and both matter more than the words.

**Keepalived has no separate idea of an outgoing address.** To keepalived, the VIP and the source address
are both entries in the same `virtual_ipaddress` block. They belong in the same block, because only the
node that currently holds an address answers for it. A source address that does not move together with
the VIP sends the servers' replies to a node that no longer carries the traffic. That failure shows up at
failover, not when you configure it.

**HAProxy sets the source per backend, not per listener.** A site may therefore leave from a different
address than the one it arrived on. Each VIP still names a default source, so the normal case needs no
setting. The [`sources` table](#optional-per-cluster-sections) is there for the exception.

`unicast_src_ip` is spelled out in full everywhere in this document. It is the node's own address, and it
never moves. Confusing it with a source address gives a cluster that looks correct and cannot fail over.

**What uses an address.** *Network* lists, beside each VIP, source address and reachable-from group, the
objects that use it - three by name, then how many more. A change to a shared address or group therefore
shows what it touches before it is saved.

- A VIP counts the objects served on it.
- A source address counts the objects that leave from it, whether as their VIP's source or named.
- A group counts the objects that name it as a source anywhere: who may reach them, who is refused, an
  access rule, or the exempt list of dynamic blocking.

*not used* means nothing names the value. A dash means the objects could not be read.

### Ports the cluster takes itself

A VIP carries its objects' ports and nothing else. What the cluster runs for itself listens on the nodes'
own addresses or on loopback. A tcp, DNS or syslog object may therefore take any port its VIP does not
already serve. A publish refuses only these:

| Port | Why |
|---|---|
| 80 and 443 | on a VIP that serves http or https objects |
| a port another object takes on the same VIP | one address and port is bound once |
| a port `manual/reservations.yaml` reserves | the handwritten half binds it |
| a port another program holds on every address of a node | it holds the VIP's port too |

The Prometheus exporter, dnsdist's statistics (9521), the shared counters' port and the WAF engine (9520,
loopback) never take a VIP's port.

The last row of the table comes from the nodes themselves. A publish that changes objects or the network
reads each node's status. The refusal names the program and the node - *agent listens on main port
6556/tcp, which cmk-agent-ctl holds on every address of lb-01*. Have the program listen on the node's own
address, or choose another port. Two programs cannot take an address, and the refusal says what to do
instead:

- the Checkmk agent (`cmk-agent-ctl`) can only move to another port: `pull_port` in
  `/var/lib/cmk-agent/cmk-agent-ctl.toml`;
- `systemd-resolved` holds 5355 for LLMNR, a local name lookup. Debian turns LLMNR on, Ubuntu does not.
  Turn it off with `LLMNR=no` in a file under `/etc/systemd/resolved.conf.d/`, then restart
  `systemd-resolved`.

A node that does not answer does not stop the publish; its ports are not checked, and the deploy still
rolls back if the port is taken there. `haprion-node-status` on a node shows the same
list, as *Every address*.

### HTTP/3

On *Network*, a VIP's row in edit mode has *HTTP/3*. It serves the https sites on that address over QUIC
as well - on UDP, at the https port, with the same certificates and TLS version.

Every answer over TCP then carries `alt-svc: h3=":443"; ma=86400`. A browser that can reach UDP moves to
HTTP/3 and remembers it for a day. One that cannot goes on over TCP without any sign of trouble.

The setting belongs to the VIP and not to an object, since the UDP listener belongs to the address and
every site on it shares it. An https object's page says *HTTP/3 on VIP …*. Access rules, blocking and the
WAF act on the request, so they apply over HTTP/3 as they do over TCP.

Limits:

- QUIC carries TLS 1.3 only, so a VIP whose TLS version is *TLS 1.2 only* refuses HTTP/3.
- A dns or syslog object that takes the same UDP port on the same address is refused at publish.
- A failover cuts a QUIC connection, as it cuts a TCP one, and the client connects again.

Outside the interface, UDP to the https port must be open to the VIP in the nodes' firewall. For clients
outside, the outer firewall must forward it too. Until it does, nothing breaks: clients try QUIC, get no
answer, and stay on TCP.

### DNS objects

An object whose protocol is *DNS* is served by dnsdist, a DNS load balancer, on the same nodes and VIPs.
It listens on UDP and TCP, on port 53 unless another port is written.

**When it is offered.** The form offers DNS once every node of the cluster reports that dnsdist is
installed. A node without it refuses a release that carries a DNS listener.

**Servers.** The pool's servers are addresses or host names, with a port, and the list shows the names.
dnsdist takes addresses only, so the manager looks a name up when the object is **saved**, and stores the
address in the object beside the name:

```yaml
servers:
  - host: dc1.example.com
    port: 53
    address: 192.0.2.53      # written when the object was saved
```

- A name that gives no address, or several addresses of one family, refuses the save.
- Publishing looks nothing up: it writes the stored address. Publishing something else - a log target, a
  neighbouring object - therefore never moves a DNS server, and never fails because DNS does.
- A name stored without an address refuses the publish with *save the object again*. An object written by
  hand gives the `address` itself.
- The address is the one the name had when the object was saved. `haprion-status` and the object's page
  say when the name has moved since. *Look up again*, beside that warning, saves the object with the
  address the name has now, for the next publish.

*Details:* the web service itself reaches nothing beyond localhost. It looks names up by asking
`haprion-resolve-helper` over `/run/haprion/resolve.sock`.

**Balancing** is one of dnsdist's:

- `roundrobin`.
- `leastOutstanding`.
- `firstAvailable` - the first server that is up. This is how a DNS pool does active/passive, since dnsdist
  has no backup server.
- `chashed` - one query name keeps one server.

**Health check.** dnsdist asks every server a real question: `a.root-servers.net.` for `A` unless another
is given, once a second by default. *Test health check* asks that question from the nodes before the
object is saved, judging the answer as dnsdist does. Any answer counts except SERVFAIL, so NXDOMAIN and
REFUSED count. A named server is asked at the address the manager looks it up to.

**Who may ask.** *Reachable from* is who may ask; anybody else is answered REFUSED.

What belongs to HAProxy - TLS, rate limits, deny lists, the WAF engine, maintenance, headers, advanced
config - is not offered, and refused if written by hand. The client's address reaches the servers behind
as EDNS Client Subnet, so a Pi-hole's per-client limits and logs see each client rather than the node.

**One DNS object per address and port.** dnsdist tells its objects apart by the address and port a query
arrives on. Two DNS objects therefore cannot share a VIP on port 53, and the form refuses the second. Two
DNS services - the domain controllers and a pair of Pi-holes, say - need a VIP each. Add one on the
*Network* page, publish and deploy it, and choose it on the second object. No DNS name is needed for the
new VIP, since clients are given a resolver by address anyway. Another port on the same VIP works only for
clients that can be told to ask on it, and few can.

### Syslog objects

**What a syslog object cannot do, first:**

- **UDP only.** Syslog over TCP or TLS is not forwarded. Senders that use it send straight to the
  receivers.
- **No list of who may send.** Every packet that reaches the address and port is forwarded. Protect the
  address in front of the nodes, with the firewall that guards the network it is on.
- **The network has to let the senders' addresses through.** A message leaves the node with the node's own
  MAC address and the *sender's* IP address, so the receivers see who sent it. Anything between the nodes
  and the receivers that filters on the source IP address drops it: the Proxmox firewall's *IP filter* on
  the node's network card, a switch's *IP Source Guard*, and uRPF or anti-spoofing on a router when the
  receivers are in another network. Filters on the MAC address - VMware's *forged transmits*, Proxmox's
  MAC filter - are not affected. Nothing has to route back through the nodes, since syslog over UDP is
  never answered.
- **A udp check cannot see such a filter.** It counts a receiver down only when the receiver's host answers
  that nothing listens. A datagram dropped on the way gets no answer, so a receiver behind a firewall that
  drops it reads as up. Use a *tcp* check where the receiver also listens on TCP, or send a test message
  and look for it.
- **The receivers are addresses**, in the VIP's address family, with a port. There is no backup receiver;
  *firstAvailable* is how a pool does active/passive.

**How it works.** An object whose protocol is *Syslog (UDP)* is forwarded by the Linux kernel's own load
balancer, IPVS, which keepalived configures on the same nodes and VIPs. It listens on port 514 unless
another port is written.

**When it is offered.** The form offers syslog once every node of the cluster reports that
`keepalived.conf` includes `/etc/keepalived/ipvs.conf` at its top level - see
[Installing Haprion](install.md#optional-components). Until then the choice is greyed out. A node without
the include:

- refuses a release that carries a syslog object;
- reads *NOT FORWARDING* in `haprion-status`, which counts the node as not running its release;
- shows as *Include missing*, with the node, in the object list.

A syslog object can share a port number with tcp objects and with the cluster's own ports, which are TCP.
It cannot share one with a DNS object or another syslog object on the same VIP.

**Balancing** is one of three:

- *roundrobin*: message by message, in turn.
- *source*: one sender keeps one receiver; when a receiver goes, only its senders move.
- *firstAvailable*: every message to the first receiver in the list that is up.

**Health check.** The check is keepalived's:

- *udp* sends a datagram to the receiver's port. It counts the receiver down when the receiver's host
  answers that nothing listens there. A host that is gone altogether is noticed when the node stops finding
  it on the network, after about fifteen seconds.
- *tcp* connects to a port of the receiver's - its own unless another is given - and nothing more.
- With no check, a receiver is never taken out.

There is an interval and *Checks to fall*, but no *Checks to rise*: one passing check puts a receiver back.
The form suggests *udp* when the protocol is chosen.

*Test health check* tries the check from the nodes' own addresses, as keepalived does, and shows the answer
of the node holding the VIP. *udp* sends one empty datagram and waits five seconds - keepalived's own wait
- for a refusal, and says *not refused* when none came. *tcp* connects and closes. On the command line,
`haprion-probe -c <cluster> -t <address:port>[,...] --udp` asks the same.

**Status and metrics.** The editor's *What the nodes report* and the lamp in the object list show each
receiver up or down, as keepalived on the node holding the VIP sees it. That is the node the messages pass
through, as for every other object. The object's metrics are messages and bytes, per pool and per
receiver, counted by IPVS on the node that holds the address. A receiver taken out and put back starts
counting from zero, and the interval it happened in has no figure rather than a wrong one. No message is
stored.

What belongs to HAProxy - TLS, rate limits, deny lists, a source address, the WAF engine, maintenance,
headers, advanced config, cookies and connection limits - is not offered, and refused if written by hand.

## Accounts and signing in

The installation creates the first administrator, a break-glass account; see
[First administrator](#first-administrator). Further accounts are made either by root on the management
host, with `haprion-user`, or by an admin in the interface (below):

```bash
sudo haprion-user add operator --role admin
```

The password is typed at the terminal, twice. There is deliberately no flag to pass it as an argument,
because that would put it in the shell history and the process list. For automation, `--password-stdin` on
`add` and `reset` reads it as one line from a pipe instead.

An account name is at most 64 characters, with no line breaks, no invisible characters and no spaces at
either end. A version records the name as who published it, so the tool, the *Users* form and a first
sign-in through the provider all refuse a name that could not stand there.

**The break-glass path.** The same tool is the way back in when the only administrator is locked out,
forgotten or gone. An account it creates is a **break-glass** account unless `--no-break-glass` is given.
A break-glass account signs in with its password even while sign-in goes through an OIDC provider.

| Command | What it does |
|---|---|
| `add <user> --role admin\|reader [--no-break-glass] [--password-stdin]` | create an account |
| `init-admin` | create `admin`, a break-glass admin, if there is no account at all |
| `delete <user> --yes` | remove an account and its sessions for good; without `--yes` it only says what it would do |
| `break-glass <user> [--off]` | mark a local account break-glass, or unmark it |
| `reset <user> [--password-stdin]` | set a new password **and end every session that account has** |
| `role <user> admin\|reader` | give a local account another role |
| `disable <user>` | block sign-in and end every session |
| `enable <user>` | allow sign-in again |
| `unlock <user>` | clear the sign-in throttle |
| `revoke <user>` | end every session without changing the password |
| `list [--json]` | accounts, roles, kind (`local`, `break-glass`, `sso`), and how many live sessions each has |
| `apply <file> [--prune] [--check] [--json]` | the accounts a file lists, written where they differ (below) |

`reset` and `disable` end the account's sessions on purpose. Whoever had the account would otherwise keep
it through the cookie in their browser, even though they can no longer sign in - and taking the account
back is usually why either command is run.

**Accounts from a file**, for automation. `apply` reads a list of accounts and writes only what differs
from what is stored. It goes through the same code and the same database guards as the *Users* page:

- It refuses to remove the last active admin, or the break-glass admin that sign-in through a provider
  needs. Nothing of a refused file is written.
- A password is compared with the stored one, not set again, so applying the same file twice changes
  nothing. A changed password ends that account's sessions, as `reset` does.
- The file carries passwords, so it is refused unless only its owner may read it (mode `0600`).
- An account the provider created takes only `disabled` from the file.
- An account no entry names is left alone, unless `--prune` is given. `--prune` removes local accounts
  only.
- A new account is not break-glass unless the file says so.

```yaml
accounts:
  - username: admin
    role: admin
    break_glass: true
    password: "from the vault"
  - username: viewer
    role: reader
    disabled: false
```

```bash
sudo haprion-user apply accounts.yaml --check
sudo haprion-user apply accounts.yaml --json
```

**Changing your own password.** Anyone signed in with a password, reader or admin, can change it from the
account menu (**Change password**). The entry is not shown to an account that signs in through an OIDC
provider, since such an account has no password here. The form asks for the current password. It is
tried as a sign-in is, under the same throttle: a wrong one counts as a failed sign-in for that name and
address, and the right one as a sign-in. A session someone else is holding can therefore not be used to
guess the password, nor to lock the account for everyone else. The change ends the account's other sessions and keeps the one it
was made from. It is recorded as `password_changed` with `via: web`.

**Managing accounts in the interface.** An admin manages the other accounts under **Settings → Users**, on
installations with `management_writes` on. The verbs are those of the table above: add, change role,
disable and enable, set a new password, mark break-glass, end sessions, unlock and delete.

- The signed-in admin session is the proof; no second password is asked.
- A new role, a new password and the break-glass mark are saved together, in one step.
- Delete asks first, on its own page.
- The admin's own account is not changed there.
- Each action is audited under the same names as the tool's, plus `role_changed`, `break_glass_changed` and
  `account_deleted`, with the admin as actor and `via: web`.

**There is always an active admin.** The database itself refuses to leave no active admin, whether the
change comes from the tool or from the interface. The last one cannot be demoted, disabled or deleted. The
check runs under a lock, so two admins who disable each other at the same moment cannot both succeed. If
the last admin is lost anyway, the break-glass answer is `haprion-user add`.

A deleted account's sessions go with it. Jobs and the audit trail name the account as text, and keep it.
An account that signs in through an OIDC provider has no password here, and its role comes from the
provider.

*Details:* `haprion-user` reads the database name, and the database role to connect as, from a root-owned
file written by `02-platform-database`: `/etc/haprion/ui-admin.conf`. It cannot be pointed at another
database by an environment variable or a working directory. Root connects as the role that owns the
schema, so the tool works when nobody can sign in.

### What the two roles see

A **reader** sees the state of the clusters and can press nothing. A reader's menu has the dashboard,
*Proxies*, *Versions*, *Certificates*, *Metrics*, *Traffic logs*, *Network* and *Events*, plus *WAF logs*
when the WAF engine switch is on and *Node backups* when node backups are on
([Features and advanced configuration](#features-and-advanced-configuration)).

Pages that carry the configuration itself are an administrator's: an object's page, a version's *Diff*,
*Settings*, the certificate receivers, node restores and the audit trail. They show every backend address,
whatever an advanced text wrote, or where key material goes. A reader who opens one is told
*Administrators only*.

An **admin** can queue the operations the interface offers, and sees two more things:

- **The error code** of an operation that did not end cleanly, such as `cluster_not_converged` or
  `ssh_unreachable`. It is a fixed string that does not depend on the environment, and it is shown as it
  is rather than translated. The command line prints the same string beside its message, and the audit
  trail records it, so what a terminal said and what the page says can be compared directly.
- **The operation's diagnostics**: its error output, with secrets masked, and the evidence a refusal
  carries. They are folded away under the job until you open them. Before the text is stored, private
  keys, sensitive paths and any assignment to a token, password, secret, credential, API key, access key
  or private key are masked. The text is capped at 64 KiB.

The diagnostics contain **real host names, node names and HAProxy's own output** - that is what makes them
worth showing. Masking covers secrets, not the identity of your environment. So a screenshot of that panel
does not belong in an issue, a README, a support ticket or anywhere else outside the installation.

Readers do not see the diagnostics. Administrators do, because the person who runs the installation needs
them to find a fault without opening an SSH session every time something fails.

### How a session works

- **Passwords are hashed with Argon2id.** Its parameters are set in the code rather than taken from library
  defaults, and the database refuses any hash that is not Argon2id. A change of algorithm therefore has to
  be a planned database change, not a side effect of a library upgrade.
- **The session token is random and lives only in the cookie.** The database stores only its SHA-256 hash,
  so a copy of the session table - a dump, a backup, a mistake - cannot be replayed as a login. The token
  carries no claims, and there is no signing key to leak.
- **Cookies are `Secure`, `HttpOnly` and `SameSite=Lax`.** Lax rather than Strict, so that arriving from a
  link in a mail or a dashboard still works. That is a normal way to reach an operations interface.
- **Two clocks, not one.** About ten hours without activity ends a session. An absolute lifetime also caps
  a session that a forgotten browser tab keeps alive. Using the session moves the first clock forward; the
  web service cannot change the second.
- **CSRF tokens are derived from the session token**, not stored. Making one requires the cookie, which a
  form posted from another site can make a browser send but cannot read. The login form itself is
  protected the same way, by a short-lived cookie that is only sent to `/login`.
- **A new token on every login**, so nothing a browser held before signing in is still valid after.

*Details:* the clocks are set under `[session]` in `ui.toml`: `inactivity_minutes` (default 600) and
`absolute_hours` (default 168, one week).

### The throttle

Failed sign-ins are counted per username **and** client address together. Counting per username alone
would let one attacker lock every real user out. Counting per address alone would let one address work
through a list of names.

Each account also has a budget of its own across all addresses: ten times the limit (`max_failures`) in
the same window. It stops many addresses guessing at one name. An attempt refused by the throttle is not
counted again, so one address that keeps trying cannot use up that budget for everyone else.
`haprion-user unlock` clears both. An IPv6 address counts as its /64. *Settings -> Users* marks an account
*Locked* by this same rule, so a name the sign-in refuses is never shown as *Active*;
`haprion-user list` shows it too (its STATE column, and `locked` in `--json`), reading the limit and window from the
same configuration.

The web service can add and read sign-in attempts, but cannot change or delete them. A counter the web
process could reset would be a lock whose key is kept behind the door. An unlock therefore deletes
nothing: `haprion-user unlock` (and, for an admin, the interface) records an unlock, and the throttle
counts failures since the latest success or unlock for that name. The failed attempts stay in the record.

**The client address.** It is taken from `X-Forwarded-For`, which the nginx site *overwrites* rather than
appends to, so a request cannot supply its own. The web service accepts connections only on
`/run/haprion-web.sock`. Only root and nginx's workers (`www-data`) may open that socket, so no other
process on the manager can reach the web service past nginx with a header of its own. An address that
will not parse is counted as loopback, rather than becoming an unthrottled bucket of its own.

Every sign-in, failure, sign-out and account change is written to the audit trail, in the same transaction
as the thing it describes. The login page, on the other hand, says one and the same sentence for every
kind of failure. An unknown account, a wrong password, a disabled account and a throttled address cannot
be told apart from outside, and each takes the same amount of time.

### Signing in through an OpenID Connect provider

You can let people sign in through an identity provider: authentik, Keycloak, Entra ID, ADFS, Authelia,
Okta, Zitadel, or any other that follows OpenID Connect Core and Discovery. Who may sign in, and with which
role, is then decided by the provider's groups.

**How the manager reaches the provider.** The web service reaches localhost and nothing else
(`IPAddressDeny=any`), and that does not change. Every request to the provider goes through
`/run/haprion/oidc.sock` to `haprion-oidc-helper`, which platform step 17 installs. The helper runs as an
account of its own (`OIDC_USER`, the identity policy's `roles.oidc`), not as root, and it is the one part
that may reach the network.

- It takes no URL from the web service. The issuer comes from the settings, and every other address from
  that issuer's own discovery document.
- It speaks verified TLS only. It trusts the system's certificate authorities, plus a CA certificate pasted
  into the settings when one is set.
- It follows no redirect and uses no proxy from the environment.
- It limits every answer to ten seconds and one megabyte.

**The client secret.** The web service encrypts the client secret with the public key step 17 made, and
only the helper can decrypt it. The encrypted secret names the issuer, the client and the CA certificate
it was saved for, and the helper refuses to open it for any other. Changing the issuer or the CA therefore
means typing the secret again. A session that changes where sign-in goes, or whom it trusts to say so,
cannot also send the old secret there. A secret sealed without a CA named in it opens only while no CA
certificate is set; with one set, type the secret again once.

**Checking the sign-in.** The helper verifies the id_token as OpenID Connect Core lays out for the
authorization code flow (section 3.1.3, step 7):

- the signature: RSA, RSA-PSS or ECDSA against the provider's key set, or HMAC with the client secret,
  which authentik uses when no signing key is chosen - never `none`;
- the issuer, the audience and `azp`;
- the expiry, with one minute's leeway;
- the sign-in's own nonce.

Userinfo is added when it names the same subject, and ignored otherwise; it is never a reason to refuse.
Names and groups are read from the claims the settings name, written as a dotted path
(`realm_access.roles`). A claim that is an object counts as its keys. A provider that sends a pointer to
the groups instead of the groups themselves (Entra ID does this above 200 groups) is refused, with a
sentence that says to use app roles.

**How long a role lasts.** The role is read from the groups at every sign-in through the provider, and not
in between. A session made that way therefore ends after at most `oidc_absolute_hours` (under `[session]`
in `ui.toml`, default 10), whatever the activity. A group taken away at the provider stops counting here
by then. The provider's own token lifetime is not used for this. To end someone's access sooner, **End
sessions** on the account does it at once.

**Accounts from the provider.** An account is made at its first sign-in through the provider, with the
role its groups give. There is no list of such accounts to keep here, and none is made in advance. The
account is bound to the issuer and the subject it first signed in with, not to its name. Changing the
issuer - another provider, or the same provider's application under a new name - therefore leaves every
such account bound to the old one, and sign-in says so. Remove those accounts under **Settings → Users**;
each is made again at its next sign-in.

#### Examples: three providers

In every case, the provider gets:

- a confidential client (one with a secret);
- the authorization code flow;
- exactly one redirect URI: the one the settings page shows, `https://<SERVER_NAME>/login/oidc/callback`.

Type the issuer exactly as the provider states it. **Verify** says so when it is not, and quotes the
provider's own value. Menu names change between provider versions. What matters is what ends up in the
id_token, which **Test sign-in** shows.

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

**The settings page.** The settings are an admin's, under **Settings → Users → OIDC configuration**, on
installations with `management_writes` on:

- issuer, client ID and secret;
- client authentication (`client_secret_basic` or `client_secret_post`);
- scopes, the claims for the name and the groups, and the admin and reader groups;
- the button text;
- sign-out: this interface only, or also at the provider;
- local sign-in: break-glass accounts only, or all;
- an optional CA certificate;
- whether the provider is always asked to make the person sign in again.

The redirect URI to register at the provider is shown there, to copy. The web service's `ui.toml` names the
public key step 17 made (`[oidc] public_key`, added by the step). Without it, the page says the helper is
not installed.

**Verify** asks the helper to check, and lists each check:

- discovery against the issuer;
- the key set;
- the client's authentication method;
- the signing algorithm;
- whether the provider accepts the client and its secret. The helper sends a code that was never issued. A
  provider answers `invalid_grant` when it accepted the client, and `invalid_client` when it did not.

Sign-in through the provider can be turned on only with settings that passed Verify, and only while an
active admin is break-glass. Every change to the settings counts as new, unverified settings. Saving while
sign-in is on runs Verify first, and either saves the settings as verified or saves nothing. Each change is
audited (`oidc_configured`, `oidc_verified`, `oidc_enabled`, `oidc_disabled`); the secret never is.
Turning it off signs out everyone who signed in through the provider, at once; the page and the audit
event say how many sessions ended. Local and break-glass accounts stay signed in.
Turning it on with *Break-glass accounts only* does the opposite for local accounts: the sessions of local
accounts that are not break-glass end at once, since they could not sign in again. So do the same accounts'
sessions when that rule is chosen while sign-in is on, and an account's sessions when its break-glass mark
is removed in that state (`haprion-user break-glass --off` and `apply` do the same). Your own session
stays when you are one of them. The page and the audit event (`sessions_ended`, `sessions_revoked`) say
how many ended; so does the answer of `haprion-settings apply` and `haprion-user apply` (`sessions_ended`
in `--json`).

**Settings from a file**, for automation. `haprion-settings`, run as root on the manager, sets what three
parts of the settings set: *External monitoring*, *Features* and the OIDC configuration. It uses the same
code and the same refusals, and is audited with `via: cli`.

- Each of the three sections is optional. A section the file leaves out is left alone.
- Only what differs from what is stored is written, so the same file twice changes nothing.
- `--check` says what would change and keeps nothing.
- `show --json` prints what is set, never the client secret.

```yaml
status_access: [192.0.2.10, 198.51.100.0/24]   # [] switches /status/ off
features:
  node_backups: true
  advanced_config: false
oidc:
  issuer: https://idp.example.com/realms/main
  client_id: haprion
  client_secret: "from the vault"
  auth_method: client_secret_basic
  scopes: openid profile
  username_claim: preferred_username
  groups_claim: groups
  admin_group: haprion-admins
  reader_group: haprion-readers
  button_text: Sign in with SSO
  prompt_login: false
  logout_mode: app                 # app or provider
  local_login: break_glass_only    # break_glass_only or all
  enabled: true
  interface_url: https://mgr.example.com
```

```bash
sudo haprion-settings apply settings.yaml --check
sudo haprion-settings apply settings.yaml --json
sudo haprion-settings show --json
```

The `oidc` section holds what the configuration page saves. `enabled` is the page's *On* and *Off*.
Turning it on runs Verify first, as the page does. The page takes the redirect URI from the browser; the
command takes it from `interface_url`, the address people sign in at. Settings saved while sign-in is off
stay saved when Verify then fails, and the command says why sign-in did not turn on.

The stored client secret is encrypted for the helper, so the command cannot compare it with the file. The
secret from the file is therefore stored only when none is stored yet, when the issuer, the client or the CA
certificate changes, or with `--replace-oidc-secret`. Otherwise the stored one is kept, and the answer says
`"sealing": "kept"`. A file that carries the secret is refused unless only its owner may read it (mode
`0600`). `--oidc-secret-stdin` reads the secret from one line on standard input instead.

## Features and advanced configuration

**Settings → Features** has six switches. An admin flips them, on an installation with `management_writes`
on; `haprion-settings apply` flips them from a file, with the same refusals (*Settings from a file*,
above).

| Switch | On a new installation | What it controls |
|---|---|---|
| Certificates for other hosts | off | certificate receivers and certificates installed by hand |
| Node backups | off | node backups, their timers and node restores |
| Cluster colours | on | a coloured rule down each cluster card's left edge |
| Advanced config | off | the *Advanced config* button on an object's page |
| WAF engine | off | whether objects are offered the WAF engine, and the *WAF logs* page |
| Update check | off | a daily check for a newer release |

Turning a capability off hides its tab, its pages and its operations. A bookmarked URL to one of its
pages then answers 404. A new installation also enables no backup timer: an installation opts in.

**Certificates for other hosts.** Off hides:

- the receivers page;
- the receiver choices in the certificate forms and in *Publish to…* and *Remove from…*;
- the certificates page's second view;
- *Installed by hand*, with its downloads and key export.

Nothing that already exists stops working. Receivers already registered go on getting renewed
certificates, and a certificate's *Used by* still names them. Certificates for other hosts stay in the registry
and are still renewed.

**Node backups.** Off hides node backups and node restores, and also stops every cluster's backup timer.
It does this by queuing one `backup_schedule` job per running timer, with the schedule unchanged and
`enabled: false`. The schedules it stopped are remembered, and turning the switch on starts exactly those
again. Archives already taken are kept.

Turning it off is refused:

- while a cluster has a job running;
- while a node restore is running or waiting;
- for a cluster whose backup reading is not fresh, or whose retention could not be read;
- for a cluster whose schedule the form cannot write back.

`haprion-state-backup` and the restore commands on the manager work either way.

**Cluster colours.** This switch hides nothing. It draws the rule down each cluster card's left edge, in
one of six colours. The colours are handed out in the order the cluster file lists the clusters
([Cluster definitions](#cluster-definitions)) - the same order the dashboard draws the cards in - so
reordering the clusters there reorders both. Until the poller has read the cluster file, the order of
`clusters` in `ui.toml` is used instead. With more than six clusters the switch is off and cannot be
turned on. Each card shows the cluster's name either way.

**Advanced config.** On, an object's page has an *Advanced config* button, between *Edit* and *Remove*. It
opens a dialog where you paste HAProxy configuration as a layer on top of the object. The object stores
the text as `advanced` in its YAML.

Off hides only the button and the dialog. An object that has text keeps it, its page says so, and the
generator writes it on every publish: what a cluster runs must not depend on an interface setting.

**WAF engine.** On, the form of an http or https object offers the *WAF* group, and *WAF logs* appears in
the menu ([The WAF engine](#the-waf-engine)). The switch's row says which engine and rule set versions are
installed, or where the engine is missing - *Not installed on node-a*. Off hides the *WAF logs* page, and
the *WAF* group on objects that do not use the engine. It cannot be turned off while an object uses the
engine, in any mode but `off`: a WAF the interface no longer shows would still filter traffic. The refusal
names the objects.

**Update check.** It is off from the start on every installation, so the manager never contacts GitHub
unless you ask it to. Everything the manager and the nodes reach is listed under
[What the machines must reach](install.md#what-the-machines-must-reach).

- On, the poller asks GitHub once a day for the project's latest release. When that release is newer than
  the one running, the header says `· v0.9.3 available` beside the version, with a link to its release
  notes.
- The switch's row says when GitHub last answered, or since when it has not.
- When GitHub does not answer, the last answer stands, and the poller asks again every hour until it does.
  Nothing is raised on *Needs attention*.
- The poller asks GitHub directly; its service is given no proxy setting. The manager must therefore be
  allowed to reach `api.github.com` on port 443.
- The check installs nothing. `sudo apt update && sudo apt upgrade` installs a release
  ([The packages](install.md#the-packages)).

### What the advanced layer does, line by line

The dialog's *Validate the proxy* shows where each line of the text goes.
`haprion-objects -c alpha --advanced <name>` prints the same answer.

**The object's own lines.** Lines outside any section, and lines under the text's own `frontend` or
`listen`, belong to the object:

- An http object's lines go to every pool it has.
- A tcp object's lines go to its frontend where HAProxy accepts the keyword there, and to its pool
  otherwise.
- They are written **after** the generated lines of the same section. The cluster's abuse brake and the
  object's rate limit therefore run first, and the text can read their counters.

**Sections the text may add.** A `backend`, `cache`, `http-errors`, `userlist` or `ring` section is written
as it stands, under a name that must begin with `<object>-`. A section named otherwise is refused, not
renamed, because other files may refer to it by name. Every other section is refused - `global`,
`defaults`, `program`, `peers`, `resolvers`, `mailers` and the rest belong to the cluster or to the HAProxy
process.

Each line of an added section must be a keyword that section takes. Any other word is refused:

| Section | Keywords it may hold |
|---|---|
| `backend` | the proxy keywords HAProxy takes in a backend, under the rules below |
| `cache` | `total-max-size`, `max-object-size`, `max-age`, `process-vary`, `max-secondary-entries` |
| `http-errors` | `errorfile`, naming one of the packaged error pages |
| `userlist` | `user`, `group` |
| `ring` | `description`, `format`, `maxlen`, `size`, `timeout connect`, `timeout server`, `server` |

A ring's `backing-file` is refused: HAProxy creates and overwrites that file as root.

**Lines that are refused:**

- routing, listening and the outgoing address, which belong to the form: `use_backend`, `default_backend`,
  `bind`, `source` and `usesrc` (also as a server parameter), and their deprecated forms `dispatch`,
  `transparent` and `option transparent`;
- `guid`, on a section or a server, since the generator gives every section its identity;
- a keyword HAProxy does not take in that place - on an http object, for example, a frontend-only keyword,
  since the frontend is shared with other objects - and a word that is not an HAProxy proxy keyword at all;
- on a tcp object, every HTTP keyword (`http-request`, `redirect`, `option forwardfor` and the like), since
  a tcp object has no requests;
- a line that begins with `.` - conditional blocks and directives belong to the process;
- a line longer than 4096 characters.

**Lines that touch what the generator owns are refused too:**

- **Stick counters.** `track-sc0` (the cluster's counter), `track-sc1` while the object's rate limit is on
  (the limit's counter), and `track-sc3` and `track-sc4` while its dynamic blocking is on. The text counts
  on `sc2`, with its tables in a backend of its own: `track-sc2 src table <object>-logins`. Reading `sc0`
  and `sc1` is allowed; changing them is not.
- **Stick tables.** A `stick-table` on the object's own lines is refused, because its pool already
  carries the rate limit's table.
- **The WAF engine's wiring.** The engine's SPOE filter, and the `txn.coraza.*` variables its verdict is
  read from. A line that set them could make the engine's answer say something it did not.
- **Files.** A file HAProxy is told to serve - `errorfile`, and `file`, `lf-file` or `errorfile` in a
  `return` or `http-error` - must be one of the packaged error pages under `/etc/haproxy/errors/`. HAProxy
  reads such a file as root and hands it to whoever asks, so any other path is refused.

**Lines that reach the node itself are refused.** HAProxy opens files and sockets as root when it loads
its configuration, during the check before a publish too. So the text may not name one:

- a list read from a file - `-f` in an ACL, or a `map` converter - unless it is one of the cluster's
  lists under `/etc/haproxy/maps/`. The actions that change a list while HAProxy runs, `set-map`,
  `del-map`, `add-acl` and `del-acl`, are refused, since other objects may read the same list;
- a key or certificate file in `jwt_verify`, `jwt_verify_cert` or `jwt_decrypt_cert`. A variable that
  holds the key is allowed;
- a log target other than `global`, a ring the text adds, or a syslog server's network address. A
  path, `unix@`, `fd@`, `stdout`, `stderr` and `backend@` are refused;
- a server reached at anything but a network address, such as a socket path;
- a server's `crt`, `crl-file` or `namespace`, or a parameter HAProxy does not have. A server's
  `ca-file` must be `@system-ca` or one of the cluster's authorities under `/etc/haproxy/certs/ca/`;
- the `crt` keyword, since the form chooses an object's certificates;
- `server-state-file-name` and `load-server-state-from-file`, since state across a reload is the
  cluster's;
- `external-check command`, `external-check path` and `option external-check`, which run a program;
- the `spoe` and `opentracing` filters, which read a configuration file, and the `fcgi-app` filter.
  The text may add `compression`, `comp-req`, `comp-res`, `cache`, `bwlim-in`, `bwlim-out` and `trace`;
- an environment variable in double quotes, such as `"${HOME}"`. HAProxy fills it in from the node, and
  what it holds is not checked.

Escapes count as HAProxy reads them: `\x67lobal` is `global`.

**Lines that are skipped.** `mode` is skipped, since the form sets the protocol. So are the lines that set
what the form owns for the pool - servers, balancing, health checks, cookie, and the connect, server,
queue, tunnel and check timeouts - while the form writes the pool.

Tick *The text writes the pool* to hand the object's one pool to the text instead. The YAML then keeps
`servers: []` and nothing else, the form shows no pool fields, and the text must carry at least one
`server` line. Unticking gives the pool back to the form, with the text's `server name host:port` lines as
its servers.

**Reviewing the text.** *Validate the proxy* and *Save* in the dialog list every line of the text with its
*Fate* - placed, skipped, ignored or refused - and *Where* it went. That list is your review before a
publish.

- A `haproxy -c` error in a generated file is reported as the object and the line of its text.
- A publish is refused when HAProxy warns about a pasted line. A warning there means the line would be
  ignored, which `haproxy -c` alone would let pass.
- Beyond what is refused here and what `haproxy -c` checks, what the text does is the author's
  responsibility. A valid line can still mean something other than intended.
- Stick tables in the text start counting again when HAProxy reloads, and when the address moves to the
  other node. A cluster's shared counters are for the generated tables only
  ([Sending the traffic log elsewhere, and metrics](#sending-the-traffic-log-elsewhere-and-metrics)).

## Access rules

An object can refuse visitors by their address, by what a request asks for, and by the size of what it
sends. All three are in the *Access* group of the object's form (*Edit* on the proxy's page, or *New
proxy*), below *Reachable from*, *Rate limit* and *Rate window*
([An http or https object, field by field](#an-http-or-https-object-field-by-field)):

- **Denied** (http, https and tcp). *Denied — groups* and *Denied — addresses* name who is refused: groups
  from the *Network* page, and addresses, ranges or countries, one per line. *Denied — mode* is *log* or
  *deny*.
- **Max request body** (http and https) is the largest body a request may declare, such as `10m`.
- **Deny rules** (http and https) are tried in order, and any one of them is enough. *Add rule* adds one
  and *Remove rule* drops it. A rule has a *Name*, a *Mode* (*log* or *deny*), and the conditions it names:
  - a *Path*, with its *Path match* (*prefix* or *exact*);
  - one or more *Methods*;
  - a *Header*, with its *Header match* (*equals*, *prefix* or *contains*) and *Header value*;
  - a *Source*. *Not from these sources* turns the source around.

When the group is closed, its line counts the rules that only look and those that refuse - *1 logging*,
*2 denying* - so the form shows whether anything on the object turns visitors away.

In the object's YAML, the same fields are keys beside `allow_from`. The generator writes them into the
shared frontend after `allow_from`, before anything is routed.

```yaml
deny_from:                       # http and tcp
  mode: log                      # log (the default) or deny; tcp takes deny only
  sources: [scanners, 203.0.113.0/24]
deny_rules:                      # http only; tried in order, any one is enough
  - name: admin-post             # lowercase, shown on the traffic record
    mode: deny
    path: /admin                 # prefix by default; match: exact for one path
    methods: [POST, PUT]
    header: {name: User-Agent, contains: sqlmap}   # equals, prefix or contains
    source: [office]
    source_negate: true          # all but these sources; needs source
max_request_body: 10m            # http only; k, m and g are 1024-based
```

Every condition a rule names must hold. *Not from these sources* (`source_negate`) turns the source into
"from anywhere but these". The rule above therefore refuses a POST or PUT under `/admin`, whose User-Agent
contains `sqlmap`, from anyone outside `office`. A rule that names no condition is refused, since it would
refuse everything the object serves. Header values are matched as plain text, never as patterns.

**A rule's path is read the way the least strict backend would read it.** Different web servers read the
same path differently, and an attacker picks the spelling that slips past the rule. So before matching, the
path is:

- percent-decoded, with runs of slashes made one, as nginx matches its locations;
- made lower case, as IIS ignores case;
- stripped of `;parameters` in each segment, as Java servers do;
- stripped of dots and spaces at the end of a segment, as Windows does.

`/%61dmin`, `//admin`, `/admin%2Fusers`, `/Admin`, `/admin;x` and `/admin.` all meet a rule on `/admin`.
Behind a backend that does tell `/Admin` from `/admin`, a rule on one refuses both. The backend still
receives the path exactly as it was sent.

Two kinds of path are answered 400 on an object with a refusing path rule:

- a path with a `.` or `..` segment once decoded - `/./admin`, `/x/../admin`, `/%2e%2e/admin` - recorded
  `path-dots:deny`;
- a path with a control character - `%00`, a line break - recorded `path-chars:deny`.

When the object's path rules only look, these are recorded with `:log` instead. Browsers send neither.

Write a rule's own path decoded: without `%`, `//`, `;`, `.` or `..`, and with no segment ending in a dot.
Its case does not matter.

**A range is written as a network or as one address.** `192.0.2.0/24` or `192.0.2.1`, never
`192.0.2.1/24`: every list that takes ranges - *Reachable from*, *Denied*, a rule's *Source*, an
exemption from blocking, a network group on the *Network* page, the cluster settings' sources, a
receiver's whitelist and the `/status/` access list - refuses host bits when it is saved or applied,
in the same words. An object or a group stored with them before keeps loading as the network it
stands for, until it is next saved.

**Countries.** Wherever a group or a range may be named - *Reachable from*, *Denied* and a rule's *Source*
(`allow_from`, `deny_from` and `source`) - a country may be too, written `country:SE` (two letters, as ISO
3166 spells them).

Publishing looks up the networks of each country an object names in the IPFire Location database on the
management host. It writes them to `managed/maps/geo-se.lst`, and the nodes receive the file with the
release, in `maps/`, as they receive every map file. A country the database does not know refuses the
publish.

The database comes with the CLI package, which recommends `location` and `python3-location`, so apt
installs both unless recommended packages are turned off. The package starts with the distribution's copy
of the database, and enables `location-update.timer`, which fetches a new, signed database once a day. For
that, the management host needs to reach `location.ipfire.org`; without it the database ages but keeps
working. On a host installed without recommended packages, a publish that names a country says what is
missing:

```bash
sudo apt install location python3-location
```

A cluster takes up the new database at its next publish, whatever that publish changes, and not on its
own. *Settings → Location data* shows the database's date and, for each cluster that names a country, the
date its published lists were made from. The data is IPFire Location, licensed under CC BY-SA 4.0
(https://location.ipfire.org); each generated file names it in its first line.

**Look before refusing.** A new rule starts in *log* mode. The request is served, and the rule's name is
written on its traffic record as `admin-post:log`. In *deny* mode the visitor gets a 403, and the record
says `admin-post:deny`.

- The first logged rule a request meets is the one recorded. A refusal always names itself.
- *Denied* (`deny_from`) is recorded as `deny-from`.
- A tcp object has no traffic record for a logged match to appear on, so *Denied — mode* there must be
  *deny*.

**Behind a trusted proxy** (the cluster's `trusted_proxy_cidrs`), every address condition - *Reachable from*,
*Denied* and a rule's *Source* - reads the visitor from the last element of `X-Forwarded-For`, as the rate
limit does. An object restricted with *Reachable from* then admits only the visitors it names, not
everything that comes through the proxy. A request from the proxy with no header has no visitor address:
*Reachable from* refuses it, and *Denied* lets it pass.

**The body limit holds the declared size.** A request that states how long its body is gets a 413
(`body-limit:deny`) when that is more than *Max request body*.

A chunked request states no length, and HAProxy sees only what fits in its buffer (16 kB by default,
`tune.bufsize`). Such a body is refused if what has arrived is already over the limit. Otherwise it is let
through and marked `body-unbounded:log`. Browsers send the length with forms and uploads, so the mark shows
whether anything else reaches the object. The hard limit for a chunked body is the backend server's own,
such as nginx's `client_max_body_size`.

## Dynamic blocking

An http, https or tcp object can block a source address for a while once it asks too much. Every request
from a blocked address is refused for the time set. Every request over the limit during the block starts
that time again. A block therefore lasts as long as the attack plus the time set, and then ends on its own.

The rate limit is a different tool: it refuses only what is over the limit, and serves the rest.

**In the form**, *Dynamic blocking* sits between *Access* and *WAF*.

- *Requests* and *Errors* are what start a block (on a tcp object: *New connections*). With both empty
  there is no blocking.
- *Window* (`10s`), *Block for* (`30m`) and *Answer with* (`404`) come filled in.
- *Never blocked* takes groups from the *Network* page, and addresses or ranges, as *Reachable from* does.

**Watching and lifting blocks.** The object's page lists the addresses its block holds, with the nodes
holding each and the time left. An admin ticks them and presses *Unblock*. The cluster's dashboard card
says how many addresses are blocked. An admin's *Operations* row names the objects - three of them, then
how many more - with a link to each.

The same in the object's YAML:

```yaml
dynamic_block:
  window: 10s          # the default; seconds or minutes
  max_requests: 300    # http/https: requests per window (optional)
  max_errors: 20       # http/https: 4xx answers from the servers per window (optional)
  # tcp instead: max_new_connections
  block_for: 30m       # 1m to 24h
  status: 404          # http/https: 403, 404 or 429; 404 is the default
  exempt: [monitoring, 192.0.2.10]   # groups and ranges never counted or blocked
```

At least one trigger must be set.

**What counts as an error.** The errors are the 4xx answers the object's servers give - what a scanner or
a password guesser leaves behind. A 5xx is the application's fault and is not counted. Nor are answers
HAProxy gives itself, so a block cannot extend itself. A blocked request's traffic record says
`dynamic-block:deny`, which tells it apart from a 404 the application gave. A tcp object closes a blocked
address's connection before a byte is forwarded.

**Which address is blocked.** The one the rate limit counts: behind a trusted proxy, the last element of
`X-Forwarded-For`; otherwise the address the connection came from. Many visitors behind one NAT address
are blocked together. Name such an address in `exempt`, and also monitoring that polls the object often.
A country cannot be exempt.

**Where the block lives.** Each node keeps the block, with its own clock, as an entry in an HAProxy stick
table (a small in-memory table) that expires after `block_for`. On a cluster with shared counters, the
block reaches the other nodes and survives a reload and a failover. Without them, it is per node.

*Details:* the tables are two backends with no servers, `mgd-<object>-dynblock-rate` and
`mgd-<object>-dynblock`. `show stat` lists them; the node status leaves them out.

**What the cluster's core configuration needs.** Dynamic blocking uses the fourth and fifth stick counter
slots (`sc3` and `sc4`). HAProxy has three unless `global` says otherwise, so the cluster's
`core/haproxy.cfg` needs:

```
    tune.stick-counters 5
```

The nodes list and lift blocks on the admin socket that the core configuration names for drain and
maintenance (`stats socket /run/haproxy/manager.sock mode 600 level admin`). Before anything is validated,
a publish is refused, with the missing line, when it needs more counter slots than the core allows, or
when an object blocks on a cluster whose core has no such socket.

**What the nodes report.** Each node reports its blocked addresses in its status (`blocked`): per object,
how many, and the first 100 with the time left, read on the admin socket `/run/haproxy/manager.sock`.

**Lifting a block from the command line.** From the management host, a block is lifted on every node at
once, and each node is asked twice:

```bash
haprion-server-state -c alpha -o shop unblock 203.0.113.7 2001:db8::7
```

- `done` means no node blocks any of the addresses any more.
- `partial` names the nodes that still do, or that did not answer. Running the command again finishes the
  job.
- A node that does not run blocking for the object yet says to deploy.

*Details:* on a node, a block is lifted by `haprion-server-state unblock <object> <address>...`, which the
server state key's forced command allows. It clears the address from both tables, since an address left
in the count would be blocked again by its next request. A cleared entry is not shared, and another node
can send the block back, so a block is lifted on every node and then checked again.

## The WAF engine

An http or https object can have its requests inspected by a web application firewall (WAF): Coraza, with
the OWASP Core Rule Set (CRS). The engine runs beside HAProxy on every node, on loopback. For each request
of an object that has `waf`, HAProxy asks the engine about it: its query, its headers and its body - the
body as far as HAProxy's buffer holds it.

```yaml
waf:
  mode: log                # log (the default), block, or off
  on_engine_error: deny    # deny (the default) or allow
  paranoia: 1              # CRS paranoia level, 1 to 4
  exceptions:              # false alarms let through, each as narrow as it can be
    - rule: 942100         # a CRS rule ID
      field: ARGS:q        # optional: one part of the request; absent = all of it
      paths: [/search]     # optional: exact paths; absent = every path
      reason: SQL examples in the docs  # optional: why, one line of at most 200 characters
      by: admin            # who made it, and when (the WAF page fills these in)
      at: 2026-10-03T09:10:00Z
  large_bodies: [/upload]  # optional: paths where a body past the buffer is expected
```

`off` keeps the settings and the exceptions while the engine inspects nothing. The release then carries no
trace of the engine, as for an object without `waf`.

**Look before refusing.** In `log` mode, a request the engine would refuse is served. Its traffic record
says `crs:log`, with the CRS rules it matched and its anomaly score. In `block` mode the visitor gets a 403,
and the record says `crs:deny`. The engine checks a request after the access rules, so a request those
refuse is never inspected.

*WAF logs* shows the records with a match, and explains what each rule is. It covers the last seven days,
or fewer if the traffic log keeps fewer. A finding leaves the page seven days after its last match. An
object turned `off`, or without `waf`, shows no findings, since an exception would change nothing there.
They come back if the engine is turned on again within those days.

A rule that matches traffic the site is meant to receive is a false alarm. Let it through with an
exception; once the false alarms are handled, the object can leave `log` mode. A higher `paranoia` level
catches more attacks, and also raises more false alarms.

**Exceptions** are as narrow as the finding allows.

- `field` names the part of the request the rule reacted to, as the rule set's own log names it: `ARGS:q`
  (a query or form field), `ARGS:json.q` (a field in a JSON body), `REQUEST_HEADERS:User-Agent`,
  `REQUEST_COOKIES:session`. Only that part stops being inspected by that rule; the rest of the request
  still is.
- `paths` are compared exactly, after the engine decodes and normalises the path. `/%73earch` is `/search`,
  while `/search/`, `/search/x` and `/search/../admin` are not.
- Without `field`, the rule is off for the whole request on those paths. Without `paths`, it is off on
  every path. Without either, it is off on the whole object.
- A field name with characters other than letters, digits and `_ . - [ ]` cannot be named. Except the path
  instead.
- The rules that decide and report rather than detect (CRS 949xxx, 959xxx, 980xxx) cannot be excepted:
  that would turn the engine off.
- `exclude_rules` is not accepted; it is refused with a message that says to use `exceptions`.

*Allow*, on *WAF logs*, makes an exception and takes an optional *Reason*. The exceptions list shows the
reason in a column of its own, because why the traffic is let through outlives the findings that led to
it.

A finding that an exception covers leaves *Findings* - unless the rule still matches it after the first
deploy that followed the exception. Then the finding stays, and both it and the exception are marked *Not
working*. An exception without its time (`at`), or one deployed only from the command line, cannot be
judged this way.

Findings include the rule set's NOTICE rules - an empty `Accept` or `User-Agent` header, for example. They
add to the score like the others.

**What an exception lets through.** Each exception counts its hits, as a firewall rule does. The
exceptions list shows *Let through*, *Clients* and *Last seen* for the last seven days. The engine leaves
no trace of a check it was told to skip, so the generator writes a counter beside each exception: the rule
itself, as the installed rule set writes it, narrowed to the exception's field and paths, logging and
scoring nothing. It counts every request the rule would have matched there, including requests that other
rules refuse.

- Up to six exceptions on the same rule in one object are counted. A seventh shows a dash.
- An exception on a rule the installed rule set does not define shows a dash, and so does one still in a
  draft.
- The counter is written when the cluster is published, so an exception counts from the publish that
  carries its counter.

**A body longer than the engine reads.** HAProxy hands the engine as much of the body as its buffer holds:
about 15 kB of 16 kB (`tune.bufsize`). The rest would reach the backend unread, so an attack hidden after
enough padding would pass. Therefore:

- In `block` mode such a request is refused with a 413 and recorded `waf-body:deny`.
- In `log` mode it is served and recorded `waf-body:log`. This shows where large bodies arrive before you
  turn `block` on.
- `large_bodies` lists the paths that expect them - an upload, a large JSON call. Each covers itself and
  what lies under it, matched as an access rule's path is. There the request is served, with what fitted
  in the buffer inspected. `/` covers the whole object.
- That does not apply to a path with a `.` or `..` segment in it (`/upload/./x`, `/upload/../admin`),
  which a backend may resolve to somewhere else. Such a path is held to the limit like any other.
- A body that arrives too slowly is answered 408 after a second.

**A request the engine cannot read.** The rule set inspects what the engine took apart, so what it could
not take apart would pass as clean. The engine therefore judges these as it judges a rule set match:

- a body it could not parse (broken JSON or XML);
- a malformed multipart upload;
- more than 1000 arguments from one source - the query, the path or the body - since the rest would go
  uninspected;
- an address it could not parse.

In `block` mode such a request is refused with a 403 and recorded `crs:deny`. In `log` mode it is served
and recorded `crs:log`. The record carries the rule (1900xx), and *Findings* shows it as *Unreadable*.
These cannot be excepted, because what was not read cannot be narrowed to a field. A client that sends
such requests must be corrected, or its object stays in `log`. On a `large_bodies` path, a body cut off at
the buffer is not refused as unparseable, since its end never reached the engine. A whole body that does
not parse still is.

**When the engine does not answer** - stopped, restarting or overloaded - `on_engine_error` decides, and
either way the answer comes at once:

- `deny` answers 503 and records `waf-engine:deny`. This is the default: a WAF that lets requests through
  uninspected is no control.
- `allow` serves the request uninspected and records `waf-engine:log`. Choose it for an object where
  staying up matters more.

A node whose engine is not running, while the published release has rules, is marked *WAF engine stopped*
on the dashboard. `haprion-status` shows the engine on each node, with a warning for that node.

**The engine's log.** Each rule the engine matched is logged on the node, with the part of the request and
the matched value, in the engine's own journal (`journalctl --namespace=haprion-waf -u coraza-spoa`). It is
collected to the management host with the traffic log - a page of up to 20 000 lines per node and minute -
when the management host has a database. The matched value is the requester's own text: it is kept to
1024 characters and always shown as text. The part of the request is kept only when an exception could
name it. The deciding and reporting rules are not kept at all, since the traffic record already carries
the score and the decision.

**The engine's memory** is held to a share of the node's, so that HAProxy always keeps at least 60 %:

- Above 30 % (`MemoryHigh`), the engine is slowed down and made to give memory back.
- At 40 % (`MemoryMax`), it is stopped and restarted. While it restarts, `on_engine_error` decides what the
  object's requests get.

The share is taken of the memory the kernel sees when the service is loaded, so a node given more memory
gives the engine more after the engine's next restart. One object's rules take about 50 MB, and each
further object a few MB more. The dashboard shows each cluster's CPU and memory in use - the VIP owner's
figure, with every node's on hover - and marks a cluster when any node is at 85 % or more.

**Installation.** The engine and the rule set are two packages built from pinned sources (see
[the installation guide](install.md#the-waf-engine)).

- The engine package goes on the management host and on every node. The rule set goes on the management
  host only.
- Publishing compiles the rules on the management host before they leave it, and copies the rule set into
  the release's `waf/`. Every publish of a cluster with rules takes up the rule set installed at that
  moment, whatever the publish changes. A cluster therefore runs the rule set it was published with, and
  going back to an older version gives back that version's rule set.
- The form offers the engine on an object only when the manager and every node of its cluster have it.
  Otherwise the *WAF* group says where it is missing.
- A node starts the engine when a release carries rules, and stops it when one no longer does. It refuses
  a release with rules if the engine is not installed.
- The engine listens on `127.0.0.1:9520`. Nothing else on a node may use that port.

CRS is licensed under the Apache License 2.0 (https://coreruleset.org), as is Coraza.

## Certificates

Certificate tools, provider keys and trust are configured during installation. See
[The certificate registry](#the-certificate-registry),
[ACME configuration and challenge routing](#acme-configuration-and-challenge-routing)
and [Preparing Microsoft AD CS / NDES for CSR enrollment](#preparing-microsoft-ad-cs--ndes-for-csr-enrollment).

### Publishing certificates

A certificate reaches its clusters and receivers without a step of its own. Issuing it, importing it,
renewing it and *Publish to…* all end the same way: the certificate is published, and the clusters it
goes to are rolled out. After a Let's Encrypt renewal, certbot runs the deploy hook
`/etc/letsencrypt/renewal-hooks/deploy/50-haprion`, which platform step 14 installs. The hook runs
`haprion-cert-publish --deploy`.

**Seeing where a certificate is.** On *Certificates*, the *State* column says what the clusters' nodes
report carrying, for example *On all 4 nodes*, *Not on the nodes* or *Nodes hold an older copy*. Click a
row to open it. *Published to* then lists every cluster and receiver the certificate goes to. For a
receiver it also shows the day its copy was written, and *(older version)* when that copy is behind.

**When a target is behind.** If a target lacks the current copy, the open row's *State* has a
*Publish now* button. It publishes that certificate and rolls out its clusters, as
`haprion-cert-publish --certificate <id> --deploy` does below. If a cluster's nodes hold an older copy,
the button is *Deploy to nodes* instead, and it rolls that cluster out again. When several clusters are
behind, there is one *Deploy* button per cluster, each with the cluster's name. Both buttons are an
admin's, on an installation with `management_writes` on.

**How it works.** `haprion-cert-publish` is the one path from a certificate's source to every place it
is read. It runs as root. It takes no file, directory or account on its command line: the registry
says which certificates exist, where each comes from, and where each goes.

| Source | Read from |
|---|---|
| `acme` | `/etc/letsencrypt/live/<lineage>/` - `fullchain.pem` and `privkey.pem` |
| `import` | `/etc/haprion/certificates/<id>/` - the same two files, written by the import helper |

| Target | Written as | Owner and mode |
|---|---|---|
| a cluster | `<certificate_root>/<cluster>/<id>.pem` | `root`, the group that owns `certificate_root`, `640` |
| a receiver | `<path>/<id>/fullchain.pem` and `<path>/<id>/privkey.pem` | the receiver's `owner`, `600` |
| a receiver, `format: pkcs12` | `<path>/<id>/<id>.pfx` and `<path>/<id>/<id>.password` | the receiver's `owner`, `600` |

A cluster's file holds the private key followed by the full chain, which is the format HAProxy reads.
Each cluster has its own directory, so two clusters that carry the same certificate each get their own
file, and both are rolled out. For a receiver, the publisher makes the per-certificate directory
`<path>/<id>/` itself: owned by `root` with the receiver account's group, mode `750`.

**Nothing is left half-done.** Before the first file is written, every certificate is checked: it
parses, its private key belongs to it, and it has at least seven days left. All of its targets are
looked up first too. So a certificate that cannot be published leaves nothing behind.

Each file is written under a temporary name in its own directory, flushed to disk and renamed over the
previous version. A reader sees the old file or the new one, never a partial one. A file whose bytes
already match is not touched. That is why the command can run after every renewal, or by hand at any
time, without cost.

Only one publish runs at a time. A second run waits for the first rather than being refused, for up to
120 seconds; after that it is refused with `operation_locked`. Waiting is safe because the publisher
only writes what differs, so the second run does exactly the right thing after the first.

**PKCS#12 bundles.** A `.pfx` file comes out different every time the same certificate is exported,
because it is salted. So the publisher compares the certificate inside the bundle, not the bytes. The
password is made once per certificate and receiver, and kept across renewals. The receiver imported
the bundle into its certificate store with that password; a new password at every renewal would make
every renewal a manual re-import.

An `import` entry whose directory does not exist yet is reported as skipped, not failed, and its
published copy is left as it is. That is what a certificate placed in a cluster's directory by hand
looks like.

**Rolling out.** With `--deploy`, every cluster that received a new version is rolled out afterwards
with `haprion-cert-deploy`, once each, after every file is written.

`--deploy` also rolls out every cluster that an earlier run published to but could not roll out. The
files alone cannot show that: a cluster's PEM file is the same whether its nodes took it or not. So
the publisher keeps a note beside the registry, `certificates.pending-deploy.json`. A cluster is marked
in it before its material is written, and cleared only when `haprion-cert-deploy` succeeded for it
(exit code 0). Running the same command again after a failed rollout therefore finishes the rollout,
without issuing or rewriting anything. Without the note it would find the files in place and answer
`done`.

Adding a cluster to a certificate (*Publish to…*) marks the cluster in the same way. If the note
cannot be read, every cluster counts as due: each is rolled out once, its current nodes are skipped,
and the note is written whole again. A cluster removed from the configuration is dropped from it.

*Details:* `certificates.pending-deploy.json` has the registry's owner and mode. The lock is
`/run/haprion/locks/cert-publish.lock`. A receiver's PEM pair is two renames, not one; the reference
fetch scripts check that the two files they fetched belong together and fetch again on their next run
if they do not.

**From the command line:**

```bash
haprion-cert-publish                 # publish what changed, report per certificate
haprion-cert-publish --json          # the same, as a result envelope
haprion-cert-publish --deploy        # ... and roll out the clusters that changed or are still due
haprion-cert-publish --certificate example.com   # one registered certificate only
```

### Issuing a certificate

*New certificate* on the *Certificates* page opens the form. *Domain* becomes the certificate's name;
`*.example.com` also covers `example.com`. *Certificate authority and challenge* is one of four:

- *DNS-01* - Let's Encrypt, proved with a DNS record; wildcards included. *DNS profile* is the DNS
  profile it uses, chosen from the ones in effect ([The life of a profile](#the-life-of-a-profile)).
- *HTTP-01* - Let's Encrypt, proved through the webroot; single names only. It is greyed, with the reason
  beside it, while the runtime policy names no `acme.webroot`.
- *NDES* - the organisation's Microsoft AD CS; wildcards included. *NDES profile* is the NDES profile
  ([Enrolling and renewing through NDES](#enrolling-and-renewing-through-ndes)). Greyed while no profile is
  in effect.
- *CSR* - any CA. The key is made on the manager, and the signing request is downloaded from the row and
  signed elsewhere. *Key type* takes the profile's place ([Importing a certificate](#importing-a-certificate)
  says how the signed certificate comes back).

**Targets.** Under *Targets*, *Clusters and receivers* lists every cluster and every registered
receiver, each with a box; tick at least one. While the **Certificates for other hosts** switch is off,
the list is called *Clusters* and holds clusters only. A receiver also has a format: *PEM pair*, or
*PKCS#12 + password*, which publishes a `.pfx` and a `.password` file. With the switch on, *Targets*
also offers *Installed by hand*: a certificate with no targets, downloaded with its key
([Certificates installed by hand](#certificates-installed-by-hand)).

The form chooses among the receivers already registered. A new one is registered on the *Receivers*
page ([Registering a receiver](#registering-a-receiver)). The form refuses a wildcard over HTTP-01
before anything is queued, and a target it did not offer. The other two things HTTP-01 needs are in
[ACME configuration and challenge routing](#acme-configuration-and-challenge-routing).

**Sending it.** *Request the certificate* queues the job, and the page goes back to the registry. The
new row says *Requesting* until the CA has answered. If the answer is no, the row carries the CA's own
words. The Events page keeps the job's record, certbot's output included. The queue runs one
certificate job at a time; while one runs, the form says so and cannot be sent.

**How it works.** For DNS-01 and HTTP-01 the form queues one `cert_issue` job. The worker runs it
through `haprion-cert-issue-helper` ([worker helper configuration](#what-the-worker-may-run)).
`haprion-cert-issue` obtains one ACME certificate and takes it all the way to its targets: certbot,
then the registry entry, then the publish and the rollout of the clusters named. It runs as root only.
The whole run is timed and the time is part of its result, because the point of the command is that
number: a certificate on its targets in minutes, from one line.

**When it stops after certbot.** The lineage exists by then, so the run ends `failed`, never `blocked`.
If the registry does not take the entry - another certificate job held the lock for more than 120
seconds - the message says what to do with the lineage. If the publish does not start, the certificate
is issued and registered: *Needs attention* says *Certificate issued; distribution failed*, and
*Publish now* on the certificate's row finishes it.

The ACME account is the one certbot already has on this host; the command registers none. The
certificate becomes an ordinary certbot lineage. It is renewed by `haprion-certbot-renew.timer`, which
runs twice a day, and published by the deploy hook described in
[Publishing certificates](#publishing-certificates), like every other.

The registry file is rewritten as a whole. Its owner and mode are kept, and the new version is loaded
back through the engine before it replaces the old one. Comments in the file do not survive the first
write by the program; the file's header says so.

**From the command line:** `--dns-profile` names the DNS profile to use. Leave it out only on an
installation whose runtime policy still names a Cloudflare credential file
(`acme.dns_cloudflare_credentials`); otherwise DNS-01 is refused without it.

```bash
sudo haprion-cert-issue --domain www.example.com --method dns-01 --dns-profile cf-main --cluster alpha
sudo haprion-cert-issue --domain '*.example.net' --method dns-01 --dns-profile cf-main \
  --cluster alpha --receiver lb-01.example.net
sudo haprion-cert-issue --domain intranet.example.com --method dns-01 --dns-profile cf-main \
  --receiver certserver1.example.net --format certserver1.example.net=pkcs12
```

The ACME policy and challenge routes must already be configured; see
[ACME configuration and challenge routing](#acme-configuration-and-challenge-routing).

### The life of a profile

A profile holds one DNS provider's credentials under a short ID you choose, such as `cloudflare-main`
(lowercase letters, digits and hyphens, at most 32 characters). The ID is the profile's name
everywhere: in the certificate form's choice list, in the credentials file, and in `--dns-profile` on
the command line. So pick one that reads well when typed from memory.

An administrator makes and retires profiles at **Certificates → DNS profiles** (`/dns-profiles`), or
with `haprion-profiles` on the manager (below).

**Saving a profile.** When you save or replace a profile, the web process encrypts the values within
that same request, with the manager's public key, and queues a `dns_profile_apply` job. Only a root
helper can open them. It checks them against the list of supported providers and writes the
credentials file that certbot reads. The page waits a few seconds for that job, so on an idle queue the
new row shows **In effect** straight away. If the job takes longer, the row says **Applying** and the
page refreshes itself until the file is written.

Only one certificate job runs at a time. While another certificate job is queued or running, saving is
refused: wait for it to finish on the Events page, then save again.

Only a profile whose current version has been applied is offered when a certificate is issued. The
status column reads:

| Status | Meaning |
|---|---|
| In effect | the file certbot reads holds what the row holds; the certificate form offers it |
| Applying / Removing | its job is queued or running |
| Apply failed | the helper refused it - the Events page has its account, without the values |
| Replaced; not applied | a newer version was saved, and no apply job has been run for it |
| Remove failed | a removal failed for another reason than the profile being in use; it is no longer offered |
| Not applied | no apply job for the row was found at all |

A removal that was refused because something still uses the profile does not change the status: the
profile stays **In effect**, and the row adds a **Removal refused** link to the job. The link shows for
an hour, and goes away once nothing names the profile any more.

The values themselves are never shown again. To change one, **Replace** re-enters every value. The new
values become the next version and are applied by a job of their own.

**Removing a profile.** **Remove** uses the same helper. It is refused while the certificate registry
or a certbot renewal file (`renewal/*.conf`) still names the profile. The profile is deleted from the
database only after the helper has removed it successfully.

A certificate issued through a profile also renews through it. Certbot writes the profile's
credentials path and the provider's propagation wait into the lineage's renewal settings, and
`haprion-cert-renew` ([The certbot environment](#the-certbot-environment)) restores what a certbot
plugin cannot store there itself. Removing a profile that a certificate still renews through would
break that renewal, which is why the registry and the renewal files are checked first.

If a profile is missing or unreadable anyway, only its own certificates stop renewing. The renewal
run, which `haprion-certbot-renew.timer` starts twice a day, names each of them, renews the others,
makes the NDES pass, and ends with an error.

*Details:* the helper takes no arguments. It reads the sealed row, checks that profile, provider, key
and version all match, and writes a `0600 root:root` credentials file plus root-only metadata under the
directory the runtime policy names, in one atomic step. The database row is deleted only after the
helper's successful result for that same version.

**From the terminal**, `haprion-profiles` does the same for DNS and NDES profiles, as root. Each
profile the file lists is encrypted with the same code as the form, against the same key, stored the
way the page stores it, and applied by the same job.

- The stored values cannot be compared with the file once they are encrypted. So a stored profile is
  left as it is, unless `--replace <id>` asks for it or, for NDES, the endpoint differs. Running the
  same file twice changes nothing.
- A DNS profile keeps its provider. Another provider means another ID.
- An NDES profile's `endpoint` must be a server confirmed on the manager
  ([Adding an NDES server](#adding-an-ndes-server)); the file is refused otherwise.
- `--prune` removes the stored profiles of a kind the file lists but does not name. `remove` removes
  one. A removal is refused for the same reasons as on the page.
- Only one certificate job runs at a time. So the command queues each change, waits for the worker to
  finish it (`--wait`, 120 seconds by default), and stops at the first change that did not apply. It
  is refused with `operation_locked` while another certificate job is running.
- The file carries credentials. It is refused unless only its owner may read it (mode `0600`).

```yaml
dns_profiles:
  - id: cloudflare-main
    provider: cloudflare
    fields: {api_token: "from the vault"}
ndes_profiles:
  - id: internal-ca
    endpoint: https://ndes.example.com/certsrv/mscep/mscep.dll
    challenge: "from the vault"
```

```bash
sudo haprion-profiles apply profiles.yaml --check
sudo haprion-profiles apply profiles.yaml --json
sudo haprion-profiles remove dns cloudflare-old
sudo haprion-profiles list --json
```

### Deleting a certificate

A deletion can remove a certificate that a cluster is serving. Nothing else in this project removes
certificate material, and the helpers say so in their headers. The cleanup exists anyway, because a
registry that only grows is not caution. After a few years it holds hundreds of certificates that
expired or stopped mattering, and without a way to remove them the registry becomes unusable.

**Where it is.** The registry view on *Certificates* (*All certificates*, `/certificates?view=registry`)
has a box on every row for an admin, on an installation with `management_writes` on. Below the list
is a row of buttons, each grey until something is ticked:

- *Publish to…* and *Remove from…* - add a target or take one away
  ([below](#publishing-to-another-target-and-withdrawing-from-one));
- *Renew…* - wakes for exactly one ticked row ([Importing a certificate](#importing-a-certificate));
- *Export…* - wakes for one row of a certificate installed by hand, and only while the
  **Certificates for other hosts** switch is on ([Certificates installed by hand](#certificates-installed-by-hand));
- *Delete selected…* - the deletion.

*Delete selected…* leads to a confirmation page that says, per certificate, what deleting it means.
Confirming queues one `cert_delete` job for the whole selection, at most 32 certificates at a time.
One job, not one per certificate: a cleanup of seventy rows must not become seventy jobs.

**What one deletion does.** Four layers, in this order, for each certificate in the job:

| Layer | What goes |
|---|---|
| 1. the material | `<certificate_root>/<cluster>/<id>.pem` in every cluster, and the files in every receiver directory the entry named |
| 2. the source | `certbot delete --cert-name <lineage>` for `acme`; `/etc/haprion/certificates/<id>/` for `import` |
| 3. the registry entry | the certificate stops being published |
| 4. the node copies | each node of every cluster the entry named is asked `cert-remove <id>` over the trigger identity |

Why this order:

- The source goes in step 2 because a dead certificate would otherwise renew forever.
- The registry entry goes only after the material and the source. An entry that outlives its material
  is a certificate the next run can finish deleting. An entry that went first would leave material
  nothing can find again.
- The node copies come last. They are the one layer that may be left behind. A node is asked by the
  certificate's name, so it needs no registry entry.

The whole job holds the publisher's lock (`/run/haprion/locks/cert-publish.lock`), as issuing,
publishing and target changes do. The renewal timer publishes outside the job queue. Without the lock,
a renewal between the layers could put a still-registered certificate's material back, or leave a
deleted one's node copies behind. Under the lock, the layers are one step as far as the renewal is
concerned.

**A deletion can be run again.** Every layer can be repeated safely and reports `absent` where there
was nothing to remove. A layer can fail: certbot refuses, a file cannot be removed, a node is
unreachable or does not know the request. The failure is reported on the certificate's row, and the
registry entry stays as long as a layer above it failed. Deleting the same selection again picks up
where it stopped.

A certificate that is no longer registered is still looked for by name: its PEM file, a lineage of the
same name, its import directory and the copy on every node of every cluster. Only a certificate that
nothing holds anywhere is refused, as `not_registered`. A row is gone from the registry view once its
entry is deleted, so node copies left behind after that are finished from the terminal, with
`haprion-cert-delete <id>` (below). The confirmation page answers such a name with *Not in the
registry; nothing to delete.*

**The guards.** A certificate is refused, with nothing touched, when:

- a proxy object in a cluster's committed configuration still names it;
- it is a cluster's `default_certificate`;
- it is the only certificate of a cluster it is published to - a cluster that names no certificate
  cannot be loaded, so its next publish would be refused;
- another registry entry has the same certbot lineage as its source - the lineage is removed whole, so
  it must be this entry's alone;
- it serves the manager's own interface (`serves_interface`; see
  [From the certificate registry](#from-the-certificate-registry));
- a draft in the interface's database still names it.

A refused certificate stops nothing else in the batch: it is reported on its own row, and the others
go through. The job's outcome is:

- `done` when every certificate went;
- `partial` when any was refused or left a layer behind;
- `blocked` when every certificate was refused;
- `failed` when nothing at all went.

**Drafts.** The draft check is the web's. It is made on the confirmation page, and again when the job
is queued. If a draft names a certificate after the confirmation page was drawn, confirming is refused:
the page asks again with the draft shown on the row, and nothing is queued until you confirm what it
now says. The worker cannot read drafts, so a draft written after the job was queued is the one gap
left. Its publish then fails on a missing file, which can be fixed.

**What is left behind, and said.** A node whose trigger does not know the `cert-remove` request yet
answers "unknown request". The copy is then reported as kept, per node. The file does no harm there:
HAProxy loads certificates through lists of certificate files, and a PEM file no list names is never
loaded. So an installation can delete certificates before its nodes have the current node package, and
the job says which node still holds what.

On the node, the script refuses to remove a certificate that any installed certificate list,
`haproxy.cfg` or `conf.d` fragment names. It is the same guard as the manager's, measured against what
the node actually serves rather than what is committed. It does not reload HAProxy, because nothing
changed for HAProxy.

**Nothing here can be undone.** A deleted lineage has to be issued again, and a deleted import has to
be imported again. The confirmation page says so, and the job's rows say what went.

*Details:* the worker runs inside a sandbox that may only write to listed directories.
`07-platform-services` creates the import store `/etc/haprion/certificates` (root, `700`) before it
writes the worker unit, because the unit lists that directory as writable and requires it to exist. If
the directory is missing, the worker does not start rather than silently losing access; rerun step 7.

**From the terminal**, `haprion-cert-delete` sends the same request to the same helper, as root, and
prints its rows (`--json`: the helper's envelope). A certificate already gone, refused as
`not_registered`, counts as deleted. The command exits 0 when every certificate was removed or was
already gone, so running it again is harmless. It does not read the interface's drafts: publish or
discard a draft that names the certificate first.

```bash
sudo haprion-cert-delete old.example.com stale.example.net --json
```

#### Publishing to another target, and withdrawing from one

Two more buttons under the registry, *Publish to…* and *Remove from…*, answer the two questions short
of a deletion: a certificate that should also go to another cluster, and one that went to a cluster
(or a receiver) it should not be on. Each leads to a page that offers only the targets the change
would touch. For a publish, that is the targets some chosen certificate is not on yet; for a removal,
the targets some chosen certificate is on. Confirming queues one `cert_target` job for the selection
and that one change.

The job applies the change to each certificate as the registry holds it when the job runs. So thirty
certificates sent to the wrong cluster are one job. And a certificate somebody else changed in the
meantime is not overwritten with an old list of targets.

**Publishing** adds the target to the certificate's registry entry, publishes the material there, and
rolls each added cluster out once with `haprion-cert-deploy`. Its nodes fetch the certificate and
**replace it in the running HAProxy** (`set ssl cert`, no reload). They reload only where HAProxy does
not hold the certificate yet, or refuses the new one. A receiver fetches on its own schedule. A
certificate already on a chosen target is reported `unchanged`.

**Removing** takes the target off the registry entry and removes the copy that target held:

- each node of a removed cluster is asked `cert-remove <id>` over the trigger identity. There is no
  reload: a file nothing names is not loaded;
- for a removed receiver, this certificate's files in the receiver's directory on the manager are
  deleted, together with the certificate's own directory there. Every certificate has its own
  directory under a receiver, so the receiver's other certificates are not touched. What the receiver
  host already fetched stays there; the manager cannot reach into it.

Nothing else is touched: not the material for the remaining targets, not the lineage, not the entry.

**The guards are the deletion's, limited to the removed cluster.** A certificate is refused, with
nothing touched, when:

- a proxy object in *that* cluster's committed configuration still names it;
- it is that cluster's `default_certificate`;
- it is the only certificate that cluster has;
- a draft in that cluster names it (the web's check, as for a deletion).

An object in another cluster does not hold the certificate back. A refused certificate stops nothing
else in the batch, and the job's outcome follows the rows the way a deletion's does. A node that kept
its copy makes the row `incomplete`: the registry has changed, and running the removal again asks the
node again.

**From the terminal**, `haprion-cert-target` sends the same change to the same helper, as root. A
certificate already as asked is `unchanged`, so the command can be run again. `--format` says how a
receiver added here is written, and `--no-deploy` publishes without rolling the clusters out. Like
`haprion-cert-delete`, it does not read the interface's drafts.

```bash
sudo haprion-cert-target add shop.example.com api.example.com --cluster beta
sudo haprion-cert-target remove shop.example.com --cluster alpha --json
```

### Importing a certificate

`haprion-cert-import` brings in a certificate issued elsewhere, whose key you already hold: from an
internal CA, a purchased certificate, or a wildcard exported from a Windows CA. It runs as root only.
Like `haprion-cert-issue` it goes all the way: the import store, the registry entry, the publish and
the rollout of the clusters named.

```bash
sudo haprion-cert-import --id intranet.example --certificate intranet.example.crt --key intranet.example.key \
  --chain issuing-ca.pem --cluster alpha
sudo haprion-cert-import --id intranet.example --pkcs12 intranet.example.pfx --password-file /root/intranet.example.pw \
  --cluster alpha
```

**What is read.** PEM files, or one PKCS#12 file (`.pfx`/`.p12`) holding everything.

- The PKCS#12 password is read from the first line of a file, never from the command line, where every
  user on the host can read it (`ps`).
- An encrypted PEM key is refused. Decrypt it first with `openssl pkey`: a passphrase the publisher
  would have to know is a secret kept in a second place.
- Bag attributes and comments between blocks are dropped, so a Windows export is read as it is.

**What is checked before anything is written.**

- The material is split into blocks. The leaf is the one certificate whose public key matches the key,
  so a chain handed over in the wrong order, or a PKCS#12 with the CA certificates first, comes out
  right.
- A key that belongs to no certificate is refused (`key_mismatch`).
- The chain is followed by issuer from the leaf upward. A self-signed root is left out: clients have it
  already, and serving it adds nothing.
- A certificate that has already expired is refused (`expired`).
- An ID certbot has a lineage for (`already_exists`), an ID registered as `acme` (`not_import`), and an
  unknown cluster or receiver are refused too.

None of these refusals leaves anything behind.

**What is written.** First `/etc/haprion/certificates/<id>/` with `privkey.pem`, `cert.pem`, `chain.pem`
and `fullchain.pem`, root-only, in one rename. These are the same four files certbot's `live/`
directory holds, so the publisher and the listing read both sources the same way. Then the registry
entry, `source.kind: import`, with the targets named. Then the publish of that one certificate and the
rollout of its clusters, exactly as after an issue.

Once the material is written, a stop is `failed`, not `blocked`. If the registry does not take the
entry - another certificate job held the lock for more than 120 seconds - import again. If the publish
does not start, the certificate is imported and registered, and *Publish now* finishes it.

**Importing again.** Importing the same ID a second time replaces the material - a rotated key, or a
renewed certificate from the same CA - and keeps every target the entry has. Targets named on the
second import are added to them; they never replace them. Taking a target away is *Remove from…*
([Deleting a certificate](#deleting-a-certificate)). The manager does not renew an imported
certificate. Its expiry date is on the registry view, and importing a new one before that date is up
to you.

**From the interface.** *Certificates → Import certificate* takes the same material as a file: PEM
(certificate, key and chain in any order), PKCS#12 with its password, a DER certificate or a PKCS#7
bundle, at most 32 kB, plus the name and the targets.

The web process encrypts the file within the request that carries it, with the installation's public
key - the key pair platform step 15 creates for DNS profiles. It then queues a `cert_import` job that
carries only the encrypted file. The worker runs `haprion-cert-import-helper`, which opens the file
with the private key and imports the material exactly as the command does. So the key is readable in
the web process for the length of one request, and in the root helper. It is never in the database,
the job row or the audit record, and none of those can reach the private key. That is a narrower
promise than "the web never sees a key". If you want the key to stay off the web entirely, use the
command-line import.

The encrypted file stays in the finished job's row for a day. `haprion-retention prune` then removes it
and keeps the row as the record of the import. A database dump taken before that holds the encrypted
copy until the dump is rotated out (seven days); opening it takes the installation's private key.

**A certificate without a key.** A file without a key is accepted for a name whose key the manager
already holds. That covers an imported certificate renewed on the same key, and the certificate a CA
returns for a signing request made here. *Renew…* under the list, with that row ticked, takes exactly
this: the certificate only. A file holding a key, in any format, is refused there and pointed to the import page,
where replacing the key is the stated intent. Enrollment from a Microsoft CA needs no file at all
([Preparing Microsoft AD CS / NDES for CSR enrollment](#preparing-microsoft-ad-cs--ndes-for-csr-enrollment)).

**A CA certificate for the pools.** *Import certificate → CA certificate* takes a CA's certificate,
without a key, and the clusters whose pools may verify servers against it. It is for a pool that reaches
its servers over HTTPS and checks their certificates, when your own CA issued them
([A pool over HTTPS](#a-pool-over-https)). It may hold several: a
root and its intermediates, or an old root beside its successor while servers move over.

- *Upload* takes a file in the forms above. A key in it is refused.
- *The NDES CA* takes the CA certificates of every confirmed NDES server, each once: those the
  NDES profiles' certificates are signed by, read by root on the manager.

Every certificate in the file must be a CA (`basicConstraints CA:TRUE`). A server certificate is
refused (`not_authority`), and so is a file in which every certificate has expired.

The registry holds it as `source.kind: authority`, and the import store holds it as `fullchain.pem`
alone. Each cluster gets it as `ca/<id>.pem` in its directory under the distribution root. The nodes
fetch it into `/etc/haproxy/certs/ca/` (the trigger's `ca-pull`), beside the certificates and not among
them. They reload only when an installed pool names it.

On *Certificates* its row reads *CA*, *Used by* lists its clusters, and the state says which nodes
carry it. Imported again under the same name, it replaces the file and keeps the clusters. A CA that a
committed object or a draft names cannot be deleted, or taken off that object's cluster. From the
terminal:

```bash
sudo haprion-cert-import --id corp-root --authority corp-root.pem --cluster alpha
sudo haprion-cert-import --id corp-root --ndes-ca --cluster alpha
```

A node whose package does not know `ca-pull` answers *unknown request*. The rollout to that node then
fails until its node package is updated.

**Renew…** is one button for every source. Tick exactly one row:

- on a certbot certificate, it runs the renewal timer's `certbot renew --cert-name <lineage>` now, with
  `--force-renewal` (`haprion-cert-renew --acme-now <id>` from the terminal). Let's Encrypt issues at
  most five identical certificates a week;
- on an NDES certificate, it enrolls again from the same profile, with the same names and targets
  ([Preparing Microsoft AD CS / NDES for CSR enrollment](#preparing-microsoft-ad-cs--ndes-for-csr-enrollment));
- on an imported certificate, or a signing request waiting for its certificate, it is the page with
  the file field.

**A signing request made here.** Some CAs the manager cannot talk to: a purchased certificate, an
internal PKI without SCEP, anyone else who signs. For those, the key can be made on the manager instead
of imported:

```bash
sudo haprion-cert-request --id intranet.example --domain intranet.example --domain '*.intranet.example' \
  --cluster alpha [--key-type ec-p256|rsa-2048|rsa-4096]
```

- `--id` is the certificate's name in the registry.
- The first `--domain` is the CN. It cannot be a wildcard. Each further `--domain` is an extra name
  (SAN), and a wildcard goes there.
- EC P-256 is the default key type. Choose RSA only for a CA that requires it.

The command writes `/etc/haprion/certificates/<id>/privkey.pem` (root-only, never printed), with
`request.csr`, `request.json` and `targets.json` beside it, and prints the CSR.

The request is *not* in the registry yet: an entry without material would make every rollout to its
clusters fail. The listing shows it from the store instead, as **Awaiting signature**, with a
*Download CSR* button on the row. The name is refused while anything else holds it: a registry entry,
a certbot lineage, imported material, or an NDES request in progress.

When the CA has signed, the certificate comes back without a key. Use `haprion-cert-import --id <id>
--certificate <file> [--chain <file>]` with no `--key`, or *Upload certificate…* on the row. The
certificate is matched against the stored key, imported, and published to the targets the request
named, plus any named now. A certificate for another key is refused, and the request is kept.

Deleting the row ([Deleting a certificate](#deleting-a-certificate)) removes the key with it.
Otherwise a request nobody signs does no harm, and stays until it is deleted.

In the interface the same thing is the fourth choice on *New certificate*, **CSR**, with the key type
where the other methods have their profile. There the *Domain* field gives both: its base name is the
CN and the certificate's name, and a wildcard becomes an extra name beside it. It queues a
`cert_request` job, which the worker runs through `haprion-cert-request-helper`. Its sudoers rule and
platform step 07 are part of the release.

### Enrolling and renewing through NDES

Once an NDES server is confirmed and an NDES profile on it is in effect, root enrolls a
certificate from the terminal with:

```sh
haprion-cert-scep --id example-cert --profile internal-ca --domain example.test --domain '*.example.test' --json
```

**When the CA holds the request for approval**, the command returns `state: pending` with the outcome
`partial`. The certificate is **not** registered yet. The registry names only certificates that
exist, because each cluster's certificate list and the checks before a rollout are built from it, and
an entry without material would make every rollout to its clusters fail.

The request is kept in root-only state instead: the key, the profile, the names and the chosen
targets. The listing reads it there, so the row shows as **Request pending** all the same. Resume with
`haprion-cert-scep --id <id> --resume`. The original key is kept, the targets are the ones the request
was made with, and a resume that disagrees with the record is refused.

A returned certificate must pass checks of its chain, names, key usages and key before it goes through
the normal import and publish path. Only then is the certificate registered and published.

**When a request ends without a certificate.** A request the CA rejects, or one Certmonger never took,
removes its own state, so the same ID can be requested again. A request that is neither answered nor
rejected - the approval is not coming, or the process died - is given up with *Abandon request…* in
the registry's button bar, or `haprion-cert-scep --id <id> --abandon`. Both discard the key. Deleting the
certificate removes its request state too.

A waiting request is bound to its profile as it was: its revision, its server and that server's CA. A
profile is therefore not replaced while one of its requests waits. The profile's row then says **Apply
refused**; abandon the request, or let it finish, and save the profile again. A resume that finds any of
them changed names what changed, and is refused. The certificate's row then says **Renewal failed**, and
*Abandon request…* gives the request up from there too.

A row keeps *Resume enrollment* and *Abandon request…* for as long as the CA holds a request for its ID,
whatever its label. While a job runs on the row, *Resume enrollment* waits for it to end. A **Renewal failed** row may hold one because the CA did not answer in time; a resume
then finishes it, or says what changed. A file imported over an NDES certificate does not end its request
either: the row shows it as **Renewal pending** until it is resumed or abandoned.

**Scheduled renewal.** `haprion-certbot-renew.timer` runs `haprion-cert-renew` twice a day. After
certbot's renewals, it makes an NDES pass. It renews every registered certificate whose source names an
NDES profile and whose expiry date (`not_after`, read at its source) is less than `ndes.renew_days`
away (30 by default). It enrolls the certificate again:

- under the same ID and with the same profile;
- with the names the current certificate carries (CN first);
- to the targets the registry holds.

It is the same request as a first enrollment, with a fresh key. The published material is replaced
only once the new certificate has been checked. If the CA holds the request, the row says **Renewal
pending**, with the same *Resume enrollment* button, and the next pass resumes that request rather than
asking again.

One record per certificate under `<state_root>/renewals/` says what the pass's last attempt did. The
listing shows a failure as **Renewal failed**, with the CA's sentence, rather than letting the expiry
date creep closer. The record is about the certificate the pass tried to renew. It ends when a new
certificate is imported, or the CA takes a request for it, whichever way that was asked for: the pass,
*Renew…*, *Resume enrollment* or `haprion-cert-scep`. Abandoning the request or deleting the certificate
removes it too. A pass that finds another enrollment running for the certificate skips it and asks
again next time.

**Renewing by hand.**

- `haprion-cert-renew --ndes-now <id>` renews one NDES certificate at once, due or not, and skips
  certbot's renewals. Use it to test the path on a certificate template whose validity cannot be
  shortened per request, or to rotate a key.
- `--acme-now <id>` does the same for a certbot lineage, forced. It skips certbot's normal renewal of
  the other lineages, but the NDES pass still runs as usual.
- `--dry-run` says which certificates would renew.

The interface's *Renew…* renews the same way as `--acme-now` or `--ndes-now`, depending on the source.
Its outcome is its job's. While the CA holds a request for an NDES certificate, *Renew…* points to the
row's *Resume enrollment* instead, which is what `--ndes-now` does then.

**From the interface**, *Certificates → New certificate* offers *NDES* beside the two Let's Encrypt
challenges. It is greyed while no NDES profile is in effect. A wildcard domain becomes the base name as
CN, with the wildcard as an extra name (SAN). The submission is one `cert_scep` job, run by
`haprion-cert-scep-helper`; its sudoers rule and platform step 07 are part of its installation. A
pending request shows **Resume enrollment** in its registry row, which queues the same job with only
the ID.

A certificate the CLI enrolls is registered as `source.kind: import`, with `source.ndes_profile`
naming the profile whose challenge enrolled it. The interface shows such a certificate as **NDES**
rather than **Imported**.

Removing a profile (*Certificates → NDES profiles → Remove*) runs one job that deletes the root-only
record and then the row. It is refused while the registry still names the profile, or while an
enrollment request under `state_root` is still tied to it. A refused removal leaves the profile in
effect.

### Certificates installed by hand

Some devices that want a certificate will never be connected to this manager: a server's BMC, a NAS, a
printer, a camera, a UPS card. For those, the manager is where the certificate is ordered and taken
out, and you install it by hand. This is behind the **Certificates for other hosts** switch, together
with the receivers.

**Making one.** *New certificate* → *Installed by hand* (the switch under *Targets*). It is the same
form, for one host name and with no targets.

- DNS-01, HTTP-01 or NDES; not CSR, because the point is a key that can be handed out.
- The key is RSA 2048, which every device takes; several take no EC key.
- A wildcard is refused: its key would answer for every name under it.

From the command line, use `haprion-cert-issue --exportable` or `haprion-cert-scep --exportable`, with
no `--cluster` and no `--receiver`.

The registry marks the entry `exportable: true`. The mark is set when the entry is made and never
changes. An exportable entry can never be given a target: *Publish to…* refuses it. So a certificate
HAProxy or a receiver carries is never one whose key can be downloaded. Renewal works as for every
other certificate from the same source - the renewal timer or the NDES renewal - and keeps the mark.
Installing the renewed certificate on the device is up to you.

**Taking it out.** Tick the row and press *Export…*. It is an admin's, and wakes for one such row and
no other. The page offers two zip files, one click each:

- `<name>.zip` - the certificate, the chain, and both together, as PEM. A device that takes one file
  wants the one with both. One that asks for the certificate and the issuer separately wants the other
  two.
- `<name>.with-key.zip` - the same, plus the private key:
  - as PEM, for a device that takes certificate and key as two files (Supermicro's BMC, for one);
  - as two PKCS#12 bundles, under a password made for this download and written beside them.
    *Modern* is what OpenSSL writes today: AES-256, PBKDF2, a SHA-256 MAC. *Compatible* is 3DES with
    a SHA-1 MAC, for older Windows, Java and embedded readers. It is not OpenSSL's `-legacy`, whose
    certificate part is 40-bit RC2.

**After a renewal.** The row says which version was last taken out, by whom and when. It reads
*Installed by hand* while that is the version the manager holds, and *New version not downloaded* once
the certificate has been renewed since; that also appears under *Needs attention*. "Taken out" is all
it can say: nothing here sees the device, so checking that the device got it is still yours. A
certificate taken out before downloads were recorded reads *No download recorded*, and is not raised.

**How the key is protected.** The key is read by `haprion-cert-export-helper`, which runs as root on
`/run/haprion/cert-export.sock`. Only the web account may connect to that socket. The helper refuses
every entry without the mark, writes nothing, and logs what it exported for whom
(`journalctl -u 'haprion-cert-export-helper@*'`). The web writes a `certificate_export` audit event
with the certificate's fingerprint, and a `certificate_download` event for the zip without the key.
Nothing keeps a copy. The password is never stored: it is made for the download and exists only in the
zip. Root at the terminal can ask the helper directly, with the same request document.

Not every device can take a key at all. HPE iLO makes its own key and asks for its CSR to be signed;
the manager does not sign an uploaded request - see [What it does not do](#what-it-does-not-do).

### Registering a receiver

A receiver is a host outside the clusters that fetches certificates from the manager on its own
schedule, each with its own account, directory and key. Receivers are behind the
**Certificates for other hosts** switch ([Features and advanced configuration](#features-and-advanced-configuration)).
With the switch on, *Receivers* on the *Certificates* page lists them, with *Receiver*, *Transport*,
*Account* and what each *Holds*. An admin registers, changes and removes them there.

*Register a receiver* opens the form:

- *Receiver* is the fetching host's DNS name or address. Access is locked to it: a key used from
  another host is refused.
- *Transport* is one of:
  - *rsync* - Linux hosts with rsync; the key is locked to one read-only directory;
  - *sftp* - any host with an OpenSSH client, Windows included; locked into its own directory
    (chrooted), read-only;
  - *https* - no key: a list of allowed addresses, under the interface's own certificate. It can hold
    any certificate, wildcards included.
- *Public key*, for rsync and sftp, is the one line from the `.pub` file the host's own `ssh-keygen`
  wrote. Above the field are the commands that make the key pair on the host and print its public
  half, for Linux and, with sftp, Windows. The private half never leaves the host.
- *Allowed addresses*, for https in place of a key, are the addresses or networks, one per line, that
  may fetch.

*Register the receiver* queues one job, which takes a few seconds; the queue runs one certificate job
at a time. For an https receiver the next page, headed *Password for* and the receiver's name, shows
its password once, with the commands that store it on the host.

The new receiver's row has *Fetch commands*: what its host runs to fetch, for Linux and, where the
transport allows it, Windows. The account, the manager's name (the interface's `SERVER_NAME`) and each
certificate it holds are filled in. The fetch is safe to run again and again, from a timer. You then
publish a certificate to the receiver from the registry with *Publish to…*, or choose the receiver on
*New certificate*.

On a receiver's row:

- *Replace SSH key* (rsync and sftp) takes a new public key, for a host that was installed again.
- *New secret* (https) makes a new password and shows it once.
- *Remove* is offered once no certificate names the receiver. One that is *in use* is first taken off
  its certificates with *Remove from…* in the registry.

The form takes the name, the transport and the key or the addresses, and nothing else. The account
name is made from the receiver's name, and the directory goes under `receiver_root`, as below. A
receiver whose account name would be too long, or that needs a name of its own or a directory
elsewhere, is registered from the command line with `--owner` or `--path`. The command creates the
account, so `--owner` must name one that does not exist; a name already in use is refused.

**From the command line.** A receiver is four things at once: an account, a directory only that
account may read, a lock that binds its key to that directory, and the registry entry.
`haprion-cert-receiver` makes all four, or none:

```bash
# The receiver makes its own key pair and sends you the public half.
sudo haprion-cert-receiver add lb-02.example.net --transport rsync \
  --public-key /tmp/lb-02.pub

sudo haprion-cert-receiver add lb-03.example.net --transport sftp \
  --public-key /tmp/lb-03.pub --owner crx-lb-03

sudo haprion-cert-receiver add 192.0.2.40 --transport https --allow 192.0.2.0/24 \
  --show-password
sudo haprion-cert-receiver secret 192.0.2.40 --show-password   # the old one stops at once
sudo haprion-cert-receiver key lb-02.example.net --public-key /tmp/lb-02-new.pub

sudo haprion-cert-receiver list
sudo haprion-cert-receiver remove lb-02.example.net
```

**The account name** is `crx-` followed by the ID, with its dots turned into dashes
(`crx-lb-02-example-net`). *crx* stands for *certificate receiver*, a prefix nothing else on the
machine uses, so `ls -l` under the receiver root names the receiver. Linux limits an account name to
32 characters. An ID that would not fit is refused rather than cut short, and `--owner` names the
new account instead: two long IDs must never quietly become one account. An `https` receiver has no
account of its own; nginx serves it.

**The ID is the fetching host**: its DNS name or its IPv4 address, and nothing else. That is what the
access lock is bound to: `from=` in the account's `authorized_keys` for rsync and sftp. An https
receiver is held to its *Allowed addresses* (`--allow`) and its password instead.

**The key line carries both the name and its addresses**, for example
`from="lb-02.example.net,192.0.2.10"`. The reason: sshd's `UseDNS` setting is off by default, and then
`from=` matches addresses only. A lock naming the host alone would refuse the very host it was issued
for, and the log would say *correct key but not from a permitted host*. The address is what sshd always
has; the name is what an operator reads, and what `UseDNS yes` would match.

- The addresses are looked up once, at registration. A host that changes address is removed and added
  again.
- A name that does not resolve is refused, because there would be nothing to write into the lock.
- The reverse (PTR) record is not looked at. One address commonly carries several names in a zone -
  the host's own and one per service - and whichever of them the reverse lookup answers with, the
  address half of the lock admits the host.
- An IPv6 address is not accepted as an ID: the ID is also a directory name and part of a URL path,
  and `:` fits neither. A host that fetches over IPv6 is registered under its DNS name, and its IPv6
  address goes into `from=` with the rest.

**A host installed again keeps its receiver.** *Replace SSH key* on its row
(`haprion-cert-receiver key`) takes the new public half and changes nothing else. The directory, the
certificates it fetches and the `from=` it was registered with stay. The old key stops working once
the job is done.

**Where the directory goes** is `receiver_root` in the runtime policy. A new receiver's directory is
`<receiver_root>/<id>` unless `--path` names another. The registry, not the root, says where each
receiver actually is. So the root is optional until the first `add`, which is refused with
`dependency_unavailable` until it is set.

**The private key is never given to the manager.** The key pair is made on the receiver
(`ssh-keygen -t ed25519`), and `--public-key` takes the `.pub` file. A private key that passed through
the manager has passed through one machine too many.

| Transport | How it fetches | What holds it there |
|---|---|---|
| `rsync` | `rsync` over ssh | `restrict,from="<id>,<addresses>",command="/usr/bin/rrsync -ro <path>"` - one directory, read-only, no shell |
| `sftp` | `sftp`, read-only | the same key line without the forced command, plus a `Match User` block with `ChrootDirectory <path>` and `ForceCommand internal-sftp -R` |
| `https` | `GET` with the receiver's own password | an address whitelist in nginx and the password, both required (`satisfy all`) |

The rsync account has `/bin/sh` as its login shell, because OpenSSH runs a forced command
(`authorized_keys command="..."`) through that shell with `-c`. The shell gives no interactive login:
the key still carries `restrict`, `from=` and the fixed `rrsync -ro` command, and no unrestricted key is
installed. An sftp account keeps `/usr/sbin/nologin`, because `internal-sftp` is sshd's built-in server
and needs no shell.

**https is a deliberately lower level of trust.** A password is not a key pair. What such a receiver
may hold - a wildcard, a certificate the clusters serve - is your decision, not the program's. It
reaches nothing but its own directory.

- **The password** is made once, when the receiver is registered. The interface shows it on the page;
  the command prints it when given `--show-password`, and refuses without it.
- The manager keeps only its salted hash, in `/etc/nginx/haprion-receivers/<id>.htpasswd`
  (`root:www-data`, 0640). Neither the registry nor the interface's job holds the password.
- A lost password is replaced with `secret` (or *New secret* on the page). The old one stops working
  at once.
- The receiver keeps the password in a netrc file (`/root/.certfetch.netrc`, mode 600), which curl
  reads with `--netrc-file`, so it is on no command line.

It is served from the interface's own server block, on port 443, under the interface's certificate and
host name, at `https://<server name>/certdist/<id>/<certificate>/`. The `location` blocks live in
`/etc/nginx/snippets/haprion-receivers.conf`. Only this command writes that file, and the interface's
site pulls it in with one `include` line; a receiver never edits the interface's server block itself.
It is not a server block of its own beside the interface's: nginx serves the first server block for a
name and port and silently ignores a second one, so such a block would test clean and never answer.
Platform step 05 adds the include and creates the empty snippet. Without them,
`add --transport https` is refused with `dependency_unavailable` rather than registering a receiver
nothing serves.

**What the receiver trusts.** The receiver's `curl` must verify the interface's certificate. For that
purpose the certificate is served as a file at `https://<server name>/certdist/manager-ui.pem`. It is a
copy under `/srv/certdist/`, written by `haprion-tls` at every replacement and by `haprion-tls publish`;
the TLS directory itself is root-only, and nginx's worker processes are not root. The receiver saves the
file once - with `curl -k -o manager-ui.pem …` on that first contact, or with `openssl s_client` where
openssl exists - and passes it as `--cacert` to every fetch after that. So it trusts exactly that
certificate. A receiver whose host already trusts the CA that issued the interface's certificate needs
neither the file nor `--cacert`.

**Every change is tested before it stays.** Each change to sshd's drop-in file is followed by
`sshd -t`, and each change to the receivers' nginx snippet by `nginx -t`. If the test fails, the
previous file is put back before the error is reported. A broken sshd locks out everyone, not only the
receiver being registered.

The account's home is the receiver's directory: one directory per receiver, owned by root, with the
lock in a root-owned `.ssh` inside it. So an sftp receiver sees `.ssh` in its chroot beside its
certificates: its own public key, readable and not writable, and nothing else.

**Removing** is refused while any certificate still names the receiver. *Remove from…* in the interface
([Deleting a certificate](#deleting-a-certificate)) is how a certificate lets go of a target, and it is
the operation that also says what that costs. There is no operator command for that step: the
interface queues a `cert_target` job, and the worker runs `haprion-cert-target-helper`, which takes its
request on stdin and is not meant to be typed. Once nothing names the receiver, its layers go in an
order that never leaves a way in open:

1. the lock first, so the key stops working before the material goes - for https, the receiver's
   `location` block and its password file;
2. the directory;
3. the account (rsync and sftp);
4. the registry entry last, because it is what the other three are rebuilt from.

Reference fetch scripts for each transport are in
[`../examples/receivers/`](../examples/receivers/). A receiver's own operator adapts them; the manager
never pushes.

**The interface's job.** The form queues one `cert_receiver` job, run by `haprion-cert-receiver-helper`.
It does not go through `sudo` but through a socket, `/run/haprion/cert-receiver.sock`, served by a unit
of its own that platform step 07 installs
([The worker's way to the receiver helper](#the-workers-way-to-the-receiver-helper)). The helper takes
the key as text, never as a path, so the interface cannot point it at a file. Removal from the page is
refused while any certificate names the receiver, as at the terminal.

*Details:* a receiver's files belong to its fetch account (`0600`). Inside the worker's sandbox, root
is only user ID 0, and the file permissions apply to it like to anyone else. So the worker unit carries
`CAP_DAC_READ_SEARCH`, the capability to read and look into any directory, which the poller has too.
Without it, a target change from the interface ends `target_missing` on a directory that
`haprion-cert-publish`, run as root from a terminal, publishes to without complaint.

## Nodes and clusters

### Adding and removing a node

The management host knows a node in six places, all owned by root:

- its entry in `clusters.yaml`;
- its host key in root's `known_hosts`;
- its two fetch keys in the pull accounts' `authorized_keys`;
- where the traffic-log collector is installed, its entry in the collector's node list and its host key
  in the collector's own `known_hosts`.

Adding a node in the interface, or with `haprion-node` on the command line, changes all six as one,
through the same root helper. The fetch keys are written so that they read the node's own cluster
alone, and only from the addresses its host name resolves to ([Ssh identities](#ssh-identities)). So a
host the manager cannot resolve is refused.

**Adding a node.**

1. On the new node, install the node package (`sudo apt install haprion-node`). It prints the node's
   **enrollment block** - one line starting with `haprion-node-v2:` - and its host key's fingerprint.
   `sudo haprion-node-key` prints a block again. A block from an older node package starts with
   `haproxy-node-v2:` and is read the same way.
2. Under *Settings → Nodes & clusters*, open the cluster. In *Add a node*, paste the block into
   *Enrollment block* and press *Read block*. The section also has a link to download the node package.
3. The page then shows a section headed with the node's name, such as *Add node-c*. It shows the host
   key fingerprint and the host the manager will reach the node at (*DNS name or IP*). Nothing has
   changed yet. Compare the fingerprint with what the node printed.
4. Type the node's name and press *Add node-c* to queue the addition.

The block carries the node's name, a suggested host name, its ed25519 host key, the public halves of
its two fetch keys and a **one-time key**. Copying it from the node's console is what creates the
trust: the manager takes the host key from the block, never from the network.

A host key another node already has - two machines cloned from one image - is added anyway, and the
job and the command's answer say so. SSH cannot tell the two apart, so give one of them a new host key
and add it again.

**The join.** The manager then joins the node once. It connects with the one-time key as
`_haprion-join`, whose only command is `haprion-node-join`, and hands over its own keys, its host key,
the cluster and the VIP. The node prepares itself with them: the packages HAProxy needs, the release
layout, the sudo rules, `node.conf`, the manager's keys each with its own forced command, and sshd on
the address the manager came in on. A purpose the manager has no key for gets no line, so a key an earlier
manager left for it stops working. Then it removes the one-time key. This takes from half a minute to
a few minutes, most of it apt.

If adding the node is rolled back after the join, the node stays joined and its block is used up.
Add the node again with the same block: the join is tried first, and when the block turns out to be
used up, a node that already answers as itself in the cluster is not joined a second time. A join that stopped while preparing the node has not used the block up, and the
same block may be tried again within the 24 hours.

The one-time key is valid for 24 hours and works once. Keep the block to yourself until it has been
used: whoever holds it can join the node to a manager. apt also keeps the package output, block
included, in its logs (`/var/log/apt/term.log` and the unattended-upgrades dpkg log) until the block is
used or expires, so make the join within its 24 hours. The web never stores it. It is encrypted for the
root helper (with the same key pair that protects DNS provider credentials) before the job is queued,
so neither the job nor the audit record holds it. A node whose sshd limits who may log in
(`AllowUsers`, `AllowGroups`) must let `_haprion-join` in.

On the command line the block goes on stdin, as root:

```bash
sudo haprion-node add -c alpha --host node-c.example.com < block
sudo haprion-node remove -c alpha node-c
sudo haprion-node host -c alpha node-c --host lb-03.example.com
```

`--host` is the name the manager reaches the node at. The block's suggestion is the node's own
`hostname -f`, which may not be the right one. With `--json` either command prints the helper's
envelope instead (`schemas/v1/haprion-cluster-node`); `haprion-cluster` takes it too.

A node prepared by hand with `04-node-prepare` prints a block that names its cluster
(`haproxy-node-v1:`) instead. It is added the same way, without a join
([install/README.md, step 4](../install/README.md#step-4--each-node)).

**The manager checks the node answers.** After writing, the manager asks the node for its status as
the status identity, with strict host key checking. The node reports its own host name and cluster. So
an answer proves three things: the host key, that the node has the manager's keys (from the join, or
from step 3's answers on a node prepared by hand), and that the block described the node that answered.
Anything short of that puts every file back and says why.

**Changing a node's host.** A node that is renamed or given another address is the same machine. It is
moved rather than rebuilt: *Change host* on its row under *Settings → Nodes & clusters*, or
`haprion-node host`.

- The host keys pinned for the node move to the new name, in root's `known_hosts` and the collector's,
  and its line in `clusters.yaml` follows.
- The manager asks the node at the new name. The answer must come with a key already pinned, and name
  the node and its cluster. Anything else puts every file back, and the node keeps its old host.
- Its fetch keys stay the node's, written again with the new host's addresses in `from=`.
- With counter sharing on (`peers`), the next publish and deploy carry the new address to the nodes.

A machine whose name stays and whose address changes in DNS needs `sudo haprion-node pull-keys`
instead. A machine with another host key is another machine: that is a restore, or a removal and an
addition.

**A node change is a configuration change.** Every node's `keepalived.conf` names its peers. So an
addition, a removal and a host change are each published as a version of their own - *Nodes: node-c
added* in the cluster's history. They take the same path an object change takes: generated, checked
with `haproxy -c` and released. The cluster then shows as behind until it is deployed.

A publish can be refused: somebody's unsaved edit in the cluster's worktree, or a configuration that
does not validate. The node change is then made anyway, and the job and the terminal say why the
publish was refused. The release keeps the nodes it had until a change is published.

The new node has no certificates until `haprion-cert-deploy -c <cluster>` runs (*Deploy certificates*
on the dashboard). A configuration deploy before that stops and says so, since the node has none.

**Deploying in the same job.** If every node ran the published version before an addition or a
removal, the node change is the only thing a deploy would roll out. The interface then deploys it in the
same job: the certificates and then the configuration after an addition, the configuration after a
removal. The job ends as the deploy ended, and also says what the node change did.

If the cluster was already behind - a version somebody published and did not deploy, or a node that
could not be read - nothing is deployed, since that would roll out the other change as well. The job
then offers *Deploy configuration*. In the terminal, `haprion-node add` and `remove` take `--deploy`
for the same thing, under the same rule.

**Removing a node.** A removal takes the node's lines out of all six files, so it can no longer fetch
configuration or certificates. It is refused for the node that reports holding the VIP, and for a
cluster's last node. A cluster has one to eight nodes ([Cluster definitions](#cluster-definitions)). On
a cluster created in the interface, the version the removal publishes carries every remaining node's
`keepalived.conf` with the new peer list, and the next deploy rolls it out
([keepalived on the nodes](#keepalived-on-the-nodes)).

That version is published before the files change. The removed node is then asked for one last deploy
while its keys still work. The release it reads no longer names it, so it:

- stops keepalived and HAProxy;
- disables both, so a reboot does not bring them back;
- leaves the marker `/etc/haprion/left-cluster`.

Why: left running, its keepalived would keep the old peer list. Once the remaining nodes had their new
list they would stop hearing it, and it would take the cluster's addresses beside them. The job says
whether the node stopped.

A node that cannot be reached - usually why it is being removed - is removed all the same. The job
then says to stop keepalived and HAProxy on it, or to shut it down, before it is started again.

If the node is added back later, the first release that names it is checked and installed with both
services still stopped. HAProxy then starts on it, keepalived last, and the marker goes. A release the
node refuses, or a HAProxy that does not start on it, leaves the node stopped with its marker. A
`keepalived.conf` somebody wrote by hand (one whose first line is not the product's) is left alone, as
it is by every deploy.

**An interrupted change is put back.** A reboot, a killed process or a power cut cannot leave the files
half changed for long:

- Before the first file is touched, the whole change - every file's content before and after, and for
  a cluster the directories it creates or moves - is written to `/var/lib/haprion/change-journal.json`
  (root-only) and synced to disk. It is removed only once the change is on disk.
- While a change runs, the helper holds back the signals that would stop it (SIGTERM, SIGINT and
  SIGHUP) until it has finished or put everything back.
- A record left behind is put back by the next node or cluster change, before that change runs. The
  helper's log says so, for example `NOTICE: a node add of cluster 'alpha' did not finish and was put
  back`.
- If a file was edited after the interrupted change, nothing is put back: the request is refused with
  `change_interrupted` and touches nothing. The record stays for a person to read, and to remove once
  the files are right.

**Which file is the record.** Once installation step 2 has written `clusters.yaml`, that file is the
record. A second run of step 2 keeps it unless `REWRITE_CLUSTER_FILE=yes` asks for the answers file's
version, and step 13 reads the collector's nodes from it rather than from the answers file. The runtime
policy is kept the same way (`REWRITE_POLICY=yes`), because it holds blocks no answer produces, such as
`acme` and `ndes`.

### Creating and removing a cluster

A manager may have no clusters, and a cluster may start with one node and no certificate. You create a
cluster with *Create cluster* under *Settings → Nodes & clusters*, or with `haprion-cluster`, through the
same root helper as a node. It needs:

- its ID, VIP and display name (the ID unless you give one). The VIP is an IPv4 address: the node
  scripts do not reach IPv6 yet, and an IPv6 address is refused when the cluster is created;
- the block its first node printed when its package was installed. The node is joined as any node is
  ([Adding and removing a node](#adding-and-removing-a-node)).

The cluster's next nodes are added to it.

**The first cluster.** On a new installation, the first line of the dashboard's *Getting started* opens
*Set up your first cluster* for an admin. It has five steps:

1. *Name and address* - ID, display name and VIP;
2. *First node* - the command to run on it, with the node package offered for download from the manager,
   and its block pasted back;
3. *Second node* - the same, or *Skip*;
4. *Deploy*;
5. *Done*, which says which node carries the VIP.

Each step is the operation above, adding a node, or the deploy. So a guide left half-way is continued
from the dashboard, or finished under *Settings → Nodes & clusters*. Once the cluster is deployed, the
dashboard is the normal dashboard.

```bash
# On the management host, the block on stdin (two blocks and two --host options make both nodes at once):
sudo haprion-cluster add -c beta --vip 203.0.113.10 [--display-name Beta] \
    --node-path beta --host node-c.example.com [--certificate example.com] \
    [--prefix 24] [--interface eth0] < block

sudo haprion-cluster remove -c beta
```

**What a creation writes**, as one change:

- the cluster's entry in `clusters.yaml`;
- with `--certificate`, that certificate's registry entry gains the cluster as a target;
- a configuration repository - the bare history and the worktree - seeded with the same
  `core/haproxy.cfg`, `manual/` and `managed/network.yaml` that step 1 makes, and owned like the others;
- an empty release directory;
- a `sudoedit` rule per handwritten file in the operator editing policy, checked with `visudo -cqf`
  before it is installed;
- the two repositories in root's git `safe.directory`;
- its nodes, in the six places of [Adding and removing a node](#adding-and-removing-a-node).

Then each node is asked for its status, as a single added node is. Anything short of that removes the
repository and the release directory again, and puts every file back.

The ID, the node path, and the nodes' names and hosts must all be free. A certificate you name must
already be in the registry. A cluster without a certificate serves plain HTTP and TCP; an HTTPS object
waits for a certificate issued or uploaded for it.

**After creation.** The poller polls and draws the new cluster from its next pass
([Which clusters get polled](#which-clusters-get-polled)). Its first version, *Cluster alpha created*,
holds the layout and the files generated for its nodes. It is published as the cluster is made: version
1, with no objects yet, checked like any other. The first deploy rolls it out. It writes each node's
`keepalived.conf` and starts keepalived, so the VIP is held before there is anything to serve
([keepalived on the nodes](#keepalived-on-the-nodes)). A deploy with nothing published is refused
before any node is asked (`nothing_published`).

There is no backup schedule until one is set on the Node backups page. Its retention is the default
until then.

**Removing a cluster** takes it out of `clusters.yaml`, out of every certificate's targets, out of the
editing policy and `safe.directory`, and takes its nodes out of the six places. It also stops
`haprion-state-backup@<cluster>.timer`.

A cluster with drafts or saved changes is not removed. The page names them; publish or discard them
first, so no work is left behind where no page can open it.

Nothing is deleted. Each of these is moved into `.removed/<cluster>-<time>/` under its own root
directory:

- the configuration repository and its history;
- the release directory;
- the cluster's certificate directory;
- the nodes' backup archives.

The retention file becomes `.removed/<cluster>-<time>.json` beside it. Each move stays on the same file
system, so it is a rename, and whatever protects the root directory protects the archive.

The ID cannot be used again while its archive is there. Deleting an archive is a separate, deliberate
step. The nodes are not touched and keep serving the VIP until they are shut down: the manager only
stops managing them. Jobs and versions in the interface's database stay as history.

## The interface certificate

### Replacing it

Not by running the installer again. The command that owns the certificate, `haprion-tls`, comes with
the `haprion-ui` package; platform step 5 checks that it is there.

```bash
sudo haprion-tls show
sudo haprion-tls install --cert /path/to/ui.crt --key /path/to/ui.key
```

`install`:

- checks that the certificate and the key belong together, by comparing their public halves;
- refuses an expired certificate, and warns when less than 30 days are left;
- installs the pair owned by root - the certificate `0644`, the key `0600`;
- runs `nginx -t`, and **puts the previous pair back if nginx refuses the new one**.

A management host whose interface stopped answering is a worse outcome than a refused replacement.

**HSTS is off until you turn it on**, after installing a trusted pair:

```bash
sudo haprion-tls hsts on
sudo haprion-tls hsts off
```

HSTS makes a certificate warning impossible to click through, so `hsts on` refuses while the certificate is
self-signed: it would lock every operator out of the interface - including whoever would fix it. The choice
is kept as `HSTS=yes` or `HSTS=no` in `/etc/haprion/ui-tls.conf`, and every update writes the same header
again. `show` says which it is.

### From the certificate registry

The pair can instead come from the certificate registry ([The certificate registry](#the-certificate-registry)):
an entry marked `interface: true`. It is issued over ACME or NDES, or imported, like any other
certificate, and renewed by the same timer. Publishing that entry runs `haprion-tls install` with it -
with the same checks and the same rollback as above - after two checks of its own:

- the certificate must name this host's `SERVER_NAME` (a wildcard covers one label);
- a certificate nginx already serves is not installed again, so renewing some other certificate costs
  no reload.

**Who installs it** depends on where the publish runs. `haprion-cert-publish` and the renewal timer run
as root outside any sandbox, and install directly. The certificate helpers the worker starts through
`sudo` run inside the worker's sandbox (`ProtectSystem=strict`), where `/etc/haprion` is read-only.
They name the entry by its ID to `haprion-tls-helper` on `/run/haprion/ui-tls.sock`, a root service
that platform step 07 installs. That helper reads the registry and the material itself, and refuses any
entry not marked `interface: true`. The key never passes through the web process: the interface names a
certificate, never bytes and never a path.

**At the terminal** the mark is `--interface` on `haprion-cert-issue`, `haprion-cert-scep`,
`haprion-cert-request` and `haprion-cert-import`, with no `--cluster` or `--receiver` beside it.
Issuing, a signing request and an NDES enrollment refuse names that do not cover `SERVER_NAME`
before a CA is asked. A signing request, or an NDES enrollment the CA is still holding, remembers
the mark until the certificate arrives. A rotated or renewed interface certificate keeps the mark.

**Moving to a new certificate.** A new certificate under another ID takes the mark over:

1. the registry moves the mark to the new entry;
2. publishing installs the new certificate;
3. only once nginx serves it is the previous entry deleted, through the ordinary deletion.

If the install is refused, the previous pair keeps serving, and its entry stays in the listing without
the mark and without targets. The entry that serves the interface cannot be deleted
(`serves_interface`).

`haprion-tls install` and `self-signed` remain the way back. Running either replaces the served pair
whatever the registry says, and the next publish of the marked entry puts it back.

## Backups, and proving they restore

```bash
sudo haprion-backup dump            # what the daily timer runs
sudo haprion-backup verify-restore  # what the weekly timer runs
sudo haprion-backup list
```

**Dumps are root-owned `0600` in a `0700` directory**, and step 6 verifies that none of the three
application identities can read one. This is not tidiness. A dump contains every Argon2id password hash
and every session hash in the installation, so it sits behind the same boundary as nginx's private key.

That rule shapes the restore test. `pg_restore` there runs as the `postgres` superuser - the only
identity that may create and drop a database - and that account must not be able to open the dump. So
root opens the file and hands the open file over. The archive is read without ever becoming readable to
another account.

#### What the dump does

- `pg_dump --format=custom`, written under a `.partial` name and renamed into place. Anything reading
  the directory sees a complete dump or none - never a file still being written that looks finished.
- Read back with `pg_restore --list` **before it is kept**. A zero exit from `pg_dump` says the command
  ran. This check says the archive can be opened and its contents parsed, which is what a truncated or
  corrupt dump fails.
- One dump per day - today's replaces today's - and the seven newest are kept. Retention counts files,
  not calendar days, so a week with the machine switched off does not delete the last dump that exists.
- Warns when the filesystem holding the dumps is over 85% full, and dumps anyway. A backup that refuses
  to run because a disk is filling is a backup that stops precisely when things are going wrong.

#### What the restore check does

It restores the newest dump into a scratch database that it creates and drops itself. Never into a
database named in configuration: a restore test that can be pointed at the wrong database will one day
overwrite something real. Then it compares the result with what the archive holds:

- **Row counts** for `alembic_version`, `app_user`, `app_session`, `audit_event`, `login_attempt` and
  `job`. They are named explicitly, so an empty restore cannot pass by matching zero against zero. The
  expected count is read from the archive's own data, not from the live database. The live database
  moves on after the dump - a sign-in adds a session, retention removes old jobs - so a check measured
  against it would fail on a perfect restore. The live count is printed beside each table, to show how
  far the installation has moved since.
- **The schema version.** The restored database must hold it. It is the one row every installation
  has, including a new one with no account yet. A dump `haprion-backup restore` would refuse fails the
  check, and one it would migrate says so.
- **One row compared whole.** The oldest local account's password hash, as the restored database holds
  it, must be identical to the same row in the archive, because counts can match while the contents are
  unusable. OIDC accounts have no hash and are not read.

Any mismatch fails the unit. The scratch database is dropped either way.

#### What is not covered

This is a database backup, and the database is not the whole installation. It does not hold the
HAProxy configuration - that lives in Git - nor the cluster definitions, the keys or the release tree.

The DNS profiles it holds are encrypted. Without the private key in
`/etc/haprion/ui-secrets/dns-profile-keys/` ([The DNS profile key pair](#the-dns-profile-key-pair)), a
restored dump lists every profile but can apply none of them, and the way to recover is to enter them
again.

**Nothing here survives losing the host**, and nor does anything else on it: the release tree, the
runtime policy, the keys, the sudoers rules. **Backing up the management host itself is a very good
idea**, and how that is done is entirely up to whoever runs it. If it is backed up whole, these dumps
come along.

That does not make the dumps redundant. An image of a running database is only crash-consistent, not
transactionally clean, and nobody restores a single table out of a machine image under pressure. The
dump is what makes "put that one table back" an ordinary afternoon.

#### After restoring the database or the host: waiting jobs and sessions

A restored database holds the jobs that were waiting at the moment of the backup. Those jobs ran at the
time. Running them again would be a new request nobody made: a *Drain* that was later replaced by
*Ready* would drain the server again.

So no job queued before the manager last started runs by itself. A restored host always starts again,
and the worker holds every such job:

- *Events → Jobs* shows it as *Held*, with **Run** and **Discard** for an admin, and *Needs attention*
  says how many wait. Until it is answered it holds its cluster's place in the queue, or the
  certificates' place. A new job there is refused with a sentence that says so, a certificate form says
  so before it is sent, and every badge or row that names the job says *Held* in amber, without the
  spinner of a job that runs; the page does not refresh for it. A job no worker holds is said the
  same way, as *No worker* in red.
- A discarded job that waits in the queue ends *blocked* with the code `held_discarded`; nothing more
  of it ran.
- A waiting job whose answer the manager already kept is not run again. That is a node change, for
  example, that ran after the backup was taken. **Run** and **Discard** end it on that answer, as for a
  running job below. Its row on *Jobs* and its audit entry carry the warning `answer_kept`.
- A job that was *running* when the host went down or was backed up is held too; stopping only the
  manager's services holds nothing. Its own step may have finished: a node change, for example, whose
  answer the manager kept. **Run** goes on with what follows it in the job, such as the deploy after a
  node change. **Discard** ends it on what it already did and runs nothing more. Either way it is judged
  first, as after any worker failure: one whose outcome cannot be read ends `unknown`.
- While an update of the manager pauses the queue, nothing is taken up again, held or not.
- A job queued just before an ordinary reboot is held the same way, and needs the same click.
- An answer holds until the next start. A job answered **Run** that was still waiting or running when
  the host was backed up is held again when that backup is restored, and asked about again.

A snapshot taken **with the host's memory** does not start again when it is put back: the manager
carries on from the moment of the snapshot, as from a pause. Nothing is held then, and the jobs that
were waiting run. The clock is behind as well. Restart the manager straight after such a restore - the
worker then holds what was waiting, and the clock is set. Take snapshots for restoring without memory.

**Restoring only the database** from one of its dumps is one command. `haprion-backup list` shows the
dumps; give the one to restore:

```bash
sudo haprion-backup restore /var/lib/haprion-ui/dumps/<dump>
```

It stops everything that writes the database - the web and its socket, the worker, the poller, the
traffic collector and the timers - and refuses while a connection to the database remains. It then
dumps the database it is about to replace to `before-restore/` under the dump directory, so a wrong
dump chosen can be undone; the newest three are kept, and the daily dumps' retention neither counts
nor removes them. The last line of the command names the directory. If that dump cannot be made,
nothing is restored and what was stopped is started again. The command then
makes the database again from the dump, checks its privileges with `03-verify`, holds the waiting jobs
and ends the sessions (`after-restore`), starts what it stopped, and replays the traffic log (below).
A dump from before an update that changed the schema is migrated to the installed release's schema
before that check; one the release cannot take, such as one from a newer release, is refused before
anything stops.

If the restore fails after the stop, for example on a damaged dump, a failed migration or a full disk,
the services stay stopped and the command says what failed. Correct it and run the same command again,
with this dump or another: once a restore finishes, it starts what the failed run stopped. After a
failed privilege check, a service can be started by hand instead once the restored jobs are held with
`sudo haprion-backup after-restore`, which also lets the update, a rollback and a setup go on. After a failed migration, do not: the schema is still the dump's,
behind the code, so correct the cause and run the restore again. A reboot in between starts the services
as any boot does, and the next restore stops them again.

`after-restore` holds every waiting or running job in the same way, and ends every session: the
restored sessions include ones that were signed out or revoked since. Run on its own, it does the same
for a database restored some other way, and refuses while the worker runs: stop the worker first. Both
actions are in the audit record. After a host restore, end the sessions yourself: *Settings → Users*, the account,
**End sessions**.

Apart from the hold, the worker never runs a job that has waited more than two hours unless an admin
chose **Run**: it ends *blocked* with `request_expired`. A job the worker had already started is judged
from what the cluster shows, as after any worker failure
([Jobs and status freshness](#jobs-and-status-freshness)).

#### After restoring the database on its own: replay the traffic log

Restoring the whole host puts the database and the collector's staging area back together, and nothing
more is needed.

Restoring **only the database** from a dump is different. For each day file in staging, the collector
remembers how far it has imported, and that position is newer than the dump. Its next run would go on
from there, and every request between the dump and the restore would be missing from the log page,
although the records are still in staging ([Mirroring node traffic logs](#mirroring-node-traffic-logs)).
`haprion-backup restore` replays it for you. After a database restored another way, run this once, as
the collector account (`COLLECTOR_USER`):

```bash
sudo -u <collector> /opt/haprion/current/bin/haprion-traffic-collector \
  --replay-database /etc/haprion/traffic-collector.json
```

It waits for a run in progress, then forgets the import positions and nothing else. The day files, and
how far each node has been fetched, stay. The next run imports every staged day again. The table's own
duplicate check passes over records the database already holds, so nothing is counted twice. What
staging no longer holds (older than the retention window plus one day) cannot be replayed.

The WAF engine's matches are replayed the same way, from the nodes rather than from staging. The
command also forgets how far each node's WAF journal has been imported. The next runs then read each
journal again from its oldest entry, a page per minute. What a node's journal no longer holds (older
than its 14 days) cannot be replayed.

## Node backups

On the Node backups page, an administrator can set each cluster's backup schedule, on the manager's
clock:

- run every day, on chosen weekdays, or on one day of the month (1–28), at a chosen time;
- keep a chosen number of archives per node (1–365);
- enable or disable it, and save it with *Save schedule*;
- *Back up now* runs a backup at once.

The terminal path is:

```bash
sudo haprion-state-backup -c alpha
haprion-list-backups -c alpha
sudo haprion-backup-schedule -c alpha --time 03:30 --weekly Mon,Thu --retention 14
```

`haprion-backup-schedule` asks the same root service as the page's *Save schedule*. It changes
something only when the timer or the retention differs from what is asked, so running the same command
twice changes nothing.

- Without `--weekly` or `--monthly <day>` it runs every day.
- Without `--retention` each node keeps the number of archives it keeps now.
- `--disable` stops the timer. Without `--time` the schedule stays as it is.
- `--check` says whether it would change anything.
- `--json` prints the service's envelope, with `changed`.

*Node backups* under Features is the interface's switch. The command works either way, but turning the
switch on restarts the schedules that turning it off stopped. So set a schedule after the switch is on.

Archives are root-only and belong to one specific node. For backup identities, storage and timers, see
[Runtime policy](#runtime-policy).

## Restoring a node onto an empty VM

A lost node is rebuilt from its state archive. Install an empty VM and run `haprion-node-restore`.
The VM becomes that node - its host name, address, SSH host keys, accounts, node scripts and keepalived
role - and then fetches its configuration and certificates the way a deploy does. Nothing is installed
on the VM beforehand.

**What counts as an empty VM.**

- Ubuntu 26.04 or Debian 13, installed from its cloud image. Which of the two the node ran before does
  not matter: both write their network settings as Netplan, which is what the restore writes.
- One network interface, with the same name as the node's.
- A temporary address the management host can reach.
- An administrator account with `sudo`.
- Neither `haproxy` nor `keepalived` installed. The restore installs them itself, with their services
  held off until their configuration is in place.

The node's own address must not answer. A restore while the old node is still up would put two
machines on one address, so the preview stops.

The same command also repairs a node that still runs, over itself - see *Repairing the node itself*
below.

**Three steps, each its own command**, run as root on the management host:

```bash
# 1. Choose the node, the archive (by its version, from haprion-list-backups) and the VM.
sudo haprion-node-restore prepare -c alpha --node node-a \
    --archive 2026-01-01_04-00-00 --target 192.0.2.120

# It prints one line. Paste it on the VM, as its administrator. It adds this run's
# one-time key to root's authorized_keys - restricted, and accepted only from the
# management host's address - shows the line that landed, and prints the VM's
# host key fingerprint.

# 2. Compare: the fingerprint it printed is the one the preview is given.
sudo haprion-node-restore preview --run <run> --fingerprint SHA256:...

# 3. Carry out exactly what the preview showed, confirmed with the node's name.
sudo haprion-node-restore run --run <run> --confirm node-a

# To abandon a run: remove its directory and one-time key.
sudo haprion-node-restore discard --run <run>

# How a run stands: running, finished (and how), stopped mid-run, or not started.
sudo haprion-node-restore status --run <run>
```

**The same three steps from the interface.** An administrator with management writes has *Restore…*
on each archive row of the Node backups page. The form takes the temporary address and the mode: the
node itself, or a test with its own host name, address and VIP. The run's own page,
`/backups/restore/<run>`, then:

1. shows the line to paste on the VM;
2. takes the fingerprint (*Preview the restore*) and shows the plan;
3. takes the node's name as confirmation (*Restore* and the node's name, or *Overwrite* and the node's
   name when it repairs the node itself).

Each step is one job - `node_restore_prepare`, `node_restore_preview`, `node_restore` - run by the
worker through the root helper on `node-restore.sock`, with the same engine as the command. The page is
drawn from those jobs alone; nothing else is stored. While a job runs, it holds the cluster's job slot,
so a deploy to that cluster waits. A job held since the manager last started shows as *Held*, with a
link to it on *Events → Jobs*, where an admin answers it. A job no worker holds shows as *No worker*,
with the same link ([The worker](#the-worker)). *Discard this run* on the run's page is the
fourth job, `node_restore_discard`.

**When the run's job loses its answer.** The job ends `unknown`, because the helper may have carried on
as root and changed the node. The page says *Outcome unknown* rather than failed. *Ask for the outcome*
queues the fifth job, `node_restore_status`, which reads the run's directory and changes nothing. A
finished run is then shown with its own answer. Otherwise the page says what was found: still running,
stopped mid-run (look at the target), or never started. The helper's socket takes one connection at a
time, so while a restore still holds it, the answer is *ask again when it has finished*.

**A run has an hour** from *prepare* to the start of *run*. After that the run has expired: the Node
backups page stops listing it, its page accepts nothing more, and the command and the helper refuse it
and remove its directory. Prepare a new one.

- Every call to the command or the helper, and every node state backup, clears away the runs past their
  hour that no step is working on.
- A run that never began writing to the target is removed whole.
- A run that did begin loses its one-time key, `known_hosts` and preview at the hour. It keeps
  `request.json`, `prepared.json`, `started.json` and `result.json` for seven days - as long as the web
  keeps its jobs - so its outcome can still be read with `status`.
- The pasted line carries an `expiry-time` two hours after *prepare*. So the VM itself stops accepting
  the one-time key even if nothing on the management host ever runs again.

**What the preview shows:**

- the target's OS, network interface and MAC address, and its host key fingerprint;
- the name and address the VM will have;
- every file written, and every archived file that is not: the VM's own files in a directory it shares
  with the OS image, the archive's APT sources, and old `.replaced-` copies (kept on the node for 30
  days - see [What a node keeps and for how long](#what-a-node-keeps-and-for-how-long));
- the node package that will prepare the node;
- for a node that had the project's package repository, that repository on the VM - the WAF engine and
  the repository key come from it. For a node installed from files: the WAF engine package, when the
  node ran it, and the repository key package;
- every account, with its user and group IDs and its groups;
- in test mode, every rewritten field with its old and new value.

**What stops the preview:**

- this manager's CLI release carries no node package, or one that does not verify (see
  [Part 3](#part-3--the-versioned-cli-release));
- for a node that ran the WAF engine, on a target without it: the release carries no engine package, or
  one that does not verify;
- for a node without the project's repository: the release carries no repository key package, which the
  node package depends on;
- a `node.conf` in the archive that cannot be read back into installation answers;
- a fingerprint that is not the one given - then nothing is sent at all;
- a target whose clock is more than five minutes from the manager's. A VM put back from a snapshot
  often runs days behind, and apt then refuses every repository;
- an archive that is not of the chosen node;
- a target that is not Ubuntu 26.04 or Debian 13;
- `haproxy` or `keepalived` already installed - unless an earlier restore run left them there, so a run
  that rolled back can be tried again;
- the final address, or the node's own, already answering;
- an account whose primary group the archive does not carry.

**User and group IDs.** A number the VM already uses stops nothing, because an account or group is
identified by its name. One the VM already has keeps the VM's number. A new one gets the archive's
number where it is free, and otherwise a free number of the same kind (system or ordinary). The preview
lists every such change. The restored files are owned by name, so they follow.

`run` asks the VM again, and refuses unless the archive, the VM and the plan are exactly what the
preview saw. So what was approved is what is written.

**What `run` does, in order.** Three SSH sessions with the one-time key:

1. **On the temporary address:**
   - the archive's groups and accounts, numbered as above, before any package can take a number.
     Password hashes are set only for accounts that have no password on the VM.
   - the HAProxy package repository for the VM's own distribution and release, on the branch the node
     ran. The archive's APT sources name the release it was taken on and are not written; the VM keeps
     its own. The repository's signing key ships with the product and is used only when its
     fingerprint is the one pinned in the code; it is never fetched at restore time.
   - then `haproxy keepalived rsyslog openssh-server rsync python3 netplan.io`, with service starts
     held off until their configuration is in place;
   - then the files. Only paths the export copied get the archive's owner and mode. A directory the
     export created only to hold a file is made if missing, and otherwise left alone.
   - What the product shares with the OS image is restored file by file, not directory by directory. In
     `sudoers.d` and `sysctl.d`, only the file `04-node-prepare` writes comes back. In
     `sshd_config.d`, only the product's `05-haprion-listen.conf` comes back, and `sshd_config` itself
     stays the VM's own. An operator's own file in these directories comes back when the node names it
     in `EXTRA_BACKUP_PATHS`.
   - The files, the node package and the engine and key packages travel in one transfer of at most
     64 MiB. The preview adds them up and names the largest files as a problem when they pass that, so
     a restore that could not be carried out is not started. Keep `EXTRA_BACKUP_PATHS` to
     configuration, not data.
   - then the HAProxy release layout, the services and the host name, and sshd is restarted. The
     archive's `05-haprion-listen.conf` has sshd listen on the node's own address. Until step 3, a
     second drop-in, `04-haprion-restore-listen.conf`, keeps it listening on the temporary address as
     well, so the next session can still reach the VM. The step checks that sshd answers on every
     address it names.
   - when the archive shows the node ran the WAF engine, the engine package that the manager's own CLI
     release carries is installed next. It is in no repository, and the node's deploy refuses a release
     with WAF rules without it.
   - last, the node package of the manager's own CLI release is installed on the VM, and its
     `04-node-prepare` runs with an answers file read back out of the archive's `node.conf` (and the
     manager's publish root). The package puts the node scripts of the running release in place, not
     the archive's. The step writes `node-installation.json`, the sudo rules and the traffic-log
     directory, and renders `node.conf` again - to the same bytes, which the preview's answers are
     tested against. If the archive shows the traffic log was on, `haprion-traffic-log-enable` turns it
     on again, prune timer included.
2. **Still there:** the archive's Netplan, bound to the VM's MAC address, applied three seconds after the
   session ends. A timer puts the VM's own Netplan back after 180 seconds unless step 3 cancels it.
3. **On the node's own address, with the archive's host key:**
   - the timer is cancelled;
   - the temporary drop-in is removed and sshd restarted, so sshd listens on the node's own address
     only;
   - HAProxy starts on a placeholder release whose only listener is a root-only unix socket;
   - the node's `haprion-cert-pull` fetches the cluster's CA files and then its certificates, and its
     `haprion-pull-deploy` the published configuration - the same scripts a deploy triggers;
   - keepalived starts as `BACKUP`;
   - **last**, root's `authorized_keys` is replaced by the archive's, which removes the one-time key.

If the node never answers on its own address, the timer returns the VM to its temporary address, and
the run reports `failed` with the network rolled back. A session that breaks or times out once writing
has begun is a `failed` run in that session, never a refusal. A restore takes about a minute; the longest
part is the package installation.

*Details:* the run's result is kept in `/var/lib/haprion/restore/<run>/result.json`, root-only `0600` in a
`0700` directory. `started.json` is written just before the first write to the target.

**Test mode proves a restore before it is needed.** Add `--test --test-hostname <name>
--test-address <address/prefix> --test-vip <address/prefix>` to `prepare`. The node is restored as
above, except that:

- the host name, the node address in Netplan, keepalived's own address and its virtual addresses are
  rewritten to the test values, and the preview lists every one;
- the `include` of the published address list is removed;
- sshd's `ListenAddress` is rewritten to the test address;
- keepalived is masked, so it can never join the production pair's VRRP;
- the VM keeps its own SSH host keys;
- the VM fetches its configuration and certificates from this manager as a node does, with the fetch
  keys it made for itself. For the run alone, the manager lets those keys in from the test address
  only - the same read-only line a node's own has, ending by itself after two hours - and takes them
  out when the run ends, however it ends, and when the run is swept or discarded. If they cannot be
  taken out, the result says so and the next restore command does it once the run is past its hour. `haprion-node pull-keys`
  leaves them alone. The manager and the VM are the same as in a real restore, so what the restore
  proves includes the fetch;
- no password hash is sent: the accounts are created locked, and the preview says passwords are not
  restored in test mode. The password step is proved by a restore as the node.

The test address must be in the node's network, because the node's routes come with the archive.
`--confirm` takes the test host name.

**Repairing the node itself.** The same restore, with the node's own address as `--target`, puts the
archive back over the node - for a node left in a bad state by hand. You choose nothing for this: the
preview tells the two cases apart by the host key the target offers. The archived key means the node
itself; any other means an empty VM in its place, with the rules above. The paste and the three steps
are the same. Over the node itself, this differs:

- The node must be reached at the address its archive gives it.
- The preview takes a state backup of the cluster and checks the pair: whether this node holds the VIP,
  and whether its neighbour is healthy (answering, with HAProxy and keepalived active). It lists every
  file whose contents differ from the node's, how many are already equal, what goes to quarantine, and
  whether the network differs.
- `run` refuses when that backup failed, unless you add `--backup-failed-ok`. It also refuses when the
  node may hold the VIP while its neighbour is not healthy, unless you add `--break-traffic` - which
  does what it says.
- Before its first write, the run copies every path it or `04-node-prepare` may change to
  `/var/lib/haprion-restore/<run>/before/` on the node. It then stops keepalived, so the VIP moves to
  the neighbour before anything changes. The copy stays 30 days (see
  [What a node keeps and for how long](#what-a-node-keeps-and-for-how-long)).
- The node's software is its own. No repository file is written, and only a product package the node
  lacks is installed (`apt-get install --no-upgrade`, from the node's own sources). The WAF engine,
  which no source has, comes from this manager's release. The node package is not replaced: the node's
  own `04-node-prepare` runs, and a node without the package is refused before anything is written.
  The HAProxy releases and `current` are not touched.
- Whatever `/etc/haprion` and `/etc/systemd/system/haproxy.service.d` hold beyond the archive and what
  `04-node-prepare` writes goes to quarantine on the node. The run does not delete it; it is removed
  with the run's directory after 30 days
  ([What a node keeps and for how long](#what-a-node-keeps-and-for-how-long)). The directories the
  product shares with the OS image keep the image's files, as for a new VM.
- Netplan is written only when the node's differs from the archive's. Otherwise the network session is
  skipped and nothing is applied.
- If a session fails, the node is put back from its copy in the same session. After a network change
  that never came up, the timer puts the network back first, and then the management host restores the
  copy once the node answers again. keepalived is started again, and the run is `failed` with
  `rolled_back`. When the run was put back, the one-time key stays in root's `authorized_keys` until its
  `expiry-time`.
- If a session breaks from the management host's side - it ran out of time, or the connection was lost -
  the host asks the node to put itself back from its copy before it records `failed`. If that fails
  too, the run says that keepalived may be stopped and where the copy is
  (`/var/lib/haprion-restore/<run>/before/` on the node), and `rolled_back` stays false.

**What it does not do.** It does not restore onto an OS other than Ubuntu 26.04 or Debian 13. And it
does not set up what belongs to your environment rather than the product - a configuration-management
baseline, monitoring agents, an operator's own sudo rules. That runs afterwards, as on any new machine.

The restore is one piece of a recovery plan. The rest - where the VM comes from, how the management
host survives, who fails over - is yours to decide. [`DISASTER-RECOVERY.md`](DISASTER-RECOVERY.md)
lists the questions.

## What a node keeps, and for how long

Three kinds of copies build up on a node, and a fourth on the management host. Rollback copies and
restore runs are removed automatically after **30 days**; configuration releases are removed by count. Each kind is cleaned up only at the
moment a new copy of the same kind is made - nothing runs on the node on a schedule for this. A node
that is never reinstalled, deployed to or restored keeps its copies until it is.

| What | Where | Made by | Removed |
|---|---|---|---|
| rollback copy of a file an installer replaced | `<file>.replaced-<yyyymmdd-hhmmss>` beside the file | `04-node-prepare` (so every node package installation and every restore) | when the same file is next installed, if the time in its name is more than 30 days old |
| a configuration release | `/etc/haproxy/releases/<yyyymmdd-hhmmss>/` | `haprion-pull-deploy`, once per deploy that changed something | after a deploy that completed, all but the newest 10 |
| a published release (on the management host) | `<publish path>/releases/<commit>/` | every publish, revert and node change | after a deploy that read every node: all but the newest 10, except the one `current` names and any a node reports it runs; an unfinished one (`.<commit>.…`) once it is an hour old |
| a restore run's directory | `/var/lib/haprion-restore/<run>/` | `haprion-node-restore` (the terminal or the web page) | when a later restore run begins writing to the same node, if the run is more than 30 days old |

**What is always kept:**

- the newest rollback copy of each file, however old. Example name:
  `/etc/haprion/node.conf.replaced-20260924-200115`;
- the release `current` names, the one that ran before the last deploy, and one an interrupted deploy
  left behind. A release holds everything a deploy installed: `haproxy.cfg`, `conf.d/`, the
  certificate lists, `waf/`, `dns/` and `keepalived/`;
- the current restore run. A run's directory holds the `before/` copy an overwrite took, its
  `quarantine/`, and the node package it installed. Its age is the date in its ID, `r<yymmdd>-…`.

**Why 30 days.** A copy is for the days after a change, until the change has proved itself. After that,
the node's history is the state backups on the management host, taken on each cluster's schedule
([Node backups](#node-backups)). A node package is rolled back with the previous package (see
[node package rollback](#rollback)), not with these copies.

The age of a `.replaced-` copy is the time in its name, not the file's modification time: `cp -a`
keeps the original's.

**Keeping something longer.** Move it out of those names before the next installation or restore.
Anything not named `<file>.replaced-<yyyymmdd-hhmmss>`, and any directory under
`/var/lib/haprion-restore` that is not a run ID, is left alone.

*Details:* the periods are `REPLACED_KEEP_DAYS` in `install/node-lib.sh`, `KEEP_RELEASES` in
`haprion-pull-deploy`, and `RUN_KEPT_DAYS` in `haprion/restore_agent.py`. Each removal is printed:
`pruned <path>` in the installer's and the deploy's output, and an `old-runs` step in the restore's
`apply` session.

The manager's own installers use the same `install_file`, and so the same rule for the files they
write. The manager is backed up as a whole machine and needs no older copies than that.

## Keeping jobs, sessions and metric history bounded

```bash
sudo haprion-retention report              # quick overview; log row counts are estimates
sudo haprion-retention report --exact      # count every traffic/WAF log row
sudo haprion-retention prune --dry-run     # the same, deleting nothing
sudo haprion-retention prune               # what the daily timer runs
sudo haprion-retention budget --dry-run    # which traffic days the hourly budget would drop
```

**The traffic and WAF tables also have a space budget.** Their retention is counted in days, and a flood
can fill a volume well within them. So every hour `haprion-retention budget` (its own timer) drops the
oldest finished days of both tables while either is true:

- they hold more than a quarter of the volume PostgreSQL writes to;
- less than a tenth of that volume is free.

It never drops today or a day ahead, and it writes a warning to the timer's journal for each day it
drops.

The collector keeps its copy of the nodes' days within the same share of its own filesystem. It removes
the oldest finished days first. While today alone is over the limit, it fetches nothing, and the
attention list says that collection is paused. The nodes keep their days, within their own budget,
until it can fetch again.

**The reports.** The quick report adds up estimated row counts and total storage (indexes included),
from the leaf partitions only. It labels the counts as estimates, and lists partitions that have no
statistics. Run `report --exact` when you need an exact log count. Neither report changes any data.

**Uploaded keys.** `prune` also removes the encrypted file from each finished `cert_import` job a day after
it finished. The job row stays; only the file in it goes.

**Why it is a root command.** No application role may delete from the jobs, the audit trail or the
sign-in records, and none is going to: a compromised web or worker process must not be able to remove
the record of what it did. The roles delete only their own working rows - a draft, an acknowledgement,
the poller's derived state - and the installation check lists exactly which. The database role that owns the tables
(the migration role) may delete from them, and only root may connect as that role. The installation
step verifies this rather than assuming it: if an application identity could connect as the owning
role, `delete` being withheld would mean nothing.

#### What it removes, and what it will not

- **Finished jobs older than seven days.** A management request older than that has been acted on or
  superseded, and what it did is in the audit trail. These jobs stay, whatever their age:
  - **never a `pending` or `running` job.** Those are the states that stop a second operation starting
    against a cluster; removing one would let it start while the cluster is still being changed. Every
    other state always has a finish time, so the age test cannot match a row without one;
  - **never the twenty most recent jobs.** Without that floor, a quiet fortnight would empty the jobs
    list on the Events page completely, which reads as the interface having lost its history rather
    than as nothing having happened. Twenty is the number the page itself lists, **sorted the way the
    page sorts them**, so the floor is exactly the set a reader can see. Sorted any other way, it would
    keep a different twenty rows and quietly stop promising anything;
  - **never the jobs that carry a profile's or a draft's state.** A DNS or NDES profile's status is read
    from its apply jobs, so the newest job of each existing profile, and its newest apply, stay as long
    as the profile exists. Removed, a profile in effect for months would read *Not applied* and drop out
    of the certificate form. In the same way, the publish job of a draft, a saved network description or
    a settings change stays as long as that draft or change exists: the interface clears them by
    reading it.
  - **never the newest publish and the newest deploy of each cluster, nor the publish that deploy
    carried.** A WAF exception's *Not working* is judged from when a deploy carried it; with these
    removed, an exception that does not work would read as covering its finding;
  - **never the newest finished job of each step on each thing** - a cluster's deploy, one certificate's
    issue, one object's server state, one DNS or NDES profile. A job on several certificates counts for
    each of them. *Needs attention* reads a failure from it until the same step on
    the same thing works again; removed, a failure nothing had settled would leave the list, and
    `/status/attention.json` with it.
- **Audit records older than two years** (730 days), except each certificate's newest
  `certificate_export` or `certificate_download` record. The registry row reads from that record which
  version was last taken out, so a certificate nobody fetched for two years does not start to read as
  never downloaded. This command is the only thing that removes audit records, and only by age; no
  application role may remove one.
- **Node events older than ninety days** - what the nodes did on their own, shown under *Events →
  Nodes*: a server down or back up, the VIP moving.
- **OIDC sign-ins in progress older than a day.** Each sign-in through the identity provider leaves one
  row, usable once and for ten minutes. A day is kept, so a failed sign-in can still be looked at the
  next morning.
- **Sessions that ended more than thirty days ago**, expired or signed out. A live session is never
  touched.
- **Sign-in attempts older than ninety days**, far outside any throttle window (at most a day) -
  **except each name's newest successful attempt**, which is what *Last sign-in* on the Users page reads.
  A break-glass account may go unused for longer than ninety days and must not then read as never used.
- **Diffs of versions no longer listed.** The poller keeps what each version changed, and may only add.
  After a history reset, or once a version is older than the listing reaches, its diff is removed here.
  A cluster whose last listing failed is left alone.

The timer runs daily, after the daily dump rather than before it, so the newest dump still contains the
rows the prune removes.

**Metric history.** The same command also maintains the metric tables, in this order:

1. it creates the metric tables' future partitions (one partition holds one day);
2. it writes the pools' hourly rollup;
3. it removes expired partitions.

The rollup and its completion boundary (`metric_rollup_state`) are written by one SQL statement, so a
failed statement advances neither. Only then may raw pool partitions be dropped, and only when their
complete day is at least one more day behind that boundary. Listener metrics have no rollup, and keep
their fixed seven days of raw samples.

The rollup keeps one reading per pool and hour for a year. The interface does not read it. Windows
longer than a day are read from per-hour sums of the samples' stored differences, which a trigger keeps
up to date as samples arrive, for frontends and pools alike. The command deletes those sums when they
are older than 31 days, one more than the longest window. `report` still prints the rollup boundary,
because it decides when raw pool partitions may go.

The timer is daily because that normally keeps the completed boundary six days ahead of the seven-day
raw retention. The explicit boundary is what keeps a longer outage correct; the schedule is not taken
as proof that the work finished.

## Traffic logs and metrics

### A basic log viewer, on purpose

The *Traffic logs* page answers one question: what did the recent requests look like? It is kept simple
on purpose.

**Filtering.** You can filter by cluster, by status class (2xx to 5xx), by whether the WAF matched a rule
(*Rule hits* or *No rule hits*), by a search text and by a from/to time. The search finds text in the host,
the path and the backend, and understands AND, OR, NOT, parentheses and quoted phrases. A filter searches
every day the database holds. The page then shows the newest matches: at most `max_lines` of them, 500 by
default and 10 000 at most.

**Sorting.** A column heading sorts only the rows already on the page. It does not ask the database for
another order. Sorting on *Bytes* therefore shows the largest of the newest matches, not the largest
request of the week.

**What a row shows.** The time, the cluster and node, the client, the request, the status, the destination
and the size - nothing more. When the WAF matched a rule, the *Request* cell starts with a badge naming
the rule: red when the rule refused the request, amber when it only logged it. Rows can be ticked and
saved with *Export selected (.csv)*. The file has the row's columns plus *Rule* and *Mode* (`denied` or
`logged`), empty when no rule matched; from *WAF logs* it is named `waf-logs-…`.

**One object's requests.** An object's page links to its own requests: *Traffic log* and *WAF logs* on
its *Metrics* card, and a link beside each backend on the cluster's *Metrics* page. They open the page
narrowed to that object. A line above the table says so and links back to all of them. An object's
requests are:

- the requests sent to its backends, and
- the requests for its hostnames that never reached a backend - because an access rule, dynamic blocking
  or the WAF refused them, or because they were redirected.

**Why it stays basic.** Aggregation over time, dashboards, alerting, long retention and correlation with
other systems are what dedicated log platforms such as Loki or Elasticsearch do well. Rebuilding them here
would make a second, weaker copy. An installation that needs them should send the logs to such a
platform, and the nodes can do that themselves: see
[Sending the traffic log elsewhere and metrics](#sending-the-traffic-log-elsewhere-and-metrics).

**Under heavy traffic.** Every request is kept on its node and reaches the manager. The page, however,
shows at most the newest `max_lines` matches (500 by default) - during a flood, that is a few seconds'
worth. A filter narrows those rows; it does not summarise the rest. After a burst, the newest rows can
arrive a minute or two late, because the collector fetches for at most thirty seconds per node each
minute. Until they have arrived, the page's warning says *catching up*. How many requests, which statuses
and from where, over time, is the work of the [exporter](#sending-the-traffic-log-elsewhere-and-metrics)
and a log platform. Set them up before they are needed.

### Sending the traffic log elsewhere, and metrics

Each cluster has three optional settings:

- **Log receivers.** The cluster sends its traffic log to up to four external receivers.
- **The exporter.** The nodes expose HAProxy's own Prometheus exporter.
- **Shared counters.** The nodes share their counters with each other.

All three are part of the cluster's HAProxy configuration. They are kept in `managed/cluster.yaml` in the
cluster's repository and published as a version like any other change: with a lock, a validated
candidate, *Published by*, and a revert that takes them back. Nothing is relayed through the management
host. After `haprion-deploy`, the nodes send and listen themselves. They send to the receivers through
the node's own rsyslog, which the deploy configures.

```yaml
# managed/cluster.yaml
log_targets:
  graylog:
    address: 192.0.2.20      # an IP address, never a name
    port: 6514
    disk_mib: 1024           # optional; the queue on the node's disk, 64 to 65536 MiB
    tls: false               # optional
not_logged_from:             # optional; a monitor's answered requests are not logged
  - 192.0.2.40
metrics:
  port: 8405
  sources:
    - 192.0.2.0/24           # who may scrape; everyone else gets 403
peers:                       # optional; counters shared between the nodes
  port: 10000
```

**In the interface.** An admin edits these under **Settings → Logs & metrics**: one row per cluster, and a
page for each. This needs `management_writes` on. Saving keeps the change until it is published from
*Versions*. Deploying it is what reaches the nodes.

**From the terminal.** `haprion-cluster-settings -c <cluster>` prints what is set: the log receivers, the
exporter and the shared counters. `--set` publishes a file at once. It uses the same helper *Versions*
publishes with, and publishes against the version it has just read: a change somebody else published in
between is refused rather than overwritten. The command runs under `sudo`, and the version records the
person who typed it:

```bash
sudo haprion-cluster-settings -c alpha
sudo haprion-cluster-settings -c alpha --set cluster.yaml -m "Send the traffic log to graylog"
haprion-deploy -c alpha
```

For automation, `apply` compares first and publishes only where the file differs from what is stored.
`--check` says whether it would publish, and `--json` answers with `changed`:

```bash
sudo haprion-cluster-settings apply -c alpha cluster.yaml --check --json
```

**The log** is the same structured record the node's own file gets
([Mirroring node traffic logs](#mirroring-node-traffic-logs)), with `node`: the host name of the node
that wrote it. The path is:

1. HAProxy writes one line per request to the node's syslog socket.
2. The node's rsyslog writes it to the day file and sends it to each receiver as syslog over TCP
   (RFC 5424, octet-counted). It does this whether or not the local stream is on.
3. The header carries the node's host name and the tag `haproxy-traffic`.

This one transport reaches the common platforms through their usual receivers. Graylog takes it
directly. Loki takes it through a syslog receiver such as Grafana Alloy's `loki.source.syslog`.
Elasticsearch and OpenSearch take it through Logstash or Vector with a syslog input.

With `tls: true`, the node checks the receiver's certificate chain against the node's system trust store
(rsyslog's GnuTLS driver, `rsyslog-gnutls`). It does not check the receiver's name.

A receiver is named by **address, never by host name**. That way, where the nodes send does not depend on
what their resolver answered at the moment rsyslog started.

**Not logged from** keeps a monitor's checks out of the log. A monitor that asks thirty services once a
minute makes some 43 000 lines a day that nobody reads - in the node's file, the *Traffic logs* view, the
dashboard's response times and every receiver. The rule:

- A request from a listed address or network that is answered below 400 is written nowhere.
- A request answered 400 or above is logged as any other. A monitor that is refused, or finds a service
  down, still shows.
- Only the connection's own address counts, never a header the request carries.
- The exporter's counters include these requests either way.

**Each receiver has a queue on the node's disk**, `disk_mib` large. The queue is what carries the log
through an outage or a burst:

- While a receiver is away, or reads slower than the traffic arrives, rsyslog keeps the lines on disk.
  It sends them when the receiver reads again.
- The queue survives a restart of rsyslog or of the node.
- At about 800 bytes a line, 1 GiB holds some 1.3 million lines.
- What does not fit is dropped for that receiver alone, and counted. Neither the traffic nor the node's
  own day file waits for a full queue.

A deploy that changes the receivers restarts rsyslog. The lines HAProxy writes meanwhile wait in its log
socket ([HAProxy and keepalived baseline](#haproxy-and-keepalived-baseline)). If rsyslog refuses the new
receivers, the node puts the previous ones back. The deploy then fails, with the HAProxy configuration
already live. The node is not current, just as when an address list is left half-way
([Optional per-cluster sections](#optional-per-cluster-sections)), and the next deploy finishes it.

Measured with rsyslog 8.2512 on one core: 25 000 lines a second forwarded and written to file used 9 % of
the core. 100 000 lines queued while the receiver was away arrived about a second after it came back.

**Seeing each receiver's queue.** Each queue shows per node:

- `haprion-status` prints a `Log forward:` line per node.
- The cluster's page under **Settings → Logs & metrics** has a **Delivery** table: each receiver as each
  node sends to it, its queue and its state.
- **Needs attention** lists a receiver whose queue has neither emptied nor shrunk for three minutes, or
  holds 10 000 lines or more. It lists one that dropped lines in the last hour as critical
  ([Needs attention, and external monitoring](#needs-attention-and-external-monitoring)).

The exporter's counters are complete either way.

When the node's rsyslog cannot connect, it says why, and the node passes that on. *Connection refused* or
*Connection timed out* shows beside the queue - in the terminal, in the table and in the attention row -
until the receiver is reached again. What it usually means:

| Reason | Usually |
|---|---|
| *Connection timed out* | a firewall between the node and the receiver drops the connection; or the address is wrong and nothing answers there |
| *Connection refused* | the receiver's host answers but nothing listens on the port: the receiver is stopped, or the port or protocol is wrong (a TLS port given without TLS, or the other way round) |
| none, and lines are not delivered | the connection is made but the receiver does not read: it is overloaded, or TLS is refused after connecting - its own log says which |

**The exporter** answers `GET /metrics` on the port given, on each node's own address - the address its
`mgmt_host` gives, never a VIP. Prometheus therefore scrapes the nodes by name, and scraping each node is
what shows the passive one as well. Only the listed sources get an answer; anything else gets 403, and
any other path gets 404. An object may use the same port on a VIP. A publish refuses a port that
`manual/reservations.yaml` reserves. Opening the nodes' firewall for the scraper, and for the nodes to
reach the log receivers, is part of the installation, not of this setting.

**Shared counters** keep the counts of the abuse brake and the rate limits the same on every node of the
cluster. A failover or a deploy then does not start them from zero. How it works:

- With `peers` set, a publish writes a `peers` section with one line per node, and every generated stick
  table names it.
- Each node keeps the others up to date over the port. A node that reloads takes the counts back from
  the others within seconds.
- A node that reloads while no other node is up starts from zero.
- What is shared is counters, not connections. A connection open on the node that fails still ends, and
  the client's next connection is counted with what it had already used.
- Persistence is unaffected. It is a cookie or a hash and needs nothing shared.

The address of each node is looked up from its management host name when the cluster is published.
A node that changes address therefore needs its DNS record changed and a publish. A name that does not
resolve, or resolves to more than one address, refuses the publish and names the node. A node finds its
own line by its host name, which has to be the node's name.

The port has to be open between the nodes, both ways, and nowhere else. That firewall is the
installation's. The traffic is not encrypted and carries client addresses and their counts. On the
dashboard, a node whose counters do not reach another node, or that shares none while the others do,
reads *Counters not shared* with the reason.

**DNS objects are scraped from dnsdist.** In a cluster with the exporter and a DNS object, dnsdist also
answers `GET /metrics` on port 9521 of each node's own address, for the same sources, and on loopback for
the node itself. Without the exporter, it answers on loopback only. Its metrics are dnsdist's own
(`dnsdist_*`). Each server is named `<pool>/s<n>`, and each object's queries are counted by the rules
`<pool>`, `<pool>/tcp` and `<pool>/refused`. Its API stays closed.

**The names a dashboard shows.** The exporter labels every backend metric with `proxy="<name>"`, and
carries nothing else that could name it - a backend's `description` is not exported (HAProxy 3.4). So a
pool is called in HAProxy exactly what it is called on the object form. Pool `web-80` of object
`shop-web` is the backend `web-80`, on the interface's metrics page and in a dashboard alike. That is why
a pool's name must be unique in the cluster. It is also why a pool's name may not begin with `mgd-`:
that is what the generator calls its own sections (the exporter's frontend, the VIP frontends, the WAF
engine). A redirect has no pool and is named after its object and path, for example
`shop-web-redirect-old`.

**A rename keeps its history on the interface's pages.** The metrics page lists only the backends that
the cluster's newest poll reports. Each card also reads the names its backend had before - any name a
publish renamed. What counts as a rename:

- for a pool: exactly one of an object's pools goes and one comes in the same publish. Two pools renamed
  at once are not paired.
- for a redirect: its object is renamed.

The pair is recorded when the publish is done. A publish that is refused or fails renames nothing. A name
given to a backend again stops counting for the backend that had it before. A dashboard reading the
exporter sees a new series under the new name, because HAProxy's counters begin again with it.

*Details:* the pairs are kept in the table `metric_backend_alias`.

#### Counters across a reload

Every deploy reloads HAProxy. A reloaded HAProxy starts its counters from nought, unless the cluster's
`core/haproxy.cfg` names a file to keep them in:

```
global
    shm-stats-file /run/haproxy/stats.shm
```

A new cluster's core has the line. HAProxy then keeps each frontend's, listener's and server's counters in
that file. After a reload it finds them again by the GUID (a fixed unique ID) the generator gives every
object. A deploy therefore puts no step into a dashboard reading the exporter. Changing a server's address
makes it a different server, which starts again. Reordering a pool changes nothing.

- **A pool's own figures still start again on every reload.** HAProxy 3.4.6 carries a backend's own
  counters badly: each reload attaches the backend to the other of two places in the file, so its totals
  show the figures of the process before last. The generator therefore gives backends no GUID until
  HAProxy does this right. A pool's servers are carried. A redirect has no server, so nothing of it is
  carried.
- **A restart still resets everything.** HAProxy gives the file up when it is stopped properly, and
  `/run` is emptied when the node starts. HAProxy opens the file as root before it changes into its
  chroot, so the path is the node's own. The validation on the manager gives the check an empty
  `/run/haproxy` to create the file in, so another path is refused there.
- **The interface's own figures are right either way.** A node reports whether its HAProxy has the file
  in use (`runtime.shared_counters` in `haprion-status --json`). The metrics count a reload as a restart
  only when the counters did start again: when they were not kept, or when one of them went down.

**A DNS object's card** is counted by dnsdist rather than HAProxy, under the pool's name like any other:

- *Queries*: everything that reached the listener.
- *Answered*: what its servers answered.
- *Refused*: refused because of `allow_from`.
- *Unanswered*: asked, less refused, less answered - a server that timed out, or no server up to ask.
- *Over TCP*.

On the metrics page, a DNS object's pool is one of the backends, in the same list and on the same scale;
its line counts queries. Per-server figures are left to the logging the nodes send elsewhere. Response
codes (NXDOMAIN, SERVFAIL) are not shown, because dnsdist 2.1 counts them for the whole process, not per
pool. dnsdist's counters are read on the node and are not part of HAProxy's exporter, so a dashboard
reading the exporter does not see them.

## Jobs and status freshness

### Getting started

A new installation's dashboard shows an admin a *Getting started* list: what is still to set up, one line
each, with the page that does it. A line is ticked when the installation shows it done, never by being
pressed:

- *Nodes and a cluster*: a cluster whose VIP a node holds;
- *TLS and source address*: a TLS version chosen on every VIP;
- *Interface certificate*: an interface certificate that is not self-signed;
- *Users and sign-in*: a second account, or sign-in through SSO;
- *Certificates for your proxies*: a certificate in the registry other than a CA - issued over ACME or NDES,
  imported, or signed from a request.

The optional lines come last: the features, node backups (scheduled on every cluster), the traffic log
(forwarded from every cluster) and external monitoring. The features come first among them, since node
backups are one of the features. While the first cluster is not yet serving, its line names the guide's
step, and **Continue** opens it. Once the first node has joined, **Continue** opens *Deploy*: the second node
is optional, and *Deploy*'s **Back** returns to it.

*Hide getting started* removes the list for the whole installation. For seven days after that,
*Show getting started* beside *Clusters* brings it back; then that button goes too. The audit record says
who did either.

### Needs attention, and external monitoring

Under the dashboard's four cards, *Needs attention* lists what is wrong and needs somebody, across every
cluster, the worst first. For an admin, each row links to where it is fixed. When nothing is wrong, the
box is not shown.

**What is listed:**

- **Certificates** that are running out, cannot be read, or are not where they should be - the
  interface's own included. A certificate renewed by hand is a warning with 30 days left; one from ACME
  with 25 days left (certbot renews at 30, so 25 means renewal is failing). Under seven days it is
  critical.
- **Jobs**: the latest job of an operation on a cluster that failed, partly worked, was blocked or ended
  *unknown* - until a later run of the same operation on the same thing works, however long that takes.
  A blocked job changed nothing and is a warning.
  A job on several certificates is settled certificate by certificate: when its answer says which ones
  it did not finish, only those wait for a later run. A certificate that was issued or imported but
  not distributed says so, and a later publish of it, or a certificate deploy of each cluster it missed,
  settles it. A removed cluster's jobs are not listed.
- **Clusters** with a fault no single node shows: a VIP in split brain or with no owner while every node
  reports Online, or a status reading that failed or returned no node.
- **Nodes** that are down or have a warning - for example *Counters not shared*. A node that is only
  behind the published version is not listed: that is a publish waiting for its deploy.
- **A node to prepare again**, as a warning, when its node package brings a changed preparation step:
  run `sudo haprion-node-prepare` on it ([Installing and changing node scripts](#installing-and-changing-node-scripts)).
- **A node on another node package than the manager's**, as a warning: its `haprion-node` is older than
  the one the manager's release carries, or newer. Older: an upgrade has not reached the node yet, and
  `apt upgrade` on it clears it. Newer: the manager has not been updated yet, or its CLI was rolled back.
- **A node package not configured**, as a warning: its install script failed on the node, or its unpacking
  stopped. `sudo dpkg --configure -a` there finishes the first; for the second, dpkg says to reinstall it
  with `sudo apt install --reinstall haprion-node`. `haprion-status` and `check-compatibility` say the same.
- **Objects whose servers are not up**, as their lamp on *Proxies* says it. Critical when no node reaches
  any of them; a warning when some are down, or down on one node only. An object without a health check
  has no lamp and is not listed.
- **A cluster whose status has not been read** for two poll intervals.
- **A WAF exception** marked *Not working*.
- **A node backup** that is missing, old or failed.
- **Traffic log collection** on a node that failed, has not succeeded for five minutes, or is still
  behind after five runs or with older days waiting. Catching up after a burst is left to the log page's
  own warning.
- **A traffic log receiver** whose queue on the node has neither emptied nor shrunk for three minutes, or
  holds 10 000 lines or more - with the reason the node's rsyslog gave, when it gave one. One that dropped
  lines in the last hour is critical.
- **The manager's own services**, judged by what they leave in the database:
  - the poller has not read the clusters for two poll intervals (at least five minutes), or never has -
    critical;
  - a job has been queued for ten minutes with none running while writes are on, so the worker is taking
    none - critical. A job no worker holds does not count as running, and nor is the row raised while an
    update of the manager pauses the queue;
  - a job still *running* that no worker has held for 50 minutes, while no other job runs and writes
    are on: the worker is stopped, hung or crashing, or waits for something that will not come by itself -
    critical. *Jobs* shows it as *No worker*, and the worker's journal says why it waits:
    `journalctl -u haprion-worker`;
  - jobs held after a restart or a restore, waiting for an admin to choose *Run* or *Discard*
    ([The worker](#the-worker)) - a warning;
  - the nightly maintenance (`haprion-retention`) has not run: the daily partitions it makes ahead of time
    fall more than a day short (a warning), or there are none at all (critical); or it has run but not
    finished for two days - it stopped after the partitions, so jobs and records stopped being pruned
    (a warning). The run's own log says why: `journalctl -u haprion-retention.service`.
- **A newer version waiting** for one of the manager's own `haprion-*` packages, as a warning, until
  `apt upgrade` installs it. Nothing is fetched to know this: the answer comes from the lists apt already
  holds, so it is as new as the machine's last `apt update`.

**What is not listed:** what somebody chose. A drained server, a maintenance page, a block, a publish not
yet deployed - those are on the cluster's card and *Operations* line, and on *Versions*.

The rows for WAF exceptions and traffic log collection appear only while traffic logging is on. The rows
for node backups appear only while the *Node backups* feature is on.

**Acknowledging a row.** Some things are known and left as they are - a restore given up, a receiver down
on purpose. An admin can **acknowledge** such a row (with `management_writes` on). The row is then left
out of the list, and out of what monitors are told, until it has gone: when what it says is put right, or
when a later run of the job's operation works. The same trouble coming back after that, or a job of the
operation failing again, makes a row again. Each acknowledgement is in *Audit*, with who made it and what
the row said.

**The same list for a monitor.** A monitor can read the list without signing in:

```
GET https://<manager>/status/attention.json
GET https://<manager>/status/metrics
```

The first answers `{"generated_at", "fresh", "counts": {"critical", "warning"}, "items": [...]}`. Each
item has `kind`, `severity`, `cluster`, `subject`, `message`, `since` and `link`.

`fresh` is how a monitor sees that the manager itself has stopped reading. It is `true` when every
cluster's status was read within the last two poll intervals - or, on an installation with no cluster yet,
when the manager read its list of clusters within that time. It is `false`:

- once any cluster's status reading is older than two poll intervals;
- while a cluster has never been read;
- when the manager has stopped reading even its list of clusters.

The second is Prometheus's text format: `haprion_attention_items{kind, severity}` for every kind, and
`haprion_status_age_seconds{cluster}` for every cluster that has been read.

**Who may ask.** The allowed monitors are a list on *Settings → External monitoring* (*Edit* on its row):
addresses or networks, one per line. An address that stays on the list keeps who added it and when.
Every other address is answered 404. While the list is empty, every address is answered 404 - an empty
list switches the endpoint off. So a monitor that is answered 404 is not on the list.

The address checked is the one nginx hands the interface. With a reverse proxy in front, it is the client
the proxy names - but only when the proxy is set as trusted (`TRUSTED_PROXIES`, see
[Behind another reverse proxy](#behind-another-reverse-proxy)). Otherwise it is the proxy's own address.

`haprion-settings apply` sets the same list from a file (*Settings from a file*, under
[Signing in through an OpenID Connect provider](#signing-in-through-an-openid-connect-provider)).

**Choosing what to alert on.** Any monitor that can make an HTTPS request will do; three ways follow. In
each, *healthy* means nothing red on the dashboard and every cluster read recently. Warnings - a
certificate running out within its warning window, a backup overdue - are better a second, quieter check
than a page at night.

#### What the answers look like

With nothing to do:

```json
{"generated_at":"2026-10-11T20:00:00Z","fresh":true,"counts":{"critical":0,"warning":0},"items":[]}
```

With a certificate running out and a failed node backup:

```json
{
  "generated_at": "2026-10-11T20:24:09Z",
  "fresh": true,
  "counts": {"critical": 2, "warning": 0},
  "items": [
    {"kind": "certificate", "severity": "critical", "cluster": null, "subject": "shop.example.com",
     "message": "expires in 4 days", "since": null, "link": "/certificates?view=registry"},
    {"kind": "backup", "severity": "critical", "cluster": "beta", "subject": "beta",
     "message": "node backup · Last scheduled run failed", "since": null, "link": "/backups"}
  ]
}
```

And the metrics, shortened:

```
haprion_attention_items{kind="backup",severity="critical"} 1
haprion_attention_items{kind="certificate",severity="critical"} 1
haprion_attention_items{kind="certificate",severity="warning"} 0
haprion_attention_items{kind="job",severity="critical"} 0
haprion_status_age_seconds{cluster="alpha"} 12
haprion_status_age_seconds{cluster="beta"} 14
```

`kind` is one of `backup`, `certificate`, `cluster`, `forwarding`, `job`, `logs`, `manager`, `node`,
`reading`, `service` and `waf`. Every kind and severity pair is present, even at 0, so an alert
expression never meets a missing series.

#### Uptime Kuma

A monitor of type **HTTP(s) - Json Query**:

| Field | Value |
|---|---|
| URL | `https://<manager>/status/attention.json` |
| Heartbeat interval | `60` |
| Json Query | `counts.critical = 0 and fresh = true` |
| Expected value | `true` (condition `==` where the version asks for one) |
| Method | `GET`, no body, no headers |

The monitor is up while the expression is true. It goes down within one interval of anything turning
red, or of the manager no longer reading the clusters. For the quieter second monitor:
`counts.critical = 0 and counts.warning = 0 and fresh = true`.

Uptime Kuma runs on Node.js, which trusts its own list of public CAs rather than the operating system's.
If the manager's certificate is issued by your own CA, the monitor says *unable to verify the first
certificate*. You have two choices:

- Give Uptime Kuma the root: name its PEM file in the environment variable `NODE_EXTRA_CA_CERTS`, then
  restart Uptime Kuma.
- Or tick *Ignore TLS/SSL errors* on this monitor. That stops it checking who answered.

#### Prometheus

```yaml
scrape_configs:
  - job_name: haprion
    scheme: https
    metrics_path: /status/metrics
    scrape_interval: 60s
    tls_config:
      ca_file: /etc/prometheus/your-root-ca.pem
    static_configs:
      - targets: ["<manager>:443"]
```

```yaml
groups:
  - name: haprion
    rules:
      - alert: HaprionNeedsAttention
        expr: sum(haprion_attention_items{severity="critical"}) > 0
        for: 2m
        annotations:
          summary: "Haprion: {{ $value }} critical item(s) on the dashboard"
      - alert: HaprionWarnings
        expr: sum(haprion_attention_items{severity="warning"}) > 0
        for: 1h
      - alert: HaprionStatusStale
        expr: max(haprion_status_age_seconds) > 300
        for: 5m
      - alert: HaprionEndpointDown
        expr: up{job="haprion"} == 0
        for: 5m
```

`haprion_status_age_seconds` is the number of seconds since each cluster was last read. At the default
poll interval of 20 seconds, it stays well under a minute.

#### Anything else: a script

For a monitor that runs a command and reads its exit code - Nagios, Icinga, Zabbix, Checkmk, or cron with
mail:

```sh
#!/bin/sh
# 0 OK, 1 warning, 2 critical, 3 unknown - the Nagios convention.
MANAGER=manager.example.com
CA=/etc/ssl/your-root-ca.pem
answer=$(curl -fsS --max-time 10 --cacert "$CA" \
         "https://$MANAGER/status/attention.json") || { echo "UNKNOWN: no answer"; exit 3; }
critical=$(printf '%s' "$answer" | jq -r '.counts.critical')
warning=$(printf '%s' "$answer" | jq -r '.counts.warning')
fresh=$(printf '%s' "$answer" | jq -r '.fresh')
items=$(printf '%s' "$answer" | jq -r '[.items[] | "\(.subject): \(.message)"] | join("; ")')
[ "$fresh" = true ] || { echo "CRITICAL: the manager has stopped reading its clusters"; exit 2; }
[ "$critical" -eq 0 ] || { echo "CRITICAL: $items"; exit 2; }
[ "$warning" -eq 0 ] || { echo "WARNING: $items"; exit 1; }
echo "OK: nothing needs attention"; exit 0
```

The message carries each item's subject and sentence, so the alert says what is wrong without opening the
dashboard.

### Events: jobs, the nodes and the audit record

*Events* has three views: *Jobs*, *Nodes* and *Audit*.

**Jobs** lists the newest jobs and their outcome, and under *By*, who queued each one, taken from the
record. An admin also sees each job's diagnostics.

**Nodes** shows what the nodes did on their own:

- a server that went down or came back up, with the check's reason;
- the VIP moving from one node to the other;
- a node that stopped answering, or answers again.

A node just added is *Joining* until it answers the first time, and that first answer is not an event. A
server's row names its object and links to its servers. Both roles can read this view. It pages and
filters by cluster, a word and time, as *Audit* does. The nightly retention removes rows older than 90
days.

The poller writes this view by comparing each status reading with the one before:

- A server's change is dated by HAProxy's own count of how long ago it changed, so the time is right to
  the second. But a server that went down and came back between two readings leaves no row.
- Servers are read from the node holding the VIP, as the metrics are. The other node's health checks
  leave from an address it does not have.
- A server in drain or maintenance keeps its last state until it is checked again.
- The first reading of a new server or a new installation is a starting point, not an event.
- A restart of HAProxy is not listed. A reload starts HAProxy's uptime again too, so the two cannot be
  told apart, and a deploy is already listed under *Jobs*.

**Audit**, for an admin only, is the rest of the record, newest first, fifty to a page by default. It
holds:

- sign-ins and failed attempts;
- account and role changes, and password changes;
- the identity provider and feature switches;
- key exports;
- saved and discarded changes and drafts;
- every queued job, with a link to it while the job is still listed.

Each row is one sentence; a row with more to it opens beneath itself when clicked. You can filter by
cluster, by who or by a word (a search reaches back 90 days), and page through it as through the traffic
log. A failed sign-in under a name no account has shows as *unknown user*, never the name typed - which
may have been a password. The record is append-only: no role may change or delete a row. The nightly
retention removes rows older than two years.

On an object's *Servers* card, a server in drain or maintenance says *Set by <name> · <time>*: the newest
request that asked for the state it is in.

### How often status is refreshed

The poller reads the clusters every `poller.interval_seconds` (in `ui.toml`): 20 seconds by default,
between 10 and 3600. The interval is a pause *after* each pass, not a fixed period. The real cadence is
therefore the interval plus however long a pass takes - measured at 2-3 seconds for two clusters on the
reference machine. A pass for two clusters is about eight helper calls: one for the cluster list, one for
the manager's own certificates, and three per cluster. Of those, only each cluster's status reading
reaches the nodes.

**A finished job wakes the poller, as well as the clock.** Publishing or deploying through the interface
queues a job, and the poller reads the clusters again as soon as that job ends. Those changes therefore
appear without waiting. A change made *outside* the interface does wait: `haprion-publish` or
`haprion-deploy` run on the command line queues no job, nothing is notified, and until the next pass the
pages show the reading taken before the change. An object deployed from the command line therefore keeps
its *Inactive · deploy to add* badge for up to one interval. That is the interface being careful, not
wrong.

**What a version changed** works the same way. `haprion-list -c <cluster> --diff <version>` prints one
version against the version before it, file by file. The poller asks the helper for the same thing for
each version it has no diff for yet, and keeps the answer, since a version's diff never changes. Both read
it the same way, limited to 200 files and 256 KiB of patch text. A diff past that limit says it was cut.

*Details:* the poller's request is `diffs`, with at most ten commit hashes per request.

**Two kinds of failure are kept apart.** `poll_error` means the poller could not get an answer: sudo
refused, the helper is missing, or the output was not JSON. An `outcome` of `failed` or `partial` means
the cluster answered and the answer is bad news. Mixing them up would send somebody to read sudoers when a
node is down, or the reverse.

### The worker

The worker runs the jobs the interface queues. When it starts, it connects to the database and reports
which database role it is actually running as.

**With `management_writes` off, it runs no job.** That is the state a rollback of the write path returns
to, so it has to be a state that runs. It does one thing at start, writes on or off: it holds the jobs
that were queued before the machine last started (see below).

**With writes on, it runs each job through an exact privileged helper.** Most helpers run over `sudo`; the
few that write under `/etc` run over a root-owned socket. The worker's systemd unit therefore lets `sudo`
raise privilege (`NoNewPrivileges=no` and a short, named set of capabilities); every capability is
explained in the unit file beside it. The real limit is not the sandbox but
`/etc/sudoers.d/haprion-worker`. It names each helper and permits no arguments. Widening the unit does not
widen what may be run; only that file does.

**A helper that outlives its worker.** The helpers behind sockets - node and cluster changes,
node backups and restores, receivers - run in systemd units of their own. A worker that is stopped or
restarted on its own - a UI release, `needrestart` - does not stop them; a reboot does. Nor does a client
that stops waiting: a node's join runs apt, and a slow mirror can keep it past the 14 minutes its
client waits. Each helper keeps its answer in `/var/lib/haprion/answers` (root's, readable by the
worker). The job stays *running* while its helper works, and then ends on the helper's own answer, with what follows it in the same job: a node
change's deploy runs then. A helper that ended without an answer leaves the job `unknown`, and so does
one a reboot ended mid-work. An answer is kept two weeks from its helper's end. A held job whose answer
is gone by then ends `unknown` with the code `answer_absent`: when nobody answered in time, or after the
host was restored from an image older than that. A job whose helper answered, but whose deploy after it
was stopped twice, ends `unknown` with the code `follow_up_exhausted` and the helper's answer kept with it.

**Jobs from before a restart or a restore.** A manager restored from an image or a backup comes up holding
the jobs that were waiting when the backup was taken - and those ran back then. Running them again could,
for example, drain a server that has since been set ready. The worker guards against this in two ways:

- At start, it holds every job queued before the machine last started. A held job waits on *Jobs* until
  an admin chooses *Run* or *Discard*, and *Needs attention* lists it. A job queued just before an
  ordinary reboot waits for that choice too. If the start time cannot be read, nothing is held.
- A job that has waited more than two hours when it is first taken is not run. It ends as `blocked`,
  saying how long it waited; ask again if it still applies. The wait counts to when the job was first
  taken. A job retried after its worker died is held to that same wait; one first taken in time has been
  judged on evidence (below) and runs.

**A job whose worker died.** With writes on, each pass first settles jobs whose worker stopped. Each job is
held under a lease, a claim the worker keeps renewing. An expired lease says only that the process holding
the job stopped renewing it. It does not say whether the work was done. So the job is judged by what can
be read, rather than retried on assumption:

- **A publish of any kind, or a revert** - publishing objects, saved changes, the network or *Logs &
  metrics* - is judged by whether a version carrying that request exists, and whether its release was
  published.
- **A deploy or a certificate deploy** needs no evidence. Both read the cluster before they act, so
  running one again is safe; that is how they work.
- **Any other operation** has no evidence to read, and ends as `unknown`.

Evidence older than the expired lease is not weak evidence but none: it describes a moment when the
operation could still have been running. A job with only such evidence waits rather than being decided.
A job is handed to a worker at most twice. One that has been taken twice and answered neither time ends
as `unknown`. That outcome is reserved for "nobody can say whether this took effect", and is never
retried automatically.

Only a running worker settles a job. One stopped, hung or crashing leaves its job *running*: *Jobs*
shows it as *No worker* once no worker has held it for 50 minutes and no other job runs, and *Needs
attention* lists it.
So does a job whose evidence the worker waits for and cannot read.

This settling also happens only with writes on. With writes off, apart from the hold at start, no job
moves - including one somebody would rather see moved. That is what makes the switch a rollback rather
than a pause.

*Details:* the worker may not touch the `proxy_draft` table; only the web role holds grants on it. The
worker publishes from the job's payload, never from the table. That is why a draft that has been
published is cleared by the interface on its next read, not by the worker as it finishes. The clearing
matches on the publish's idempotency key, which carries the draft's revision. A draft edited after the
publish was asked for therefore has a different key and is left alone. A draft and a saved change of the
same object are two rows (`stage`), each cleared by its own publish.

## Automation from the terminal

Everything the interface sets can also be set from a shell on the management host. A configuration tool
can then describe an installation, and run again without changing anything. The interface stays the first
way in. The commands go through the same helpers, the same code and the same refusals, and their writes
are audited and versioned the same way.

| In the interface | From the terminal |
|---|---|
| *Proxies*: new, edit, remove, advanced config, WAF exceptions | `haprion-objects apply`, `haprion-objects remove` |
| *Network* | `haprion-network apply` |
| A cluster's *Logs & metrics* | `haprion-cluster-settings apply` |
| *Versions*: deploy, revert | `haprion-deploy`, `haprion-revert` |
| Drain, maintenance, unblock | `haprion-server-state` |
| *Settings → Nodes & clusters*: nodes and clusters | `haprion-node`, `haprion-cluster` |
| *Certificates*: issue, import, request, NDES, publish | `haprion-cert-issue`, `-import`, `-request`, `-scep`, `-publish`, `-deploy` |
| *Certificates*: renew | certbot's: `haprion-cert-issue --domain <id> --renew`; NDES: `haprion-cert-scep --id <id> …` |
| *Certificates*: publish to, remove from, delete | `haprion-cert-target`, `haprion-cert-delete` |
| *Certificates*: DNS profiles and NDES profiles | `haprion-profiles` |
| External certificate receivers | `haprion-cert-receiver` |
| *Node backups*: schedule, run, restore | `haprion-backup-schedule`, `haprion-state-backup -c <cluster> --json`, `haprion-node-restore` |
| *Settings → Users* | `haprion-user` |
| *External monitoring*, *Features*, OIDC | `haprion-settings` |
| The interface's own certificate | `haprion-tls` |

What they have in common:

- **A file says what should be.** `apply` reads a file (or, for objects, a directory of files) and writes
  only what differs from what is stored, so the same file twice changes nothing. What the file does not
  name is left alone. `--prune`, where a command has it, removes what the file does not name.
- **Each key once.** A file that gives the same key twice in one place is refused, with the line. A
  copied block that was not renamed would otherwise replace the first one without a word.
- **`--check`** says what would change, and changes nothing.
- **`--json`** prints one answer in the contract's format, called the envelope (`docs/CONTRACT.md`,
  `schemas/v1/`). It includes `changed` where the command decides it, also when the command stops early.
  The exit code follows the envelope's outcome: 0 for done, 69 for partly done, 75 for blocked, and a code
  from the contract's *Exit codes* for a failure.
- **Publishing is not deploying.** `haprion-objects apply`, `haprion-network apply` and
  `haprion-cluster-settings apply` publish a new version. `haprion-deploy` rolls it out - the same two
  steps *Publish & deploy* takes.
- **With sudo, on the manager.** `haprion-user`, `haprion-settings` and `haprion-profiles` write the
  interface's database as root, and `haprion-export` reads it. They need the platform installed.
  `haprion-profiles` also needs a running worker with writes on, since a profile takes effect as a job.
  The other commands are the engine's: they hand their request to a root helper. Run as root, they run
  that helper directly, and it records the person sudo names.
- **Secrets come from a file only its owner may read, or from standard input** - never as an argument. A
  file that carries a password, a client secret or credentials is refused unless its mode is `0600`. A
  secret that is stored encrypted cannot be compared, so it is replaced only when it must be, or when the
  command is asked to (`--replace-oidc-secret`, `--replace <id>`).

What is not a setting cannot be described in a file: drafts, previews, downloads of key material, and the
password a person changes for themselves. `haprion-user` still has one-off commands for an account:
`reset` sets a new password and ends every session, `revoke` ends every session without changing the
password, and `disable`, `enable` and `unlock` block sign-in, allow it again and clear the sign-in
throttle.

`haprion-export` writes what is set now as the files these commands take, as a starting point.
[Automating with Ansible](#automating-with-ansible) shows the whole of it as a playbook.

### Automating with Ansible

A playbook drives the commands above and reads `changed` from their answers. The interface remains the
way in for a person. The playbook is how the same installation is described, rebuilt, or kept from
drifting.

**Where it runs.** The commands live on the management host and run as root, so the play targets that host
with `become: true`. Some PAM setups make sudo ask for the password twice; there, `--ask-become-pass` waits
for an answer that never comes. In that case, run `ansible-playbook` itself as root on the manager
(`sudo ansible-playbook …`) and drop `become`.

**Start from what is set.** On the manager:

```sh
sudo haprion-export /home/operator/haprion
```

The directory must be new or empty. It is created with mode `0700`, its files `0600`, and handed to the
person who ran sudo. `--cluster <id>` (repeatable) limits the export to some clusters. `--json` answers
in the contract's format (`haprion-export` in `docs/CONTRACT.md`).

| File | Taken by |
|---|---|
| `accounts.yaml` | `haprion-user apply` |
| `settings.yaml` | `haprion-settings apply` |
| `profiles.yaml` | `haprion-profiles apply` |
| `clusters/<id>/objects/<name>.yaml` | `haprion-objects apply -c <id> clusters/<id>/objects` |
| `clusters/<id>/network.yaml` | `haprion-network apply -c <id>` |
| `clusters/<id>/cluster-settings.yaml` | `haprion-cluster-settings apply -c <id>` |
| `clusters/<id>/backup-schedule.yaml` | the flags of `haprion-backup-schedule -c <id>` |

Applied to the installation it came from, every file changes nothing - that is the first thing to run.
What the export cannot express it lists as `skipped`, with the reason:

- an object the generator refuses;
- a network that comes from the cluster definition (there is no document to apply);
- a backup schedule never set, or set to a calendar the form cannot express.

`--prune` removes what the files do not name. So `haprion-objects apply --prune` on the export's directory
removes an object that was skipped. Mend the object first, or apply without `--prune`.

**What the export leaves out.**

- Accounts made through the identity provider. Each is made at its first sign-in, from its groups, and a
  file has nothing to say about one. An account the file does not name is left alone, and `--prune` never
  removes one of the provider's accounts.
- Secrets. Nothing secret is read back, so none is written either: no account passwords, no OIDC client
  secret, no DNS provider credentials (`fields`), no NDES challenge. Applied where they came from, the
  stored secrets are kept.

For a new installation, add the secrets - from Ansible Vault, never in the files you keep in version
control:

- an account's `password` in `accounts.yaml`, which must then be mode `0600`;
- the client secret on standard input with `--oidc-secret-stdin`, and `interface_url` in the `oidc`
  section to turn sign-in on;
- a DNS profile's `fields` and an NDES profile's `challenge` in `profiles.yaml`, mode `0600`.

**The order.** Some steps depend on others:

1. Profiles, before a certificate that is issued through one.
2. Accounts, before the interface settings: sign-in through a provider can be turned on only while there
   is an active break-glass admin. With `--prune`, an account no entry names is removed - but never one
   the provider created, and never the last active admin.
3. Interface settings, before the backup schedules. Turning *Node backups* on starts the schedules it had
   stopped, and `haprion-settings` ends when they have run, so a schedule set after it stays as set.
4. Per cluster: the network before the objects - an object on a VIP the cluster does not have is
   refused - then *Logs & metrics*, then the deploy.
5. The deploy, on every run. A node that is current is left alone, and a deploy that failed on an
   earlier run is finished on the next.

**Changed and failed.** Every command answers with one envelope when given `--json`. Exit code 0 means
done. Ansible's `command` module fails the task on any other exit code: a refusal or an error, which the
envelope's `error` names, and also a partial result (69), where the envelope says what was done.
`changed` is the answer's own:

```yaml
changed_when: (result.stdout | from_json).result.changed
```

`haprion-deploy` reports per node; a node `updated` is the change.

**Check mode.** Ansible skips `command` tasks under `--check`. Give each command its own `--check` instead,
and let the task run:

```yaml
argv: "{{ [...] + (['--check'] if ansible_check_mode else []) }}"
check_mode: false
```

`haprion-deploy` and `haprion-revert` have no `--check`. Leave them out of a check run
(`when: not ansible_check_mode`).

**A playbook.** It expects the export's layout under `haprion_files` on the manager, one cluster, and the
client secret from Vault. `--oidc-secret-stdin` is for a `settings.yaml` with an `oidc` section; without
one, leave it and `stdin` out. A cluster whose backup schedule the export skipped has no
`backup-schedule.yaml`; leave that cluster out of the schedule's loop.

```yaml
- name: The HAProxy management host
  hosts: manager
  become: true
  gather_facts: false
  vars:
    haprion_files: /srv/haprion
    clusters: [alpha]
    check: "{{ ['--check'] if ansible_check_mode else [] }}"
  tasks:
    - name: DNS and NDES profiles
      ansible.builtin.command:
        argv: "{{ ['haprion-profiles', 'apply', haprion_files ~ '/profiles.yaml', '--json'] + check }}"
      register: profiles
      changed_when: (profiles.stdout | from_json).result.changed
      check_mode: false

    - name: Accounts
      ansible.builtin.command:
        argv: "{{ ['haprion-user', 'apply', haprion_files ~ '/accounts.yaml', '--json'] + check }}"
      register: accounts
      changed_when: (accounts.stdout | from_json).result.changed
      check_mode: false

    - name: Sign-in, External monitoring and features
      ansible.builtin.command:
        argv: >-
          {{ ['haprion-settings', 'apply', haprion_files ~ '/settings.yaml',
              '--oidc-secret-stdin', '--json'] + check }}
        stdin: "{{ vault_oidc_client_secret }}"
      register: settings
      changed_when: (settings.stdout | from_json).result.changed
      check_mode: false
      no_log: true

    - name: Network
      ansible.builtin.command:
        argv: >-
          {{ ['haprion-network', 'apply', '-c', item,
              haprion_files ~ '/clusters/' ~ item ~ '/network.yaml', '--json'] + check }}
      loop: "{{ clusters }}"
      register: network
      changed_when: (network.stdout | from_json).result.changed
      check_mode: false

    - name: Proxy objects
      ansible.builtin.command:
        argv: >-
          {{ ['haprion-objects', 'apply', '-c', item,
              haprion_files ~ '/clusters/' ~ item ~ '/objects', '--json'] + check }}
      loop: "{{ clusters }}"
      register: objects
      changed_when: (objects.stdout | from_json).result.changed
      check_mode: false

    - name: Logs & metrics
      ansible.builtin.command:
        argv: >-
          {{ ['haprion-cluster-settings', 'apply', '-c', item,
              haprion_files ~ '/clusters/' ~ item ~ '/cluster-settings.yaml', '--json'] + check }}
      loop: "{{ clusters }}"
      register: cluster_settings
      changed_when: (cluster_settings.stdout | from_json).result.changed
      check_mode: false

    - name: Read each backup schedule
      ansible.builtin.slurp:
        src: "{{ haprion_files }}/clusters/{{ item }}/backup-schedule.yaml"
      loop: "{{ clusters }}"
      register: schedules

    - name: Node backups
      ansible.builtin.command:
        argv: >-
          {{ ['haprion-backup-schedule', '-c', item.item, '--time', s.time,
              '--retention', s.retention | string]
             + (['--weekly', s.weekly] if s.weekly is defined else [])
             + (['--monthly', s.monthly | string] if s.monthly is defined else [])
             + ([] if s.enabled else ['--disable'])
             + ['--json'] + check }}
      vars:
        s: "{{ item.content | b64decode | from_yaml }}"
      loop: "{{ schedules.results }}"
      register: schedule
      changed_when: (schedule.stdout | from_json).result.changed
      check_mode: false

    - name: Roll out what is published
      ansible.builtin.command:
        argv: [haprion-deploy, -c, "{{ item }}", --json]
      loop: "{{ clusters }}"
      register: deploy
      changed_when: >-
        'updated' in ((deploy.stdout | from_json).result.nodes | map(attribute='outcome'))
      when: not ansible_check_mode
```

**Certificates and nodes** are operations more than settings. Run them as needed rather than describing
them in files:

- `haprion-cert-issue`, `-import`, `-request` and `-scep` make a certificate.
- `haprion-cert-target add|remove` and `haprion-cert-delete` are safe to repeat: a target already there,
  or a certificate already gone, is no change.
- `haprion-node`, `haprion-cluster` and `haprion-node host` change what the manager reaches.

Run them the same way, with `--json`. Their answers have no single `changed` field, so base
`changed_when` on what each one reports. `haprion-cert-target` lists the certificates it changed under
`changed`, empty when nothing changed. `haprion-cert-delete` lists the certificates it removed under
`removed`; one already gone is listed under `refused` with the code `not_registered`, and the command
still exits 0.

## Maintenance

### Keeping HAProxy current

The configuration this project generates is written for **HAProxy 3.4 or newer**. Debian 13 ships 3.0, and
Ubuntu 26.04 ships 3.2.

Where a host has an older HAProxy, the installation steps (step 1 on the management host, step 4 on a
node) add the HAProxy maintainer's repository and install 3.4 from it: Vincent Bernat's PPA on Ubuntu, or
`haproxy.debian.net` on Debian, with a pin. These are the same key, source and pin a restored node gets.
The steps leave alone a host already on 3.4 or newer, whatever source it came from, and never upgrade a
node that already serves a release. A publish on a management host older than 3.4 is refused with a
sentence saying so, rather than with HAProxy's own error.

After that, which HAProxy version runs, and when it is upgraded, is up to you. That is a boundary in the
design rather than an omission, and it is worth knowing why before it matters.

Upgrading the package restarts the data plane. The whole privilege model here exists so that this tool
cannot do that on its own. Every management identity is a forced command that can ask a node to *pull*
something, and nothing else. There is no push path, and a tool that could silently restart HAProxy on a
live node would need one. Package upkeep belongs to whatever already patches these hosts - unattended
upgrades, a configuration-management run, your own maintenance window - on a schedule you choose and can
pause.

Two things this project does depend on:

**The branch you run should still be receiving fixes.** HAProxy publishes the maintenance status of each
branch at [haproxy.org](https://www.haproxy.org/), and the binary states it too:

```console
$ haproxy -v
HAProxy version 3.4.4 2026/08/28 - https://haproxy.org/
Status: long-term supported branch - will stop receiving fixes around Q2 2031.
```

Distribution packages are often frozen at an early point release of a branch, and carry backported
security fixes only. That is different from running the branch's current release. Both are defensible;
choose between them deliberately rather than by default.

**The management host and the nodes should run the same branch.** The management host checks a candidate
configuration with its own `haproxy -c` before any node is asked to pull it. That check is only
meaningful while it is at least as strict as the nodes are. A checker on a *newer* branch can accept a
directive the nodes then reject. The deploy then fails on the first node and rolls back, so nothing
breaks - but the check has stopped doing its job. When you upgrade, do the nodes first and the management
host last. Then the checker is never the newer of the two.

**One node at a time is fine, and it is shown.** You can patch one node and leave the other a day or two -
to try a release before the second node gets it, with the old one still there to go back to. Nothing
here refuses a deploy over it. The dashboard shows it on the node that is behind, in its *Runtime* cell,
until both match. `haprion-status` shows the same on that node's `HAProxy ver:` line. The notes are:

- `Older than 3.4.7` - its HAProxy process is an older release than another node's. This is the running
  process, not the package: a node that was patched but not restarted still says it.
- An older package than another node's. This covers HAProxy's own package, keepalived, dnsdist, the WAF
  engine, and the OpenSSL library HAProxy uses. The dashboard says `Older package: keepalived, OpenSSL`,
  and pointing at it gives the versions. `haprion-status` says it per package, with the newer version:
  `keepalived older than <version>`. When the HAProxy process is already older, the note for HAProxy's
  package is left out. Packages are compared as dpkg compares them, on the whole version. A security
  update that changes only the revision (`3.5.5-1ubuntu3.7` to `-1ubuntu3.10`) counts, and so does a PPA
  rebuild of the same release (`3.4.6-1ppa1` to `-1ppa2`), whichever source the package comes from.
- `Manager validates with 3.4.7` - the management host's HAProxy is newer than this node's; see the
  order above.

A package one node does not have is not compared, and neither is the kernel.

Package sources and pinning are described under
[Where the package comes from](#where-the-package-comes-from).

### Updating Haprion

While the update check is on, a newer release shows in the header, beside the version. Updating is `apt`
on each machine: the manager first, then the nodes.
A new HAProxy is the exception: when `apt list --upgradable` on the manager shows `haproxy`, the nodes go
first and the manager last, so its check is never the newer
([Keeping HAProxy current](#keeping-haproxy-current)).

**The manager.**

```bash
sudo apt update && sudo apt upgrade
```

The web interface's package updates the running platform itself. It:

1. installs the platform's service files again;
2. checks the new release against everything installed;
3. takes a dump of the database before a schema change;
4. migrates the database;
5. switches to the new release.

A job that is running is finished first, and new jobs wait. The pages stop answering for a few seconds
while the services restart. When it is done, the header shows the new version.

If the update fails, it says why in its own output, and nothing has changed for the users: the previous
release is still running, with the files it ran with. Correct what the output names, then run the update
again with `sudo dpkg --configure -a`. If the previous release could not be put back either, the output
says so: the new release runs, not yet proved. Every later update, of that release or a newer one, goes
on from the release last proved, and goes back to it if it fails after its switch. Until then the update
keeps what it goes back to in `/var/lib/haprion-ui/platform-update`. A release whose migration the
release last proved cannot run on is refused for that reason. To keep the unproved release instead, and
go on from it, remove `/var/lib/haprion-ui/platform-update/update`, then run `sudo dpkg --configure -a`.

While a restore has stopped the services and not finished, the update, a rollback and a setup refuse before they change anything: run
`sudo haprion-backup restore` again to the end first, and a restore itself holds the others off while it runs.

A newer certbot that fails its trial renewal is not made current. The update says so, the previous
certbot keeps renewing, and the update goes on.

**The nodes**, one at a time, the standby first. The standby is the node that does not hold the virtual
address, as the dashboard shows it:

```bash
sudo apt update && sudo apt upgrade
```

An upgrade can restart HAProxy and the WAF engine on that node; that is why the active node goes last.
Until every node has the release's node package, the manager's check says which are behind:

```bash
sudo /usr/share/haprion-ui/install/platform/check-compatibility
```

It reads the whole installation - the CLI, the platform, the database, the nodes - and ends with
`COMPATIBLE` when every part fits.

**After an upgrade, the next publish carries more than your change.** Every publish also builds again
what the product generates for every object. If the new version generates differently, the next publish
- *Publish this version* included - carries that for all objects, not only the ones you changed. Read
the version's Diff after it.

### CLI rollback

Install the retained previous package; apt then puts the older version in place. If the web interface
needs a newer engine than that package provides, apt offers to remove the interface instead. Answer no.
The installed `haprion-ui` package names the engine it needs, and `haprion-rollback` does not change
that: the CLI goes back past it only together with an older `haprion-ui` package. That works when no
migration came between the two. Past one, the older package's update is refused, and the files it
replaced are put back ([What it does not do](#what-it-does-not-do)).

```bash
sudo apt-get install --allow-downgrades /path/to/haprion-cli_<previous version>_all.deb
```

The package's install script (`postinst`) runs the release installer with the wheel and node package it
carries. If a matching release is already installed, it is verified, and `current` is switched back to
it in one step. Without the package, run the installer again with the retained wheel, node package and
their recorded digests.

Before `current` moves, the installer asks the target release to read the runtime policy and the
cluster file in force. A release that cannot - a field added by a newer release - is refused, and
`current` stays where it was. Remove the field first, as for the interface's rollback.

**Ten releases stay on disk; older ones go when a new one is activated.** The installer removes old
releases only after a successful activation, never before - a failed activation is exactly when nothing
may be removed. It always keeps the release it just activated and the one that was current before,
whatever their age, so the rollback path is never the one removed. Ten is enough because a release can be
rebuilt from its commit: the wheel is built from `git archive <commit>`, so removing an old directory loses
nothing Git holds. The installer's `--keep N` changes the number (at least two).

### Rolling a release back

```bash
sudo haprion-rollback --list
sudo haprion-rollback                       # the previous release
sudo haprion-rollback --to <release-id>     # a named one
```

A rollback looks like "point `current` back and restart". Doing only that, however, can leave the
interface down, for three reasons, none of them visible from the symlink:

- **Configuration is validated strictly.** Unknown keys are refused, which makes a typo an error rather
  than a setting that silently does nothing. It also means that a configuration written for release N
  makes release N−1 refuse to start. **Configuration follows the same expand/contract rule as the
  database schema:** a key added for a newer release has to be removed before rolling back past the
  release that introduced it.
- **Units name programs.** A systemd unit installed for a newer release can start a program an older
  release does not contain.
- **The schema may be newer than the target.** After an update, the database is at the new release's
  schema. An older release runs on it only when every migration since its own schema is declared safe for
  it. The release that carries the schema answers that, from its migrations' declarations. With no such
  release on disk, or a target older than they are safe for, the rollback is refused. The way back is then
  the dump taken before the update. `haprion-backup restore` migrates a dump to the installed release's
  schema, so it does not by itself take the database back past a migration.

So the command checks all three against the target *before* switching. It asks the target's own
validator, because the answer is whatever that release says rather than what the script believes.
Afterwards it checks that the interface answers, and **rolls forward by itself if it does not**. Somebody
running this is already having a bad day; leaving them on a release that does not answer, with the
rollback reported as done, is the worst outcome possible.

A rollback, an update and `haprion-setup` run one at a time. One started while another runs stops at once
and names the process that holds the lock.

The sudo rules, units and site stay as the installed package wrote them; a rollback moves only the release.
`check-compatibility` names a sudo rule for a helper the target release does not run as a warning, not a
failure. The package's next update writes the files again.

`--list` shows the releases newest first, ordered by the time of the commit each was built from, not by
name. A release id ends in a commit hash, which sorts alphabetically and says nothing about when it was
built. Without `--to`, the target is the newest release that is not the current one.

How far back that list reaches is limited. `update-platform-release` keeps the ten newest releases. It
removes the rest only after the update has been proved, and always keeps the release just activated and
the one it replaced. A release can be rebuilt from its commit, so nothing older is lost with the
directory. `RELEASES_KEPT` in the command's environment changes the number (at least two).

## What it does not do

These gaps are not on the way to being filled. Each one is either impossible without changing something
the manager does not own, or left out because the alternative is better done elsewhere. The details are
in the section linked.

- **A UDP service whose server answers - RADIUS, NTP, SNMP - is not balanced.** A server answers the
  address it sees. To let it see the client's own address, the answer must either pass back through the
  node, or come from the VIP itself. Passing back through the node means the node has to be the servers'
  gateway, or be made one by a route in the network. Coming from the VIP means the VIP has to be
  configured on every server. Both change the servers or the network, and the manager does neither.
  Letting the servers see the node instead would work, but makes the node their only client, with one
  shared secret for every device behind it. DNS is balanced because dnsdist understands it and passes the
  client on inside the query ([DNS objects](#dns-objects)). Syslog is balanced because it is never
  answered ([Syslog objects](#syslog-objects)).
- **A port another program takes on a node after the publish is caught only by the deploy.** The publish
  refuses a port a node reports as held on every address
  ([Ports the cluster takes itself](#ports-the-cluster-takes-itself)). But a node that did not answer at
  publish time, or a program started since, is found only when HAProxy binds. The deploy then fails on
  that node, rolls back to the previous release and shows HAProxy's own reason -
  `cannot bind socket (Address already in use)`.
- **A pool's own counters start again on every reload**, while its servers' and the frontends' counters
  are kept. HAProxy 3.4.6 does not carry a backend's own counters correctly
  ([Counters across a reload](#counters-across-a-reload)).
- **Syslog over TCP or TLS is not forwarded**, and nothing restricts who may send to a syslog object. The
  network between the nodes and the receivers must let the senders' addresses through
  ([Syslog objects](#syslog-objects)).
- **Two DNS objects cannot share an address and port.** dnsdist tells them apart by where a query arrives
  ([DNS objects](#dns-objects)).
- **The update check does not go through a proxy.** A manager that reaches the internet only through one
  cannot use it; its row says GitHub has not answered
  ([Features and advanced configuration](#features-and-advanced-configuration)).
- **A signing request made elsewhere is not signed here.** A device that makes its own key and takes only a
  certificate for its own CSR - HPE iLO, for one - gets it from the CA directly. For an internal name, the
  Microsoft CA's own web enrollment signs an uploaded CSR. Every other device takes an
  [external certificate](#certificates-installed-by-hand) with its key.
- **A publish does not show its changes before it is made.** Publishing does not touch the nodes: what the
  new version changed is read under *Versions* before it is deployed
  ([Configuration and deployment](#configuration-and-deployment)). *Publish & deploy* on the dashboard
  does both at once, without that look.
- **A restore that includes the host's memory is not recognised.** The manager cannot tell a snapshot
  put back with its memory from a pause, so jobs that were waiting run without being held. Restart the
  manager after such a restore
  ([After restoring the database or the host](#after-restoring-the-database-or-the-host-waiting-jobs-and-sessions)).
- **The VIP is not moved from the interface.** Patching a pair means restarting the standby, then the node
  holding the VIP and letting the VIP move. That needs nothing from the manager. A button that stopped
  keepalived on a node would be the first management action able to move traffic
  ([Updating Haprion](#updating-haprion), [Keeping HAProxy current](#keeping-haproxy-current)).
- **An account through the provider is not made in advance.** It is made at the first sign-in, from the
  groups. To let only some people in, give them a group of their own at the provider
  ([Signing in through an OpenID Connect provider](#signing-in-through-an-openid-connect-provider)).
- **No ACME client of its own.** Renewal reuses certbot and the NDES enrollment client: the manager runs
  them twice a day from `haprion-certbot-renew.timer` and publishes what they renew
  ([Certificates](#certificates)).
- **A certbot lineage from before the installation is not taken over.** Issuing a name certbot already
  has is refused, because issuing it again would make a second lineage. A lineage kept from an earlier
  setup is added to the registry by hand, with its targets
  ([The certificate registry](#the-certificate-registry)).
- **The database dump and its restore check are watched only for failing.** When the last run of
  `haprion-backup.service` or `haprion-restore-check.service` failed, *Needs attention* shows
  *Database dump* or *Restore check* with the command to start the unit again (starting the unit is what
  clears the row). It says nothing while they succeed, and nothing for one that is not installed, or when
  the runtime policy has no `backup_root` (the state is read with the node backups' listing); it does not notice a timer that never fires. Backing up the
  management host is the backup; the dump is for putting one table back
  ([Backups, and proving they restore](#backups-and-proving-they-restore)). The nightly retention is
  watched: a missed run shows under *Needs attention*, from the partitions it makes ahead of time.
- **An existing `haproxy.cfg` is not imported.** A real configuration nearly always holds what the objects
  do not express - chains of ACLs, maps, `use_backend` logic, Lua. Put it in the handwritten layer
  (`core/haproxy.cfg` and `manual/`), where it runs beside the objects and shows on *Proxies* as *Manual*.
  Then move the sites to objects one at a time.
- **A traffic log receiver's TLS certificate is checked against the node's system trust store.** For a
  receiver with a certificate from your own CA, add that CA to the trust store on each node.
- **An NDES server's HTTPS is checked against the manager's system trust store only.** The SCEP client
  checks its requests there, so a CA file of the server's own cannot stand in for it. Add the CA that issued
  the server's HTTPS certificate to the manager's store (`update-ca-certificates`).
- **An update does not take the database back past a migration.** No migration has a downgrade. An older
  `haprion-ui` package installed over the one that migrated the database is refused, and the files it
  replaced are put back. Install the newer package again, then `haprion-rollback` switches to an older
  release that runs on the schema; for one that does not, the way back is the dump taken before the update
  ([Rolling a release back](#rolling-a-release-back)).
- **A request the WAF engine could not read cannot be excepted.** A broken body, a malformed upload or
  arguments past the limit are judged by the object's mode, like a rule set match. But no exception lets
  one through: what was not read cannot be narrowed to a field
  ([A request the engine cannot read](#the-waf-engine)).


## Environment reference

This part is the reference for administering and troubleshooting an installation: how a deployment is laid
out, what it needs, its configuration files, its service accounts and keys, and how the nodes are prepared.
To install the application, follow the [installation guide](install.md) instead.

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

Three rules shape the whole design. Every step below follows from one of them:

1. **The management host never pushes.** It can ask a node to pull, and nothing else. Every SSH identity
   the management host uses is a forced command: it runs one fixed command on the node, and none of them
   can copy a file or open a shell there. A node fetches its own configuration from the management host,
   over a separate, restricted account.

   There is one deliberate, temporary exception. Restoring a node onto an empty VM
   ([Restoring a node onto an empty vm](#restoring-a-node-onto-an-empty-vm)) writes as root, through a key
   the operator pastes into that VM's console for one run. The key works only from the management host's
   address, and the run removes it as its last step.
2. **Configuration is versioned before it is deployed.** Editing produces a draft. Publishing turns the
   draft into a release that never changes afterwards. Deploying brings the nodes to a published release.
   Each stage is a separate command with its own privilege.
3. **The application never holds privilege.** Work that needs root happens in small root-owned helpers.
   A caller cannot hand a helper a path, and it reaches the helper only through exact sudo rules. See
   [`PRIVILEGE.md`](PRIVILEGE.md) for the contract these rules implement.

### Prerequisites

The manager and the nodes run **Ubuntu 26.04 or Debian 13** on amd64. The packages are built and tested for
those two, and `haprion-setup` refuses any other. Sizes are in the
[installation guide](install.md#requirements) and, for the nodes, under *Size* in
[Part 2](#part-2--the-nodes).

Everything else comes with the packages or is installed by the installation steps. The packages come from
the project's signed apt repository ([The packages](install.md#the-packages)). Each package depends on what
it needs - `haprion-cli` and `haprion-node` on the WAF engine and the repository key, `haprion-ui` on the
rest of the manager's packages - so one `apt install` on each machine brings everything:

- **On the manager:**
  - `haprion-cli` depends on the distribution's Python (3.13 or newer, at `/usr/bin/python3`) with
    PyYAML 6, PyNaCl 1, psycopg 3 and PyJWT 2, and on `git`, `rsync`, `openssh-client` and `sudo`.
  - `haprion-ui` depends on nginx.
  - `haprion-certbot` carries its own certbot.
  - The setup installs PostgreSQL 18 where the host has no PostgreSQL cluster: from the distribution on Ubuntu
    26.04, and from the PostgreSQL project's repository on Debian 13. A PostgreSQL that already runs
    version 16 or newer is kept. A cluster that is stopped, or is a standby, stops the setup until it is
    started or promoted; a second version is never installed beside it.

  16 is a hard floor, not a preference. From version 16 on, PostgreSQL lets each role membership carry
  its own `INHERIT` setting, and the installation sets it explicitly on every grant. On an older version
  it would depend on whatever role attribute happened to be set when the grant was made.
- **On every node**, the `haprion-node` package and the join install HAProxy, keepalived, rsyslog, dnsdist
  and what the scripts need.
- **HAProxy 3.4 or newer** on both. Where the distribution's HAProxy is older, the installation steps add
  the HAProxy maintainer's repository and install it from there
  ([Keeping HAProxy current](#keeping-haproxy-current)).

**Names and addresses you decide before you start**

| Thing | Example | Notes |
|---|---|---|
| management host | `mgr` | reachable by name from every node |
| cluster IDs | `alpha`, `beta` | lowercase, used in every command as `-c <cluster>` |
| node names | `node-a`, `node-b` | two per cluster in the reference layout |
| virtual address | `192.0.2.10` | per cluster, if keepalived is used |
| management network | `192.0.2.0/24` | how the host and nodes reach each other |

#### Where the package comes from

A distribution freezes HAProxy at one version for its whole life. To run the current release of a HAProxy
branch instead, the installation takes HAProxy from the repositories that
[haproxy.org](https://www.haproxy.org/) links to, one per branch:

- on Ubuntu, the `vbernat/haproxy-<branch>` PPA
- on Debian, [haproxy.debian.net](https://haproxy.debian.net/)

They follow upstream closely but not instantly. A point release has reached them a day or two after
haproxy.org announced it, and `apt` offers it only after its next list update after that.

**The installation steps set this up themselves**, wherever a host's HAProxy is older than 3.4: step 1 on
the manager, `04-node-prepare` on a node. A host that already runs 3.4 or newer keeps the source it has.
For the branch's repository, the step writes three files:

- the repository's signing key, shipped beside the steps, as
  `/etc/apt/keyrings/haproxy-ubuntu-ppa.asc` or `/etc/apt/keyrings/haproxy-debian-net.asc`
- the source, `/etc/apt/sources.list.d/haproxy-3.4.sources`
- an apt pin, `/etc/apt/preferences.d/haproxy-3.4.pref`

The pin makes apt prefer the repository's HAProxy over the distribution's. On Ubuntu it also stops the PPA
from upgrading anything else:

```text
# /etc/apt/preferences.d/haproxy-3.4.pref on Ubuntu 26.04
Package: haproxy*
Pin: release o=LP-PPA-vbernat-haproxy-3.4
Pin-Priority: 600

Package: *
Pin: release o=LP-PPA-vbernat-haproxy-3.4
Pin-Priority: 100
```

```text
# /etc/apt/preferences.d/haproxy-3.4.pref on Debian 13
Package: haproxy*
Pin: release o=PPA-haproxy,n=trixie-backports-3.4
Pin-Priority: 600
```

What the numbers mean:

- **600** puts HAProxy from the repository above the distribution's packages, which apt ranks at 500.
  Below 1000, apt never downgrades, so a repository that stops answering leaves the installed version in
  place rather than falling back to the distribution's older branch.
- **100** (Ubuntu only) holds every other package in the PPA below the distribution's, so a source trusted
  for HAProxy cannot upgrade anything else. haproxy.debian.net needs no such line: it marks its suites so
  that apt never takes a package from them unasked - which is also why, without the first pin, apt would
  keep Debian's own older HAProxy.

`apt-cache policy haproxy` shows the pin working: the repository's version at priority 600. An origin
(`o=`) that does not match the repository's own `Release` file matches nothing, and the pin then silently
does nothing.

**A node that already serves a release is not upgraded by the step.** Upgrading HAProxy restarts it, and
`04-node-prepare` does not do that to a node that may carry traffic. On such a node with an older HAProxy
the step stops and tells you to upgrade HAProxy to 3.4 in a maintenance window, then run the step again.

The dashboard's *Runtime* column shows the version each node's HAProxy process is running, read from its
runtime socket. After an upgrade, the new version appears there once the service has restarted.

### Part 1 — the management host

#### Service accounts and the config group

Each part of the application runs under its own system account. The accounts are locked and cannot log in.
Their names are fixed by the software, not chosen per installation. The leading underscore is Debian's
mark of a system account, and it keeps an account from being named like the command it runs.

| Account or group | What it is for |
|---|---|
| `_haprion-web`, `_haprion-worker`, `_haprion-poller` | the web, worker and poller processes |
| `_haprion-collector` | the traffic-log collector |
| `_haprion-oidc` | the helper for signing in through OIDC |
| `_haprion-pull`, `_haprion-cert-pull` | the accounts the nodes log in to, to fetch releases and certificates |
| `haprion` (group) | the configuration group; only the worker is a member |
| `_haprion-ui` (group) | the interface's group; web, worker and poller are members |

The two pull accounts are reached by the nodes over SSH, each key with a forced command. sshd runs a forced
command through the account's login shell, so these two have a real shell (`/bin/bash`). The others have
none.

*Details:* `install/sysusers/haprion.conf` declares all of them. Step 1 installs it under
`/etc/sysusers.d/` and applies it with `systemd-sysusers`, which creates what is missing and leaves what
exists.

Human administrators are deliberately not in that file. Adding an administrator to the config group is a
separate action, on an account that already exists:

```bash
sudo usermod -a -G haprion <your-account>
```

#### Directory layout

The management host keeps each cluster's configuration in a Git repository, the published releases beside
it, and the registry files under `/etc/haprion/`. These are the installation's default places:

```text
/srv/haprion/config/alpha.git/            authoritative history, bare
/srv/haprion/config/alpha/                linked draft worktree - what you edit
/srv/haprion/config/alpha/{core,managed,manual}

/srv/haprion/published/alpha/releases/    immutable published releases
/srv/haprion/published/alpha/current      symlink to the current release

/srv/haprion/validation/certs/            validation-only certificate material
/etc/haprion/registry/clusters.yaml       cluster definitions
/etc/haprion/runtime-policy.yaml          the outer path boundary
```

The first two blocks repeat for every cluster.

**Which paths are fixed.** Of the paths above, only `/etc/haprion/runtime-policy.yaml` is fixed by the
software: it is where the code looks unless told otherwise. The others are deployment choices. Put the
trees wherever your environment keeps them, and name them in the runtime policy. The software itself
installs to fixed places: `/opt/haprion` for the CLI releases and `/opt/haprion-ui` for the interface,
whose own settings are in `/etc/haprion/ui.toml`.

**Who may write.** Config repositories and published releases are **owned by root and never
group-writable**. The config group can read them, not write them. Publishing writes into root-owned
history, so it happens through a helper, not directly.

**The two halves of a repository.** `alpha.git/` is a bare Git repository and `alpha/` is a worktree linked
to it. Each holds a path reference to the other. Restoring only one of them breaks the link;
`git worktree repair` mends it without touching the configuration.

##### Handwritten listeners: `manual/reservations.yaml`

A cluster's configuration has a generated half (objects made in the interface) and a handwritten half
(`core/` and `manual/`). `manual/reservations.yaml` is where the handwritten half declares which hostnames
and ports it already uses, so that a generated object cannot take them too:

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

**Why it exists.** Both kinds of collision are silent in HAProxy:

- Two frontends that bind the same port both get it, because HAProxy binds with `SO_REUSEPORT`. The kernel
  then splits new connections between them at random. The publish reports success, and the node answers
  correctly for about half the traffic.
- A hostname claimed twice is answered by whichever frontend HAProxy reaches first.

Nothing can work this out automatically: the application never interprets the handwritten configuration
in `manual/`. A promise written by a person is the only source available.

**Ports.** A bare port and a port written `:8443` mean the same thing: the port is claimed on every address.
That matches a `bind` line without an address, which really does take the port everywhere. Give the
address when the claim belongs to one VIP. Otherwise a cluster with several VIPs cannot reserve a port
without blocking it for every managed object on all the others. An IPv6 address is written in brackets,
`[2001:db8::1]:8443`, exactly as on a bind line.

**`reviewed:` keeps the declaration current.** A reservation file written once and never revisited looks
exactly like a complete one, and a listener added to a fragment later would go unnoticed. So you list each
handwritten fragment with the SHA-256 digest of the content you read. When the file changes, the digest
stops matching, and the next publish asks you to look at it again. Get the digest with
`sha256sum core/conf.d/0010-stats.cfg`.

- The files it covers are fixed: everything under `core/conf.d/` and `manual/conf.d/`.
- List a fragment even if it reserves nothing. That is how you say you read it and it claims no listener -
  the confirmation is the point, whether or not it produced any reservations.
- A confirmation for a file outside those directories, or a digest that is not SHA-256 hex, is refused,
  not quietly ignored.

This proves the declaration is current and that somebody looked. It does not prove it is complete - only
reading the fragments could do that.

The file is created empty with the cluster, and the operator editing policy names it, so administrators
can edit it with `sudoedit`. Empty is correct as long as nothing handwritten defines a listener. A publish
tells you when the cluster has handwritten fragments this file does not account for, and when a fragment
has changed since it was confirmed.

##### The cluster's `core/haproxy.cfg`

`core/haproxy.cfg` is the cluster's handwritten `global` and `defaults` section: the file every generated
fragment is assembled behind. It must contain two things - the `default-path config` line and the TLS
defaults that every listener without a TLS policy of its own falls back to:

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

**A publish is refused while either is missing or wrong**, and the refusal prints the exact line to write
and the `sudoedit` command for the file. A **revert** is never refused for this: going back to a release
that was good before must not depend on a file being current.

- **`default-path config`.** Without it, HAProxy resolves the relative path to a certificate list against
  whatever directory it was started from. The manager's own validation would still pass, and the node
  would refuse to start - the worst place to find out. **Read your handwritten layers before adding the
  line.** It changes how every relative path in the configuration resolves, so a `crt`, `map` or
  `errorfile` written as a relative path would start pointing somewhere else. Generated configuration uses
  absolute paths throughout, so only `manual/` and `core/conf.d` need checking.
- **The two cipher lines**, `ssl-default-bind-ciphers` and `ssl-default-bind-ciphersuites`, must match the
  manager's own lists exactly. (`ssl-default-bind-options` is not compared.) The reason is that both lists
  are in force at once. A generated bind line that names a TLS policy carries the manager's list, and every
  listener naming no policy inherits this one. If they differ, what protects a given listener depends on
  which line HAProxy read last - and each file looks entirely correct on its own. That is how two such
  lists once came to differ by one cipher without anything reporting it.

The manager's lists are Mozilla's intermediate recommendation, guideline v5.7. Nothing fetches them at run
time. If you deliberately change them, change the manager's copy first and then every cluster's `core/`;
the refusal tells you which clusters are still behind.

*Details:* the manager holds the lists in `haprion/tls_policy.py`, with the date they were last checked.

**End a `log /dev/log` line with `alert`**, for example `log /dev/log local0 info alert`. HAProxy logs a
backend left without a server as `emerg`, and journald writes every `emerg` message to every terminal on
the node. On a node that does not hold the VIP, that happens for every object whose servers it cannot
reach from there (an object with a `source` on the VIP). The last level on the line caps the severity, so
the message is still logged, as `alert`. A `core/` without a `log` line - as `haprion-cluster` writes it -
is not affected.

**An HTTPS object may override its VIP's TLS policy.** The generated certificate list then has an explicit
row, filtered by SNI, for every object, so several names can use the same wildcard certificate with
different policies. The first row has no filter, on purpose: a client that sends no SNI, or an unknown one,
gets the VIP's (or the bind line's) policy. When one listener carries several policies, HAProxy also
answers `421 Misdirected Request` if the request's Host belongs to a different policy group than the
connection's SNI. Browsers can still reuse an HTTP/2 connection between names in the same group.

#### Runtime policy

`/etc/haprion/runtime-policy.yaml` is the outer security boundary, not a convenience file. It names the
directories (roots) that every path in `clusters.yaml` must stay inside, and the code refuses any cluster
path that escapes its root. It also names the manager's SSH keys and the settings for issuing
certificates. Step 2 writes it; this is what it writes with the installation's defaults:

```yaml
schema_version: 1

cluster_file: /etc/haprion/registry/clusters.yaml
config_root: /srv/haprion/config
publish_root: /srv/haprion/published
validation_certs_root: /srv/haprion/validation

deploy_identity:
  key: "/root/.ssh/id_ed25519_config_deploy"

certificate_root: /srv/certdist/haproxy
cert_deploy_identity:
  key: "/root/.ssh/id_ed25519_cert_deploy"
certificate_registry: /etc/haprion/registry/certificates.yaml
receiver_root: /srv/certdist/receivers

status_identity:
  key: "/root/.ssh/id_ed25519_node_status"

probe_identity:
  key: "/root/.ssh/id_ed25519_node_probe"

server_state_identity:
  key: "/root/.ssh/id_ed25519_server_state"

backup_root: /srv/haprion/state-backups
backup_identity:
  key: "/root/.ssh/id_ed25519_node_backup"
```

Step 2 also writes an `acme:` block (see
[ACME configuration and challenge routing](#acme-configuration-and-challenge-routing)), and an `ndes:` block
can be added for Microsoft AD CS
([Preparing Microsoft AD CS / NDES for CSR enrollment](#preparing-microsoft-ad-cs--ndes-for-csr-enrollment)).

**The file itself** must be owned by root, a regular file (not a symlink), not writable by group or others,
and at most 1 MiB. The reader rejects unknown fields, so **install a release that understands a new field
before adding it** - otherwise every command that reads the policy fails, not only the new one.

##### SSH keys and the accounts they reach

Each `*_identity` entry names only its private key. The account it logs in to on a node is fixed:

| Policy entry | Account on the node | What it does |
|---|---|---|
| `deploy_identity` | `_haprion-trigger` | asks the node to pull a configuration release |
| `cert_deploy_identity` | `_haprion-trigger` | asks the node to pull its certificates |
| `server_state_identity` | `_haprion-trigger` | puts one server in drain or maintenance, or back to ready |
| `status_identity` | `_haprion-status` | reads the node's status |
| `probe_identity` | `_haprion-status` | asks the node to try a health check |
| `backup_identity` | `_haprion-backup` | fetches the node's state archive |

Step 2 writes the status, probe and server-state entries whenever the answers file names their keys, and
the installation's defaults name all three. An answers file that sets a key's name to empty leaves that
entry out.

**`status_identity`** is the key `haprion-status` uses to read a node. `haprion-deploy` uses it too: a
rollout reads every node before and after every step, and it reads with the key that cannot change a node
rather than the one it triggers with. Both commands refuse to run without it, instead of falling back to the
deploy key, and `haprion-status` says exactly which field is missing. It is deliberately not the deploy
key. Reading status is the one thing the manager asks of a node that cannot change it, so this key can be
granted most widely - and keeping it separate preserves that difference.

**`probe_identity`** lets the interface ask a node to *try* a health check. The node opens a connection to
the servers an object names, from the address that object leaves from, and reports whether they answered.
It logs in to the same account as status but has its own key, because it is a different thing to grant:
status reads what a node already knows, while a probe makes the node connect to an address the caller
chose. The forced command behind it needs no sudo, returns a status and never a response body, and refuses
anything that is not a bounded list of targets. Without it, the button in the editor says the probe is
unavailable; nothing else changes.

**`server_state_identity`** puts a server in drain or maintenance on the nodes
([Drain and maintenance](#drain-and-maintenance)). It logs in to the trigger account with a key of its own.
Its forced command takes one server GUID and one of three states, and nothing else. It changes where
HAProxy sends traffic without a deploy, which is why it is neither the deploy key nor the status key.
Without it, `haprion-server-state` says which field is missing; nothing else changes.

**`backup_identity`** is the separate key that fetches a node's state archive. It must not reuse the
deploy or status key: unlike their answers, this archive holds password hashes and private SSH keys.
Step 3 creates the key. For a node prepared by hand, it prints the public half to put in that node's
answers file; a node joined from the interface gets it from the manager. The private half stays root-only
on the manager.

##### Certificates: `certificate_root`, `certificate_registry` and `receiver_root`

**`certificate_root`** is the directory the manager publishes certificates into, for the nodes to fetch.
With a certificate registry it holds one directory per cluster, and each cluster's nodes can read only
their own ([SSH identities](#ssh-identities)). Without a `certificate_registry` in the policy, the directory
is filled by something else, flat, and every cluster's nodes read all of it.

`certificate_root` is also what a publish reads to check that each site's certificate covers its
hostnames. HAProxy loads a certificate without checking it against the objects that use it, so a name the
certificate does not cover reaches visitors as a browser error while every layer here reports success.
**Leave the root unconfigured and that check does not run** - the publish succeeds, and nothing says the
check was skipped. To use a certificate that does not cover a name on purpose, use the certificate mismatch
override. It is asked for per publish, not stored in the object.

**`certificate_registry`** names the file that says which certificates exist and where each one goes
([The certificate registry](#the-certificate-registry)). **`receiver_root`** is where a new receiver's
directory is made ([Registering a receiver](#registering-a-receiver)).

##### Node backups: `backup_root`

**`backup_root`** is where the state backup writes one directory of archives per node. It is also what
`haprion-list-backups` reads.

- Called without a cluster, `haprion-list-backups` lists every configured cluster in turn. It reads
  `clusters.yaml` as the calling user - the same way `haprion-cluster-config` does - only to learn which
  clusters exist. Each listing is still made inside the privilege boundary, by one helper call per
  cluster.
- Only metadata ever comes out of the listing: archive name, size and modification time. The archives
  themselves hold password hashes and private SSH keys. So the root stays root-owned, and only one command
  opens an archive: `haprion-node-restore`, running as root, to restore it
  ([Restoring a node onto an empty vm](#restoring-a-node-onto-an-empty-vm)). The listing helper exists
  precisely so that an unprivileged caller can learn that a backup exists without being able to read it.

**What a backup run does.** Step 2 installs `haprion-state-backup@.service`. Each instance backs up every
node in exactly one configured cluster.

- **How many archives are kept.** 14 per node, unless the *Node backups* page set another count (1-365).
  The root socket helper records that count in `/etc/haprion/backup-retention/<cluster>.json`, readable by
  root only. Every run reads that file - including `haprion-state-backup` run from the terminal - so a
  manual run prunes to the same count as the schedule. A file that is present but cannot be read stops the
  run, rather than falling back to 14.
- **One exception to the count:** an archive that a node restore can still use - prepared within the hour
  and not yet carried out, or being carried out now - stays until that restore is done, so the count is
  briefly one higher. A prepared restore older than an hour holds nothing, and each backup first puts such
  restores away, as a restore command would.
- **Time limits.** A run has ten minutes in all. It waits at most two minutes for another backup or restore
  to finish; if it cannot start, it answers `backup_busy` and takes nothing. It gives each node up to five
  minutes. A node it had no time left for is reported as `backup_budget_exhausted`, and the archives it did
  take are kept.
- **When the manager cannot store an archive.** A full or unwritable backup volume is reported per node as
  `backup_storage_failed`, with what the system said; it does not mean the node's archive was bad. If the
  archive was saved but the "latest" link or the pruning of old ones then failed, the node counts as done
  and carries a `backup_retention_failed` warning.

The ordinary listing and the *Node backups* page show every archive kept for each node, and name the node
it came from. Archives are not interchangeable between nodes: hostnames, network settings and SSH
identities differ.

**The schedule.** On the *Node backups* page an admin can, per cluster:

- set the schedule, on the manager's clock: every day, chosen weekdays, or one day of the month at a given
  time (days 1-28, so no month is skipped)
- enable or disable it
- set how many archives are kept
- run a backup of the cluster immediately

The browser sends no unit name or systemd calendar expression. The root socket helper builds both from the
configured cluster and the bounded request (for example `Mon,Wed,Fri *-*-* 05:00:00` or
`*-*-07 05:00:00`), writes them as a drop-in on the cluster's `haprion-state-backup@<cluster>.timer`, and
reads the timer's effective state back before reporting success. Listings read the same timer. A calendar
edited by hand on the manager is shown on the page exactly as written, not translated into the form's
choices. From the terminal, the break-glass path is `sudo haprion-state-backup [-c <cluster>]`.

##### Who published a version

The web interface's worker account, `_haprion-worker`, is the one caller whose word a version takes about
who published it. A publish or revert from the browser records the signed-in person as *Published by*,
beside the worker account that actually ran it. Anyone else who may run those helpers - an operator at the
terminal - is recorded as the account sudo proves, whatever the request says. So the column can be trusted.
The account is fixed, not a policy setting.

#### Cluster definitions

`/etc/haprion/registry/clusters.yaml` defines each cluster: its address, its paths, its nodes. Creating a
cluster in the interface (or with `haprion-cluster add`) writes its entry; this is what one looks like:

```yaml
schema_version: 1

clusters:
  alpha:
    display_name: Alpha
    vip: 192.0.2.10
    config_path: /srv/haprion/config/alpha
    publish_path: /srv/haprion/published/alpha
    node_path: a
    nodes:
      - name: node-a
        mgmt_host: node-a.example.com
      - name: node-b
        mgmt_host: node-b.example.com
    validation_certs: /srv/haprion/validation/certs
    default_certificate: example.com

    # Opt in to the separate structured stream used by the traffic-log
    # collector.  The setting reaches the nodes when an object is next
    # published; changing this file alone does not deploy a configuration.
    traffic_logging: true
```

- **`node_path`** is the subdirectory a node fetches from on the management host. It is the only
  per-cluster value the node side needs.
- **`publish_path`** must be `<publish_root>/<cluster>` and nothing else. A node asks for
  `<cluster>/current/<node path>/`, and its fetch key can read only that tree.
- **Which certificates a cluster carries** comes from the certificate registry, which the installation sets
  up by default ([The certificate registry](#the-certificate-registry)). `default_certificate` stays here
  and must be one the cluster carries; it is optional, since a new cluster may start without certificates.
  Only an installation whose policy names no registry lists the certificates here instead, as
  `certificate_ids` (a non-empty list). With a registry, a `certificate_ids` list in this file is refused.

##### How many nodes and clusters

A cluster has **between one and eight nodes**.

- **Why up to eight.** keepalived itself sets no limit: one VRRP instance shares its addresses between any
  number of nodes, by priority. A third node adds a standby, not capacity. Eight is a ceiling nobody is
  meant to reach, not a size to aim for: the pages were measured to show eight nodes per cluster without
  scrolling sideways, and every node costs the poller a read (below).
- **Why one is enough to start.** A cluster is created with its first node, and further nodes are added to
  it. A cluster of one serves traffic, but has nothing to fail over to.

For a cluster created in the interface, the deploy writes each node's `keepalived.conf`, including its
priority and its `unicast_peer` list ([keepalived on the nodes](#keepalived-on-the-nodes)).

There is **no hard limit on the number of clusters** - not in the engine, the interface configuration or
the database. Two is the recommended starting point, commonly one internal and one external trust zone,
not a maximum.

**It has been run with two clusters of two nodes each, and is built for up to about ten clusters and twenty
nodes.** Nothing enforces that figure. It is where the manager's reads, which run one after another, stop
being comfortable:

- **The poller** reads cluster by cluster and node by node. With two clusters of two nodes, a pass takes
  about two and a half seconds, against a default `interval_seconds` of 20. The status read costs about
  0.3 s per node, and the cluster's other readings about 0.7 s whatever its size. A node that is switched
  off adds five seconds to every pass (the SSH connect timeout). A node that connects and then never
  answers adds up to sixty (the status read's own limit). Either one delays every cluster's reading, not
  only its own.
- **The traffic-log collector** runs once a minute and fetches from up to eight nodes at once - about a
  second for four current nodes. A node with a backlog is fetched for up to thirty seconds before the run
  imports what it has. A node that does not answer holds one of the eight slots for ten to thirty seconds.
  A run that takes longer than its minute delays the next one, which never overlaps it.
- **The worker** runs one job at a time for the whole installation. A deploy or backup on one cluster
  queues every other cluster's jobs behind it.

An installation growing past that size should time a complete poller pass and a collector run against
their intervals before it adds more.

Each cluster card is marked with one of six colours
([Features and advanced configuration](#features-and-advanced-configuration)). With more than six
clusters the colours are switched off and the name alone marks the card. That limits the colours, not the
clusters.

##### What a release holds

A release directory holds the `node_path` subdirectory and, beside it, `MANIFEST.json`: the manager's own
record of what each object in that release amounts to. It sits outside `node_path` on purpose. A node
fetches that subdirectory whole, deleting what is not in it, and HAProxy loads everything in `conf.d` - so
a file the manager keeps for itself has no business in either place. Nothing on the node reads it. For a
release without the file, the status reports each object as unknown rather than guessing.

##### The address form: `address_prefix` and `address_interface`

These two optional values say how the cluster's nodes write the addresses they carry. They are set when
the cluster is created: *VIP prefix* and *VIP interface* on *Create cluster*, or `--prefix` and
`--interface` on `haprion-cluster add`. In the file they look like this:

```yaml
    address_prefix: 24          # from the nodes' own virtual_ipaddress block
    address_interface: ens192   # likewise; names differ between installations
```

They are used for one thing: writing the keepalived address list that a release carries.

**Read both values off the nodes rather than choosing them.** The generated list has to reproduce what
stands in the nodes' `virtual_ipaddress` block today. A line reading `<address>/24 dev ens192` means
`address_prefix: 24` and `address_interface: ens192`.

- No particular interface name is required - the field exists because names differ between installations.
- If the nodes name no interface, leave `address_interface` out, so keepalived keeps using the
  `vrrp_instance`'s own interface.
- Without `address_prefix`, an address is written bare, which keepalived reads as `/32` on the
  `vrrp_instance`'s own interface. **A bare address is not the same address.** A `/32` carries no subnet
  route and is not chosen as a source address on the segment. So a cluster whose nodes use a prefix must
  say so here; otherwise moving the list into the generated file would change the network, not only where
  the list is written.

They live here, not in `managed/network.yaml`, because a prefix length describes the network the nodes sit
on, not which addresses the cluster serves. `clusters.yaml` is root-owned, so the interface sets them only
when it creates the cluster and cannot change them afterwards.

##### Optional per-cluster sections

The sections below may be added to a cluster. All of them are optional; a cluster that leaves them all
out behaves exactly as the example above.

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

**More about `vips`.** Besides `address` and `source`, a VIP takes two optional settings:

- `tls` is one of three policies: `intermediate` (TLS 1.2 and 1.3), `modern` (TLS 1.3 only) or
  `tls12only` (TLS 1.2 only). `tls12only` is not a Mozilla profile. It exists for one client that breaks
  on TLS 1.3, and it turns 1.3 off to get there.
- `http3: true` turns on HTTP/3 for the VIP. It needs TLS 1.3, so it is refused together with `tls12only`.

Two VIP names may not share one address.

**More about `unknown_host`.** `status` is an HTTP status code (200-599); `redirect` is an absolute
`http://` or `https://` URL.

**Three more sections** are read from the same place:

```yaml
    # Addresses of proxies in front of the cluster whose X-Forwarded-For
    # header is believed.
    trusted_proxy_cidrs:
      - 203.0.113.0/24

    # A brake on one source address: over the limit within the window,
    # requests are refused with 429 and new TCP connections are rejected.
    abuse_protection:
      window: 10s
      max_requests: 100
      max_errors: 20
      max_new_connections: 50

    # The VRRP router ID the product's keepalived.conf uses.
    vrrp_router_id: 1
```

- **`trusted_proxy_cidrs`** lists the proxies whose forwarding headers the cluster trusts. Normally every
  generated frontend deletes `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Host` before setting
  its own, because a visitor can send any header and claim to be anybody. A request from a listed address
  keeps its chain, and the visitor's address is read from the last `X-Forwarded-For` element. A range
  covering a whole address family (`/0`) is refused.
- **`abuse_protection`** limits how much one source address may do within `window` (a number with `s` or
  `m`, `10s` by default). `max_requests` and `max_errors` count HTTP requests and errors and answer 429
  above the limit. `max_new_connections` counts new connections on TCP objects and rejects them above the
  limit. At least one of the three must be set. Behind a trusted proxy, the forwarded address is counted
  instead of the proxy's.
- **`vrrp_router_id`** (1-255) is given to a cluster when it is created in the interface: the lowest ID no
  other cluster of this manager uses. Two clusters may not share one. A cluster that has it gets a
  generated `keepalived.conf` ([keepalived on the nodes](#keepalived-on-the-nodes)).

**`vip` itself is unchanged by all this.** It is the address whose ownership `deploy` checks before it
acts. One node holds every virtual address at a time, so that single check answers for all of them.

**Three of those sections have a second, preferred home.** `vips`, `sources` and `networks` may instead
live in `managed/network.yaml` inside the cluster's repository, and that is where a new installation puts
them:

```yaml
# <config_root>/<cluster>/managed/network.yaml
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

Where the file exists, it wins. A cluster without one keeps answering from `clusters.yaml`, and nothing has
to be migrated.

The reason for the split: these three describe *what gets published*, while everything left in
`clusters.yaml` describes *how the system itself runs* - paths, identities, keys, the resolvers section,
the certificate settings and the `vip` line. The cluster repository belongs to the application, so these
tables can be edited in the interface through the same publish path as a proxy object: the same lock, the
same history, the same revert - and without the web accounts gaining any access to the engine's
configuration.

`vip` deliberately stays in `clusters.yaml`. It is what `deploy` checks node ownership against, and a
control the interface can rewrite is not a control. A `managed/network.yaml` that names `vip` is refused
outright.

**From the terminal**, `haprion-network apply` publishes a file as the cluster's network description, the
way the *Network* page saves it:

- It compares the file with what is committed. (`haprion-network -c alpha --json` shows the committed one
  as `document`.)
- Where they differ, it publishes one version, against the version it read. Where they do not, it
  publishes nothing.
- `--check` shows the difference without publishing.
- A cluster still answering from `clusters.yaml` has no description to change, and is refused.

```bash
sudo haprion-network apply -c alpha network.yaml --check
sudo haprion-network apply -c alpha network.yaml -m "Add the office network"
haprion-deploy -c alpha
```

**Adding a VIP here is only half the job, unless the deploy writes the addresses.** The other half is
keepalived on the nodes. No node carries an address until it is in the `virtual_ipaddress` block, and
until then no traffic reaches the frontend, however correct the generated configuration is. The same goes
for a source address, which must also sit in the *same* block as the VIP - see
[Addresses, and what to call them](#addresses-and-what-to-call-them).

**The deploy can do the other half.** Every published release carries `keepalived/addresses.conf`, made
from `managed/network.yaml`: every VIP and every source address, one per line, with a comment saying which
is which. `haprion-pull-deploy` installs it on each node as `/etc/keepalived/addresses.conf`. On a node
whose `keepalived.conf` includes that path, the deploy then runs `keepalived --config-test` and reloads
keepalived - **only** if the test passes (exit 0). keepalived skips an address it cannot parse at runtime
and carries on, so without the test a mistyped address would become a VIP that never appears and never
says why. If the test fails, the previous list is put back, and the deploy is reported as failed, with the
HAProxy configuration already live.

**That failure leaves the node half-way, and the status says which half.** The configuration is live on
the new release while the address list is the old one. The release hash alone would report the node as up
to date, and a second deploy would skip the node that still needs the work. So `haprion-node-status`
reports three things about the list: the digest the release publishes, the digest the node installed, and
whether `keepalived.conf` includes it. Both `haprion-status` and `haprion-deploy` call a node current only
when every component the release owns is in place - the address list, the IPVS file and the log
forwarding - and every step after the reload has finished, `keepalived.conf` among them. Fix the cause and run the deploy again: it finishes the half that was left, because the node
script syncs these components even on a release it already runs.

Whether `keepalived.conf` includes the list is reported, never treated as a target. Adding the include line
is a step a person takes, one node at a time (below). A deploy that treated it as a target would try
forever to reach a state only a human can put the node in.

#### keepalived on the nodes

Who writes `keepalived.conf` depends on how the cluster came to be.

**A cluster created in the interface** gets a VRRP router ID when it is created. Every publish then writes
one `keepalived.conf` per node into the release (`keepalived/node-<name>.conf`). The deploy installs the
node's own file, tests it with `keepalived --config-test`, and starts keepalived the first time or reloads
it after that. The file always has the same shape:

- `state BACKUP` and `nopreempt` on every node. The priority follows the cluster's node order (100, 90,
  80 ...) and only decides who takes the address on a cold start.
- Unicast to the other nodes, with `check_unicast_src`: an advert from an address that is not a peer is
  discarded and logged once. There is no VRRP password. It would be eight bytes of clear text on the
  wire, and VRRPv3 dropped it.
- A node alone names `127.0.0.1` as its peer. With an empty peer list keepalived would fall back to
  multicast on the segment; with the node's own address it would read its own adverts and warn every
  second.
- The interface is the cluster's `address_interface`, or else the one carrying the node's own address.
- The address list is included in `virtual_ipaddress`, the IPVS file at the top level, and the `notify_`
  lines are set.

The file's first line, `# Written by Haprion - a deploy replaces this file.`, is how the deploy knows the
file is the product's. Delete that line and the file is yours: from then on the deploy leaves it alone and
writes only the address list.

**Adding a node** changes the peer lists. The change is published as a version, and the deploy (in the
same job or the next) takes it to the nodes as a reload, so the address stays where it is. The new node is
deployed after the node that owns the address, so it starts as a standby.

Until its first deploy, a node has no `keepalived.conf`. The dashboard says *Keepalived not configured*,
and no node carries the address. The first deploy goes to the nodes in the cluster's order and brings the
address up. It does not warn that the VIP is down: nothing has served yet. Later deploys do warn when no node
owns the address.

**A cluster whose `keepalived.conf` a person wrote** keeps it. The application writes the address list and
nothing else. `priority`, `virtual_router_id`, `authentication`, `unicast_src_ip`, `unicast_peer` and the
`notify_` lines stay in the file the person edits. Those settings decide who owns an address, and getting
one wrong gives two masters or none - neither of which `--config-test` catches, because both are runtime
behaviour, not syntax. An extra line in `virtual_ipaddress` cannot cause either, which is what makes the
address list safe to generate.

**Switching a node over to the generated address list, in this order:**

1. Deploy once, so `/etc/keepalived/addresses.conf` exists. Until a node's `keepalived.conf` mentions that
   path, the file is installed but has no effect, and the deploy says so.
2. Compare it with the addresses in the node's own `virtual_ipaddress` block. They must already agree:
   this step changes where the list is written, not what is in it.
3. On **one node at a time, the address owner last**, with a backup of `keepalived.conf`: replace the
   addresses in the block with `include /etc/keepalived/addresses.conf`, run
   `keepalived --config-test -f /etc/keepalived/keepalived.conf`, and reload only if it passes.
4. Prove it from another host - the address still answers ARP from the same node - before you touch the
   next node.

keepalived will not start with an `include` that names a file that does not exist yet. That is the whole
reason step 1 comes first.

**The node's status helper has to follow that include.** `haprion-node-status` decides whether a node
carries the address by reading the `virtual_ipaddress` block and looking the address up on the interface.
Once the block holds nothing but the include, a helper that reads only the block finds no address and
answers that ownership is unknown - on every node. That is not just a cosmetic answer: a deploy refuses to
run without a known owner (unless it is given `--allow-vip-unknown`), so the cluster's whole deployment
path stops. Install the node scripts from the same release as the manager before switching a node over.
Afterwards, confirm with `haprion-status -c <cluster>` that the owner is named and the state is
`single_owner`.

**A cluster that sets `resolvers` must provide the section itself in `core/`.** Nameserver addresses are
environment values, and the generator never invents them:

```text
resolvers cluster-dns
    nameserver ns1 192.0.2.53:53
    resolve_retries 3
    timeout resolve 1s
    timeout retry 1s
    hold valid 10s
```

#### The certificate registry

The certificate registry is one root-owned file, beside `clusters.yaml`, that says for every certificate
where it comes from and where it goes: to which clusters, and to which other machines (receivers). The
installation sets it up by default. Step 2 names it in the runtime policy as `certificate_registry`
(`/etc/haprion/registry/certificates.yaml`), and the worker's sandbox opens the registry's directory.

```yaml
schema_version: 1

receivers:
  lb-01.example.net:
    path: /srv/certdist/receivers/lb-01.example.net
    owner: svc-app
    transport: sftp            # rsync | sftp | https; left out, rsync
    layout: per-certificate    # the only layout; may be left out
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

**One answer to "which certificates does this cluster carry".** With the registry, a cluster's
certificates are the ones that name it under `clusters`. A `certificate_ids` list left in `clusters.yaml`
is refused, because the two would be two answers to one question, free to drift apart unnoticed. An
installation that adds a registry later therefore declares it and moves the lists out of `clusters.yaml` in
one edit. `default_certificate` stays in `clusters.yaml` and must still be one the cluster carries.

##### Receivers

A **receiver** is a machine other than a cluster node that certificates are published to. In the registry
it is a directory under the distribution root, and the account whose fetch key is locked to that
directory. Register a receiver with `haprion-cert-receiver`
([Registering a receiver](#registering-a-receiver)), not by hand. An account, a key and a directory are
what let anyone fetch key material at all, and none of the three is safe without the others. What the
interface may change is which certificate goes to which receiver that is already registered. It does that
through a helper that accepts only targets registered in this file.

- **`transport`** says how the receiver fetches: `rsync`, `sftp` or `https`. Left out, it is `rsync`.
- **`layout`** says how the receiver's directory is arranged. The only layout, and the default, is
  `per-certificate`: each certificate gets a directory of its own under the receiver's.
- **`allow`** (`https` only, and required there) lists which addresses may fetch at all.

Neither `path` nor `transport` is edited afterwards. A receiver would find out about a moved path or a
changed transport only at its next fetch, which is a renewal away. To change them, `remove` the receiver
and `add` it again.

**PKCS#12 for one receiver.** A certificate's `receivers` list may name a receiver as
`{id: <id>, format: pkcs12}` instead of a bare ID. That pair - this certificate, this receiver - is then
published as a PKCS#12 bundle (`.pfx`) with a password file beside it, instead of as a PEM pair. A bare ID
means `pem`. The choice belongs to the pair, because one host can want PEM for HAProxy and a `.pfx` for
IIS.

You choose the format where you choose the receiver:

- on the command line, `--format <receiver>=pkcs12` beside `--receiver`, on `haprion-cert-issue`,
  `haprion-cert-import` and `haprion-cert-scep`
- in the interface, the select beside the receiver's box on the certificate form and in *Publish to…*

When the targets change, a receiver that stays keeps its format unless a new one is given. Giving a
different one rewrites that receiver's files in the new format at once.

**The bundle's password is not a protection.** It is published beside the bundle, in the same directory,
with the same owner and mode, so whoever can read one can read the other. It exists because a PKCS#12
import asks for a password. It is made once per pair and kept across renewals, so the receiver's import
script need not change. What protects the key is the same as for a PEM pair: the receiver's account, its
directory and the transport's lock. Publishing a `.pfx` to a receiver is exactly as sensitive as
publishing `privkey.pem` to it.

##### Certificate entries

Each entry under `certificates` takes these fields:

- **`source.kind`** says where the certificate comes from:
  - `acme` - issued from Let's Encrypt and renewed by certbot
  - `import` - signed elsewhere and imported, including a certificate enrolled through NDES
  - `authority` - a CA certificate (one or more, no key) that a cluster's pools verify their servers
    against. It goes to clusters only: no receivers, not the interface, not exportable
    ([Importing a certificate](#importing-a-certificate)).
- **`source.lineage`** (`acme` only) is the certbot lineage name. Left out, it is the certificate ID, which
  is what a certificate issued from the interface gets. Set it only where an existing lineage has another
  name - renaming a lineage moves certbot's archive, and is not worth it.
- **`source.dns_profile`** (`acme` only) names the DNS profile the certificate was issued with. Renewal
  uses it where the plugin keeps no credentials setting of its own (see
  [The certbot environment](#the-certbot-environment)).
- **`source.ndes_profile`** (`import` only) names the NDES profile whose challenge enrolled the
  certificate ([Enrolling and renewing through NDES](#enrolling-and-renewing-through-ndes)).
- **`clusters`** and **`receivers`** are the targets.
- **`interface: true`** marks the certificate the management host's own interface is served with
  ([HTTPS and the certificate](#https-and-the-certificate)). It is issued, imported and renewed like any
  other entry, but it is published to nginx instead of to targets. It names no cluster and no receiver -
  the loader refuses either - and only one entry may carry it.
- **`exportable: true`** marks a certificate whose key may be taken out of the manager
  ([Certificates installed by hand](#certificates-installed-by-hand)). It is set when the entry is made and
  never changes, and such an entry can have no clusters, no receivers, and cannot serve the interface.

##### Changing the file, and reading it

**One writer at a time.** Every command that changes the file - issue, import, delete, a target change, a
receiver's registration or removal, the scheduled renewal - reads it, changes it and writes it back under
one lock: the publisher's, `/run/haprion/locks/cert-publish.lock`. The interface queues one certificate
job at a time, but the renewal timer and an operator's command run outside that queue. Without the lock,
two writers in the same second would lose one update in a way the loader cannot see: the file that wins is
valid, it just lacks what the other one wrote. A command that finds the lock held for more than two
minutes refuses with `operation_locked` instead of waiting longer.

**Listing.** `haprion-cert-list` reports `source` and `targets` for every certificate the registry names.
For a file in a cluster's directory that no entry names - a certificate placed there by hand - both are
`null`, so it can be registered rather than hidden.

- `haprion-cert-list -c <cluster>` answers for one cluster.
- `haprion-cert-list --registry` asks the manager for the whole registry and for what the interface is
  served with. It answers even before the first cluster exists.

The poller reads it the same way, once a pass.

#### Certificate publication hook

**The certbot deploy hook is what publishes a renewed certificate and rolls it out.** certbot runs every
file in `/etc/letsencrypt/renewal-hooks/deploy/` after every successful renewal, whichever certificate
renewed. Haprion's hook there is `50-haprion`.

Platform step 14 (`14-platform-certbot`, which `haprion-setup` runs) installs it, root-owned with mode 755,
from the copy the `haprion-ui` package carries (`/usr/share/haprion-ui/install/certbot-deploy-hook`; in the
source tree [`../install/certbot-deploy-hook`](../install/certbot-deploy-hook)). A hook there that differs
from the release's copy is replaced, and each update of `haprion-ui` installs the new copy. The step then
proves it with a dry-run renewal
([The certbot environment](#the-certbot-environment)). To reinstall and test it, run the step again:

```bash
sudo /usr/share/haprion-ui/install/platform/14-platform-certbot -
```

The hook runs `haprion-cert-publish --deploy` and nothing else. That publishes every registered
certificate that changed, and rolls out the clusters that received a new version - including a cluster an
earlier run published to without a rollout that succeeded, so a renewal finishes what a failed one left.
The publisher finds what changed by comparing file contents, so the hook has no per-certificate logic that
could go stale when a certificate is added.

If the hook directory holds another hook that publishes certificates - for example one written for a
single lineage, or one that walks a list file - remove it. Otherwise every renewal publishes twice.

The hook renews nothing itself. `haprion-certbot-renew.timer` runs certbot twice a day; the hook is what
publishes after a renewal.

#### ACME configuration and challenge routing

When you issue a certificate, you supply only a domain, a challenge method and targets the registry
already knows. Everything else certbot is told is fixed - `certonly`, the lineage name (which is the
certificate ID), `--key-type ecdsa`, non-interactive, directory hooks off for this one run - or read from
the `acme:` block of the runtime policy:

```yaml
acme:
  dns_cloudflare_credentials: /etc/letsencrypt/cloudflare/example.ini
  webroot: /var/www/acme
  certbot: /opt/haprion-certbot/current/venv/bin/certbot
  dns_profiles:
    directory: /etc/haprion/dns-profiles
    private_keys:
      - /etc/haprion/ui-secrets/dns-profile-keys/0123456789abcdef.key
```

- **`certbot`** names the certbot program the helper runs: the product's own, once
  [The certbot environment](#the-certbot-environment) has installed it. Step 2 writes it. Left out, the
  helper runs the distribution's `/usr/bin/certbot`, with the distribution's plugins.
- **`dns_profiles`** is where the DNS provider credentials entered in the web interface end up, and which
  private keys may open them. [The DNS profile key pair](#the-dns-profile-key-pair) makes the keys.
- **`webroot`** is the directory for `http-01` challenges (below).
- **`dns_cloudflare_credentials`** is a Cloudflare credentials file, used for `dns-01` when no DNS profile
  is given.

| Method | certbot | What the installation is responsible for |
|---|---|---|
| `dns-01` | the plugin and root-only file selected by `--dns-profile`; without it, `--dns-cloudflare` with the policy file above | the profile may edit that zone |
| `http-01` | `--webroot -w <webroot>` | `http://<name>/.well-known/acme-challenge/` reaches that directory |

A method whose setting is missing is refused by name before certbot runs. A wildcard (`*.example.net`,
which also covers `example.net`) needs `dns-01`, and is refused with `http-01`. The command does not create
routes, change the published configuration or check that the name resolves.

**`http-01` needs more than the webroot setting.** Port 80 for a proxied name ends at the cluster's VIP,
not at the manager. Three things must be in place, all of them yours to set up:

1. the webroot directory named in the policy
2. something on the manager that serves that directory over plain HTTP - a port-80 `server` block in nginx
   that exposes only `/.well-known/acme-challenge/` from the webroot
3. a rule in each cluster that sends that path to the manager, written once into `core/` or `manual/`,
   never generated:

```text
# core/ or manual/ - hand the ACME HTTP-01 challenge to the manager
backend acme_challenge
    server mgr 192.0.2.5:80

# in the HTTP frontend, before any host routing
acl acme_challenge path_beg /.well-known/acme-challenge/
use_backend acme_challenge if acme_challenge
```

Here `192.0.2.5` stands for the manager's own address. Without all three, an `http-01` request fails at
the challenge, with certbot's own explanation.

When certbot fails, its output is printed after the error line at a terminal, and carried whole under
`error.details.diagnostics` in the JSON result. So the explanation of a failed challenge reaches whoever
asked, in certbot's own words.

#### The certbot environment

**Why the product carries its own certbot.** The distribution's certbot runs on the system Python, which
accepts no packages beyond the distribution's own - and the distribution packages only about a dozen DNS
plugins. The product offers many more DNS services, so it carries its own certbot, with every DNS plugin
the web interface can offer.

- [`../certbot/pyproject.toml`](../certbot/pyproject.toml) names certbot and those plugins.
- `certbot/uv.lock` pins the whole set, with hashes, as resolved together. What the interface can offer is
  exactly what that lock resolved.
- Nothing installs a plugin at runtime. A few plugins are published only as source code. They are built
  with the setuptools the lock holds, installed first from its hashed wheel, so nothing in the build is
  fetched unpinned.

**How it is installed.** The `haprion-certbot` package carries that environment, built from the lock for
one distribution and unpacked under `/opt/haprion-certbot/releases/`. Platform step 14, which
`haprion-setup` runs, makes it current. A newer package runs the step itself when it is installed.

To build the environment from a source tree's lock instead, give the step a `uv`:

```bash
cd /usr/share/haprion-ui/install/platform
sudo UV_BIN=/path/to/uv ./14-platform-certbot /path/to/answers.env /usr/share/haprion-ui
```

Built that way, the step hands the lock to
[`../tools/install-certbot-env.py`](../tools/install-certbot-env.py). That tool lets uv install exactly the
locked set into `/opt/haprion-certbot/releases/<certbot version>-<lock hash>/venv`, proves that every
plugin in it loads, and then runs `certbot/verify-integrations.py` with the new environment's Python:

- It feeds the catalogue's sample credentials through every offered plugin's own credential setup, and
  exercises Azure through its SDK with the network mocked.
- It runs with network sockets disabled, so a plugin that reaches out fails instead of passing quietly.
- A missing, empty or failed report refuses the release.
- The catalogue states per provider what has been proved (`packaged`, `loaded`, `integration-tested`,
  `live-verified`), and the verifier refuses a catalogue that claims more than the run showed.
- The names of the checks that passed are recorded in `INSTALLATION.json`.

The installer then makes the tree root-owned and read-only, and points `/opt/haprion-certbot/current` at
it.

**The gate: a dry-run renewal.** Next, the step runs
`haprion-cert-renew --certbot <new binary> --dry-run --run-deploy-hooks` against every certificate lineage
on the host. That is the one gate a certbot upgrade has. If it fails, the step puts the previous release
back before it stops.

**Only then does renewal move over.** The distribution's `certbot.timer` is masked, and
`haprion-certbot-renew.timer` takes over: the same schedule, the release's certbot, the same
`/etc/letsencrypt`. Its wrapper runs certbot once per lineage. Most plugins store their credentials-file
setting in the lineage's renewal configuration. Route53 has no such setting, so the wrapper sets
`AWS_SHARED_CREDENTIALS_FILE` from the registry's `source.dns_profile`. One certbot owns all the lineages.
Renewal walks all of them and fails on one whose plugin it cannot load - which is why the distribution's
timer is masked rather than only disabled.

**The worker's sandbox must open certbot's directories.** The step checks that the worker's unit opens:

- certbot's directories (`/etc/letsencrypt`, `/var/lib/letsencrypt`, `/var/log/letsencrypt`)
- the runtime policy's roots, among them the publisher's target and the registry's directory, which step 07
  writes into the unit from the policy
- the DNS profile directory (`/etc/haprion/dns-profiles`)

The issue helper runs certbot inside the worker's sandbox. Without those paths, every issuance from the
web interface fails on a write, such as certbot's log lock. Step 07 installs the unit; if it lacks them,
rerun step 07 from a `haprion-ui` package that has them before running step 14.

**Upgrading certbot.** The runtime policy names the release's certbot (`acme.certbot` in
[ACME configuration and challenge routing](#acme-configuration-and-challenge-routing), written by step 2),
so the issue helper runs it too. An upgrade is a newer `haprion-certbot` package, a few times a year. It is
built from an updated `certbot/uv.lock` (`uv lock --upgrade` in `certbot/`), and installing it runs step 14
with the same gate.

- A plugin that no longer resolves against the newer certbot drops out of the lock, and so out of what the
  interface offers.
- A release that fails the dry run is never made current. The installation itself does not fail on it: the
  package says why, and the previous environment keeps renewing. Once the cause is fixed - often the
  staging server or the network - try again with
  `sudo /usr/share/haprion-ui/install/platform/14-platform-certbot -`.
- Rolling back by hand is one symlink, which the step prints, followed by the same dry run.

#### The DNS profile key pair

**What it protects.** A DNS provider's credentials are entered once, in the web interface, and stored
encrypted. The web process encrypts them with the installation's public key and keeps only the encrypted
form. Only the root helper that runs certbot holds the private key that can open them (a libsodium sealed
box, through PyNaCl). So a compromised web process can add or replace a profile but never read one back,
and a database dump holds nothing a reader can use without root's key file.

**Making the pair.** Platform step 15 makes it; `haprion-setup` runs the step:

```bash
cd /usr/share/haprion-ui/install/platform
sudo ./15-platform-dns-keys /path/to/answers.env /usr/share/haprion-ui
```

- The private key goes to `/etc/haprion/ui-secrets/dns-profile-keys/<key id>.key`, readable by root only.
- The public key goes to `/etc/haprion/dns-profile-keys/<key id>.pub`, readable by the platform group.
- The key id is a digest of the public key, so it is read off either file rather than assigned. A stored
  profile names the key id it was encrypted with.
- Each file is one tagged line, and a private key placed where a public one belongs is refused by its tag.
- The step proves the pair by encrypting and opening a test message with the files it wrote. It never
  overwrites an existing key; run on an installation that has a pair, it keeps it.

**Who is told about it.** Two readers need to know the pair.

**The runtime policy** names the private keys, and the directory where the helper writes credential files
([ACME configuration and challenge routing](#acme-configuration-and-challenge-routing)). Step 2 adds this
block, with every key step 15 made, when it writes the policy. If the policy already exists without it,
step 15 does not edit the policy: it prints the block to add, and warns about any private key the policy
does not list.

```yaml
acme:
  dns_profiles:
    directory: /etc/haprion/dns-profiles
    private_keys:
      - /etc/haprion/ui-secrets/dns-profile-keys/0123456789abcdef.key
```

**The web interface's** `/etc/haprion/ui.toml` names the public key. Step 15 adds this table itself when
`ui.toml` names no key, and restarts the web service to read it. A `ui.toml` that already names a key is
checked, not changed.

```toml
[dns_profiles]
public_key = "/etc/haprion/dns-profile-keys/0123456789abcdef.pub"
```

A new runtime policy key needs a CLI release before the policy is edited, and a platform release after it,
in that order. `check-compatibility` reads the policy through the platform's own copy of the engine, and
the installed engine refuses a key it does not know.

**Replacing the key.** Run the step with `ROTATE=1`: it adds a second pair beside the first. Then:

1. List both private keys under `acme.dns_profiles.private_keys` in the runtime policy, and under
   `ndes.profiles.private_keys` too if the `ndes` block lists keys of its own.
2. Point `ui.toml` at the new public key, and restart the web service.
3. Re-enter each profile, so it is encrypted with the new key. A profile encrypted with a key the policy no
   longer lists cannot be used until it is re-entered.
4. Remove the old pair last.

The private key file is part of the host's disaster-recovery material, like the SSH keys in
[SSH identities](#ssh-identities). Without it every stored profile is unreadable, and the recovery is to
re-enter the profiles, not to restore a database dump.

#### Preparing Microsoft AD CS / NDES for CSR enrollment

The manager can enroll certificates from a Microsoft CA through NDES, Microsoft's SCEP service. The private
key is made on the manager and never leaves it. This section covers what the manager needs and how to
prepare the Microsoft side. Using it - enrolling, renewing, pending requests - is in
[Enrolling and renewing through NDES](#enrolling-and-renewing-through-ndes).

**What the manager provides:**

- NDES profiles, with the challenge stored encrypted (*Certificates → NDES profiles*)
- the NDES servers it enrolls with, each added from its CA (*Certificates → NDES profiles → Add NDES server*)
- the Certmonger client, in the `haprion-scep` package, which speaks SCEP
- the root enrollment command, `haprion-cert-scep`, and the job helper behind it
- the certificate form's *NDES* method

Enrollment has been verified end to end against NDES, both for a single DNS name and for a wildcard with
its base name.

**How enrollment works.** The manager creates an RSA key and a PKCS#10 certificate request (CSR) locally.
It sends the request to NDES through SCEP over verified HTTPS, validates the certificate that comes back,
and then publishes and distributes it like any other certificate. The private key stays on the manager. The
manager needs no domain membership or AD account, and does not visit `mscep_admin` during normal operation.

**The SCEP client.** [Certmonger](https://codeberg.org/freeipa/certmonger/) provides the SCEP support. It
runs as a temporary process with a private socket for each request, and Certmonger's own renewal is
disabled: the manager schedules renewal itself. It comes in the `haprion-scep` package, with the
distribution's certmonger package, its source code and its license (below).

**Other SCEP servers.** The client speaks plain SCEP. The manager makes two choices that NDES needs and
other servers accept: a signature-and-encryption request, and the challenge as a PrintableString. Only
NDES has been verified. Another SCEP CA should work but is untested - step-ca is the quickest to stand up,
and EJBCA, OpenXPKI and network appliances also serve SCEP. The profile and policy fields keep their NDES
names.

##### Adding an NDES server

A profile enrolls with one of the NDES servers the manager has confirmed. Add a server under
*Certificates → NDES profiles* with *Add NDES server*:

1. Enter the server's `mscep.dll` address and choose *Fetch the CA*. The manager asks the server for its CA
   certificates over HTTPS, checked against the manager's system certificate store, and shows each one with
   its SHA-256 and its SHA-1 thumbprint - the thumbprint Windows shows in the certificate's details. It asks
   the server directly, without a proxy, and does not follow a redirect: it names the address to give instead.
   The HTTPS check is the enrollment's: the same store, as strict and no stricter. A certificate
   that fails it is named for what is wrong: another name, a certificate on the path past its date, or a CA
   the store does not hold.
2. Compare them with the CA's own certificates. The one marked *issues for NDES* is the CA the server enrolls
   for; the others are the rest of its chain. A server that gives its chain without the root CA has it
   completed from the manager's system certificate store, and the root is marked *from this manager's
   certificate store*. When the store has no CA that issued the chain, the server is refused; add its root
   CA to the store first. The chain is checked as an issue checks it: a server
   certificate from the issuing CA must verify against the saved certificates, for a server. A chain that
   does not - a root with the right name but another key, a CA on the path past its date, a path length or
   purpose that leaves no room for a server certificate - is refused too, with OpenSSL's reason, since every
   issue would fail on it. A CA certificate beside the path takes no part, as in an issue.
3. Choose *Confirm this CA*, or *Confirm these CAs* when there are several. The manager asks the server again
   and adds it only if it still gives exactly these certificates. All of them are saved for the server.

The server list shows when each server's saved CA expires - the first of its certificates to run out - in the
same colours as the certificate registry, so a CA about to expire is seen before renewals fail on it.

When the CA is renewed with a new key, or the saved CA certificate expires, certificates from the server no
longer chain to what was saved, and an issue or renewal fails with "issued certificate does not chain to the CA
confirmed for the NDES server". Add the server again with the same address: the page says it is confirmed with
other CA certificates, and confirming the new ones replaces them. Its profiles stay.

A CA may be limited to some names (its name constraints). Confirming the server cannot check them, since no
names are known then. Each enrollment checks its names against them before it asks the CA. A name outside
them is refused with "the names asked for are outside what the CA may issue for", and so is a certificate the
CA issues for one.

The HTTPS certificate of the NDES server must be trusted by the manager's system store, both when the server
is confirmed and at each issue. A server signed by an internal CA needs that CA in the store, as any other
internal HTTPS service does (`update-ca-certificates`). When it is not, *Fetch the CA* says the server's HTTPS
certificate is not trusted.

A server is removed from the same page, when no profile uses it. The command refuses while a profile applied
on this manager names the server, or a profile record cannot be read; the interface also refuses while a
saved profile that has not been applied names it. Each change made in the interface is recorded in the activity
log, and the helper writes a line of it to the journal; a change made with the command leaves sudo's own line.
A change the service did not answer is recorded as asked for, since it may
have been made. From the command line:

```bash
haprion-ndes-server list
haprion-ndes-server add https://ndes.example.com/certsrv/mscep/mscep.dll
sudo haprion-ndes-server add https://ndes.example.com/certsrv/mscep/mscep.dll --sha256 <SHA-256> --sha256 <SHA-256>
sudo haprion-ndes-server remove https://ndes.example.com/certsrv/mscep/mscep.dll
```

`add` without `--sha256` shows the CA certificates and changes nothing, and says whether the server is
confirmed with these or with other CA certificates. To confirm, give one `--sha256` for each certificate shown.

##### Manager configuration and packaging

**The runtime policy's `ndes` block** is written by the manager when the first server is added, and removed
with the last one. Its fields:

| Field | What it is |
|---|---|
| `servers` | the confirmed servers: each `endpoint` (the HTTPS address) and `issuing_ca` (the file with the CA certificates it gave) |
| `client_root` | where the SCEP client is installed: `/opt/haprion-scep/current` |
| `state_root` | where enrollment requests are kept: `/etc/haprion/ndes-requests` |
| `profiles` | `directory` (where profile records are kept: `/etc/haprion/ndes-profiles`); the keys the profiles are sealed with are `acme.dns_profiles.private_keys`, unless the block lists `private_keys` of its own |
| `renew_days` | optional; renew this many days before expiry (1-3650, default 30) |

```yaml
ndes:
  servers:
    - endpoint: https://ndes.example.com/certsrv/mscep/mscep.dll
      issuing_ca: /etc/haprion/ndes-ca/0123456789abcdef-fedcba9876543210.pem
  client_root: /opt/haprion-scep/current
  state_root: /etc/haprion/ndes-requests
  profiles:
    directory: /etc/haprion/ndes-profiles
```

A block with one `endpoint` and `issuing_ca` beside the other fields is read as one server. A `tls_ca` in an
older policy is accepted and not used: the server's HTTPS is checked against the system store, and confirming
the server again writes it without one. The manager rewrites only the `ndes` block; the rest of the file and
its comments stay.

An earlier release may read only that one-server form, with `profiles.private_keys` listed. A rollback it
cannot read the policy for is refused and names the key. Before going back, write the block with the one server
it should keep and the keys it should read:

```yaml
ndes:
  endpoint: https://ndes.example.com/certsrv/mscep/mscep.dll
  issuing_ca: /etc/haprion/ndes-ca/0123456789abcdef-fedcba9876543210.pem
  client_root: /opt/haprion-scep/current
  state_root: /etc/haprion/ndes-requests
  profiles:
    directory: /etc/haprion/ndes-profiles
    private_keys:
      - /etc/haprion/ui-secrets/dns-profile-keys/0123456789abcdef.key
``` The two `/etc/haprion`
directories are root-owned with mode `0700`; the records and keys in them have mode `0600`.

**The client comes in the `haprion-scep` package.** `haprion-ui` depends on it, so it is installed with the
manager, and `haprion-setup` installs the client. The package carries Certmonger's own programs from the
distribution's certmonger package, with that package, its complete source and its license. The client is
installed under `/opt/haprion-scep` without a standing Certmonger service. Its libraries are the
distribution's: the package depends on what certmonger depends on, and they follow the distribution's updates.
An update of the package installs its new client, and the previous one stays current if that fails.

The release build takes the certmonger package and source the build tool pins by digest, so every build of a
release is the same. Before it writes the client, it looks the version up in the OSV vulnerability database
under the distribution's release, and refuses the build if any advisory affects it.

**By hand.** As root, `install/platform/16-platform-scep <bundle.zip> <sha256>` installs a bundle that
`tools/build-scep-client.py` built. The installer checks the hashes, the paths in the archive, the OS release
and the architecture, and asks apt for the libraries the client needs. It also creates
`/etc/haprion/ndes-profiles` and `/etc/haprion/ndes-requests`.

##### Preparing the Microsoft side

**Server prerequisites.**

- Install and configure the AD CS *Network Device Enrollment Service* role, with IIS, an issuing CA and
  valid NDES signing and encryption RA certificates. NDES and the CA may share a server, but the product
  does not require it. Microsoft's
  [NDES overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/network-device-enrollment-service-overview)
  describes the role and its IIS applications.
- For a dedicated domain service account, follow
  [Microsoft's service-account instructions](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/create-domain-user-account-ndes-service-account).
  The account needs local `IIS_IUSRS` membership, effective `Request Certificates` permission on the CA,
  and `Read` + `Enroll` on the dedicated certificate template. It need not be a domain or local
  administrator.
- Make sure the IIS `Default Web Site` exists before you configure NDES; a missing site caused setup error
  `0x80070003` in testing. The working SCEP application pool used `Load User Profile = True`.

**One dedicated, published template.** Set these values in the certificate template and publish it on the
issuing CA:

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

`Supply in the request` lets the enrolling account request whatever names the client supplies, so restrict
the template's rights and access to the endpoint according to your PKI policy. Subject alternative names
(SANs) travel as extensions in the CSR. The integration does not need the global CA flag
`EDITF_ATTRIBUTESUBJECTALTNAME2`.

Under `HKLM\SOFTWARE\Microsoft\Cryptography\MSCEP`, set `GeneralPurposeTemplate` to the template's
**internal name**, not its display name - for example `HAProxyWebServer`. A signature-and-encryption
request selects this mapping, so no template is chosen in the manager's interface. The other two mappings
need not change for this request type.

**HTTPS and trust.**

- Serve the SCEP endpoint at `https://<ndes-fqdn>/certsrv/mscep/mscep.dll`, with a server certificate that
  matches the endpoint's DNS name.
- The manager's system store must trust that HTTPS chain (`update-ca-certificates`).
  The manager separately validates the certificate the CA issues (`issuing_ca`).
- Provide the trust anchors explicitly. SCEP `GetCACert` fetches the protocol's CA and RA certificates, but
  does not by itself establish trust.
- HAProxy is served the issued certificate plus any intermediate certificates; leave the root out of the
  served full chain.

**A reusable challenge.** Unattended enrollment needs these DWORD settings:

| Registry subkey under `HKLM\SOFTWARE\Microsoft\Cryptography\MSCEP` | Value name | Value |
|---|---|---|
| `EnforcePassword` | `EnforcePassword` | `1` |
| `UseSinglePassword` | `UseSinglePassword` | `1` |

An administrator fetches the master challenge once, from `https://<ndes-fqdn>/certsrv/mscep_admin/`, and
enters it in the NDES profile under *Certificates → NDES profiles*.

- As with DNS provider credentials, the web application encrypts it with the installation's public key, and
  the database stores only the encrypted form. Only the root helper can decrypt it.
- The profile lets you replace the challenge, never read it back.
- NDES profiles are a separate profile type, checked for identity and revision. The helper writes a
  root-only profile record in one step.
- For each enrollment, the helper creates a root-owned challenge file with mode `0600` for Certmonger to
  read, and removes it when the process ends. The protected request state can still contain the challenge,
  inside its CSR.
- Normal enrollment uses only `mscep.dll` and this secret.

Microsoft's older
[single-password article](https://support.microsoft.com/en-au/topic/two-improvements-are-available-that-shorten-the-time-that-is-required-to-manage-scep-certificates-by-using-the-network-device-enrollment-service-in-windows-server-2008-c497db37-9c87-0cd0-30dc-845eeb8ba9f5)
documents the reusable, non-expiring password and its registry setting for Windows Server 2008. Use it as
background only, not as an instruction to install that hotfix on a modern server. This mode was verified on
Windows Server 2022. There, the NDES service account needed Full Control on the MSCEP registry subtree for
single-password operation; review the registry permissions your installation needs.

**The master challenge is a long-lived credential.** Protecting the endpoint and NDES stays your
responsibility. Keep the challenge in plain text out of command arguments, job data, logs, job results and
the database; only the encrypted form may be stored in the database. A CSR carries the challenge as
`challengePassword`, so treat CSRs, and any temporary OpenSSL request configuration, as secret too. Rotate
a challenge that has been exposed.

##### Interoperability and verification

**Encoding of the challenge.** The tested NDES installation accepted `challengePassword` as an ASN.1
PrintableString. A missing attribute caused NDES Event ID 28, and a different encoding caused Event ID 29.
OpenSSL `string_mask = nombstr` produced a working PrintableString. These are test findings, not a general
encoding rule from the Microsoft documents above.

**Testing with `scepclient`.** If you test the server with `scepclient 2.3.0`, it needs a CSR made in
advance for multiple SANs, and the RSA key in PKCS#1 form. Those are that client's constraints, not SCEP
requirements; the manager does not use it.

**Verifying the server from Linux.** Enroll both a single DNS name and a wildcard with its base name, using
the same challenge twice. Check the exact set of SANs, the Subject, the Server Authentication EKU, the key
usage, the validity, that the key matches, and the certificate chain. A landing page that answers, or
`GetCACaps` alone, does not prove that enrollment works. A full acceptance test also covers verified TLS,
`GetCACert`, matching each SCEP response to its request, pending and failed requests, and error messages
that carry no secrets.

**What is outside the integration.** It issues certificates requested from the command line or the
interface, and renews them on schedule
([Enrolling and renewing through NDES](#enrolling-and-renewing-through-ndes)). CEP/CES/WSTEP, discovering
templates, and fetching the password from `mscep_admin` automatically are outside it.

#### Validation certificate

Before a configuration is published, the manager validates it with a real `haproxy -c`. Any configuration
that references a certificate therefore needs certificate material present during validation - but the
validating path must never be able to read the real private keys.

A dedicated, self-signed certificate under `validation_certs_root` solves this. It is readable only by
root. It is copied into the private copy of the candidate configuration for the duration of validation,
and removed before the helper returns. It never leaves the management host and is never deployed.

#### SSH identities

All traffic between the manager and the nodes goes over SSH, and **every key has exactly one job**. A key
that can trigger a configuration pull cannot trigger a certificate pull, and neither can read status.

**Keys on the management host** - in `/root/.ssh/` unless noted, named in the runtime policy
([SSH keys and the accounts they reach](#ssh-keys-and-the-accounts-they-reach)):

| Key | Connects as, on the node | Purpose |
|---|---|---|
| `id_ed25519_config_deploy` | `_haprion-trigger` | trigger a configuration pull |
| `id_ed25519_cert_deploy` | `_haprion-trigger` | trigger a certificate pull |
| `id_ed25519_server_state` | `_haprion-trigger` | drain, maintenance or ready for one server |
| `id_ed25519_node_status` | `_haprion-status` | read node status |
| `id_ed25519_node_probe` | `_haprion-status` | try a health check |
| `id_ed25519_node_backup` | `_haprion-backup` | fetch the node's state archive |
| `/etc/haprion/traffic-collector/id_ed25519` | `_haprion-logread` | fetch the traffic log |

**Keys on each node** - in the node's `/root/.ssh/`:

| Key | Connects as, on the management host | Purpose |
|---|---|---|
| `id_ed25519_config_pull` | `_haprion-pull` | read the published tree |
| `id_ed25519_cert_pull` | `_haprion-cert-pull` | read the certificate tree |

The manager's private keys are root-owned, and no application account can read them. The one exception is
the traffic collector's key: it is owned by the collector account, because the collector never runs as root
and no privileged process takes part in moving data from a node.

**On each node, the manager's keys work only from the manager's address.** Every line step 4 writes for them
carries `from=` with the manager's host and the IPv4 addresses it resolved to, so a copied key does not work
from another machine. A manager that moves to another address reaches no node until step 4 has run again on
each of them with the new name or address: `sudo haprion-node-prepare --manager <new name or address>`. The
node then fetches from the new address too, and the manager's host key is carried over from the old one.

**A manager key that was rotated, or added after the join,** reaches a joined node only by hand, because
the manager has no way to send one. On the manager the public key is the `.pub` file next to the identity
the runtime policy names for that purpose; for `traffic_log` it is the collector's key,
`/etc/haprion/traffic-collector/id_ed25519.pub`. On the node:

```bash
sudo haprion-node-prepare --key status="ssh-ed25519 AAAA..."
```

The purpose is one of `deploy`, `cert_deploy`, `server_state`, `status`, `probe`, `backup` and
`traffic_log`. The key replaces that purpose's line, with the same forced command and the manager's
addresses as the join gives it; the other keys stay, and running it again changes nothing. A node that
has not joined (a manager joined it, or step 4 was run on it by hand), a purpose it does not know and a key that is not one ssh-ed25519 public key are refused. The command prints the key's fingerprint; compare it with `ssh-keygen -lf` on the `.pub` file.

A node also has a one-time join key. It is part of the enrollment block the node prints, and lets a manager
join the node once, as `_haprion-join`, within 24 hours; the join removes it after use.

**The node's keys are made on the node and never leave it.** The `haprion-node` package makes them when it
is installed (`haprion-node-key`), and step 4 (`04-node-prepare`) makes them on a node prepared by hand. A
private key a node authenticates with has no reason to exist on the management host; a copy there would
let the management host pretend to be the node. The node's enrollment block carries the public halves, and
adding the node writes them into the management host's pull accounts, `_haprion-pull` and
`_haprion-cert-pull` ([Adding and removing a node](#adding-and-removing-a-node)).

**One line per node, not one per cluster.** Each node has its own key, so a node that is rebuilt or
compromised can be revoked on its own. Each line reads one cluster's files, from one node's address:

```text
from="<host>,<addresses>",restrict,command="/usr/bin/rrsync -ro <publish_root>/<cluster>" <key> <node> config pull
from="<host>,<addresses>",restrict,command="/usr/bin/rrsync -ro <certificate_root>/<cluster>" <key> <node> certificate pull
```

- **`rrsync` makes the restriction real.** The forced command `rrsync -ro <tree>` allows a read-only rsync
  of exactly one directory, and nothing else. A forced plain `rsync` command would be a shell in all but
  name. So a node of one cluster cannot read another cluster's configuration or certificate keys.
- **`from=` ties the key to the node's address**, so a copied key does not work from another machine. It
  holds the node's host and the addresses that name resolved to when the line was written: sshd matches the
  connecting address, unless `UseDNS yes` is set.

**Keeping the lines current.**

- A node whose name comes to resolve to another address fetches nothing until
  `sudo haprion-node pull-keys` writes its lines again.
- A node moved to another host with `haprion-node host` gets its lines rewritten as part of that.
- The CLI package runs `haprion-node pull-keys` after every upgrade.

`haprion-node pull-keys`:

- writes each node's lines in the form above
- removes the line of a node no cluster has
- leaves a line of any other shape as it is, and says so
- gives a host that does not resolve its narrowed line without `from=`, with a warning
- keeps, with a warning, the line of a node name that two clusters in `clusters.yaml` share, as written,
  until one of them is removed
- with a certificate registry, gives each cluster its own certificate directory, copied from a shared one,
  and removes the shared copies once no line reads them

A node asks for `<cluster>/current/<node path>/`. Each cluster's published tree holds a link
`<cluster> -> .` to itself, so that path names the cluster's files under the cluster's own root.

**The published tree belongs to the pull account, not to the config group.** Giving it to the config group
looks reasonable, but it locks the nodes out of the only tree they are supposed to read - deploys then
fail while every permission still looks deliberate.

#### Sudo rules

There are two separate sudo policies, and they must not be merged:

- **Application rules.** These let the application's accounts run exact helper paths, with no arguments
  (`command ""`). The helper reads its request as one bounded JSON line on standard input. A caller that
  runs an operation it may later need to stop keeps that input open as a lifeline; see `PRIVILEGE.md`. No
  rule grants a shell, an interpreter, an editor, a wildcard path, environment preservation, or free
  arguments. The web account has no sudo rule at all.
- **Operator rules.** A `sudoedit` policy lists, by exact path, the configuration files an administrator
  may edit. `sudoedit` is what makes editing possible without making the repositories group-writable.

  **Remove the rule in the same change that removes the file.** `sudoedit` creates a file it does not find.
  So a rule naming a path that no longer exists is not merely stale: it is a standing way to place a new
  root-owned file at that path - in a directory the configuration is loaded from, outside what anyone
  reviewed. When you remove an entry:

  - Rewrite the whole alias rather than deleting the line. The last entry has no trailing comma, so
    removing a line can move that position and leave the file broken.
  - Validate with `visudo -cqf` before installing.
  - Keep the backup outside `/etc/sudoers.d/`. sudo skips file names that contain a dot, but a superseded
    policy file inside the directory sudo reads is protected only by that convention.

Every sudoers file is root-owned and read-only (`0440` or stricter). See [`PRIVILEGE.md`](PRIVILEGE.md) for
the full contract and the negative tests that prove it.

### Part 2 — the nodes

The node scripts are in [`install/node/`](../install/node/). They reach a node in the
[`haprion-node` package](#installing-and-changing-node-scripts), which puts them in `/usr/sbin`, and
[`04-node-prepare`](../install/04-node-prepare) beside its library. That step creates the accounts, the
release layout and the sudo rules.

Every installation and every update runs the same step, and running it again changes only what is not
already right. But an update is not just a copy of the scripts: the step also puts right the service
accounts, directory ownership and modes, `node.conf`, the sudoers files, the HAProxy baseline and the
complete script attestation. On the first node you update, read every line it reports as `created`,
`fixed`, `written` or `installed` before you touch another node.

This section explains what the scripts do and why. Run the script rather than following it by hand.

**Size.** One vCPU and 1 GB of memory per node carries HAProxy and keepalived. **With the WAF engine, start
from 2 GB per node.** The engine may use up to 40 % of the node's memory (see
[The WAF engine](#the-waf-engine)). Its rules take about 50 MB for the first object and a few MB for each
further one, and HAProxy keeps the rest. The DNS listener adds about 85 MB.

One vCPU is where a node starts, not what every node needs. CPU use follows the traffic:

- requests per second
- new TLS connections - a handshake costs far more than a request on an open connection
- most of all, the WAF engine, which reads every request of an object it guards, and more so at a higher
  paranoia level

How far one vCPU goes also depends on the processor behind it. As a rough guide, one vCPU at full load, with
small requests and answers, a backend that answers at once and the traffic log on:

| | Connections reused | A new TLS connection per request |
|---|---|---|
| without the WAF | about 6 900 requests a second | about 1 250 |
| WAF, paranoia 1 | about 1 100 | about 700 |
| WAF, paranoia 4 | about 750 | about 500 |

At a tenth of those rates a node uses roughly a sixth to a quarter of its vCPU. Larger bodies, slower
backends and more rules lower the rates. Only the node holding the VIP carries the traffic, so a busier
cluster needs larger nodes, not more of them. The dashboard shows each node's CPU and memory in use and
marks a cluster at 85 %; give the nodes more vCPUs before they get there.


#### HAProxy and keepalived baseline

The node package installs HAProxy and keepalived. Haprion relies on a few things about how they are
set up, listed below. For a cluster created in the interface, Haprion writes `keepalived.conf`
itself ([keepalived on the nodes](#keepalived-on-the-nodes)). If any of these is wrong, nothing
fails loudly. Deploys simply stop being safe, because the deploy order that protects live traffic
quietly stops meaning anything.

**Every node must be able to bind the virtual address, whether or not it holds it.**

```text
# /etc/sysctl.d/60-haproxy.conf
net.ipv4.ip_nonlocal_bind = 1
```

Without this setting, HAProxy fails to start on a node that does *not* hold the address: it is
asked to bind an address the kernel says is not there. With it, every node runs HAProxy all the
time, and the virtual address decides which node the traffic reaches. `04-node-prepare` sets this
and reports it. The same file also sets the queue length of HAProxy's log socket
(`net.unix.max_dgram_qlen = 8192`, described below).

**Nothing else on a node may listen on every address.** A program bound to `0.0.0.0:<port>` also
holds that port on the virtual address. HAProxy then cannot bind an object there: the deploy fails
with `cannot bind socket (Address already in use)` and rolls back.

sshd is the usual case. Out of the box it listens on `0.0.0.0:22`, which rules out a tcp object on
port 22 of the virtual address, such as an SFTP service. So `04-node-prepare` has sshd listen on
the node's own address - the one the manager came in on when it joined the node, or, on a node
prepared by hand or again, the one the node reaches the management host from:

```text
# /etc/ssh/sshd_config.d/05-haprion-listen.conf
ListenAddress 192.0.2.11
```

How the step treats sshd:

- It changes sshd only while sshd listens on every address. An sshd already limited to chosen
  addresses is left as it is.
- It refuses the virtual address, and any address the node does not have.
- After restarting sshd it checks that sshd answers on the address and no longer on every address.
  If not, it removes the file, puts sshd back as it was, and stops.
- Open SSH sessions survive the restart.
- On Ubuntu, sshd is socket activated, so the restart is of `ssh.socket`. `ip_nonlocal_bind` above
  is what lets sshd come up at boot before the address does.

Any other program listening on every address is reported, not changed, and a publish refuses an
object on its port ([Ports the cluster takes itself](#ports-the-cluster-takes-itself)).

**HAProxy's log socket survives an rsyslog restart.** HAProxy runs chrooted (locked into)
`/var/lib/haproxy`, so its `log /dev/log` is really `/var/lib/haproxy/dev/log`. Ubuntu's
`/etc/rsyslog.d/49-haproxy.conf` has rsyslog listen on that socket. Left to rsyslog, the socket
disappears whenever rsyslog stops, and every line HAProxy writes until rsyslog is back is lost -
from the node's day file and from every log receiver. So `04-node-prepare` has systemd hold the
socket instead, the way `syslog.socket` holds the system log's:

```text
# /etc/systemd/system/haprion-haproxy-log.socket
[Socket]
ListenDatagram=/var/lib/haproxy/dev/log
SocketMode=0666
ReceiveBuffer=16M
Service=rsyslog.service

# /etc/sysctl.d/60-haproxy.conf
net.unix.max_dgram_qlen = 8192
```

When rsyslog starts, systemd hands it the socket. While rsyslog restarts, HAProxy's lines wait in
the socket, so none are lost. The queue length is how many lines can wait: enough for a restart at
25 000 requests a second. Like `syslog.socket`, the unit also starts rsyslog when a line arrives
and rsyslog is not running. If `49-haproxy.conf` lacks its listen line, the step warns and leaves
the socket to rsyslog, and that node can lose lines during an rsyslog restart.

**The HAProxy unit must load `conf.d`, and load it exactly once.**

A node's configuration is a main file plus a directory of fragments. systemd has to be told about
both:

```text
ExecStart=/usr/sbin/haproxy -Ws -f $CONFIG -f $CFGDIR -p $PIDFILE $EXTRAOPTS
```

Upstream's packaging does this and sets `CFGDIR=/etc/haproxy/conf.d`. Some distribution packages
ship a unit with only `-f $CONFIG`, and some installations work around that by putting the
directory into the variable itself:

```text
# Don't. This breaks the moment the unit gains -f $CFGDIR of its own.
Environment="CONFIG=/etc/haproxy/haproxy.cfg -f /etc/haproxy/conf.d"
```

Against a unit that already loads `CFGDIR`, this reads the directory **twice**. Every proxy is
then declared twice, and HAProxy refuses to start: from HAProxy 3.3 a duplicate proxy name is an
error, not a warning. Check the command the service really runs rather than the unit file, because
drop-ins and `/etc/default/haproxy` both feed into it:

```console
$ systemctl cat haproxy
$ grep -vE '^\s*#|^\s*$' /etc/default/haproxy
```

`systemctl show haproxy -p Environment` is not a substitute. It reports only the unit's own
`Environment=` lines. `EnvironmentFile=` is read when the service starts, never appears there, and
overrides those lines.

This matters beyond startup. `haprion-pull-deploy` validates with its own explicit arguments,
naming each path once. So a configuration can validate cleanly while the service will not start.
The two only agree if the unit also names each path once.

**Every node runs keepalived as `BACKUP`, with `nopreempt`.** The example is a cluster of two
nodes:

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

    notify_master "/usr/sbin/haprion-keepalived-state MASTER"
    notify_backup "/usr/sbin/haprion-keepalived-state BACKUP"
    notify_fault  "/usr/sbin/haprion-keepalived-state FAULT"
}
```

Three details carry weight:

- **`state BACKUP` on every node, plus `nopreempt`.** A node that comes back after a failure does
  not take the address back, even with a higher priority. Taking it back (preemption) would move
  live traffic for no reason - during a rebuild, exactly when you least want it. The priorities
  still decide which node takes the address on a cold start, when no node holds it. Haprion gives
  the nodes 100, 90, 80 and so on, in the cluster's node order.
- **Unicast, not multicast.** `unicast_peer` names the other nodes explicitly. Multicast VRRP works
  until something on the path quietly stops forwarding it, and then two nodes both believe they
  are master.
- **The `notify_` lines are required.** They are how the management host learns which node holds
  the address. Without them the state file is never written, node status cannot report an owner,
  and a deploy has no way to order the nodes.

**Why the order matters.** A rollout deploys the nodes that do not hold the address first and the
address owner last. A node whose keepalived is not running yet goes after the owner, so it starts
as a standby. If the new configuration breaks, it breaks on a node that carries no traffic, and the
run stops before it reaches the owner. That protection only works if the owner is actually known.
This is why the three points above are part of the installation and not an operational detail.

**One more line, in the cluster's own configuration rather than the node's.** Status and
statistics are read from a local HAProxy stats socket. A cluster made by *Create cluster*,
`haprion-cluster` or step 1 has this line in its `core/haproxy.cfg` from the start. A core written
by hand needs it, or every node of the cluster shows *Stats unavailable* while it serves:

```text
stats socket /run/haproxy/ui-status.sock mode 660 level user
```

`level user` is read-only: enough for status and statistics, not enough to change anything. It is
a local socket and must not be exposed on the network. An existing admin socket is separate and is
not replaced by it.

A copy-paste starting point for the keepalived side is in
[`install/examples/keepalived.conf.example`](../install/examples/keepalived.conf.example).

**One thing to expect after first setup.** A clean reload of the keepalived configuration does not
necessarily cause a VRRP state change, so the state file may stay empty until the first real
change. Force one - stop keepalived on one node and start it again - or write the file once by
hand.

#### Node accounts

Every node has the same five service accounts. The management host reaches each one over SSH, and
each key it uses can run exactly one command on the node. They are system accounts with no
password, a home directory that holds `authorized_keys`, and - deliberately - a real login shell:

| Account | Reached by | May run |
|---|---|---|
| `_haprion-trigger` | the management host's deploy, certificate-deploy and server-state keys | the pull scripts and the server-state wrapper, through forced commands |
| `_haprion-backup` | the management host's backup key | the state export |
| `_haprion-status` | the management host's status and probe keys | the node status reporter and the health probe, read-only |
| `_haprion-logread` | the collector's traffic-log key | the bounded traffic-log reader, read-only and without sudo |
| `_haprion-join` | the node's own one-time key, once | `haprion-node-join`, which joins the node to a manager |

The join account is used once per join. `haprion-node-key` makes a one-time key that is valid for
24 hours and prints it in the enrollment line you paste into *Create cluster* or *Add a node*. The
manager connects with that key, and the join removes the key when it has used it.

**The real shell looks like a mistake and is not.** sshd runs a forced command - the one command a
key is allowed to run - through the account's login shell. So `nologin` here hardens nothing. It
stops every forced command from working, and the only symptom is a nologin message where output
was expected.

What limits these accounts is the key line, not the shell. Each key in an account's
`authorized_keys` carries the `restrict` option and its **own** forced command, so a session cannot
run anything else. One key, one command: a shared forced command would make the keys
interchangeable and defeat the separation. Where sudo is needed, its rules name exact absolute
commands. `_haprion-logread` needs no sudo rule and has none.

**The account owns nothing in its own home.** `/home/<account>`, `.ssh/` and `authorized_keys` are
owned by `root:root` (modes `755`, `755` and `644`). sshd accepts a key file owned by root as
readily as one owned by the account. The reasons:

- A key file the account could write would let a session rewrite its own forced command.
- A home directory the account owned would let it replace `.ssh` wholesale.
- The shell's dotfiles fall under the same rule. Debian's bash reads `~/.bashrc` before it runs a
  forced command for sshd. So no dotfiles are created, and any that exist are made root's on the
  next run of step 4.

The manager's two pull accounts follow the same rule, set by step 01. A symbolic link in such a home,
or as `authorized_keys`, stops the step: root would otherwise change what the link points at.

Edit `authorized_keys` with `sudo`.

#### Node scripts

Fifteen scripts, all owned by root under `/usr/sbin`, installed by the `haprion-node` package, and
not group-writable:

| Script | What it does |
|---|---|
| `haprion-pull-deploy` | fetches the published release, validates it, installs it, reloads once |
| `haprion-cert-trigger` | unprivileged wrapper: validates the verb (`cert-pull`, `cert-remove`, `ca-pull` or `ca-remove`) and the IDs, then escalates |
| `haprion-cert-pull` | fetches the requested certificates, validates and installs them, and swaps them into the running HAProxy, without a reload where it can (below) |
| `haprion-cert-remove` | removes the requested certificates from `/etc/haproxy/certs`, refusing any the installed configuration still names; no reload |
| `haprion-node-status` | reports version, health, carried certificates, keepalived state and the address list |
| `haprion-keepalived-state` | records the keepalived transition to a state file |
| `haprion-state-export` | writes this node's permanent state to stdout as a gzipped tar |
| `haprion-health-probe` | opens one connection per named target and reports the status line |
| `haprion-traffic-log-read` | returns whole records from a validated UTC day and byte offset, capped at 8 MiB; `waf <cursor>` returns the WAF engine's journal lines after a journal cursor, same cap |
| `haprion-traffic-log-enable` | installs or removes this node's rsyslog route and retention timer |
| `haprion-traffic-log-prune` | deletes traffic days past the 14-day window, or the oldest over the space budget, whole and never renamed; prints the hour limit the rsyslog rule writes |
| `haprion-server-state-trigger` | unprivileged wrapper: validates `server-state <guid> <ready\|drain\|maint>` or `unblock <object> <address>...`, then escalates |
| `haprion-server-state` | sets one server's state on HAProxy's admin socket and keeps it across reloads; does the other scripts' reloads; swaps certificates and lifts blocks (below) |
| `haprion-node-key` | makes this node's accounts, its fetch keys and a one-time join key, and prints the enrollment line |
| `haprion-node-join` | run by the one-time key: joins the node to the manager that connected, then removes the key |

**How `haprion-cert-pull` swaps a certificate.** It replaces the certificates in the running
HAProxy through `haprion-server-state update-certs` (`set ssl cert`/`commit ssl cert` on the admin
socket). It reloads instead when HAProxy does not hold one of them yet, or refuses it. A run that
stops between installing and reloading leaves `/run/haprion-cert-pull.pending`, and the node's
status leaves those certificates out until the next run reloads.

**What the node attests.** Step 4 also writes `/etc/haprion/node-installation.json`, and the node
package writes it again on a joined node when `apt upgrade` replaces the scripts. It records the
node compatibility API and a SHA-256 digest of each script above except `haprion-node-key`,
`haprion-node-join` and `haprion-node-prepare` - thirteen scripts. Those three only join a node or
prepare it again by hand, so they are not part of what a node attests or what its state backup carries. `haprion-node-status` recomputes the
digests on every reading, so copied metadata cannot hide a script changed after installation. The
report contains code digests only, never node configuration or key material.

**Your own files in the state backup.** The state export carries the product's own files by name.
To include files that are yours rather than the product's - a local kernel option, a site drop-in -
list them in `EXTRA_BACKUP_PATHS` in the answers file. Step 4 renders that into `node.conf`.

- Use absolute paths, separated by spaces, with only letters, digits and `. _ @ + - /`. Step 4
  refuses anything else, because `node.conf` is read by root as a shell script.
- The export copies each path into the archive at its own path and lists them in
  `meta/extra-paths.txt`, so a restore can tell them apart.
- A listed path that does not exist on the node, or a directory that holds a socket, pipe or
  device, **fails that node's backup** rather than being skipped. The management host only shows
  an export's messages when it fails, and an archive that quietly lacks a file you asked for is
  exactly the drift a backup is there to rule out.
- The files of the archive must fit, with the packages a restore adds, in the 64 MiB one restore
  transfer carries (the files may take 40 MiB). The export **fails** past that, naming the largest
  files, because an archive that is taken and can never be restored is worse than none. List
  configuration, not data.

So every node that gets the answers file must have every listed path.

Some of the scripts deserve a closer look:

**`haprion-cert-trigger` exists because sudoers cannot express a list.** The certificate IDs arrive
as SSH command arguments, and no wildcard rule can safely constrain them. So they are validated
twice: unprivileged in the wrapper, and again in the root helper. The wrapper escalates with
`sudo -n` and an exact `NOPASSWD` rule, so a policy mismatch fails at once instead of falling back
to an interactive password prompt. The wrapper knows two verbs, `cert-pull` and `cert-remove`
([Deleting a certificate](#deleting-a-certificate)), each with its own root helper and its own
sudoers rule, and the same two for CA files, `ca-pull` and `ca-remove`, which call those helpers
with `--authority`.

**`haprion-health-probe` uses the same lowest TLS version as the configuration.** A pool's object
can name a backend TLS policy, which sets the lowest TLS version HAProxy accepts from the pool
([A pool over HTTPS](#a-pool-over-https)): `modern` is TLS 1.3, `intermediate` TLS 1.2 and `legacy`
TLS 1.1. A probe with a floor of its own would refuse a backend HAProxy accepts, and report a
healthy pool as down. So each target carries a `min_version` - `TLSv1.1`, `TLSv1.2` or `TLSv1.3` -
and the script refuses anything else. A target that names none means `TLSv1.2`, the same as a pool
whose object names no policy.

**`haprion-server-state` keeps a drain through reloads and restarts.** A state set over HAProxy's
runtime socket lasts only as long as the HAProxy worker process, and every deploy and certificate
rollout starts a new worker. So:

- The node keeps the wanted state of each server in `/var/lib/haprion/server-state.json` (`root`,
  `0600`).
- Each server is named by its GUID, derived from its address and port. Reordering a pool therefore
  moves nothing, and a server given a new address starts as ready.
- The file is carried in the node's state archive. A node restored to a new VM keeps its drains; a
  node restored over itself keeps its own, newer file.
- Every reload on the node goes through `haprion-server-state reload`. It reads the worker's
  process ID, reloads, waits for a worker with another ID, and sets the kept states on a
  connection whose `show info` proves which worker took them.
- A drop-in on `haproxy.service` runs `haprion-server-state reapply` once HAProxy is ready. It is
  prefixed `-`, so a state that cannot be set never keeps HAProxy from starting.

HAProxy's own `server-state-file` is not used: it carries a server's old port over to a changed
configuration (haproxy/haproxy#3296).

The same script replaces certificates HAProxy already holds without a reload (`update-certs`), and
lifts an object's dynamic block on addresses, from its blocked table and its count (`unblock`).

It needs a socket at level `admin` that only root can open - one line in the cluster's
`core/haproxy.cfg`:

```
    stats socket /run/haproxy/manager.sock mode 600 level admin
```

Step 4 writes the trigger account's key line for it from `SERVER_STATE_PUBKEY` in the answers
file. A line already there for the same forced command is replaced. A node without the key, or a
core without the socket, offers no server state, and refuses a request by naming the line that is
missing.

**`haprion-pull-deploy` is the same on every node except for its publication path.** Everything
else - validation, release creation, the atomic symlink swap, the rollback on failure - is
identical.

#### Node filesystem layout

```text
/etc/haproxy/current -> /etc/haproxy/releases/<timestamp>
/etc/haproxy/haproxy.cfg -> current/haproxy.cfg
/etc/haproxy/conf.d      -> current/conf.d
/etc/haproxy/maps        -> current/maps
/etc/haproxy/waf         -> current/waf
/etc/haproxy/dns         -> current/dns
/etc/haproxy/certs/          local certificate directory
/run/haprion-deploy.lock
```

Each deploy is a new directory under `releases/`. `current` points at the active one, and the fixed
paths that HAProxy, the WAF engine and dnsdist read all point through `current`.

A `haproxy.cfg` or `conf.d` of your own in `/etc/haproxy` would be loaded instead of every release.
So step 4 stops on one, and lists the `mv` command that moves each aside. A deploy refuses before it
changes anything when one of these paths is not the link.

**Who may read a release.** The releases directory and `/etc/haproxy/certs` are `root:root 0750`.
HAProxy, deployment, status and backup read the releases as root, so no forced-command account
needs to pass through. Files inside a release may stay `0644` without exposing the active
configuration to those accounts. There are two exceptions, each through an access-control entry
(ACL) for a group of its own with no members:

- the WAF engine, given the group `_haprion-waf` in a systemd drop-in;
- dnsdist, given the group `_haprion-dns` the same way.

Each may pass through the releases directory to its own files, but not list it.

**How a deploy changes the configuration.** A deploy never edits the running configuration:

1. It validates the candidate in a scratch copy: HAProxy's configuration, and the WAF rules, DNS
   listener, log forwarding and IPVS file where the release has them. An invalid candidate leaves the
   node untouched.
2. It builds a new release directory, which is never changed afterwards.
3. It swaps the `current` symlink in one atomic step.
4. It validates again, through exactly the paths `systemd` uses.
5. It brings the WAF engine and the DNS listener onto the new release, then reloads HAProxy.

If the second validation, the WAF engine, the DNS listener or the reload fails, the symlink is
swapped back. A failure after a successful reload - keepalived's address list or the log forwarding
not taking - is reported as a failure but not rolled back, because HAProxy already serves the right
configuration. The node remembers the failure and reports its release as incomplete, so the next
deploy treats it as behind and runs the steps again even though it carries the published version.
A node keeps its ten newest releases and removes older ones after a successful
deploy; the active and the previous release always stay.

**The traffic log's own filesystem.** The traffic log ([Traffic logs and metrics](#traffic-logs-and-metrics))
writes its day files under `/var/log/haprion`. Like the manager's mirror, it grows with visitors.
On a busy node, give it a filesystem of its own, mounted there, and make rsyslog wait for that
mount. Then a volume that comes up late does not let the files land on the root filesystem
underneath the mount point:

```text
# /etc/systemd/system/rsyslog.service.d/10-haprion-logs.conf
[Unit]
RequiresMountsFor=/var/log/haprion
```

The traffic log cannot fill its filesystem on its own. It may use at most a quarter of whichever
filesystem it is on. rsyslog stops each hour's file at a twenty-fourth of that share, so a flood
costs the rest of that hour's records, never the disk. Every hour, the retention removes the oldest
finished days while the files hold more than their share or less than a tenth of the filesystem is
free. Each dropped hour and each day removed early is a warning in the node's system log. A
filesystem of its own keeps the rest of the node out of reach of even that quarter.

*Details:* the node scripts keep their lock files directly in `/run`, which only root can write. In
the shared `/run/lock` (mode `1777`) any local account could create a lock file first, or hold its lock,
and every deploy would answer that another one is running.

#### Installing and changing node scripts

Only an administrator can install or change a node script, by design. Every management identity
is a forced command, and none of them can copy a file. So installing or changing a node script
always goes through an administrator's own interactive SSH login and `sudo` on the node.

The repository automates everything around that step. A node release is one Debian package,
`haprion-node` (`Architecture: all`). It holds the node scripts in `/usr/sbin`, owned by dpkg, and
`04-node-prepare` with the library it reads, under `/usr/share/haprion-node/install/`. Platform
installers, examples, caches and the source tree are not in it. The answers for an environment stay
a separate input owned by root: putting them in the package would make two installations of the
same commit produce different packages.

**Updating a node** is `apt upgrade` on it - the nodes that do not hold the VIP first, the holder
last:

```bash
haprion-status -c alpha                                  # on the manager: which node holds the VIP
sudo apt update && sudo apt upgrade                      # on that cluster's other node, then the holder
```

The dashboard shows which nodes an upgrade has not reached. Such a node says *Older node package* in its
*Runtime* cell, and pointing at it gives both versions. *Needs attention* lists it until it runs the
package the manager's release carries. `haprion-status` says the same on the node's `Node package:` line.

On a node that is already joined, the package replaces the node scripts and records their digests
again; it changes nothing else. It does not run `04-node-prepare`, the step that sets up what the
scripts need (accounts, sudo rules, the release layout, dnsdist, the log socket). When a release
changes that step, the upgrade says so:

```text
haprion-node: this release changes what the node's preparation sets up; run  sudo haprion-node-prepare
```

A node upgraded without anyone reading that line says it too: its status reports it, and the
dashboard's *Needs attention* lists the node with the same command until it has run. Then run it on
that node:

```bash
sudo haprion-node-prepare
```

It runs the step again with the answers the node was prepared with, read back from
`/etc/haprion/node.conf`. The manager's keys are bound again to the manager's addresses as they are now;
the keys themselves, the manager's host key and the traffic log's route are left as they are. It works the same for a node joined from the interface and one prepared by hand.
The installation from the manager, below, also runs the step, with a state backup on each side.

##### Build and verify the package

Start from a clean, committed source tree that has passed the complete repository gate. Build into
a protected staging directory outside the repository:

```bash
tools/node-package.py build \
  --source "$(pwd)" \
  --output-dir /path/to/protected/staging
```

The builder refuses a dirty tree, an existing output file, a missing payload file and an unexpected
Git file mode. It reads the files' bytes and modes from the commit rather than the working tree.
It then prints:

- the package's path;
- its version, `<version>+git<commit time>.<commit>`, so a later commit sorts later;
- the full commit;
- the SHA-256 digest.

Record the digest beside the package. Do not trust a digest that arrived together with an untrusted
copy.

The package is deterministic: building the same commit twice gives identical bytes. To verify a
kept or transferred copy:

```bash
tools/node-package.py verify \
  --package /path/to/protected/staging/haprion-node_0.1.0+git20261009120000.0123456789ab_all.deb \
  --sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Verification rejects:

- a digest that does not match the one you give;
- another package or architecture;
- a version this project does not build;
- a file that is not one of the node package's, or has another mode or owner;
- a package over its size limit.

##### Preflight and install one node

Just before an update, check which node holds the virtual address, and pick a node that does not:

```bash
haprion-status -c alpha
```

Run the install tool as your administrator account, never as root, with absolute paths
everywhere. Start with a dry run. It verifies the package locally, opens your normal SSH path (with
the host key checked), and checks the node's cluster and prerequisites. It writes neither a backup
nor a staging file:

```bash
tools/install-node-package --dry-run \
  --node-package /path/to/protected/staging/haprion-node_0.1.0+git20261009120000.0123456789ab_all.deb \
  --sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --answers /path/to/answers.env \
  --node node-b \
  --cluster alpha
```

Remove `--dry-run` to install.

**Other packages along with it.** `--package <deb> --package-sha256 <digest>`, repeated as often as
needed, installs further packages with the node package - the WAF engine, for example. Each
`--package` needs its own `--package-sha256`, in the same order. Only the project's own
`haprion-*` packages are accepted. They are verified here and again on the node, go through the
same session, backups and checks, and are installed in the same apt call, so all or none are
installed. They must be built for the node's architecture; the preflight compares that before
anything is written, so a dry run answers it too.

**Backups when rolling across a cluster.** The state backup (`haprion-state-backup -c <cluster>`
from the installed release) archives every node of the cluster. The rule is one backup before the
first write and one after the last, not one pair per node. So when one package goes to every node
of a cluster, give the first node `--skip-backup-after`, the last node `--skip-backup-before`, and
any node in between both. Another cluster's rollout gets its own pair of backups.

The tool:

1. verifies the external digest and the package's contents before contacting the node;
2. takes a state backup of the cluster before the first remote write;
3. uses one shared SSH session, with the host key strictly checked, for staging and installation;
4. copies only the package and the separate answers file to a random mode-700 directory under
   `/tmp`, then verifies the package digest again on the node;
5. installs the package with apt, without recommended packages, and runs its
   `/usr/share/haprion-node/install/04-node-prepare` through your interactive `sudo`. That step
   checks the package's files with `dpkg --verify` and stops on a script edited by hand;
6. takes another state backup and runs `haprion-status` for the cluster; and
7. removes its staging files on the node and locally. A cleanup failure is a visible warning that
   names the exact directory; inspect that directory, then remove only it.

The SSH login and the sudo password on the node are deliberately interactive. Because the session
is shared, each is asked for once per node, not once per file. The management identities stay
forced commands and gain no ability to copy files.

Stop after the first node. Read both the install report and `haprion-status`. A successful copy
proves bytes, modes and ownership, so also run the command that uses a changed script before you
continue. Check again which node holds the VIP before every further node - never assume it stayed
where the previous status reading found it.

**Turning the traffic log route on or off restarts rsyslog.** `haprion-traffic-log-enable` and its
`--disable` path restart rsyslog, because rsyslog does not load a changed rule on HUP. On a node
where step 4 installed `haprion-haproxy-log.socket`
([HAProxy and keepalived baseline](#haproxy-and-keepalived-baseline)), HAProxy's lines wait in that
socket during the restart, and none are lost. A node without that socket cannot buffer the lines:
a request during the sub-second restart can be missing from both the structured day file and the
classic log, and a successful restart cannot recover it. The command's last output line says which
case applied. On a node without the socket, run the command on the nodes that do not hold the VIP
first, check ownership again, and then run it on the owner.

##### Rollback

**Code.** Keep the previous node package and its recorded SHA-256. To roll back, run the same
verified installation command with that kept package and `--downgrade`, which lets apt put the
older version in place. Without `--downgrade` apt refuses, so the wrong file never rolls a node back
by accident. There is no special path that skips the digest or contents checks. Run the command
that uses the script and `haprion-status` again afterwards.

**State.** State backups are taken on both sides of every update, so changes to accounts, policy and
configuration also have a recovery point. They are not restored automatically: restoring a whole
node after a partial failure could overwrite unrelated state that changed in the meantime. On a
failure, stop. Keep the reported backup, note any cleanup warning, and work out which of the
reported operations completed before you restore state.

**Optional features** have their own rollback. For traffic logging:

1. turn off the node route with `sudo haprion-traffic-log-enable --disable`;
2. remove that collector key's forced-command line from `_haprion-logread`'s `authorized_keys`;
3. remove `TRAFFIC_LOG_PUBKEY` from the node's answers file - otherwise the next run of step 4
   writes the key again and turns the route back on;
4. disable the collector on the manager.

Traffic files are deliberately kept: a rollback never deletes evidence.

### Part 3 — the versioned CLI release

The management CLI is installed apart from the application's data filesystem. A release lives
under `/opt/haprion`, so recovery and diagnostics stay available even when application storage is
not.

The application code is installed from a wheel (a Python package file), through the `haprion-cli`
package. It is never run from a checkout, an editable environment, a developer's virtual
environment or any other development path.

#### The `haprion-cli` package

This is how the CLI is installed and updated: `sudo apt install haprion-cli` from the project's
repository (`haprion-ui` depends on it), or the package file from a release. The package carries:

- the wheel;
- the node package of the same commit;
- the WAF engine and repository key packages;
- the release installer;
- the operators' sudo rules.

Its `postinst` runs the installer described below. To build the package yourself, run the complete
repository gate first. Then build it from the clean commit, with the `uv` the repository is locked
with and the engine and key packages built by `tools/build-coraza-package.py` and
`tools/build-keyring-package.py`:

```bash
tools/build-cli-package.py --source "$(pwd)" --output-dir /path/to/protected/staging --uv /path/to/uv \
    --waf-engine-package /path/to/protected/staging/haprion-coraza-spoa_0.9.0-7_amd64.deb \
    --keyring-package /path/to/protected/staging/haprion-archive-keyring_2026.10.17_all.deb
sudo apt-get install /path/to/protected/staging/haprion-cli_0.1.0+git20261009120000.0123456789ab_all.deb
```

The same commit gives the same bytes. The package installs:

| Path | What |
|---|---|
| `/usr/lib/haprion/cli/` | the wheel, the node package, the WAF engine and repository key packages, `install-release.py` and `PAYLOAD` with their digests |
| `/usr/bin/haprion-*` | one line per operator command, into `/opt/haprion/current/bin` |
| `/etc/sudoers.d/haprion` | the operators' sudo rules, checked with `visudo` when the package is built (below) |

The operators' rules let `%sudo` run each read helper without a password and each write helper
with one. They never name `%haprion`, which holds the worker.

`apt-get purge haprion-cli` also removes `/opt/haprion`; `remove` leaves the releases.

#### The release installer

`install-release.py` puts a CLI release in place under `/opt/haprion`. The package's `postinst`
runs it with the wheel and the three packages it carries - the node package, the WAF engine
package and the repository key package - each with its digest. On an installation that already has
clusters (a runtime policy at `/etc/haprion/runtime-policy.yaml`), `postinst` then runs
`haprion-node pull-keys`, which binds each node's fetch keys to its cluster and addresses. If that
step cannot finish, it warns and leaves the package installed: every node still fetches as before,
and `sudo haprion-node pull-keys` can be run again.

The installer can also be run by hand, which is what installing without the package means. Build
the wheel into a protected staging directory outside the repository and record its SHA-256 digest:

```bash
python -m build --wheel --outdir /path/to/protected/staging
sha256sum /path/to/protected/staging/haprion-*.whl
```

Build the node package from the same commit, as in
[Installing and changing node scripts](#installing-and-changing-node-scripts), and record its
digest too. The release carries it: a node restore installs exactly the package of the release that
runs it, and rolling back the CLI takes the package back with it.

Install with the absolute wheel and package paths and the digests printed by the previous
commands:

```bash
sudo /usr/bin/python3 tools/install-release.py \
  --wheel /path/to/protected/staging/haprion-0.1.0-py3-none-any.whl \
  --sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --node-package /path/to/protected/staging/haprion-node_0.1.0+git20261009120000.0123456789ab_all.deb \
  --node-package-sha256 fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
```

**The packages a release carries.** Three package arguments come in pairs, a path and its digest,
and each pair is optional:

| Arguments | Package | Copied into the release as |
|---|---|---|
| `--node-package`, `--node-package-sha256` | the node package (`tools/node-package.py build`) | `haprion-node.deb` |
| `--waf-engine-package`, `--waf-engine-package-sha256` | the WAF engine (`tools/build-coraza-package.py`) | `haprion-coraza-spoa.deb` |
| `--keyring-package`, `--keyring-package-sha256` | the repository key (`tools/build-keyring-package.py`) | `haprion-archive-keyring.deb` |

A node restore installs the packages its release carries. Each one is verified by the new
release's own verifier before anything is activated, copied into the release, and recorded in
`INSTALLATION.json` - the node package with its version, commit and digest.

They are optional so that a wheel installed without them stays installable for rollback. A release
without a node package refuses to restore a node and says why. A release is never changed in place:
installing an already installed wheel with other packages, or without the ones it has, is refused.

**What the installer checks.** It stops unless it runs as root and the digest you gave matches. It
rejects unsafe wheel contents and entry points. It checks the runtime baseline - Python 3.13 or
newer and the distribution's PyYAML 6, PyNaCl 1 and psycopg 3 packages - and that the code imports.
Then it installs:

```text
/opt/haprion/
├── current -> releases/<version>-<wheel-hash-prefix>
└── releases/
    └── <version>-<wheel-hash-prefix>/
        ├── INSTALLATION.json
        ├── haprion-node.deb
        ├── haprion-coraza-spoa.deb
        ├── haprion-archive-keyring.deb
        ├── bin/
        └── lib/
```

Release directories are `root:root`. Directories and launchers are mode `555`, other files mode
`444`. The `current` link is replaced in one atomic step, and only after the new release passes
validation. After that, the installer keeps the ten newest releases and removes older ones
(`--keep` changes the number, at least two); the new release and the one it replaced always stay.

Short stable wrappers and exact sudoers rules may point into `current/bin`. They must never point
into a source checkout.

**`current/bin` is not on `sudo`'s path.** `sudo` resets `PATH` to its `secure_path`, which does
not include `/opt/haprion/current/bin`. So the `haprion-cli` package (above) installs one line per
operator command in `/usr/bin`, of the shape

```bash
#!/bin/sh
exec /opt/haprion/current/bin/haprion-cert-receiver "$@"
```

A release switch therefore moves every command at once, and nothing points at a release directory
by name. Root helpers get no such line: a helper is run by the program that calls it, through its
exact sudo rule, and never typed. Without the package, the full path works the same:
`sudo /opt/haprion/current/bin/haprion-cert-receiver ...`.

`INSTALLATION.json` also records the engine compatibility API carried by the wheel. The
whole-installation check compares it with what the UI needs.

#### Order of operations

Install the release **before** adding runtime-policy fields that a new release introduces. The
policy reader rejects unknown fields, so the reverse order breaks every command that reads the
policy, not only the new one.

### Part 4 — the web platform

The web platform is optional, and kept separate on purpose. The command line is the authoritative
engine: it installs and runs without any of this, and a management host that only ever uses the CLI
never needs the platform. `haprion-setup` installs it
([installation guide](install.md#2-install-the-manager)), and
[`../install/platform/`](../install/platform/) describes each step. This section explains how the
pieces fit together.

#### What is installed where

```text
/opt/haprion-ui/
├── current -> releases/<version>-<commit>/
├── releases/<version>-<commit>/venv/
└── releases/<version>-<commit>/migration/
/etc/haprion/
├── ui.toml          root-owned, readable by the platform group
├── ui-secrets/      root-only, granted one file at a time
├── dns-profile-keys/, oidc-keys/   public keys, readable by the platform group
└── ui-admin.conf    the database and role the root commands use
/var/lib/haprion-ui/
├── dumps/           database backups, root-only
└── logs/            the traffic-log mirror
```

Configuration, secrets and data live **outside** the releases, each where Debian puts its kind. A
release is replaced as a whole, and rolled back by pointing `current` elsewhere, so anything that
must survive that cannot live inside it. The places are fixed, not answers in the answers file -
the same as the account names.

A release is a commit. The `haprion-ui` package is built from one commit, in a container of the
target distribution, at the release's final path and against that distribution's Python. Two
reasons: a virtual environment cannot be moved to another path, and a Python under someone's home
directory is invisible to a service that runs with `ProtectHome`. Both are checked again before
`current` is switched. The package carries the release as an archive whose digest `postinst`
checks before unpacking it, and two builds of one commit give the same bytes.

#### Identities

The platform runs three services - web, worker and poller - each under its own service account
with its own database role. One shared account would make a break-in through the web equal to
worker access, and the worker has deploy rights. Two optional steps add more accounts: the traffic
collector ([Mirroring node traffic logs](#mirroring-node-traffic-logs)) and the sign-in helper's
account (step 17).

The three share one group, `_haprion-ui`. The group grants reading only: the configuration file
`ui.toml`, the installed UI release, and the public keys beside `ui.toml` (`dns-profile-keys/`,
`oidc-keys/`). Nothing more.

Nothing signs in to the database with a password. Connections use the local socket with peer
authentication: the kernel tells PostgreSQL which operating-system user is on the other end, and
each account is named after its role. So there is no password to leak, rotate, or find in a
process listing.

#### The database

**No service can change the database's structure.** The migration role owns every table and has
no operating-system account. A service process therefore cannot run DDL (create, alter or drop
tables) - not because a grant forbids it, which somebody could add later, but because you cannot
drop a table you do not own. Running a migration is a deliberate root action, mapped explicitly in
`pg_ident.conf`.

**Grants are per column and live with the table.** The grants for a table are in the migration that
creates it - the baseline, `0100`, for every table there is today - so a column's permissions are
versioned with the column. They name contract roles -
`app_web`, `app_worker`, `app_poller`, `app_collector` - never an account; the installation
connects the accounts to those roles. Columns are listed one at a time, because a grant written for
a whole table widens itself the next time somebody adds a column.

**The web role may only ask for work.** It may insert four columns of the job table: the operation,
the cluster, the payload and an idempotency key (which lets a refresh or a double-click be
recognised as the same request). State, request ID and timestamps come from column defaults.
The only columns it may update are the answer to a held job - **Run** or **Discard**, and who
gave it ([After restoring the database or the host](#after-restoring-the-database-or-the-host-waiting-jobs-and-sessions)).
Apart from that answer, a queued job cannot be changed by the role that queued it, so there is no
path from "I asked for this" to "this is what happened".

**The poller only removes rows it derived itself.** It writes cached readings. It holds `delete`
on three tables only, each of which it rebuilds from its own readings:

- `search_entry`, the search index. Each reading is turned into the values the header's search
  looks for, and the poller replaces that reading's rows in one transaction. The web only reads
  them.
- `node_event_state`, the last state of each server, node and VIP that a new status reading is
  compared with to record node events.
- `package_waiting`, one row per manager package with a newer version waiting in the repository.

##### Where the data lives

**Give everything that grows with traffic a filesystem of its own, and keep the root filesystem out
of its reach.** Three things grow with the nodes' visitors rather than with anything the
administrator does:

- the database (its traffic-log and WAF-log tables);
- the database dumps;
- the mirror of the nodes' traffic logs.

A full root filesystem stops far more than Haprion - journald, apt, logins. So a busy week must
fill a volume that was sized for it, not `/`. The reference host has a separate volume mounted at
`/apps` for exactly this. Everything that grows lives on it, each under the path the package
expects, through a bind mount (a second view of a directory at another path), as below. The
platform's `/var/lib/haprion-ui` (dumps and the mirror) belongs on the same volume, mounted the same
way:

```text
# /etc/fstab
/apps/haprion-ui  /var/lib/haprion-ui  none  bind,x-systemd.requires-mounts-for=/apps  0 0
```

The units that write there wait for that mount (`RequiresMountsFor`), so a volume that comes up
late does not leave a dump on the root filesystem underneath it.

Put the PostgreSQL cluster's storage on that volume too, and keep the package's path. On the
reference host, `/var/lib/postgresql` is a bind mount onto a directory on the `/apps` volume - not
a cluster reconfigured with a different `data_directory`:

```text
# /etc/fstab
/apps/postgresql  /var/lib/postgresql  none  bind,x-systemd.requires-mounts-for=/apps  0 0

# /etc/systemd/system/postgresql@.service.d/10-apps-mount.conf
[Unit]
RequiresMountsFor=/var/lib/postgresql
```

The directory behind the mount is owned by `postgres` (`755`), because a bind mount shows the
target's top level as the mount point. The drop-in is what makes this safe rather than merely
working. Without it, a boot on which the volume comes up late would start PostgreSQL on an empty
directory, and it would run - freshly initialised, with no databases - until somebody noticed.

Two reasons sit behind this layout:

- The traffic-log table ([Mirroring node traffic logs](#mirroring-node-traffic-logs)) is the one
  part of the installation whose growth is set by the nodes' visitors rather than by the
  administrator. It belongs on the volume given room for exactly that, next to the dumps and the
  mirror, so the root filesystem stays predictable.
- The path stays the package's. A cluster at its own path turns every distribution upgrade into a
  special case for years, while a mount point leaves `pg_upgradecluster` and the package tools
  looking at the layout they expect.

The price is one ordering condition, proved once at installation:

```bash
findmnt /var/lib/postgresql        # SOURCE must name the platform volume
sudo systemctl restart postgresql  # and the cluster must come back on it
```

**Moving an existing cluster:** take a verified dump first
([Backups, and proving they restore](#backups-and-proving-they-restore)). Then stop PostgreSQL,
copy with `rsync -aHAX --numeric-ids`, run a second dry run that finds nothing left to copy, add the
mount, and start. Keep the old tree beside the mount until the new one has served for a day. The
backup step's 85 % disk warning watches the filesystem that holds the dumps, which is now also the
one that holds the database.

#### Verifying it

`install/platform/03-verify` is read-only and can be run at any time. It holds a **second, separate
description** of what each role may and may not do, compares it with what the running database
reports, and checks both directions.

Both directions matter more than it sounds. A check that only asks what a role must *not* do passes
completely when a role has no privileges at all - a broken system that reads as a perfectly secured
one. So it also asks what must work.

`install/platform/check-compatibility` is the read-only check one level up: do the separately
released pieces fit together? Run it after they have been installed:

```bash
sudo ./check-compatibility
```

The running UI release supplies the database revisions it accepts and the oldest CLI and node APIs
it works with. A revision past them passes when a release on the machine declares its migrations safe
for the running one, the same rule `haprion-rollback` decides by. The command:

- reports both release IDs;
- reads the database's revision from `alembic_version`;
- checks that worker, poller and web really run from `current`;
- compares the active sudo rules with the helpers the UI requires;
- reads each node's installation through the existing status helper.

It ends with one verdict, `COMPATIBLE` or `INCOMPATIBLE`, and changes no file, row, service or
HAProxy release.

**The order for an update, step by step:**

1. Run `install-ui-release --prepare <release-id>` on the release the package unpacked. The
   candidate is verified, but `current` stays on the old release.
2. Run `check-compatibility --release <release-id> --before-migration` to prove its CLI, helper and
   node requirements.
3. When the candidate's schema head differs from the database's, run
   `haprion-backup dump-before-migration <from> <to>`. That dump goes to `before-migration/` under
   the dump directory, named by both revisions and the moment. The newest three are kept, and the
   daily dumps' retention neither counts nor removes them.
4. Run `migrate --release <release-id>`, then `03-verify`, then the candidate check again without
   `--before-migration`.
5. Only when those pass, activate the same prepared release by running `install-ui-release` again
   without `--prepare`.
6. A final ordinary compatibility check proves the processes after the switch.

`update-platform-release` does that whole order for a normal update. The package's `postinst` runs
it when a newer `haprion-ui` is installed over a running platform:

```bash
sudo ./update-platform-release <release-id>
```

The CLI and the node scripts stay separate installations. The command checks them and stops before
the migration when either is too old.

**The schema starts at a baseline.** Haprion 0.99 has one migration, `0100`, which makes the whole
schema. A database from an earlier release is not migrated: the check refuses it before anything
runs, and Haprion is installed afresh ([Removing](install.md#removing)). A schema is never taken
back either. No migration has a downgrade, and `migrate downgrade` is refused; the way back from an
update is [Rolling a release back](#rolling-a-release-back) or the dump taken before it.

**The old UI must keep working on the new database.** The command also requires that the currently
running UI keeps working on the candidate's database schema - while the migration runs under it,
and afterwards as the rollback target. Every migration after the baseline says whether it is safe
in that sense:

```python
ROLLBACK_SAFE = True
ROLLBACK_SAFE_BECAUSE = "adds a table nothing older reads; no column is changed"
```

The release's metadata names the oldest revision from which every later migration is declared safe
(`rollback_safe_from`). The check accepts a running UI whose own schema is at or after it.

- A migration that changes what older code reads - a column dropped or renamed, a constraint older
  code would break - says `ROLLBACK_SAFE = False`. Then ship first a bridge UI release whose
  compatibility metadata accepts both revisions, and the migration release after it.
- A migration that takes away something only UIs older than some revision still read names that
  revision as its floor, for example `ROLLBACK_SAFE_FROM = "0072"`. It is safe for a UI at the
  floor or after it, and `rollback_safe_from` is raised to the floor.

The repository's tests refuse a new migration without the declaration, and metadata that disagrees
with the migrations. A failure after activation runs the installed UI rollback command and checks
the restored processes before returning failure.

#### HTTPS and the certificate

`install/platform/05-platform-nginx` puts nginx in front of the web service and terminates HTTPS
there. The web service itself listens only on the Unix socket `/run/haprion-web.sock`, in plain
HTTP. systemd holds that socket (`haprion-web.socket`), and only root and nginx's workers may open
it - the socket admits the group `www-data`, so step 5 requires nginx's workers to run as
`www-data`. The plain leg is deliberate: it never leaves the host. A request that arrives while the
web service restarts waits in the socket for the new process.

The rendered site also includes `/etc/nginx/snippets/haprion-receivers.conf`. Step 5 creates it
empty, and afterwards only `haprion-cert-receiver` writes it
([Registering a receiver](#registering-a-receiver)). Running the step again leaves an existing
snippet alone.

**This is the direct address, and it does not go through the HAProxy cluster.** That is the whole
point. The UI is the tool used to repair the cluster, so putting the UI behind it means a broken
publish locks you out of the only thing that could revert it. A reverse proxy elsewhere - from
another nginx to Nginx Proxy Manager on a container host - may be added in front as an *additional*
path, with its own certificate. It must never become the only path.

**The certificate is what a browser meets at login**, not something internal. At installation it
is self-signed, unless a pair already exists at the configured paths. Later it can come from the
certificate registry - an entry marked `interface: true`, issued over ACME or NDES or imported -
or from your own PKI through `haprion-tls install`
([The interface certificate](#the-interface-certificate)). ACME can only validate a name in a public
domain, so for a management host named on an internal domain use NDES, a certificate from your own
PKI, or the self-signed one.

Four answers-file keys control it:

| Key | Meaning |
|---|---|
| `SERVER_NAME` | the name the UI is reached on directly; must resolve to this host. Defaults to `hostname -f` |
| `TLS_CERT` | defaults to `/etc/haprion/tls/ui.crt` |
| `TLS_KEY` | defaults to `/etc/haprion/tls/ui.key` |
| `TRUSTED_PROXIES` | addresses or networks of a reverse proxy in front, space-separated; empty by default. See [Behind another reverse proxy](#behind-another-reverse-proxy) |

If no pair exists at those paths, step 5 generates a self-signed one, so the UI is encrypted from
the first login. Point the keys at a pair your clients already trust, and that generation never
runs.

**Plain HTTP is not a lesser option here; it does not work.** The session cookie is `Secure`, and
a browser never sends a `Secure` cookie over HTTP, so login simply stops working. Removing `Secure`
to get around that would send the session of a tool with deploy rights in clear text over the
network. A self-signed certificate gives a browser warning but real encryption - the better trade
while a proper certificate is being arranged.

*Details:* step 5 writes the three values `haprion-tls` reads - `TLS_CERT`, `TLS_KEY` and
`SERVER_NAME` - to `/etc/haprion/ui-tls.conf`.

##### Behind another reverse proxy

A proxy in front - another nginx, Nginx Proxy Manager, a load balancer - is an additional path; the
direct one stays. Unless it is told about the proxy, the management host knows every user by the
proxy's address, and three things go wrong:

- The sign-in throttle (`[throttle]` in `ui.toml`, failed sign-ins per address) is shared by
  everyone, so one person, or an attacker, locks every user out. The audit log names the proxy for
  every action.
- A certificate receiver's `/certdist/<receiver>/` location allows only the receiver's address, so
  a receiver fetching through the proxy is refused. Naming the proxy there instead would open
  certificates, and sometimes keys, to everyone who can reach the proxy.
- The sign-in provider (SSO) sends the browser back to the name the request arrived with.

**Name the proxy** in the answers file and run step 5 again:

```bash
TRUSTED_PROXIES="192.0.2.10"        # one or more addresses or networks, space-separated
sudo ./05-platform-nginx answers.env
```

Step 5 writes `/etc/nginx/snippets/haprion-real-ip.conf` on every run - `set_real_ip_from` per
entry, `real_ip_header X-Forwarded-For` and `real_ip_recursive on` - and the site includes it. From
then on:

- nginx believes `X-Forwarded-For` only on connections from those addresses.
- It takes the client to be the last address in the header that is not one of the proxies. A value
  a client wrote into the header before it reached the proxy is skipped.
- A client that reaches the manager directly and sends the header is still known by its own
  address.

Throttle, audit log, receivers' `allow` and the access log then all see the real client. Host names
and "every address" (`0.0.0.0/0`, `::/0`) are refused. To stop believing the proxy, empty the key
and run step 5 again.

**What the proxy must do:**

- **Use the manager's `SERVER_NAME`** as the name users reach it by, and send that name upstream as
  `Host`. The management host picks its site by that name, and the SSO provider sends the browser
  back to it. A different public name is not supported.
- **Forward to `https://<manager>:443`.** The application itself listens on a local socket only.
- **Append to `X-Forwarded-For`** rather than replace it. Other forwarded headers are optional -
  the manager's nginx sets its own.
- Leave receivers fetching directly where they can. Through the proxy they work too, once it is
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

In Nginx Proxy Manager, the same thing is a proxy host for the manager's name with scheme `https`,
the manager's address and port 443, and `client_max_body_size 1m;` in its advanced field. Check in
its generated configuration that `Host` is passed unchanged and `X-Forwarded-For` is appended.

#### First administrator

There is no default password and no first-run setup page. Both would be holes for the whole life
of an installation, only to be useful for its first thirty seconds. A shipped password survives in
the field, and an unauthenticated page that creates an administrator is exactly what it sounds
like.

So the installation itself makes the first account, on the terminal of whoever installs it:

- `haprion-setup` asks for it last, when everything else is done. `install-ui-release`, run on its
  own, asks when it activates a release.
- On an installation with **no account at all**, they run `haprion-user init-admin`. It creates
  `admin` as a break-glass admin and asks for its password twice, as `add` does. The password is
  never printed and is stored only as a hash.
- Every later release finds accounts, does nothing and asks nothing.
- Without a terminal - the installer run with its input redirected - no account is made, and the
  installer says to run `init-admin` by hand.

Nothing about the first account is the same on two installations, and nothing answers on the
network before it exists.

For account administration and password recovery, see
[Accounts and signing in](#accounts-and-signing-in).

#### Platform backup installation

`install/platform/06-platform-backup` installs a daily dump timer and a weekly restore check for
`haprion-backup`, which comes with the `haprion-ui` package. Then it takes a dump and restores it at once: the moment to discover that a backup does not
work is during installation, not during an incident.

For manual dumps, restore checks and recovery, see
[Backups, and proving they restore](#backups-and-proving-they-restore).

#### Retention installation

`install/platform/11-platform-retention` installs a daily timer for `haprion-retention` (which comes with
the `haprion-ui` package) and the hourly space budget for the traffic and WAF partitions. It is part of every installation, because creating
the coming days' partitions is its work too. It is a separate step from the backup because it is the
only part of the platform that deletes recorded history from live tables (the poller only replaces
rows it derived itself). **The step itself deletes nothing.** It reports what the first run would
remove and leaves the deciding to the timer or to an operator.

For reports, pruning and retention rules, see
[Keeping jobs, sessions and metric history bounded](#keeping-jobs-sessions-and-metric-history-bounded).

#### Mirroring node traffic logs

`install/platform/13-platform-traffic-collector` lets the manager collect each node's traffic log.
It installs a fourth, deliberately small identity - the collector - and a timer that asks each node
for its own traffic log. The step is optional and runs after the others: nothing else on the
platform depends on it.

```text
/var/lib/haprion-ui/logs/mirror     collector writes freshness metadata, the interface reads
/var/lib/haprion-ui/logs/staging    the collector's alone
/etc/haprion/traffic-collector/{id_ed25519,known_hosts}
/etc/haprion/traffic-collector.json
```

The collector program is installed with the CLI engine under `/opt/haprion/current`, not inside the
web release. This is a privilege boundary, not a packaging detail. Web releases can be entered only
by the platform group, and the collector deliberately is not in that group, so it cannot read
`ui.toml`. The engine release is owned by root, never changed in place, and can be run without
access to the platform configuration.

**The manager fetches the logs; nodes never send them.** Nothing here needs a new network path in
any topology. A node in a DMZ typically cannot open a connection to the management host, but the
management host already reaches every node over SSH for configuration, certificates and status. The
collector adds one key to that path. An installation whose firewall differs still needs nothing
new.

**A fourth account, with one narrow way into the database.** The collector is not a member of the
configuration group and has no sudoers rule. Its `app_collector` contract role can only insert
traffic rows and WAF match rows. It cannot select, update or delete them. It owns one SSH key, and
on the node that key runs one forced command, which can return only:

- one node's traffic log, from a validated day and byte offset; or
- the WAF engine's journal on that node, after a journal cursor.

The step checks that boundary rather than describing it. It checks by actually passing through
each directory, because `ls` on a directory fails whether or not an account can pass through it,
so a listing proves nothing.

**Host keys are copied from what this host already trusts, never scanned.** `ssh-keyscan` asks a
node who it is and believes the answer. If a node has no pinned key yet, the step refuses and says
so. Accept that key deliberately, once, through the path that already exists.

**The dumps beside the mirror are closed by their own mode.** The web account passes through
`/var/lib/haprion-ui` to reach the mirror. `dumps/` there holds every session and every audit
record in one file, so it is `0700 root`, and the step proves neither the web account nor the
collector can enter it. The mirror directory is set-group-id (new files take the directory's
group), because the collector is deliberately outside the web account's group and could not
otherwise create a file the interface can read.

**The traffic log is on from the start.** Nothing is done by hand:

- The step adds `[traffic_logs]` to `ui.toml` when it has none. A table that is already there,
  `enabled = false` included, is left alone.
- A cluster made by *Create cluster* logs this way from its first publish.
- A node joined from the interface is given the collector's key and turns its own route on.
- A node prepared by hand gets the key from its answers file - the step prints the
  `TRAFFIC_LOG_PUBKEY=` line - and step 4 writes it and turns the route on.

Turning a node's route on or off restarts rsyslog; a reload does not apply the rule. On a node with
the `haprion-haproxy-log.socket` that step 4 installs, HAProxy's log lines wait in that socket
during the restart and none are lost. On a node without it, HAProxy cannot buffer its lines, and a
request during the brief restart can be missing from both the structured and the classic local
log. On such a node, change the nodes that do not hold the VIP first, verify them, check VIP
ownership again, and only then change the owner.

**A cluster that has logging turned off.** A cluster defined before the collector was installed has
`traffic_logging: false` in its entry in `clusters.yaml`. Set it to `true`, then publish a real
object change so the generator's log profile reaches the nodes. Adding or removing a node from the
interface keeps the collector's node list up to date. A node added to `clusters.yaml` by hand needs
platform step 13 again, and `check-compatibility` refuses a running traffic-log view while the
collector's installed node list differs.

**Query strings.** Only the structured log stream removes query strings, and only that stream is
mirrored to the manager and shown in the interface. HAProxy's ordinary `haproxy.log` on the node is
unchanged, and its traditional HTTP log line holds the complete request target, query string
included. Treat that local file accordingly when choosing retention, backup and access controls.

**How the collector imports.** It loads complete records with PostgreSQL `COPY` and moves its local
checkpoint forward only after the database transaction commits. Repeating a batch is safe, because
each record has a fixed identity. Once `[traffic_logs]` is enabled in `ui.toml`, the interface
reads indexed database rows; the mirror metadata still reports how fresh the collection is.

A record the database cannot hold is skipped and counted in the run's output, and the import goes on
past it: text that is not valid UTF-8 (a lone surrogate), a NUL, a field past its length, a request
number beyond a 64-bit integer. A day file that fails to import stops that node's import only; the
nodes after it are imported as usual, and the failed node shows `database` in the log warning and
under Needs attention instead of `ok`. A local account on a node can write a line under the traffic
log's tag, so one node's log is not trusted beyond that node.

Successful contact does not mean the log is caught up. The log warning shows whether today's file
is incomplete, the bytes remaining at the last read, and older days still pending. The remaining
byte count is an observation, not a prediction of how much new traffic arrived afterwards. Each run:

- reads today in 8 MiB blocks until it is current, then the older days, oldest first;
- spends up to thirty seconds per node, with each block inside the 30-second SSH timeout;
- reads at least one block of today and one of the oldest open day, so both make progress even
  while today's file grows.

The transfer cap per response stays the same.

With the database configured, the collector keeps the day files in staging and one metadata file
per node in the mirror directory. It does not join the days into one log file per node: nothing
reads that file, and writing it would rewrite the whole kept history once a minute. A joined file
left from a configuration without the database is removed on the next run.

**How long the database keeps traffic.** `retention_days` defaults to seven (range 1–90). The
retention timer, which runs with privileges, creates daily partitions ahead of time and removes
expired data by dropping whole partitions. The application accounts can neither create nor drop
partitions, and none of them can delete traffic rows. PostgreSQL's `pg_trgm` extension is installed
once by platform step 2, so substring searches on host, path and backend use per-day GIN indexes.

**The manager's mirror follows that setting rather than keeping a window of its own.** Each run
keeps the days the database still holds, plus one more as the margin it would replay from after a
restore, and lets the rest go. Nothing is configured twice: a mirrored day the database has no
partition for can be neither read in the interface nor imported, so keeping it would cost disk on
the mirror's volume and buy nothing. A run that cannot reach the database keeps the wider fallback
window instead of pruning. Fetching is the part that cannot be caught up later, because each node
drops its own day files on its own schedule.

**The nodes keep fourteen days regardless.** Those cost the node's disk rather than the manager's,
and they are what makes raising `retention_days` a setting rather than a hole in the history.

**The page never asks a node anything**, so an unreachable node cannot make it slow - it can only
make that node's mirror old. The page therefore names every node and how old its mirror is
**before** the records, because a node that stopped answering renders an empty table that would
otherwise look calm. Log text is written by whoever made the request, and is shown escaped as text,
never as markup.

##### Sizing the traffic table

**Plan on 480 bytes per record, indexes included.** At the default seven days, that is about
**3.4 GB of database per million records a day**. The numbers below were measured, not estimated.

How they were measured:

- A throwaway PostgreSQL cluster with stock settings (`shared_buffers` 128 MB) on two CPUs, the
  reference size, with the real migrations.
- Fabricated traffic of realistic shape: two clusters in one time-ordered stream - a large one
  (twenty hostnames, ten proxies) and a small one with a thousandth of its requests (three
  hostnames, two proxies). Three hundred paths, weighted methods and status codes, 0.1 % 5xx, and
  0.7 % that met an access rule or the WAF engine.
- The traffic log page and the WAF page read through their own queries, as the web role and under
  its five-second statement limit, in 22 filter combinations: no filter; each cluster; status class
  and code; one word, two words, a rare word, a word nothing matches, `not` and `or`; an object;
  the WAF's requests; and time windows.

| Retention | Rows | Table | Indexes | Per row | Slowest page query | Most queries |
|---|---|---|---|---|---|---|
| 7 days × 2 M a day | 13.6 M | 3 314 MiB | 2 791 MiB | 471 B | 0.21 s (`a or b`, both rare) | under 15 ms |
| 90 days × 300 000 a day | 27 M | 6 574 MiB | 4 373 MiB | 426 B | 0.48 s (`a or b`, both rare) | under 60 ms |

The seven-day row was loaded through the indexes, the way the collector writes. The ninety-day row
had its search indexes built afterwards, which packs them tighter, so its per-row figure is low.
The host's page cache was larger than a 4 GiB manager's, so a first reading after a restart can
take longer than the table shows.

Every page query answered well inside the web's limit. The collector's write path - the same
`COPY`, with every index in place - sustained about 40 000 records per second into the full
seven-day table, and a run imports a minute's worth of traffic.

So the disk a retention window needs is `records per day × retention_days × 480 bytes`, plus the
collector's day files in staging for the same days (and one more, the replay margin), plus WAL
(PostgreSQL's write-ahead log). A cluster serving ten thousand requests a day uses tens of
megabytes. An installation nearing a million a day should have that volume sized for it, and heed
the 85 % backup warning ([What the dump does](#what-the-dump-does)). This is the number that grows
without the administrator's say-so, which is why the database sits on the platform volume
([The database](#the-database)) rather than on the root filesystem.

#### The worker and the poller

`install/platform/07-platform-services` installs both, each as its own operating-system account.
That separation is what makes the interface safe at all: a single application user would have made
a break-in through the web equal to deploy rights.

| Identity | May | May not |
|---|---|---|
| web | authenticate, audit, queue a strictly validated job | no sudo rule, no management group, no key, cannot claim a job |
| worker | call the engine's exact helpers, claim and complete jobs | read key files, run DDL |
| poller | run exact read-only metadata helpers, write the caches the pages read | read private trees directly, write a job, call any write operation |

**Memory.** Each service that reads what a node or a visitor sends has a memory limit, set from
what it was measured to use, with room above:

| Service | Limit |
|---|---|
| web, worker | 768 MB |
| poller, traffic collector | 512 MB |
| node restore helper | 512 MB |
| every other helper | 256 MB |

The worker's limit covers the root helpers sudo starts inside it. A service that passes its limit
is stopped rather than swapped, and web, worker and poller start again. A candidate's checks run in
units of their own: HAProxy's and dnsdist's in 256 MB; the WAF engine's in 128 MB plus 6 MB for
each object with `waf` - never less than 256 MB, at most half the manager's memory.

##### The poller

The poller keeps the status, inventory and other readings the pages show. It never reaches a node
itself. The engine's configuration, the status account's key and the published release tree are
all out of this account's reach by design. So the poller runs the same privileged helpers the
command line runs, through exact sudoers rules:

```
<poller> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-status-helper ""
<poller> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-inventory-helper ""
<poller> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-readings-helper ""
<poller> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-cluster-list-helper ""
```

Status and inventory reach the nodes. `haprion-readings-helper` answers, in one call, the six
readings that touch only the management host: versions, backup archives, certificates, the network
description, the cluster settings and the stored objects. It runs their own helpers, so a pass is
one sudo call rather than six lines in the host's journal.

For the polling interval and refresh behaviour, see
[Jobs and status freshness](#jobs-and-status-freshness).

The configuration file is written by `01-platform-prepare` **only when it is absent**, so an edit
there survives every later release. A changed value takes effect when the poller is restarted; it
reads its configuration once, at start.

**A rule under `/etc/sudoers.d/` does not travel with a release.** Adding a helper means installing
its line separately, checked with `visudo`. A release that carries a helper nobody may run fails at
the first call, with sudo's refusal in the diagnostics, not at install time.

**Why the rules can be exact.** Each helper **takes no arguments at all**: the cluster arrives as a
bounded JSON request on one line of stdin. `PRIVILEGE.md` forbids wildcards in sudoers argument
matching, and without the no-argument form a rule naming a cluster would need one. The helpers work
out their target inside the boundary:

- Inventory reads the exact commit named by the published RELEASE stamp, not the repository's
  working tree, so an unpublished change cannot be shown as live.
- The list helper reads saved commit metadata - version number, timestamp and comment - and no
  file content at all.
- The backup helper reads directory metadata under the state backup root and never opens an
  archive. That lets an account that must not read password hashes and private SSH keys still
  report that a backup exists.
- The certificate helper reports metadata about the distribution root, and which certificates
  certbot renews on this host. Private key material never reaches its output, because it parses
  the leaf certificate alone.
- The network helper reads one cluster's `managed/network.yaml`, in a directory only the engine's
  own group can read - which is why the interface cannot simply open it. It reports the three
  address tables and which of the two possible sources they came from.

None of them takes a lock, so these reads stay answerable while a deploy runs.

`haprion-list` itself does not use that helper. A person running it can already read the cluster
repository, so the command reads it directly; requiring `sudo` for machine-readable output would be
privilege for formatting. Both paths build their result with the same function, so they cannot come
to describe the same history differently.

The request itself is built by the engine's own code, not by a copy of it in the interface. Two
constructions of the same request are two things to keep in step, and each looks correct on its
own - the hardest kind of divergence to find.

**Where the results go.** The results go to cache tables with one row per cluster:
`cluster_status`, `cluster_inventory`, `cluster_history`, `cluster_certificates`,
`cluster_network`, `cluster_backups`, `cluster_settings`, `cluster_objects` and `cluster_list`.
Every page shows how old the answer it uses is. `observed_at` is set by the database - by default on
insert and by a trigger on update - and the poller holds no `update` on that column. A poller that
could write it could report a cluster it never reached as freshly observed.

##### The sandbox, and the three ways it failed quietly

The poller's unit is hardened like the others, with three deliberate exceptions. Each is written in
the unit file with its reason:

- `NoNewPrivileges=no`, because sudo is setuid and the whole point of this service is to run one
  helper through it;
- a capability set that permits changing user ID, for the same reason;
- network address families, because the helper reaches nodes from inside this sandbox.

**A harmless warning, filtered out.** `ProtectProc=invisible` hides the poller's own process from
the root that sudo runs as, because the sandbox withholds `CAP_SYS_PTRACE`. sudo-rs then warns on
every call that it *could not get parent process starting time*. It needs the parent's start time
only to tie a cached password to, and these rules need no password. The poller and worker units
drop that one exact line with `LogFilterPatterns=`. Everything else sudo logs, refusals included,
reaches the journal.

**Two traps that do not show as errors.** The status identity's key is owned by root and lives
under `/root`, so the unit needs a hole in `ProtectHome`:

- `ProtectHome=yes` **hides** a `BindReadOnlyPaths` under `/root`. The file stays invisible and the
  service starts perfectly. `ProtectHome=tmpfs` is what works, because the bind then lands on top
  of an empty filesystem.
- A bind mount written with a leading dash is *optional*, and systemd silently skips it when it
  cannot be satisfied. The service starts, and every cluster reports as unreachable - a failure
  that looks like a broken environment rather than a missing file. So the dash is deliberately not
  used.

Both look the same: SSH exits 255 in under a tenth of a second, and every node is
`ssh_unreachable`. If that is what the cache shows, run the helper by hand outside the unit before
suspecting the nodes:

```bash
printf '{"schema_version":1,"operation":"status","cluster":"<id>",'\
'"request_id":"'"$(uuidgen)"'","parameters":{}}' \
  | sudo -u <poller> sudo -n /opt/haprion/current/bin/haprion-status-helper
```

If that answers `done`, the sandbox is the problem and not the environment.

**One poller and one worker, enforced by the database.** Each holds a session-level advisory lock in
PostgreSQL for its whole life. A second poller finds the lock taken and exits, rather than doubling
the load on every node. A second worker exits the same way, rather than settling the first one's job
as abandoned while its helper still works. The database server releases the lock when the connection
dies, including when the process is killed without cleaning up - exactly the case a lock file gets
wrong.

##### What the worker may run

Fourteen helpers, each with no arguments, in `/etc/sudoers.d/haprion-worker`:

```
<worker> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-deploy-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-cert-deploy-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-revert-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-changes-publish-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-cert-issue-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-cert-publish-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-cert-target-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-dns-profile-apply-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-cert-delete-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-ndes-profile-apply-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-cert-scep-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-cert-import-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-cert-request-helper ""
<worker> ALL=(root) NOPASSWD: /opt/haprion/current/bin/haprion-server-state-helper ""
```

What they do:

- **Cluster changes (five):** deploy brings nodes onto the published version, cert-deploy
  distributes certificates, revert moves the cluster back to an earlier version, changes-publish
  commits the saved changes as one version, and server-state drains, readies or puts in maintenance
  one object's servers on every node.
- **Certificate jobs (nine):** cert-issue, cert-publish, cert-target, dns-profile-apply,
  cert-delete, ndes-profile-apply, cert-scep, cert-import and cert-request
  ([Issuing a certificate](#issuing-a-certificate), [The DNS profile key pair](#the-dns-profile-key-pair),
  [Deleting a certificate](#deleting-a-certificate), [Importing a certificate](#importing-a-certificate)).
  They belong to no cluster, and the queue runs one of them at a time.

`cert-delete` is the only rule in the file that removes key material;
[Deleting a certificate](#deleting-a-certificate) says what limits it. The receiver helper
([Registering a receiver](#registering-a-receiver)), which makes accounts and edits sshd's and
nginx's own configuration, is deliberately not in this file. It is reached over a socket instead,
for the reason given under *The worker's way to the receiver helper*.

Publishing is in the list because the interface is where those decisions are made. An editor that
can only save a draft is an editor whose work has to be finished somewhere else, and asking somebody
to leave the screen and log in to a shell to complete a change is how a change gets left
unfinished. Publishing still writes nothing to a node - that is deploy, a separate helper and a
separate decision.

**`07-platform-services` installs this file**, checked with `visudo`. A file installed by hand
falls behind the helpers a release adds, and the first use of a new one meets sudo's refusal. Run
the step again after a release that names a new helper.

##### The web service, and why it has no sudoers rule at all

The web service has no sudo rule. A few things it offers need more than the database, and each one
reaches a helper over a local socket instead:

| Socket | Helper runs as | What for |
|---|---|---|
| `/run/haprion/probe.sock` | root | a health check against the real nodes (below) |
| `/run/haprion/cert-export.sock` | root | the key of a certificate marked exportable, as a PKCS#12 file |
| `/run/haprion/oidc.sock` | its own account, `_haprion-oidc` | sign-in through an OIDC provider |
| `/run/haprion/resolve.sock` | a temporary account | looking up the names of DNS servers |

The probe shows why it works this way. A health check needs root, because the probe identity's key
is owned by root - no application account may hold a key that reaches a node. The obvious way to
grant it would be a sudoers rule, one exact no-argument helper, the way the poller's four rules
work. **That does not work here, and it is worth knowing why before somebody writes the rule
again.**

The web unit carries `NoNewPrivileges=yes`, an empty `CapabilityBoundingSet=` and
`RestrictSUIDSGID=yes`. Under `NoNewPrivileges` the kernel ignores the setuid bit, so `sudo` fails
*before it reads `/etc/sudoers.d/`*. It fails however the rule is written, and the rule then sits
on disk saying this account may become root while granting nothing at all. The poller solves the
same problem by relaxing its own sandbox (`NoNewPrivileges=no`, a capability set that permits
changing user ID). Doing that to the web service would trade the one boundary most worth keeping
for a button.

So the privilege stays put and the request travels instead:

```
/run/haprion/probe.sock   root:<web> 0660, created by haprion-probe-helper.socket
haprion-probe-helper@.service  runs the helper as root, one instance per connection
```

The web service opens the socket, writes one JSON request, closes its write side, and reads one
JSON answer. The far end takes no arguments and does exactly one thing. So reaching it is worth no
more than the sudo rule would have been, and the web account keeps a sandbox in which nothing it
runs can gain privilege.

`haprion-probe` on the command line still goes through `sudo`, because a person running it has a
terminal and a `%sudo` rule. Both build the request with the same function, so the two paths cannot
come to describe the same probe differently.

**The probe socket is installed by default**: it is what the form's *Test health check* asks.
`PROBE_SOCKET=no` in the answers file leaves it out, and the interface then says the probe is
unavailable rather than showing an empty result.

##### The worker's way to the receiver helper

The worker *can* use `sudo` - fourteen of its helpers go that way. The receiver helper does not,
for a reason on the other side of the boundary:

- A helper the worker starts inherits the worker unit's view of the filesystem (its mount
  namespace). That unit has `ProtectSystem=strict` with a short `ReadWritePaths` list.
- Registering a receiver writes `/etc`. `useradd` rewrites `/etc/passwd` and its neighbours through
  a rename, so the whole directory has to be writable, and the helper also rewrites
  `/etc/ssh/sshd_config.d/` and `/etc/nginx/snippets/`.
- `ReadWritePaths=/etc` on the job runner would end the sandbox for every helper to serve one. A
  sudo rule alone would fail at the first write.

So this helper, too, stays put and the request travels:

```
/run/haprion/cert-receiver.sock    root:<worker> 0660, created by haprion-cert-receiver-helper.socket
haprion-cert-receiver-helper@.service   runs the helper as root, one instance per connection
```

The worker runs `haprion-cert-receiver-ask` from its own environment, as itself: no arguments, the
request on stdin, the answer on stdout. That is the same shape every other helper runs in, so the
queue, the lease and the output cap are unchanged. The client connects to the socket, writes the
request, closes its write side and passes the answer through untouched.

- When nothing listens, the answer is an envelope that says so (`dependency_unavailable`), never
  `unknown`.
- A helper that was asked and went quiet leaves the job `unknown` (see the backup and restore
  helpers below). While it is still at work, or when the worker was stopped, the job ends on the
  helper's kept answer instead ([The worker](#the-worker)).
- A request is carried out once. Asked again with the same request ID, the helper gives the answer it
  kept and does nothing; with no answer kept, it refuses.

The helper's own stderr goes to the journal (`journalctl -u 'haprion-cert-receiver-helper@*'`), not
to the job.

The service's sandbox is `ProtectSystem=yes`: `/usr`, `/boot` and `/efi` are read-only and `/etc`
is writable, because writing `/etc` is the job. `full` and `strict` would both take `/etc` away,
which is the failure this unit removes. `haprion-cert-receiver` at the terminal does not go this
way; root runs it directly.

Step 07 installs the socket wherever it installs a worker. It reaches no node.

##### The way to the interface certificate

The same boundary once more, with a different caller. The helpers that issue, enroll and import
certificates run through `sudo` inside the worker's namespace. Publishing the entry marked
`interface: true` ([From the certificate registry](#from-the-certificate-registry)) ends in
`haprion-tls install`, which writes `/etc/haprion/tls` and a rollback directory beside it. So those
helpers name the entry by ID on a socket:

```
/run/haprion/ui-tls.sock      root:<worker> 0660, created by haprion-tls-helper.socket
haprion-tls-helper@.service     runs the helper as root, one instance per connection
```

The request carries the certificate ID and nothing else. The helper reads the registry and the
certificate material itself, and refuses an entry without the mark. The socket takes one
connection at a time. The helper takes no lock: its callers hold the publisher's lock while they
wait for it. The sandbox is `ProtectSystem=yes`, as for the receiver helper. The renewal timer and
`haprion-cert-publish` do not go this way; root runs them directly. Step 07 installs the socket
wherever it installs a worker.

##### The worker's way to the backup and restore helpers

Node backups from the interface and node restores go the same way as receivers, for the same
reason from the other direction:

- both read state archives under `backup_root` that only root may read;
- a restore keeps its run and one-time key under `/var/lib/haprion/restore`;
- both reach nodes over SSH as root.

A child of the worker started through sudo would inherit the worker's read-only view of the
filesystem.

```
/run/haprion/backup-job.sock       root:<worker> 0660, created by haprion-backup-job-helper.socket
haprion-backup-job-helper@.service      backup_run and backup_schedule, as root, one instance per connection
/run/haprion/node-restore.sock     root:<worker> 0660, created by haprion-node-restore-helper.socket
haprion-node-restore-helper@.service    node_restore_prepare, _preview, node_restore, _discard and _status, as root
```

The worker runs `haprion-backup-job-ask` and `haprion-node-restore-ask` from its own environment,
exactly as it runs the receiver client. Two answers differ from a helper that ran and refused:

- **Nothing listening** is an envelope that says so (`dependency_unavailable`, `failed`): nothing
  ran.
- **A helper that was asked and then went quiet** - the client's time ran out, or the connection
  dropped - is **no** envelope. The root service carries on without the client. While it is still at
  work, or has answered since, the job waits and ends on the answer the service kept
  ([The worker](#the-worker)); one that ended without an answer leaves the job `unknown`.

The client's sentence is in the job's stderr excerpt. The helper's own lines are in the journal
(`journalctl -u 'haprion-node-restore-helper@*'`).

The restore service needs `AF_NETLINK` besides the usual address families: `ip route get` finds the
address the target will see the manager come from, and the one-time key's `from=` is limited to
that address.

**Pausing the worker for a release.** Activating a UI release, and `haprion-rollback`, restart the
worker. So both first pause its claims (`haprion-drain`) and wait until no job is running - fifteen
minutes at most (`DRAIN_SECONDS`). After that they stop without switching anything and lift the
pause. An update of the UI package pauses before it dumps and migrates the database, so one that stops
there leaves the schema as it was. Once no job runs, the pause holds for the wait and five minutes
more. A run stopped during its wait lifts it, and one left behind by a killed run ends by itself.
While the pause holds, *Jobs* says until when.

Step 07 installs both sockets wherever it installs a worker. `haprion-node-restore` and
`haprion-state-backup` at the terminal do not go this way; root runs them directly.

##### The worker's way to the node helper

Adding or removing a node writes root's `known_hosts`, the pull accounts' `authorized_keys`, the
cluster file and the collector's files. Creating or removing a cluster writes those too, plus the
editing policy under `/etc/sudoers.d`, a new repository under the configuration root, and moves
directories into `.removed/`. A helper the worker starts through sudo may write none of these.

So `haprion-node-helper` answers both on `/run/haprion/cluster-node.sock` (owned by root, group the
worker's account, `0660`), from `haprion-node-helper@.service`, installed by step 07. The worker's
`haprion-node-ask` carries the request there. `haprion-node` and `haprion-cluster` from a terminal
run the helper directly as root.

##### Which clusters get polled

The clusters `clusters.yaml` lists, in its order. The poller asks `haprion-cluster-list-helper` on
every pass - through one sudoers rule, because the application accounts cannot read the engine's
configuration and must not - and keeps the answer in one row that the pages read. A cluster created
or removed from Settings is therefore polled and drawn from the next pass on, and its colour
follows its place in the file.

`clusters` in `ui.toml` is the fallback: the list used before the poller has read one, and while
the helper cannot be read. A pass that cannot read the list polls the clusters it knew rather than
none. An empty `ui.toml` list with no readable cluster file leaves the poller nothing to do, and it
says so instead of starting.

### Verifying the installation

Work outward, and stop at the first step that fails:

1. **Configuration status** - `haprion-config-status -c alpha` reports the published version and a
   clean draft.
2. **Node status** - `haprion-status -c alpha` reaches every node and reports the address owner,
   the release each node runs, and whether that is the published one. This proves the status key,
   its forced command, and the node reporter.
3. **The stored objects** - `haprion-objects -c alpha` lists the proxy objects as they are written,
   at the commit the repository is on. `--show <name>` prints one document exactly as stored, and
   `--advanced <name>` prints where each line of its advanced config goes. Where
   `haprion-inventory` parses what a node is serving, this reads the source that produced it - so
   an object the generator refuses is listed with the refusal rather than left out. The listing
   also names the VIP each object is served on, worked out by the generator's own rule against the
   network description. That is what the interface lists and searches by.
4. **A deploy with nothing to do** - `haprion-deploy -c alpha` with the nodes already current should
   skip every node and change nothing. A run that correctly does nothing is a real test. Step 2
   should already have said the cluster was up to date; if the two disagree, believe neither, and
   find out why before deploying anything.
5. **A deploy that does something** - publish a harmless change and deploy it. Confirm that the
   nodes that do not hold the address are deployed first, the owner last, and that the address
   does not move.
6. **The negative tests** in [`PRIVILEGE.md`](PRIVILEGE.md), run as the real installed identities
   rather than through mocks.

Do the last two on a cluster that carries no traffic, if you have one.

### What is still missing

One gap remains:

- **A rebuild from this repository alone** has not been verified end to end. That is the last step
  before 1.0.

It is closed when a new management host and a new set of nodes, with names of your own choosing,
are built from this repository alone by someone who has never seen the maintainer's environment.

Certificate renewal is not a gap: the product schedules it. Platform step 14 installs
`haprion-certbot-renew.timer`, which runs `haprion-cert-renew` twice a day. That renews certbot's
certificates and then those enrolled from a Microsoft CA over NDES/SCEP. The same step masks the
distribution's own `certbot.timer` and installs the certbot deploy hook that publishes a renewed
certificate. Issuance, import and
distribution are described under [Certificates](#certificates).
