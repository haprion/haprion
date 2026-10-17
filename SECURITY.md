# Security policy

## Reporting a vulnerability

Report a vulnerability privately, through GitHub: the repository's **Security** tab, then
**Report a vulnerability**. Please do not open a public issue, pull request or discussion for it.

A useful report says which version it applies to (`haprion-cli`, `haprion-ui` or `haprion-node`
and its package version), what an attacker needs in advance - network position, an account and
its role, access to a node - and what they gain, with the steps to reproduce it. Leave out real
hostnames, addresses, keys and configuration from your own environment; a made-up example is
enough.

Haprion is maintained by one person in their spare time. A report is acknowledged and assessed as
soon as possible, but there is no guaranteed response time. A confirmed vulnerability is fixed in a
new release and published as a GitHub security advisory once that release is available, crediting
the reporter unless they ask not to be named.

## Supported versions

The project has not reached 1.0. Only the newest release receives fixes; there are no backports to
earlier ones.

## Scope

In scope is the code in this repository: the engine and its commands, the web interface, the
worker and poller, the root helpers and the packages built from them. What the security model
promises is in [`docs/PRIVILEGE.md`](docs/PRIVILEGE.md) and the README's *Security model*; a way
around it is exactly what this policy is for.

Vulnerabilities in HAProxy, keepalived, Coraza, the OWASP Core Rule Set, Certbot, PostgreSQL or
other software Haprion installs belong with their own projects. Haprion's packaging of them - a
wrong permission, an unverified download, a version kept back - is in scope.

How the repository checks itself is described in
[`docs/SECURITY-CHECKS.md`](docs/SECURITY-CHECKS.md).
