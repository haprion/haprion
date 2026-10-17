# Contributing

Haprion is a hobby project, maintained by one person in their spare time and on a best-effort
basis. Contributions are welcome within that: there is no promised response time, and what fits
the project is decided by its direction rather than by how much work went into a change.

## Reporting a bug

Open an issue. A useful report says:

- which versions run - `dpkg-query -W 'haprion-*'` on the manager and on a node;
- what you did, what you expected and what happened instead;
- what the job page, the terminal or the log said, as text.

Leave out your own hostnames, addresses, domains, keys and configuration; a made-up example such as
`node-a`, `192.0.2.10` or `www.example.com` is enough. A vulnerability is not an issue: report it
privately, as [SECURITY.md](SECURITY.md) describes.

## Suggesting a feature

Open an issue that describes the problem first and the feature second. Some things are left out on
purpose; [What it does not do](docs/user-manual.md#what-it-does-not-do) lists them with the reason.

## Pull requests

Open an issue before a larger change, so that it is agreed before it is written.

The CI on this repository cannot run on a pull request from a fork. Its secret scan reads a private
list of the maintainer's own names and addresses, kept out of the repository on purpose, and GitHub
gives no secrets to a fork's pull request - so the check fails there by design, not because of the
change. A pull request is read and its gate run by the maintainer before it is merged. Run the gate
yourself first: [Development](README.md#development) sets it up with the repository's example list.

- Keep a pull request to one change, with tests that fail without it.
- Use made-up values in code, tests and examples, never real ones.
- Write commit messages in English, short, in the imperative: *Add …*, *Keep …*.

Haprion is licensed under the GNU Affero General Public License, version 3 or later; a contribution
is made under the same licence.
