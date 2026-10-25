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

## Releasing

The packages install independently - the CLI engine, the web platform, certbot and the node
scripts among them - and a release ships the ones a change touched. Which those are has a
measurable answer:

```bash
git show --stat <commit>
```

| What the commit touched | What to release |
|---|---|
| `src/haprion/` | the `haprion-cli` package and the `haprion-ui` package: the interface runs its own copy of the engine's modules, and reaches the helpers through the CLI's |
| `tools/` | whichever package that tool builds or installs |
| `ui/`, the manager's installation steps (`install/platform/`, `install/0[1235]-*`, `install/*.sh`) | the `haprion-ui` package; installing it runs `update-platform-release` on an installation that already has a current release |
| `install/sudoers/` | the `haprion-cli` package |
| `certbot/` | the `haprion-certbot` package; installing it runs platform step 14 on a manager where step 14 has run |
| `install/node/`, `install/04-node-prepare` | the `haprion-node` package on every node |

**The CLI package goes first when both move.** apt will not install an interface that needs a newer
engine than the one installed, and the platform's update checks the installed CLI before it migrates
anything - so an interface released first stops before it changes the database.

**The engine's API level is the contract between them.** `src/haprion/compatibility.json` holds
it, with a digest of `schemas/v1` and one of what the helpers take (their operations, parameters and
actions); a change to either fails the gate until someone decides whether the level must rise, and
records the new digest. Raise it whenever an older engine could not answer what
the new interface asks. The
interface requires the level it was built with (`ui/src/haprion_ui/compatibility.json`),
`haprion-cli` provides `haprion-engine` at its level, and `haprion-ui` depends on
`haprion-engine (>=` that level`)`, so apt will not put an older engine under it.

**Prove it afterwards.** Each install step proves its own result; the whole-installation check
answers whether the independently installed parts still work together:

```bash
sudo /usr/share/haprion-ui/install/platform/check-compatibility
```

**Every release is a commit.** Each package is built from one committed source tree and named
after it; a release built from an edited tree is one nobody can reproduce. Run the full gate before
building - a release is not the place to find out that a test fails.

Haprion is licensed under the GNU Affero General Public License, version 3 or later; a contribution
is made under the same licence.
