# Reference fetch scripts

A receiver **pulls**. The manager never pushes, whatever the transport - the same rule the nodes
follow - so what runs on a schedule runs on the receiver, and these are the scripts it adapts.

| File | For a receiver registered with |
|---|---|
| `fetch-rsync` | `--transport rsync` |
| `fetch-sftp` | `--transport sftp` |
| `fetch-https` | `--transport https` |
| `install-pkcs12.ps1` | any transport, where the pair is published as `format: pkcs12` |

`install-pkcs12.ps1` binds the certificate to the site's IP (`-SslFlags 0`), which is right for
one site on that address. Several sites on one address need SNI: the binding is then made with
the site's host name and `-SslFlags 1`, and the script says where.

All of them are written to be run from a timer. Some properties are worth keeping in an adaptation:

- **The pair is checked before it is installed.** `fullchain.pem` and `privkey.pem` are two files
  and two renames on the manager, so a fetch can catch the moment between them. The three `fetch-`
  scripts verify that the key belongs to the certificate and do nothing if it does not - the next
  run gets a consistent pair. `install-pkcs12.ps1` imports one PKCS#12 file, which carries both.
- **Nothing is restarted unless something changed.** The `fetch-` scripts compare with `cmp`, and
  `install-pkcs12.ps1` compares the certificate's thumbprint, so a run that fetched the same
  certificate is silent and costs nothing.
- **A failed reload is retried.** A `fetch-` script writes `.reload-pending` in the target before it
  replaces the first file and removes it after the reload has succeeded. If the reload fails, the
  next run finds the files identical and would otherwise do nothing; it sees the marker and reloads.
  The two files are installed under temporary names and renamed, so the service does not read a
  key beside the wrong certificate for longer than the two renames take.
- **sftp runs as a batch.** `fetch-sftp` hands its commands to `sftp -b -`: read from stdin,
  no prompt, and a `get` that fails aborts the run with a non-zero exit instead of leaving the
  next command to run against half a pair. The same form works on Windows, where there is no
  heredoc: a here-string piped in, `@"…"@ | sftp -b - -i C:\certs\certfetch …` - the
  receivers page in the interface shows it with the real names filled in. Run the Windows
  commands in an elevated PowerShell (Run as Administrator).
- **The Windows directory is the administrators'.** Each command the interface shows for Windows is
  one script block that stops at the first failure. Before anything is written it sets `C:\certs`
  and what it already holds to be owned by Administrators with only Administrators and SYSTEM
  granted, whatever was there before: a directory made under `C:\` otherwise inherits read for
  every local account.
- **The names are made up.** Host names under `example.net`, the `crx-` accounts, addresses from
  `192.0.2.0/24`, `/etc/ssl/haproxy` and `C:\certs\` are placeholders; nothing here is a real host,
  account or path.
