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

All of them are written to be run from a timer, and all of them share three properties that are
worth keeping in an adaptation:

- **The pair is checked before it is installed.** `fullchain.pem` and `privkey.pem` are two files
  and two renames on the manager, so a fetch can catch the moment between them. Each script
  verifies that the key belongs to the certificate and does nothing if it does not - the next run
  gets a consistent pair.
- **Nothing is restarted unless something changed.** The comparison is `cmp`, so a run that
  fetched the same bytes is silent and costs nothing.
- **sftp runs as a batch.** `fetch-sftp` hands its commands to `sftp -b -`: read from stdin,
  no prompt, and a `get` that fails aborts the run with a non-zero exit instead of leaving the
  next command to run against half a pair. The same form works on Windows, where there is no
  heredoc: a here-string piped in, `@"…"@ | sftp -b - -i C:\certs\certfetch …` - the
  receivers page in the interface shows it with the real names filled in.
- **The names are made up.** `lb-01.example.net`, `/etc/ssl/haproxy` and `crx-lb-01` are
  placeholders; nothing here is a real host, account or path.
