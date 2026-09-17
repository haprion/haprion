# Reference fetch scripts

A receiver **pulls**. The manager never pushes, whatever the transport - the same rule the nodes
follow - so what runs on a schedule runs on the receiver, and these are the scripts it adapts.

| File | For a receiver registered with |
|---|---|
| `fetch-rsync` | `--transport rsync` |
| `fetch-sftp` | `--transport sftp` |
| `fetch-https` | `--transport https` |
| `install-pkcs12.ps1` | any transport, where the pair is published as `format: pkcs12` |

All of them are written to be run from a timer, and all of them share three properties that are
worth keeping in an adaptation:

- **The pair is checked before it is installed.** `fullchain.pem` and `privkey.pem` are two files
  and two renames on the manager, so a fetch can catch the moment between them. Each script
  verifies that the key belongs to the certificate and does nothing if it does not - the next run
  gets a consistent pair.
- **Nothing is restarted unless something changed.** The comparison is `cmp`, so a run that
  fetched the same bytes is silent and costs nothing.
- **The names are made up.** `lb-01.example.net`, `/etc/ssl/haproxy` and `crx-lb-01` are
  placeholders; nothing here is a real host, account or path.
