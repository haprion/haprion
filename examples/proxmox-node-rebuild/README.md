# Rebuilding a node on Proxmox with one command

`haprion-node-restore` puts a node back onto an empty VM: you make the VM, paste one line on its
console, compare a fingerprint, and confirm. This example does the Proxmox half for you. It clones
a template, runs the pasted line through the QEMU guest agent, and calls the restore. The result is
the same restore, started with one command.

It is an example, not part of the product. Nothing here is packaged or covered by the product's
promises. It uses only what `haprion-node-restore --json` answers, so it keeps working as long as
that does. Adapt it, or leave it and restore by hand as the
[manual](../../docs/user-manual.md#restoring-a-node-onto-an-empty-vm) describes.

## What it does

`proxmox_node_rebuild.py run <node>`:

1. **Checks before it changes anything.** A rebuild goes ahead only where the node is gone. It
   stops if a VM with the node's name exists anywhere in Proxmox (`LB-01` and `lb-01.example.net`
   count as `lb-01`), if the VMID is taken, or if anything answers at the node's own address (ssh
   or ping). The address comes from the cluster's definition, through `haprion-status`. It also
   stops if the temporary address answers. Then it confirms that the token answers, the template
   exists, the token has the privileges listed below, and there is a backup of the node.
   `check <node>` stops after this step.
2. **Makes the VM.** It clones the template into the pool, sets the cluster's bridge, and gives the
   VM a temporary address and resolver with cloud-init. Then it starts the VM and waits for the guest
   agent and for cloud-init to finish.
3. **Prepares the restore.** It runs `haprion-node-restore prepare`, then runs the line `prepare`
   prints inside the VM, as root, through the guest agent. It reads the host key fingerprint from that
   line's output. This replaces the console step. The fingerprint comes over the hypervisor's
   channel, not the network, so the trust is the same as reading it on the console.
4. **Asks before it restores.** It shows `preview` as it is, then asks you to type the node's name. It
   runs `run` only after that. If you stop here, the run is discarded and the VM is left for you to
   look at or remove.
5. **Takes cloud-init away.** The template's cloud-init would write its own network again after a
   change in Proxmox, or ask for an address by DHCP. The example creates
   `/etc/cloud/cloud-init.disabled` in the VM and shuts the VM down. If a clean shutdown has not
   happened in two minutes, Proxmox stops the VM. A first boot can lose the request while unattended
   upgrades run. Then the example removes the cloud-init drive and its settings, starts the VM again,
   and waits for the node's own address on port 22.

`--test` restores to a test VM instead: its own VMID, a test address and a VIP no cluster uses.
keepalived stays masked on a test VM. It is the product's test mode, with the VM made for you. The
node keeps running during a test, so only the test VM's name, VMID and address must be free.

A node is named as the cluster names it, or by a short name that fits only one node in the
settings: `01` for `lb-01` when no other node ends in `01`.

## What you need

- **Proxmox VE 9.** Running commands through the guest agent needs `VM.GuestAgent.Unrestricted`, a
  privilege Proxmox VE 9 introduced.
- **A template** with Ubuntu 26.04 or Debian 13 whose network is Netplan, `qemu-guest-agent`
  installed and enabled, the agent option on in Proxmox, and a cloud-init drive.
- **A pool, and a token whose rights stop at it.** Run commands in the guest means root in every
  VM the token can reach, so the pool is the boundary. It should hold nothing but rebuilt VMs, and
  only while they are being rebuilt. For example:

  ```bash
  pveum pool add node-rebuild
  pveum role add NodeRebuildVM --privs "Pool.Audit,VM.Allocate,VM.Audit,VM.Config.CDROM,VM.Config.CPU,VM.Config.Cloudinit,VM.Config.Disk,VM.Config.Memory,VM.Config.Network,VM.Config.Options,VM.PowerMgmt,VM.GuestAgent.Unrestricted"
  pveum user add rebuild@pve
  pveum user token add rebuild@pve manager
  for who in "--users rebuild@pve" "--tokens rebuild@pve!manager"; do
      pveum acl modify /pool/node-rebuild --roles NodeRebuildVM $who
      pveum acl modify /vms/9000 --roles PVETemplateUser $who
      pveum acl modify /storage/vm-storage --roles PVEDatastoreUser $who
      pveum acl modify / --roles PVEAuditor $who
  done
  ```

  A bridge in an SDN zone needs `PVESDNUser` on that VNet as well
  (`/sdn/zones/<zone>/<vnet>`).
- **The settings** in `/etc/proxmox-node-rebuild/settings.env` (from `settings.env.example`), and
  the token in the file it names. Both are root-owned, with mode 600.

Run it as root on the manager. `haprion-node-restore` needs root, and so does the token.

```bash
sudo ./proxmox_node_rebuild.py check lb-01
sudo ./proxmox_node_rebuild.py run 01 --test     # a short name that fits only lb-01
sudo ./proxmox_node_rebuild.py run lb-01
```

## What it does not do

- It never replaces anything that exists. A node whose VM is still in Proxmox, even switched off, is
  not rebuilt: remove the old VM first. **The old node and the new one must never run at the same
  time.**
- It does not remove a VM that failed. The VM stays in the pool for you to look at. Remove it
  in Proxmox.
- It does not check SDN rights before the clone. A missing `PVESDNUser` shows up as the bridge
  change failing.
- It does not restore a node that may be compromised. The product's
  [When the restore is the wrong tool](../../docs/DISASTER-RECOVERY.md#when-the-restore-is-the-wrong-tool)
  applies here unchanged.
