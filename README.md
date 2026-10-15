# rsync-tools

A collection of Perl scripts for secure, automated rsync operations using an
unprivileged user account. These tools implement defense-in-depth security
through file permissions, SSH key restrictions, doas/sudo controls, and
OpenBSD's pledge/unveil when available.

Primary platform is OpenBSD; also runs on Linux and macOS. Not all features
are available or meaningful on non-OpenBSD platforms.

## Tools Included

### rsync-client.pl / rsync-server.pl

Automated rsync between systems using a non-privileged `_rsyncu` user, with
optional privilege escalation only for specific transfers. doas is used when
it is installed, sudo otherwise. rsync-server.pl is installed as a symlink
to rsync-client.pl.

**Key Features**:
- Unprivileged execution, with doas/sudo used only for the transfers that
  need it
- Config file and its directory validated at runtime for correct ownership
  and permissions
- SSH key restrictions via authorized_keys forced commands
- The server side accepts only the exact paths in its config, and only the
  standard server option strings plus the rsync options listed for that path
- Setup and cleanup hooks: run commands before and after each rsync operation
- Exit status checked for every setup, rsync and cleanup; failures are
  reported and give a non-zero exit status
- Logging of every server-side command and of security events
- Path validation: absolute paths only, no directory traversal
- Uses pledge/unveil on OpenBSD

**Security Model**:

1. `_rsyncu` user cannot modify system files or config
2. Config file must be owned root:_rsyncu with mode 0640, and /etc/rsync
   root:_rsyncu with mode 0750; both are checked at runtime, and the scripts
   refuse to run otherwise
3. authorized_keys restricts each SSH key to a specific command and source host
4. doas/sudo rules list each permitted rsync command with its exact
   arguments (see below), so `_rsyncu` cannot run rsync as root with
   arguments of its own choosing
5. All paths must be absolute; directory traversal rejected
6. pledge/unveil on OpenBSD restricts the script itself. They do not carry
   over to the rsync, doas or setup/cleanup commands it runs, so those are
   bounded by items 1-5 and, on rsync 3.5.0 or later, `--confine-root`.

**Configuration**:

`/etc/rsync/rsync.conf` defines what is synced, which SSH identity to use,
whether doas/sudo is required on either side, and optional commands to run
before (setup) and after (cleanup) each transfer. The same entries must be
present on both the client and the server, with identical paths and rsync
options: the server only accepts a path that matches its own entry exactly.
Host names are short names without the domain, as returned by `hostname`
up to the first dot. Lists are separated by commas, with or without spaces,
and every list in an entry has the same number of items. Example:

```
source: backupserver
destination: mailserver
source-dirlist: /var/mail/, /etc/mail/
destination-dirlist: /backup/mail/, /backup/mail-config/
rsync-options: --delete, --delete
source-sudo: no, no
destination-sudo: yes, yes
```

The `-sudo` settings mean "use doas or sudo", whichever is installed. A
sample config with more examples is in `etc/rsync.conf`, and the full format
is described in the header of rsync-client.pl.

If a setup command fails, the rsync for that item is skipped and its cleanup
still runs. A setup or cleanup may be several commands separated by `;`,
which stop at the first one that fails. Commands are run without a shell, so
their arguments cannot contain spaces or commas.

**Required File Permissions**:
```
/etc/rsync/           root:_rsyncu  0750
/etc/rsync/rsync.conf root:_rsyncu  0640
```

Consider protecting rsync.conf with immutability flags via
[syslock](https://github.com/lippard661/syslock) on OpenBSD/Linux, since
the config file describes your network topology and sync relationships.

**SSH authorized_keys**:

On the server, restrict each key to a specific command and source address.
The argument after push/pull is the client's host name:
```
command="/usr/local/bin/rsync-server.pl pull clienthost",from="203.0.113.10",restrict ssh-ed25519 AAAA... _rsyncu@client
```
(`restrict` turns off port, agent and X11 forwarding and the pty.)

**doas Configuration** (OpenBSD `/etc/doas.conf`):

List each command with `args`, so that only those exact command lines can
run as root. Do not use `setenv` or `keepenv` for `_rsyncu`: rsync runs
whatever `RSYNC_RSH` names, so passing it through would allow any command to
run as root. Versions before October 2026 needed `setenv { RSYNC_RSH }`;
remove it, after the new rsync-client.pl is installed everywhere.

On a server, for a path with `-sudo: yes`. For the sample config's pull of
`/var/db/sigtree` from bar (source-sudo yes), bar needs:
```
permit nopass _rsyncu as root cmd /usr/local/bin/rsync args --server --sender --confine-root=/var/db -vlogDtprze.iLsfxCIvu . /var/db/sigtree
```
For a push, `--sender` is absent. `--confine-root` is the path itself if it
ends in `/`, otherwise its parent directory, and is left out when that is `/`
(so the `/etc` pull has none). Options that only the receiving side uses,
such as `--delete` on a pull, are not sent to the server.

On a client, for a path with `-sudo: yes`. In the example entry above,
mailserver is the destination, so it runs `rsync-client.pl pull
backupserver`; with destination-sudo yes, mailserver needs (the ssh command
is one quoted argument):
```
permit nopass _rsyncu as root cmd /usr/local/bin/rsync args -avz -e "/usr/bin/ssh -i /home/_rsyncu/.ssh/id_ed25519 -o UserKnownHostsFile=/home/_rsyncu/.ssh/known_hosts" --delete _rsyncu@backupserver:/var/mail/ /backup/mail/
```

The `-vlogDtprze...` string depends on the client's rsync version and
options; the server's log (`~_rsyncu/rsync.out`) shows the exact command
lines it runs.
For sudo, the same command lines go in sudoers, with `,` `:` `=` and `\`
escaped by a backslash.

**rsync versions**: both rsync-client.pl and rrsync pass rsync 3.5.0
hardening options (`--confine-root`, and in rrsync `--drop-D`). On a host
with an older rsync, set `RSYNC_PRE35` to 1 near the top of each script.

**Usage**:
```
rsync-client.pl pull server-hostname
rsync-client.pl push server-hostname
rsync-client.pl both server-hostname
```
The server side is invoked via SSH authorized_keys, not directly.

---

### rrsync

Restrict rsync operations via SSH `authorized_keys` forced commands to a
single directory, optionally read-only or write-only. A Perl version of the
rrsync distributed with rsync (originally by Joe Smith, with later versions by
Wayne Davison), kept at feature parity with the current Python version, with
these additions:

- `-doas` runs rsync through doas
- logs refusals as well as transfers
- passes `--confine-root` and `--drop-D` on rsync 3.5.0 and later
- waits at most 60 seconds for another rrsync's lock, then refuses
- uses pledge/unveil on OpenBSD

Options: `-ro` (read-only), `-wo` (write-only), `-munge` (store symlinks
munged, so a pushed link cannot point outside the directory), `-no-del`,
`-no-lock`, `-no-overwrite`, `-absolute`, `-doas`. Recommended: `-ro` for
backup keys (rsnapshot), and `-wo -munge` for keys that only push (for example
distribute.pl's).

rrsync logs to `~_rsyncu/rrsync.log` only if that file already exists; create
it, owned by `_rsyncu` and mode 0600, to turn logging on.

**Usage in authorized_keys**:
```
command="/usr/local/bin/rrsync -ro /data/backups",restrict ssh-ed25519 AAAA... backup@client
```

---

### rsync-altroot.pl

Copies a running OpenBSD system to `/altroot` filesystems on a second disk,
for quick recovery of accidentally changed or deleted files from
/altroot/etc and similar locations. Useful as an additional layer of local
backup alongside rsnapshot. Less critical for VM-based systems where
snapshots are available, but still useful. Run as root.

It finds the devices for `/altroot`, `/altroot/var`, `/altroot/usr`,
`/altroot/usr/local`, `/altroot/home` and `/altroot/share` in `/etc/fstab`;
the lines may be commented out, so the disk is not mounted at boot. It then:

- mounts each one whose source directory exists (`-m`),
- rsyncs `/bin`, `/etc`, `/root`, `/sbin`, the kernels and the other root
  directories into `/altroot` (only if `/altroot` has an fstab entry), and
  `/var`, `/usr` (including `/usr/local`), `/home` and `/share` into their
  filesystems, with `--delete` (`-r`),
- unmounts them (`-u`).

With no options it does all three. It refuses to rsync into a filesystem
that is not mounted. It exits 1 if any rsync or unmount failed. The copy is
not bootable (no `/dev`).

---

## Installation

### Recommended: OpenBSD signed package

Put the public key in `/etc/signify` first, so pkg_add can check the
signature:
```
pkg_add ./rsync-tools-<version>.tgz
```

Or using [install.pl](https://github.com/lippard661/distribute) on OpenBSD,
Linux, or macOS, copy the signed package to /var/install (or
/var/installation on macOS) and run install.pl.

The package is signed with signify. To verify it by hand:
```
signify -Vz -p discord.org-2026-pkg.pub -x rsync-tools-<version>.tgz -m /dev/null
```
Public key: https://www.discord.org/lippard/software/discord.org-2026-pkg.pub

### Manual installation

```sh
# Copy scripts to /usr/local/bin/
cp src/rsync-client.pl src/rsync-altroot.pl src/rrsync /usr/local/bin/
ln -s /usr/local/bin/rsync-client.pl /usr/local/bin/rsync-server.pl
chmod 755 /usr/local/bin/rsync-client.pl /usr/local/bin/rsync-altroot.pl /usr/local/bin/rrsync

# Create _rsyncu user and group _rsyncu (OpenBSD; -g =uid makes the group)
useradd -m -g =uid -d /home/_rsyncu -s /bin/sh _rsyncu

# Create _rsyncu user and group _rsyncu (Linux)
useradd -m -U -d /home/_rsyncu -s /bin/sh _rsyncu

# macOS: create the user and group with sysadminctl or dscl. rsync-client.pl
# finds the home directory from the password database; rrsync expects
# /home/_rsyncu.

# SSH key for _rsyncu
su _rsyncu -c 'mkdir -p -m 700 ~/.ssh && ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519'

# Create config directory
mkdir -p /etc/rsync
chown root:_rsyncu /etc/rsync
chmod 750 /etc/rsync

# Create config file
touch /etc/rsync/rsync.conf
chown root:_rsyncu /etc/rsync/rsync.conf
chmod 640 /etc/rsync/rsync.conf

# Optional: turn on rrsync logging
install -o _rsyncu -g _rsyncu -m 600 /dev/null /home/_rsyncu/rrsync.log
```

Add each server's host key to `/home/_rsyncu/.ssh/known_hosts`. Transfers
that use doas/sudo also check host keys against this file.

## Platform Support

- **OpenBSD**: Full support including pledge/unveil
- **Linux**: Full support (without pledge/unveil). rsync-altroot.pl is
  written for OpenBSD's layout.
- **macOS**: Supported (without pledge/unveil). Install rsync 3.5 or later
  from Homebrew (used when present; `/usr/bin/rsync` is openrsync or 2.6.9),
  or set `RSYNC_PRE35`.

Not tested on FreeBSD or other platforms, though it may work.

## Security Notes

- rsync.conf must be 0640 root:_rsyncu and /etc/rsync 0750 root:_rsyncu;
  the scripts refuse any other mode or owner
- rsync.conf reveals network topology and sync relationships; protect it
  accordingly
- A `*` is allowed in the last component of a path (not in directory names).
  It is expanded only in source-dirlist, and not where source-sudo is yes
  (the unprivileged user could not list the directory); the config is
  rejected if both are set
- Use ED25519 SSH keys. Without `ssh-identity:`, the scripts use
  `~_rsyncu/.ssh/id_ed25519`, then `id_ecdsa`; RSA and DSA keys are not
  looked for
- Use different SSH keys for different sync relationships
- Monitor `~_rsyncu/rsync.out` for lines containing "SECURITY", "Disallowed"
  and "failed", and `~_rsyncu/rrsync.log` for "DENIED". Text from the
  client is logged with control characters escaped, so it cannot forge
  lines

## Related Tools

These tools are part of a set of security tools for OpenBSD (and Linux/macOS):

- [syslock](https://github.com/lippard661/syslock) — filesystem immutability flag management
- [distribute](https://github.com/lippard661/distribute) — uses rrsync/_rsyncu for secure file distribution
- [reportnew](https://github.com/lippard661/reportnew) — log monitoring; monitors _rsyncu activity
- [sigtree](https://github.com/lippard661/sigtree) — file integrity monitoring

## Development History

rsync-client.pl was originally written in January 2003 and has been
maintained since then:

- 2003: Initial release with DSA key support
- 2012: Added ECDSA support
- 2015: Added ED25519 support, doas support
- 2022: rrsync adopted from the rsync distribution
- 2023: Added OpenBSD pledge/unveil support
- 2024: Enhanced path validation
- 2025: Removed DSA support
- 2026: Removed remaining shell invocations, added runtime config
  validation and security logging, removed RSA support, rsync 3.5.0
  hardening (`--confine-root`); in October, ssh command passed in argv
  instead of RSYNC_RSH, exit statuses checked, rrsync option-parsing fix

## Author

Jim Lippard  
https://www.discord.org/lippard/  
https://github.com/lippard661

rrsync is derived from the rrsync in the rsync distribution, by Joe Smith
and Wayne Davison.

## License

See LICENSE and individual files for license information.

## Changelog

See docs/ChangeLog for detailed modification history.
