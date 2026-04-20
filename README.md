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
optional privilege escalation via doas (or sudo on Linux/macOS) only for
specific operations. rsync-server.pl is installed as a symlink to
rsync-client.pl.

**Key Features**:
- Unprivileged execution with narrow doas/sudo permissions for rsync only
- Config file validated at runtime for correct ownership and permissions
- SSH key restrictions via authorized_keys forced commands
- Setup and cleanup hooks: run commands before and after each rsync operation
- Comprehensive logging of all operations and security events
- Path validation: absolute paths only, no directory traversal
- Uses pledge/unveil on OpenBSD

**Security Model**:

1. `_rsyncu` user cannot modify system files or config
2. Config file must be owned root:_rsyncu with mode 0640, validated at runtime
3. authorized_keys restricts each SSH key to a specific command and source host
4. doas/sudo permits only specific rsync commands, not arbitrary escalation
5. All paths must be absolute; directory traversal rejected
6. pledge/unveil on OpenBSD restricts system calls and filesystem access

**Configuration**:

`/etc/rsync/rsync.conf` on both client and server defines what is synced,
which SSH identity to use, whether doas/sudo is required on either side,
and optional pre/post commands for setup and cleanup. Example:

```
source: backupserver
destination: mailserver
source-dirlist: /var/mail/, /etc/mail/
destination-dirlist: /backup/mail/, /backup/mail-config/
rsync-options: --delete --delete-after, --delete --delete-after
source-doas: no, no
destination-doas: yes, yes
```

**Required File Permissions**:
```
/etc/rsync/           root:_rsyncu  0750
/etc/rsync/rsync.conf root:_rsyncu  0640
```

Consider protecting rsync.conf with immutability flags via
[syslock](https://github.com/lippard661/syslock) on OpenBSD/Linux, since
the config file describes your network topology and sync relationships.

**SSH authorized_keys**:

On the server, restrict each key to a specific command and source address:
```
command="/usr/local/bin/rsync-server.pl pull clienthost",from="203.0.113.10",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ssh-ed25519 AAAA... _rsyncu@client
```

**doas Configuration** (OpenBSD `/etc/doas.conf`):
```
permit nopass setenv { RSYNC_RSH } _rsyncu as root cmd /usr/local/bin/rsync args --server --sender ...
```

**Usage**:
```
rsync-client.pl pull server-hostname
rsync-client.pl push server-hostname
rsync-client.pl both server-hostname
```
Server side is typically invoked via SSH authorized_keys, not directly.

---

### rrsync

Restrict rsync operations via SSH `authorized_keys` forced commands. A Perl
implementation with feature parity with the Python rrsync distributed with
rsync, plus logging and OpenBSD pledge/unveil support.

Can enforce read-only access, limit operations to a specific directory, or
both. Used with an unprivileged `_rsyncu` user for rsnapshot backups and
distribute.pl file distribution.

**Usage in authorized_keys**:
```
command="rrsync -ro /data/backups",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ssh-ed25519 AAAA... backup@client
```

---

### rsync-altroot.pl

Syncs a running system to an `/altroot` filesystem on a local machine,
following OpenBSD's altroot convention. Handles mounting and unmounting
safely. Useful as an additional layer of local backup alongside rsnapshot,
and for quick recovery of accidentally deleted files from /altroot/etc and
similar locations. Less critical for VM-based systems where snapshots are
available, but still useful.

---

## Installation

### Recommended: OpenBSD signed package

```
pkg_add ./rsync-tools-20260419.tgz
```

Or using [install.pl](https://github.com/lippard661/distribute) on OpenBSD,
Linux, or macOS, copy the signed package to /var/install (or
/var/installation on macOS) and run install.pl.

The OpenBSD package is signed with signify. To verify:
```
signify -C -p discord.org-2026-pkg.pub -x rsync-tools-20260419.tgz
```
Public key: https://www.discord.org/lippard/software/discord.org-2026-pkg.pub

### Manual installation

```sh
# Copy scripts to /usr/local/bin/
cp src/rsync-client.pl src/rsync-altroot.pl src/rrsync /usr/local/bin/
ln -s /usr/local/bin/rsync-client.pl /usr/local/bin/rsync-server.pl
chmod 755 /usr/local/bin/rsync-client.pl /usr/local/bin/rsync-altroot.pl /usr/local/bin/rrsync

# Create _rsyncu user (OpenBSD)
useradd -m -d /home/_rsyncu -s /bin/sh _rsyncu

# Create _rsyncu user (Linux)
useradd -m -d /home/_rsyncu -s /bin/sh _rsyncu

# Create config directory
mkdir -p /etc/rsync
chown root:_rsyncu /etc/rsync
chmod 750 /etc/rsync

# Create config file
touch /etc/rsync/rsync.conf
chown root:_rsyncu /etc/rsync/rsync.conf
chmod 640 /etc/rsync/rsync.conf
```

## Platform Support

- **OpenBSD**: Full support including pledge/unveil
- **Linux**: Full support (without pledge/unveil)
- **macOS**: Supported (without pledge/unveil)

Not tested on FreeBSD or other platforms, though it may work.

## Security Notes

- Config files should be root-readable only (0640 root:_rsyncu for
  rsync.conf; consider 0600 root:root for files not needing group access)
- rsync.conf reveals network topology and sync relationships; protect it
  accordingly
- Use ED25519 SSH keys; RSA is no longer supported, DSA was removed in 2025
- Use different SSH keys for different sync relationships
- Monitor `~_rsyncu/rsync.out` for lines containing "SECURITY"

## Related Tools

These tools are part of a set of security tools for OpenBSD (and Linux/macOS):

- [syslock](https://github.com/lippard661/syslock) — filesystem immutability flag management
- [distribute](https://github.com/lippard661/distribute) — uses rrsync/_rsyncu for secure file distribution
- [reportnew](https://github.com/lippard661/reportnew) — log monitoring; monitors _rsyncu activity
- [sigtree](https://github.com/lippard661/sigtree) — file integrity monitoring

## Development History

Originally written January 2003. Continuously maintained since then:

- 2003: Initial release with DSA key support
- 2012: Added ECDSA support
- 2015: Added ED25519 support, doas support
- 2023: Added OpenBSD pledge/unveil support
- 2024: Enhanced path validation, removed shell invocations
- 2025: Removed DSA support
- 2026: Added runtime config validation, enhanced security logging, removed RSA support

## Author

Jim Lippard  
https://www.discord.org/lippard/  
https://github.com/lippard661

## License

See LICENSE and individual files for license information.

## Changelog

See docs/ChangeLog for detailed modification history.
