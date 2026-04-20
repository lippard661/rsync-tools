# rsync-tools

A collection of Perl scripts for secure, automated rsync operations using an unprivileged user account. These tools implement defense-in-depth security through file permissions, SSH key restrictions, sudo/doas controls, and OpenBSD's pledge/unveil when available.

## Tools Included

### rsync-client.pl / rsync-server.pl

**Purpose**: Automated rsync between systems using a non-privileged `_rsyncu` user, with optional privilege escalation via sudo/doas only for specific operations.

**Key Features**:
- **Defense-in-depth security model**: Multiple layers of protection including unprivileged execution, config file validation, SSH restrictions, and sudo/doas controls
- **Flexible operations**: Support for push, pull, and bidirectional sync
- **Setup/cleanup hooks**: Run commands before and after each rsync operation
- **OpenBSD security**: Uses pledge() and unveil() on OpenBSD systems
- **Comprehensive logging**: All operations and security violations logged with source IP
- **Config file validation**: Runtime checks ensure proper ownership (root:_rsyncu) and permissions (0640)
- **Path validation**: Prevents directory traversal and restricts to absolute paths only

**Security Model**:

The security model employs multiple independent layers:

1. **Unprivileged user**: `_rsyncu` user cannot modify system files or config
2. **Config file restrictions**: Must be owned by root:_rsyncu with mode 0640, validated at runtime
3. **SSH key restrictions**: `authorized_keys` limits commands and source IPs
4. **Sudo/doas controls**: Only specific rsync commands can be elevated
5. **Path validation**: All paths must be absolute, no directory traversal allowed
6. **OpenBSD pledge/unveil**: Restricts system calls and filesystem access

**Configuration Example**:

```
# /etc/rsync/rsync.conf
source: backupserver
destination: mailserver
source-dirlist: /var/mail/, /etc/mail/
destination-dirlist: /backup/mail/, /backup/mail-config/
rsync-options: --delete --delete-after, --delete --delete-after
source-sudo: no, no
destination-sudo: yes, yes
```

**Required File Permissions**:
```bash
# Config directory
chown root:_rsyncu /etc/rsync
chmod 750 /etc/rsync

# Config file  
chown root:_rsyncu /etc/rsync/rsync.conf
chmod 640 /etc/rsync/rsync.conf

# Optional: Set immutable flag for additional protection
chflags schg /etc/rsync/rsync.conf  # FreeBSD/OpenBSD
chattr +i /etc/rsync/rsync.conf     # Linux
```

**SSH Configuration**:

On the server side in `~_rsyncu/.ssh/authorized_keys`:
```
command="/usr/local/bin/rsync-server.pl pull clienthost",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ssh-ed25519 AAAA... _rsyncu@client
```

**Sudo/Doas Configuration**:

Allow specific rsync commands only:
```
# /etc/sudoers (or /etc/doas.conf)
Defaults:_rsyncu env_keep += "RSYNC_RSH"
Cmnd_Alias RSYNC_CMDS = /usr/local/bin/rsync --server --sender -vlogDtprze.iLsfxCIvu * . /data/*, \
                        /usr/local/bin/rsync --server -vlogDtprze.iLsfxCIvu * . /backup/*
_rsyncu ALL=(ALL) NOPASSWD: RSYNC_CMDS
```

**Usage**:
```bash
# Client side
rsync-client.pl pull server-hostname
rsync-client.pl push server-hostname
rsync-client.pl both server-hostname

# Server side (typically invoked via SSH authorized_keys)
rsync-server.pl pull client-hostname
rsync-server.pl push client-hostname
```

**Supported SSH Key Types** (in priority order):
1. ED25519 (preferred)
2. ECDSA (fallback)
3. ~~RSA (deprecated - no longer supported)~~

---

### rrsync

**Purpose**: Restrict rsync operations via SSH `authorized_keys` forced commands. Can enforce read-only access or limit operations to specific directories.

**Key Features**:
- **Perl implementation**: Updated to include feature parity with the newer Python version included with rsync distributions
- **OpenBSD security**: Uses pledge() and unveil() when available
- **Flexible restrictions**: Can restrict to read-only or specific directory paths
- **Drop-in replacement**: Compatible with the standard rrsync interface

**Usage**:

In `~user/.ssh/authorized_keys`:
```
command="rrsync -ro /data/backups" ssh-ed25519 AAAA... backup@client
```

This restricts the key to read-only access to `/data/backups` only.

---

### rsync-altroot.pl

**Purpose**: Tool for backing up to `/altroot` on usually-unmounted filesystems on a local machine.

**Key Features**:
- **Safe mounting**: Handles mounting and unmounting of backup filesystems
- **Local backups**: Optimized for local machine backup workflows
- **Altroot convention**: Follows OpenBSD's `/altroot` backup convention

**Use Case**: maintaining a local backup on a separate filesystem that remains unmounted except during backup operations, providing protection against:
- Accidental deletion
- Filesystem corruption affecting the primary filesystem

---

## Installation

### From Source

```bash
# Download
wget https://www.discord.org/lippard/software/rsync-tools-20260419.tgz

# OpenBSD package (can be installed on OpenBSD with pkg_add; on OpenBSD, Linux or macOS with install.pl)
wget https://www.discord.org/lippard/software/OpenBSD-packages/rsync-tools-20260419.tgz

# Verify signature (optional but recommended for OpenBSD package)
wget https://www.discord.org/lippard/software/discord.org-2026-pkg.pub
signify -C -p discord.org-2026-pkg.pub -x rsync-tools-20260419.tgz

# Extract
tar xzf rsync-tools-20260419.tgz
cd rsync-tools-20260419

# Install scripts
sudo cp rsync-client.pl /usr/local/bin/
sudo ln -s /usr/local/bin/rsync-client.pl rsync-server.pl
sudo cp rsync-altroot.pl /usr/local/bin/
sudo cp rrsync /usr/local/bin/
sudo chmod 755 /usr/local/bin/rsync-*.pl /usr/local/bin/rrsync

# Create rsync user
sudo useradd -m -d /home/_rsyncu -s /bin/sh _rsyncu  # Linux
sudo useradd -m -d /home/_rsyncu -s /bin/sh _rsyncu  # OpenBSD/FreeBSD

# Create config directory
sudo mkdir -p /etc/rsync
sudo chown root:_rsyncu /etc/rsync
sudo chmod 750 /etc/rsync
```

### OpenBSD Package

```bash
# Install the signed package
pkg_add rsync-tools-20260419.tgz
```

## Platform Support

- **OpenBSD**: Full support including pledge() and unveil()
- **Linux**: Full support (without pledge/unveil)
- **Other Unix-like**: Should work but untested

## Security Best Practices

### 1. File Permissions

Always maintain strict file permissions:
```bash
# Config directory: 0750 root:_rsyncu
# Config file: 0640 root:_rsyncu
# SSH directory: 0700 _rsyncu:_rsyncu
# Private keys: 0600 _rsyncu:_rsyncu
# Log file: 0600 _rsyncu:_rsyncu (created automatically)
```

### 2. SSH Key Restrictions

Use `command=`, `from=`, and other restrictions in `authorized_keys`:
```
command="/usr/local/bin/rsync-server.pl pull client",from="192.168.1.100",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ssh-ed25519 AAAA...
```

### 3. Sudo/Doas Configuration

Only allow specific rsync commands with explicit paths:
- Never use wildcards in sudo rules beyond what's shown
- Each rsync operation should have its own specific rule
- Use command aliases to organize related operations

### 4. Immutability Flags

Set immutable flags on config files:
```bash
chflags schg /etc/rsync/rsync.conf  # BSD
chattr +i /etc/rsync/rsync.conf     # Linux
```

This prevents modification even by root until the flag is removed.

### 5. Monitoring

- Monitor `~_rsyncu/rsync.out` for security violations
- Look for lines containing "SECURITY" 
- Alert on repeated violations from the same IP
- Review logs regularly for unusual activity

### 6. Key Management

- Use ED25519 keys (RSA deprecated)
- Use different keys for different purposes (backup, replication, etc.)
- Rotate keys annually or after personnel changes
- Remove old `authorized_keys` entries immediately

## Troubleshooting

### "SECURITY: Config file must have permissions 0640"
Fix permissions:
```bash
sudo chmod 640 /etc/rsync/rsync.conf
```

### "SECURITY: Config directory must be group-owned by _rsyncu"
Fix ownership:
```bash
sudo chown root:_rsyncu /etc/rsync
```

### "Cannot find .ssh/(ed25519|ecdsa)_id"
Generate an ED25519 key:
```bash
su - _rsyncu
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""
```

### "Configuration file has invalid dir"
Ensure all paths in config file:
- Start with `/` (absolute paths only)
- Don't contain `..` (no directory traversal)
- Use only `[A-Za-z0-9._/-]` and `*` (in filenames only)

## Testing Your Setup

```bash
# Test config validation
chmod 644 /etc/rsync/rsync.conf
rsync-client.pl pull server  # Should fail with SECURITY error
chmod 640 /etc/rsync/rsync.conf

# Test SSH key restrictions
ssh -i ~_rsyncu/.ssh/id_ed25519 server "ls /"  # Should be rejected

# Test sudo restrictions  
sudo rsync --server -vlogDtprze.iLsfxCIvu . /etc/  # Should fail if not in sudoers

# Test actual rsync
rsync-client.pl pull server  # Should work if config is correct
```

## Development History

Originally written in 2003, these tools have been continuously maintained and updated to incorporate modern security practices:

- **2003**: Initial release with DSA key support
- **2012**: Added ECDSA support
- **2015**: Added ED25519 support, doas support
- **2023**: Added OpenBSD pledge/unveil support
- **2024**: Enhanced path validation, removed shell invocations
- **2025**: Removed DSA support
- **2026**: Added runtime config validation, enhanced security logging, removed RSA support

## License

These tools are open source, see LICENSE in repo.

## Changelog

See docs/CHANGELOG and individual script headers for detailed modification history.

**Latest Release (20260419)**:
- Runtime config file validation with ownership and permission checks
- Security event logging with source IP tracking
- Enhanced error messages using actual system errors ($!)
- Improved path validation
- Updated documentation
