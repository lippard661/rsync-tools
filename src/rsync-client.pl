#!/usr/bin/perl

# Written 2003-01-14 by Jim Lippard.
# Modified 2003-02-13 by Jim Lippard to add "both" function.
# Modified 2003-05-25 by Jim Lippard to use rsync user identity even
#    when client is root (sudo).
# Modified 2003-05-26 by Jim Lippard to add setup/cleanup for source/dest.
# Modified 2003-06-15 by Jim Lippard to make source and destination sudo
#    per-directory.  (Currently, if there are multiple rsyncs to the same
#    directory, they need to have the same settings on the server side, as
#    it will always match the first occurrence.)  Did the same for setup/cleanup.
# Modified 2003-11-05 by Jim Lippard to fix bug where cleanup didn't work on the
#    server side.
# Modified 2004-11-15 by Jim Lippard to allow use of --relative (which changes
#    the options required on the server side), which is needed so that
#    --no-implied-dirs can be used in config file.
# Modified 2008-11-10 by Jim Lippard to support new options in rsync 3.0.  It
#    might be nice to use rrsync as a base for the server side.
# Modified 2009-12-31 by Jim Lippard to use ssh -vv when $DEBUG=1.
# Modified 2011-12-20 by Jim Lippard to use _rsyncu user to avoid
#    conflict with OpenBSD's name for the _rsync daemon.
# Modified 2012-01-03 by Jim Lippard to support ECDSA and RSA
#    identities as well as DSA (priority: ECDSA, DSA, RSA).
# Modified 2014-05-10 by Jim Lippard to support option change in rsync 3.1.
# Modified 2014-11-22 by Jim Lippard to support option change in rsync 3.1.1.
# Modified 2015-10-18 by Jim Lippard to support doas and sudo.
# Modified 2015-10-23 by Jim Lippard to support ED25519 identities.
# Modified 2016-01-30 by Jim Lippard to support option change in rsync 3.1.2.
# Modified 2021-03-26 by Jim Lippard to add a configuration option to specify
#    ssh-identity per setup (since restricting allowed commands allows only
#    a single command per remote host per identity used).
# Modified 2021-07-18 by Jim Lippard to fix path through code that led to
#    uninitialized ssh_identity.
# Modified 2021-10-12 by Jim Lippard to move config file to /etc in preparation
#    for making this a package. Also clean up configuration processing logic.
# Modified 2022-02-14 by Jim Lippard to finally do the server side correctly
#    and not run twice with "both" in one invocation, just do what the client
#    expects the first time.
# Modified 2023-02-22 by Jim Lippard to die if the server side is invoked
#    and there is no SSH_ORIGINAL_COMMAND.
# Modified 2023-12-02 by Jim Lippard to use pledge and unveil on OpenBSD.
# Modified 2023-12-30 by Jim Lippard to call pledge correctly.
# Modified 2023-12-31 by Jim Lippard to expand unveil to cover
#    /usr/share/zoneinfo.
# Modified 2024-01-03 by Jim Lippard to use new perl open format.
# Modified 2024-02-10 by Jim Lippard to unveil setup/cleanup commands
#    properly (ignore ""/0).
# Modified 2024-07-09 by Jim Lippard to unveil /bin/sh if there's an *
#    in a dirlist, and to unveil containing dirs.
# Modified 2024-07-10 by Jim Lippard to add some minimal validation
#    on dirlists, restricting * to filenames (not directories) and
#    stopping unobfuscated directory traversal. The local config file
#    is still highly trusted and access should be restricted. Fixed bug
#    in client unveiling of paths and locking of unveil.
# Modified 2024-08-29 by Jim Lippard for error checking on all pledge calls.
# Modified 2024-10-08 by Jim Lippard to support new rsync 3.3.0 "s" option.
# Modified 2025-09-15 by Jim Lippard to support Linux rsync path.
# Modified 2025-09-25 by Jim Lippard to abort and complain if can't open
#    log file for writing. Removed DSA key option.
# Modified 2026-01-04 by Jim Lippard to remove @ from subroutine calls.
# Modified 2026-01-10 by Jim Lippard to break up setup/cleanup commands to
#    avoid shell.
# Modified 2026-01-11 by Jim Lippard to allow setup/cleanup commands to
#    contain multiple commands separated by semicolons.
# Modified 2026-02-06 by Jim Lippard to require absolute paths for dirs.
# Modified 2026-04-08 by Jim Lippard to fix cleanup command regex typo,
#    error in OS check for pledge/unveil for exec_server. Use File::Glob
#    instead of using shell. Simplify rsync execution logic for client and
#    server.
# Modified 2026-04-17 by Jim Lippard to validate config file ownership and
#    permissions and log failures, create log file with 0600 permissions.
# Modified 2026-04-19 by Jim Lippard to validate config file dir before
#    config file (since insufficient access on dir can prevent determination
#    if config file even exists).
# Modified 2026-04-29 by Jim Lippard to reject globs in sources where source-sudo
#    is 'yes' since those can't be expanded without privilege (which would either
#    require either using shell expansion or adding some helper cruft).
# Modified 2026-05-02 by Jim Lippard to clean up some minor errors: really remove
#    RSA SSH ID support this time, fix error message, make security_die calls
#    consistent, fix typo in error message, remove unused variable declarations
#    and some dead, commented-out code, document a couple limitations (no spaces in
#    command arguments, dir paths must be exactly consistent between client and server.
# Modified 2026-05-17 by Jim Lippard after Gemini security assessment which
#    claimed to find five security issues, all of which were bogus. Updated
#    comments to explain unveiling on setup-command/cleanup-command.
#    (Gemini claimed issues were (1) post-unveil traversal, based on
#    wrong assumption paths were from SSH_ORIGINAL_COMMAND instead of
#    config, (2) setgid denial of service on config directory, but
#    fail-closed is the intended design for a permissions error,
#    (3) server-side glob won't work, it does work and the suggested
#    change would break it, (4) confabulated stray brace at the end of
#    the script, (5) multiple commands in setup/cleanup unveil
#    "blind spot" based on false assumption that unveil environments
#    are propagated over system calls. No actual issues to fix.
# Modified 2026-05-31 by Jim Lippard to replace $RSYNC_IDENTITY constant with
#    $rsync_identity variable.
# Modified 2026-07-02 by Jim Lippard after Claude Opus 4.8 review:
#    Fix undefined behavior issue with $unveil_path, use block mode grep in
#    option match, report unveil errors, add dest-sudo glob config check,
#    improve option split to avoid leading space case. Left unfixed: system
#    return codes not checked.
#    Fix issue exposed by checking unveil errors, when sudo is used.
# Modified 2026-08-02 by Jim Lippard to update sudo locations
#    for OpenBSD (default), Linux, and macOS and now update rsync
#    location for macOS. Set $RSYNC_USER_HOME from getpwname (since
#    macOS uses /Users).
# Modified 2026-08-13 by Jim Lippard to inject --confine-root=<dir> into
#    rsync options by default, if the config doesn't already specify it,
#    for rsync versions >3.5.0.
# Modified 2026-10-15 by Claude Opus 5.5 at the direction of Jim Lippard
#    after a checklist review:
#    - Pass the ssh command to rsync as -e in argv instead of RSYNC_RSH. With
#      RSYNC_RSH passed through doas (setenv) or sudo (env_keep), _rsyncu could
#      run a whitelisted rsync command with its own RSYNC_RSH and so run any
#      program as root, with a doas log line identical to a normal one
#      (demonstrated with sudo and opendoas). The -e string now also gives ssh
#      -o UserKnownHostsFile=<_rsyncu's known_hosts>, since an elevated ssh
#      otherwise checks root's. Client-side elevated command lines change; see
#      Security note 3. Remove setenv { RSYNC_RSH } / env_keep RSYNC_RSH.
#    - Prefer doas when present, fall back to sudo (was: sudo whenever present).
#      Unveil the one in use only when a path in this pass needs it, and die
#      with a message if it is needed and neither exists.
#    - Escape control characters in client-supplied text written to the log,
#      so a newline in SSH_ORIGINAL_COMMAND cannot forge log lines.
#    - Config lists accept "," with or without following whitespace; lines
#      holding only whitespace are treated as blank.
#    - In "both" mode on OpenBSD, unveil a configured ssh-identity before the
#      second pass tests it (the first pass's unveils are already in force).
#    - Check exit statuses. Client: a failed setup skips that item's rsync
#      (its cleanup still runs), a failed rsync or cleanup is reported, the
#      remaining items still run, and the exit status is 1 if anything
#      failed. rsync exit 24 (source files vanished during the transfer) is
#      reported but not counted. A ";" chain stops at its first failure.
#      Server: a failed setup skips the rsync; a failed rsync is logged as
#      "Command failed (<reason>): ..." instead of "Command executed: ...";
#      the exit status is rsync's, or 1 for a disallowed command, path or
#      options or a failed setup or cleanup (it was always 0).
#    - Accept -vlogDtprze.LsfxCIvu, the server option string a client sends
#      for a pull with --delete-after or --delete-before (they turn off
#      incremental recursion, so no "i"); such pulls were refused as a
#      disallowed option (shown with rsync 3.2.7 and 3.5.1).
#    - Documentation: the config list format, the doas/sudo command forms
#      (including --confine-root on the server side), the key types. The
#      2026-08-13 entry's "if the config doesn't already specify it" has no
#      code behind it and needs none: rsync does not forward --confine-root
#      from client to server, so a --confine-root in rsync-options only
#      confines the client's own rsync.
#
# NOTE:
# rsync 3.5.0 portable hardening (skipped on pre-3.5 hosts). The exec'd rsync
# (sudo/doas or direct) does not inherit this script's unveil, so --confine-root
# is the only in-script confinement of the transfer's own path resolution.
#
# It closes two 3.5.0 CVE classes that this script's exact-path allow-list
# never sees, because both bypass argv:
#   1. Filter/dir-merge file paths travel over the protocol, not in the matched
#      command, so server_options_match cannot inspect them. An exclude-only
#      merge naming an out-of-tree file leaks its content (CVE-2026-53783
#      merge-open route). A daemon confines this via its module root; this
#      wrapper confines it via --confine-root set to the matched path's dir.
#   2. Absolute option paths (--temp-dir, --link-dest, --partial-dir,
#      --backup-dir, etc.): in 3.5.0 the rsync binary confines its own
#      resolution of these (CVE-2026-53795, -70460), and --confine-root ensures
#      that confinement is anchored at THIS transfer's restricted directory
#      rather than left to rsync's default.

# To Do:  Add "label" distinct from hostname, because there may be hosts behind
#   firewalls with different external names (or no external name at all) rsyncing
#   with hosts outside the firewall.  This may also allow a solution to the
#   problem with issuing multiple server commands... but maybe not (since we want
#   to have only a single command from a single host in the authorized_keys2 file).
#   (This can be done either by using different SSH keys for different commands
#   or issuing the commands via a filtering script that allows the different
#   desired options.)
# This functionality already exists, but only by sacrificing the design goal of
#   being able to use one and the same config file for all hosts (or at least for
#   both sides of a connection).

# Future enhancement:  Config file place restrictions on push/pull.  Accidents
#    are already avoided if you use the command= setting in the authorized_keys2
#    file, but another layer of protection is worthwhile.  The command= setting
#    may not be an option in some cases--e.g., where some things are being synched
#    in each direction between the same two machines.
#  Allow keywords to choose which sets of things to sync.
#  "both" attempts each direction for the same directories on the server side...
#      this is an error; it needs to make decisions based on the SSH command received.

# Script to allow rsync between machines using a non-privileged rsync user.
# This is a genericized version of a script originally written 2002-08-16 (same author).

# The current version requires local hostnames only, with no domain names
# in the config file.  To change, modify this script so that $HOSTNAME retains
# the full hostname rather than omitting the domain portion.

# Security:
# 1. Use an unprivileged rsync user with a passwordless SSH ED25519 (or ECDSA)
#    key as the initiator (client side) of the rsync, when possible.
#
# 2. Use an authorized_keys2 file on the server side which specifies a
#    specific command (calling this script with the appropriate arguments)
#    and a specific host (the host expected to be on the other side).
#    Set permissions and ownership on the authorized_keys2 file so that
#    the rsync user cannot modify it or anything else in its .ssh directory.
#    (Manually update its known_hosts file.)
#
# 3. Permit only the specific rsync commands needed, with their exact arguments,
#    in doas.conf ("cmd ... args ...") or sudoers. doas is used when installed,
#    sudo otherwise. A rule for rsync without its arguments lets _rsyncu run
#    rsync as root with any arguments, which is root access. Pass no environment
#    through (no setenv/keepenv for doas, no env_keep for sudo): rsync runs
#    whatever RSYNC_RSH names, so passing it through also gives root access.
#
#    On the server side, when using "pull" (source), the command is:
#      $RSYNC --server --sender --confine-root=<dir> -vlogDtprze.iLsfxCIvu <rsync options> . <source path>
#    and when using "push" (destination):
#      $RSYNC --server --confine-root=<dir> -vlogDtprze.iLsfxCIvu <rsync options> . <dest path>
#    where <dir> is the path itself if it ends in "/", else its parent directory
#    (--confine-root is omitted when RSYNC_PRE35 is set or <dir> is "/"). The
#    -vlogDtprze... string varies with the client's rsync version (see
#    @POSSIBLE_SERVER_OPTIONS). A source path with a * is expanded, so the
#    command carries the matching files in place of the pattern.
#
#    On the client side, when using "push" (source):
#      $RSYNC -avz -e "<rsh>" <rsync options> <source path(s)> $RSYNC_USER@<dest host>:<dest path>
#    and when using "pull" (destination):
#      $RSYNC -avz -e "<rsh>" <rsync options> $RSYNC_USER@<source host>:<source path> <dest path>
#    where <rsh> is one argument:
#      $SSH -i <identity> -o UserKnownHostsFile=$RSYNC_USER_SSHDIR/known_hosts
#    (with -vv after $SSH when $DEBUG is set, which will not match the rules).
#    For example, in doas.conf (quotes make the rsh one argument):
#      permit nopass _rsyncu as root cmd /usr/local/bin/rsync args -avz -e "/usr/bin/ssh -i /home/_rsyncu/.ssh/id_ed25519 -o UserKnownHostsFile=/home/_rsyncu/.ssh/known_hosts" /etc/pf.conf _rsyncu@backup:/backup/pf.conf
#    doas logs it with the argv joined by single spaces, no quotes:
#      _rsyncu ran command /usr/local/bin/rsync -avz -e /usr/bin/ssh -i /home/_rsyncu/.ssh/id_ed25519 -o UserKnownHostsFile=/home/_rsyncu/.ssh/known_hosts /etc/pf.conf _rsyncu@backup:/backup/pf.conf as root from <cwd>
#    In sudoers, a "," ":" "=" or "\" in an argument must be escaped with a
#    backslash (UserKnownHostsFile\=..., <host>\:<path>). It is recommended that
#    the commands be put into a command alias such as
#       Cmnd_Alias RSYNC_CMDS = <comma-separated list of commands>
#
#    The SSH identity used is the rsync user's in all cases, and the elevated
#    ssh checks host keys against the rsync user's known_hosts.
#
# 4. The server side script will only permit rsync for pathnames that are in the appropriate
#    entry in the config file.  Make sure the ownership and permissions on the config file
#    are restricted to read-only for the rsync user.
#
# It can be helpful to use separate SSH keys for push and pull operations,
# splitting them out in the authorized_keys file accordingly and specifying
# the identity to use in the ssh-identity field of the config file.
#
# NOTE: Earlier versions passed the ssh command in RSYNC_RSH and needed
# "Defaults:_rsyncu env_keep += RSYNC_RSH" (sudo) or "setenv { RSYNC_RSH }"
# (doas). Remove those: see Security note 3.
#
# Note on pledge/unveil and doas/sudo:
# pledge/unveil restrict rsync-client.pl itself, but they are NOT inherited
# across the exec into a doas/sudo child -- that child starts without restrictions.
# For a "sudo: yes" transfer the actual restriction is therefore provided by
# sudo plus the sudoers command whitelist, not by unveil.
#
# Consequence for do_unveil: source/dest path resolution in this script runs
# as the unprivileged rsync user, BEFORE the elevated rsync is exec'd. For a
# "sudo: yes" path, that user often cannot traverse into the (root/group-owned)
# directory, so unveil fails -- even though the directory exists and the
# elevated rsync will access it fine. unveil reports this inaccessibility as
# either ENOENT or EPERM, never EACCES: ENOENT when a component of the path
# can't be resolved (by design, so it doesn't reveal what lies behind an
# inaccessible directory), EPERM when the path is unveilable but not accessible
# to the unprivileged user. do_unveil therefore tolerates both errnos, but only
# for "sudo: yes" paths; the elevated rsync provides the real access, and unveil
# could not have restricted that path here in any case.
# Thus do_unveil conditionally ignores ENOENT and EPERM for sudo/doas paths,
# but raises them for non-sudo paths, where such a failure indicates a config
# typo or a permissions problem that would cause the rsync to fail anyway.

# Usage:
#   On client side: 
#   rsync-client.pl [push|pull|both] server-hostname
#   On server side:
#   rsync-server.pl [push|pull|both] client-hostname

# "push" means that the client is the source and the server is the destination.
# "pull" means that the client is the destination and the server is the source.
# "both" means that all pushes, then all pulls will be performed as appropriate.
# If you use "push" on the client side you must use "push" on the server side.

# Configuration file format:
#
# # Comment.
# source: sourcehost
# destination: destinationhost
# source-dirlist: list, of, dirs, or, files
# destination-dirlist: list, of, dirs, or, files
# rsync-options: --delete --delete-after --exclude file --exclude file, --exclude file, ""
# [optional] ssh-identity: [ssh-identity-file]
# source-setup: commandline, commandline, commandline
# source-cleanup: commandline, commandline, commandline
# destination-setup: commandline, commandline, commandline
# destination-cleanup: commandline, commandline, commandline
# source-sudo: [yes|no], [yes|no], [yes|no]
# destination-sudo: [yes|no], [yes|no], [yes|no]

# All files will be rsynced between the two hosts.  The first matching config file entry
# is used, any further settings for the same pair of hosts in the same slots (source/destination)
# will be ignored.

# The number of comma-separated items in each source-sudo, destination-sudo, source-dirlist,
# destination-dirlist, source- and dest- setup and cleanup, and rsync-options list must be the same.
# Items are separated by "," with or without whitespace around it, so no item (path, option
# or command) can itself contain a comma.
# If a given directory or file requires no rsync options, use "".  If there are files  to be
# excluded for a given directory, use "--exclude file [--exclude file [...]]" for each file in that
# directory; commas separate the exclude file lists for each directory.  Other common options
# include --delete, --delete-after, --delete-excluded, --include, and --ignore-existing.  See
# rsync's man page for more info.

# If source-sudo is yes, the rsync command on the source will be issued with sudo.
# If destination-sudo is yes, the rsync command on the destination will be issued with sudo.
# This is necessary where the rsync user lacks read permission on the source or write permission
# on the destination.

# Setup commands will be executed before rsync, cleanup commands will be
# executed after the rsync. If a setup command fails, the rsync for that item
# is skipped; its cleanup command runs whatever happened. Commands in a ";"
# chain stop at the first one that fails. The client exits 1 if any setup,
# rsync (other than exit 24, vanished source files) or cleanup failed; the
# server exits with rsync's status, or 1 if it refused the command or a setup
# or cleanup failed.

# Note on OpenBSD: Setup/cleanup commands and all commands in
# semicolon-separated chains (e.g., "cmd1; cmd2; cmd3") have their binary
# paths automatically unveiled with rx permissions. Once executed, these
# commands run without unveil restrictions inherited from rsync-client.pl,
# so they can freely access any files their normal Unix permissions allow.
# rx is used instead of x alone to avoid mysterious failures when the
# commands themselves are being rsynced (e.g., as part of a backup).

### Required packages.

use strict;
use warnings;
use Errno qw( ENOENT EPERM ); # for do_unveil sub
use Fcntl qw(:DEFAULT :flock); # for logging
use File::Basename;
use File::Glob ':glob';
use Sys::Hostname;
use if $^O eq "openbsd", "OpenBSD::Pledge";
use if $^O eq "openbsd", "OpenBSD::Unveil";

### Global constants.

# Set to 1 on hosts still running rsync < 3.5.0 -- disables --confine-root
# injection, which do not exist before 3.5.0. On an all-3.5.0 fleet, leave at 0.
use constant RSYNC_PRE35 => 0;

my $DEBUG = 0;
my $USE_SUDO = 0;

my $RSYNC_USER = '_rsyncu';
my $RSYNC_USER_HOME = (getpwnam($RSYNC_USER))[7] || "/home/$RSYNC_USER";
my $RSYNC_USER_SSHDIR = "$RSYNC_USER_HOME/.ssh";
my $RSYNC_ED25519_IDENTITY = "$RSYNC_USER_SSHDIR/id_ed25519"; # preferred
my $RSYNC_ECDSA_IDENTITY = "$RSYNC_USER_SSHDIR/id_ecdsa";

my $CONFIG_FILE = '/etc/rsync/rsync.conf';
my $LOG_FILE = "$RSYNC_USER_HOME/rsync.out";

my $DOAS = '/usr/bin/doas';
my $RSYNC = '/usr/local/bin/rsync';
$RSYNC = '/usr/bin/rsync' if ($^O eq 'linux' || $^O eq 'darwin');
$RSYNC = '/opt/homebrew/bin/rsync' if ($^O eq 'darwin' && -e '/opt/homebrew/bin/rsync');
my $SUDO = '/usr/bin/sudo';
$SUDO = '/usr/local/bin/sudo' if ($^O eq 'openbsd'); # now a port and doas is preferred for OpenBSD
my $SSH = '/usr/bin/ssh';
my $ZONEINFO_DIR = '/usr/share/zoneinfo';

my $ALLOW_MULTIPLE = 1;

my $HOSTNAME = hostname();
my $DOMAIN = '';
($HOSTNAME, $DOMAIN) = split (/\./, $HOSTNAME, 2);

# Prefer doas; fall back to sudo only when doas is not installed.
if (!-x $DOAS && -x $SUDO) {
    $USE_SUDO = 1;
}
my $ELEVATE = $USE_SUDO ? $SUDO : $DOAS;
my $HAVE_ELEVATE = -x $ELEVATE; # tested here, before any unveil

my $CLIENT = 0;

if ($0 =~ /rsync-client.pl$/) {
    $CLIENT = 1;
}
elsif ($0 =~ /rsync-server.pl$/) {
    $CLIENT = 0;
}

my @POSSIBLE_SERVER_OPTIONS = ('-vlogDtprz',
			       '-vlogDtpRz',
			       '-vlogDtprze.',
			       '-vlogDtprze.i',
			       '-vlogDtprze.f',
			       '-vlogDtprze.if',
			       '-vlogDtprze.iLf',
			       '-vlogDtprze.iL',
			       '-vlogDtprze.iLfx',
			       '-vlogDtprze.iLfxC',
			       '-vlogDtprze.iLfxCIvu',
			       '-vlogDtprze.iLsfxCIvu',
			       '-vlogDtprze.LsfxCIvu');
# The "R" option is for --relative; the e.[i] options only appear after rsync 3.0.; .f only in rsync 3.0.7+
# I probably haven't made this work for 3.0 uses of --relative.
# The "L" option appeared with rsync 3.0.8.
# The "f" disappears in rsync 3.1.0.
# The "C" option appeared with rsync 3.1.2.
# the "s" option after the dot appeared with rsync 3.3.0.
# The "i" (incremental recursion) is absent for a pull with --delete-after or
# --delete-before, which turn incremental recursion off.

# For dirlist subroutine; could add other forms of validation in
# the future for rsync options, commands, etc.
my $VALIDATE_DIRLIST = 1;

### Variables.

my ($push, $both, $other_host, $source, $destination,
    @source_dirlist, @destination_dirlist, @rsync_options, $rsync_identity,
    $ssh_identity,
    @source_sudo, @destination_sudo,
    @source_setup, @source_cleanup, @dest_setup, @dest_cleanup,
    @setup_command, @cleanup_command, $idx);
my (@this_command);
my $unveil_started = 0; # set once the first unveil() call has been made (OpenBSD)
my $failures = 0;       # client: setups, rsyncs and cleanups that failed

# Client variables.
my ($source_info, $destination_info, @rsync_command);

# Server variables.
my (@allowed_prefix, @allowed_paths, $options, $need_sudo, $command, $time,
    $path, $allowed_this_path);

### Main program.

if ($#ARGV != 1) {
    if ($CLIENT) {
	die "Usage: $0 [push|pull] server-hostname\n";
    }
    else {
	die "Usage: $0 [push|pull] client-hostname\n";
    }
}

if ($ARGV[0] eq 'push') {
    $push = 1;
}
elsif ($ARGV[0] eq 'pull') {
    $push = 0;
}
elsif ($ARGV[0] eq 'both') {
    $push = 0;
    $both = 1;
}
else {
    die "Invalid argument \"$ARGV[0]\".  Must be \"push\" or \"pull\" or \"both\".\n";
}

$other_host = $ARGV[1];

# Validate config file ownership and permissions. There's a TOCTOU window between this
# check and parse_config, but config file should be owned by root (and immutable) if
# following best practices.
validate_config_file_security();

# Parse the config file, then execute client or server functions
# as necessary. If "both" on the client side, execute push, then
# parse the config file again and execute pull. If "both" on the
# server side, look in the SSH_ORIGINAL_COMMAND for --sender -- if
# present, do a pull, if not present, do a push.
if ($CLIENT) {
    # This could be a push or a pull, but if it's "both" it's a pull.
    # (Reversed the order on both in order to allow pledge to add
    # further restrictions after the pull.)
    parse_config();
    exec_client();
    # And so, with both, we now need to do a push.
    if ($both) {
	$push = 1;
	parse_config();
	exec_client();
    }
    if ($failures) {
	print STDERR "$failures operation(s) failed.\n";
	exit 1;
    }
    exit 0;
}
# server gets invoked twice if "both" is used, need to do what the
# client expects. [Should no longer be the case.]
else {
    $command = $ENV{'SSH_ORIGINAL_COMMAND'};
    if (defined ($command) && $command =~ /--sender/) {
	$push = 0;
    }
    else {
	$push = 1;
    }
    parse_config();
    exit (exec_server ());
}

### Subroutines.

# Find appropriate entry in configuration file.
# The logic here was horrible, such that optional items (e.g. cleanup) for
# an entry, if they came after all required items, would be ignored and
# processed as part of the next entry. The workaround was to make sure the
# last item for any entry was a required item. The better fix might have
# been to process all entries before finding the match, but we went with
# removing the "check_arg" code for the "source:" field and considering
# an entry to be complete once we hit the next "source:" field.
sub parse_config {
    my ($found_match, $have_source, $have_destination, $have_source_dirlist,
	$have_destination_dirlist, $have_rsync_options,$have_ssh_identity,
	$have_source_sudo, $have_destination_sudo,
	$have_source_setup, $have_source_cleanup,
	$have_dest_setup, $have_dest_cleanup, $next_source, $have_next_source);

    $found_match = 0;
    $have_source = 0;
    $next_source = "";
    $have_next_source = 0;
    $have_destination = 0;
    $have_source_dirlist = 0;
    $have_destination_dirlist = 0;
    $have_rsync_options = 0;
    $have_ssh_identity = 0;
    $ssh_identity = '';
    $have_source_sudo = 0;
    $have_destination_sudo = 0;
    $have_source_setup = 0;
    $have_source_cleanup = 0;
    $have_dest_setup = 0;
    $have_dest_cleanup = 0;

    open (CONFIG, '<', $CONFIG_FILE) || die "Cannot open config file. $CONFIG_FILE $!\n";
    while (<CONFIG>) {
	if (/^\s*(#|$)/) {
	}
	elsif (/^\s*source:\s+(.*)$/) {
	    if (!$have_source) {
		$source = $1;
		$have_source = 1;
	    }
	    else {
		$next_source = $1;
		$have_next_source = 1;
	    }
	}
	elsif (/^\s*destination:\s+(.*)$/) {
	    check_arg ('destination', $1, $have_destination);
	    $destination = $1;
	    $have_destination = 1;
	}
	elsif (/^\s*source-dirlist:\s+(.*)$/) {
	    check_arg ('source-dirlist', $1, $have_source_dirlist);
	    @source_dirlist = &dirlist ($1, $VALIDATE_DIRLIST);
	    $have_source_dirlist = 1;
	}
	elsif (/^\s*destination-dirlist:\s+(.*)$/) {
	    check_arg ('destination-dirlist', $1, $have_destination_dirlist);
	    @destination_dirlist = &dirlist ($1, $VALIDATE_DIRLIST);
	    $have_destination_dirlist = 1;
	}
	elsif (/^\s*rsync-options:\s+(.*)$/) {
	    check_arg ('rsync-options', $1, $have_rsync_options);
	    @rsync_options = &dirlist ($1);
	    $have_rsync_options = 1;
	}
	elsif (/^\s*ssh-identity:\s+(.*)$/) {
	    check_arg ('ssh-identity', $1, $have_ssh_identity);
	    $ssh_identity = $1;
	    $have_ssh_identity = 1;
	}
	elsif (/^\s*source-setup:\s+(.*)$/) {
	    check_arg ('source-setup', $1, $have_source_setup);
	    @source_setup = &dirlist ($1);
	    $have_source_setup = 1;
	}
	elsif (/^\s*source-cleanup:\s+(.*)$/) {
	    check_arg ('source-cleanup', $1, $have_source_cleanup);
	    @source_cleanup = &dirlist ($1);
	    $have_source_cleanup = 1;
	}
	elsif (/^\s*destination-setup:\s+(.*)$/) {
	    check_arg ('destination-setup', $1, $have_dest_setup);
	    @dest_setup = &dirlist ($1);
	    $have_dest_setup = 1;
	}
	elsif (/^\s*destination-cleanup:\s+(.*)$/) {
	    check_arg ('destination-cleanup', $1, $have_dest_cleanup);
	    @dest_cleanup = &dirlist ($1);
	    $have_dest_cleanup = 1;
	}
	elsif (/^\s*source-sudo:\s+(.*)$/) {
	    check_arg ('source-sudo', $1, $have_source_sudo);
	    @source_sudo = &yes_or_no_list ('source-sudo', $1);
	    $have_source_sudo = 1;
	}
	elsif (/^\s*destination-sudo:\s+(.*)$/) {
	    check_arg ('destination-sudo', $1, $have_destination_sudo);
	    @destination_sudo = &yes_or_no_list ('destination-sudo', $1);
	    $have_destination_sudo = 1;
	}
	else {
	    die "Invalid configuration statement \"$_\" in config file.\n";
	}

	if (($have_source && $have_next_source) || eof (CONFIG)) {

	    # Do we have all required items for an entry?
	    if ($have_source && $have_destination &&
		$have_source_dirlist && $have_destination_dirlist &&
		$have_rsync_options && $have_source_sudo && $have_destination_sudo) {
	    }
	    else {
		if ($have_source) {
		    if ($have_destination) {
			die "Configuration file does not have all required fields for entry with source $source and destination $destination.\n";
		    }
		    else {
			die "Configuration file does not have all required fields for entry with source $source and no destination.\n";
		    }
		}
		die "Configuration file does not have all required fields for an entry with no source or destination.\n";
	    }

	    # Validate that all dirlists have the same number of args.
	    if ($#source_dirlist != $#destination_dirlist) {
		die "Configuration file entry for source $source and destination $destination has differing numbers of source directories and destination directories.\n";
	    }
	    if ($#source_dirlist != $#rsync_options) {
		die "Configuration file entry for source $source and destination $destination has differing numbers of source directories and rsync options.\n";
	    }
	    if ($#source_dirlist != $#source_sudo) {
		die "Configuration file entry for source $source and destination $destination has differing numbers of source directories and source-sudo entries.\n";
	    }
	    if ($#source_dirlist != $#destination_sudo) {
		die "Configuration file entry for source $source and destination $destination has differing numbers of source directories and destination-sudo entries.\n";
	    }
	    if ($have_source_setup && $#source_dirlist != $#source_setup) {
		die "Configuration file entry for source $source and destination $destination has differing numbers of source directories and source-setup entries.\n";
	    }
	    if ($have_source_cleanup && $#source_dirlist != $#source_cleanup) {
		die "Configuration file entry for source $source and destination $destination has differing numbers of source directories and source-cleanup entries.\n";
	    }
	    if ($have_dest_setup && $#source_dirlist != $#dest_setup) {
		die "Configuration file entry for source $source and destination $destination has differing numbers of source directories and dest-setup entries.\n";
	    }
	    if ($have_dest_cleanup && $#source_dirlist != $#dest_cleanup) {
		die "Configuration file entry for source $source and destination $destination has differing numbers of source directories and dest-cleanup entries.\n";
	    }

	    # Validate glob + sudo combination
	    if ($have_source_sudo) {
		for (my $idx = 0; $idx <= $#source_dirlist; $idx++) {
		    if ($source_sudo[$idx] eq 'yes' && $source_dirlist[$idx] =~ /\*/) {
			die "Configuration error: source-dirlist entry \"$source_dirlist[$idx]\" contains glob pattern (*) but source-sudo is 'yes'.\n" .
			    "Glob expansion happens before privilege escalation, so the directory must be readable by $RSYNC_USER.\n" .
			    "Either: (1) make directory readable by $RSYNC_USER and set source-sudo to 'no', or (2) use explicit file paths instead of globs.\n";
		    }
		}
	    }
	    # Ditto for destination.
	    if ($have_destination_sudo) {
		for (my $idx = 0; $idx <= $#destination_dirlist; $idx++) {
		    if ($destination_sudo[$idx] eq 'yes' && $destination_dirlist[$idx] =~ /\*/) {
			die "Configuration error: destination-dirlist entry \"$destination_dirlist[$idx]\" contains glob pattern (*) but destination-sudo is 'yes'.\n" .
			    "Glob expansion happens before privilege escalation, so the directory must be readable by $RSYNC_USER.\n" .
			    "Either: (1) make directory readable by $RSYNC_USER and set destination-sudo to 'no', or (2) use explicit file paths instead of globs.\n";
		    }
		}
	    }

	    if (((($CLIENT && $push) || (!$CLIENT && !$push)) &&
		 ($HOSTNAME eq $source && $other_host eq $destination)) ||
		((($CLIENT && !$push) || (!$CLIENT && $push)) &&
		 ($HOSTNAME eq $destination && $other_host eq $source))) {
		$found_match = 1;
		last;
	    }
	    else {
		$have_source = 0;
		if ($have_next_source) {
		    $have_source = 1;
		    $source = $next_source;
		    $have_next_source = 0;
		    $next_source = "";
		}
		$have_destination = 0;
		$have_source_dirlist = 0;
		undef @source_dirlist;
		$have_destination_dirlist = 0;
		undef @destination_dirlist;
		$have_rsync_options = 0;
		undef @rsync_options;
		$have_ssh_identity = 0;
		$ssh_identity = '';
		$have_source_sudo = 0;
		undef @source_sudo;
		$have_destination_sudo = 0;
		undef @destination_sudo;
		$have_source_setup = 0;
		undef @source_setup;
		$have_source_cleanup = 0;
		undef @source_cleanup;
		$have_dest_setup = 0;
		undef @dest_setup;
		$have_dest_cleanup = 0;
		undef @dest_cleanup;
	    }
	}
    }
    close (CONFIG);

    if (!$found_match) {
	if ($DEBUG) {
	    if ($CLIENT) {
		print "DEBUG: hostname=$HOSTNAME, other_host=$other_host, CLIENT=$CLIENT, push=$push, both=$both\n";
	    }
	    else {
		$time = time();
		$time = localtime ($time);

		my $LOG = open_log_file_secure();

		print $LOG "$time $0 hostname=$HOSTNAME, other_host=$other_host, CLIENT=$CLIENT, push=$push, both=$both, No matching entry in config file.\n";
		close ($LOG);
	    }
	}
	die "No matching entry in config file. $CONFIG_FILE\n";
    }
}

# Client function.
sub exec_client {
    # In "both" mode the first pass's unveils are already in force (not yet
    # locked), so the file test below needs the configured identity unveiled.
    if ($^O eq 'openbsd' && $unveil_started && $ssh_identity ne '') {
	unveil ($ssh_identity, 'r') || die "Cannot unveil $ssh_identity: $!\n";
    }
    if ($ssh_identity ne '') {
	if (-e "$ssh_identity") {
	    $rsync_identity = $ssh_identity;
	}
	else {
	    die "Cannot find specified ssh-identity. $ssh_identity\n";
	}
    }
    elsif (-e $RSYNC_ED25519_IDENTITY) {
	$rsync_identity = $RSYNC_ED25519_IDENTITY;
    }
    elsif (-e $RSYNC_ECDSA_IDENTITY) {
	$rsync_identity = $RSYNC_ECDSA_IDENTITY;
    }
    else {
	die "Cannot find .ssh/(ed25519 ecdsa)_id. RSA and DSA keys are no longer supported.\n"
    }
    # The ssh command goes to rsync as -e in argv, so it is part of the command
    # line doas/sudo match and log. Never via RSYNC_RSH (see Security note 3).
    delete $ENV{'RSYNC_RSH'};
    my $rsh = ($DEBUG ? "$SSH -vv" : $SSH) .
	" -i $rsync_identity -o UserKnownHostsFile=$RSYNC_USER_SSHDIR/known_hosts";

    @rsync_command = ($RSYNC, '-avz', '-e', $rsh);

    if ($push) {
	$source_info = "";
	$destination_info = "$RSYNC_USER\@$other_host:"; 
	@setup_command = @source_setup;
	@cleanup_command = @source_cleanup;
	@allowed_paths = @source_dirlist;
    }
    else {
	$source_info = "$RSYNC_USER\@$other_host:";
	$destination_info = "";
	@setup_command = @dest_setup;
	@cleanup_command = @dest_cleanup;
	@allowed_paths = @destination_dirlist;
    }

    my @sudo_for_paths = $push ? @source_sudo : @destination_sudo;
    my $need_elevate = grep { $_ } @sudo_for_paths;
    die "This entry needs doas or sudo, but neither $DOAS nor $SUDO is installed.\n"
	if ($need_elevate && !$HAVE_ELEVATE);

    # Use pledge and unveil to restrict access for client. stdio already included.
    if ($^O eq 'openbsd') {
	my ($path, $command);

	pledge ('rpath', 'wpath', 'cpath', 'exec', 'unveil', 'proc') || die "Cannot pledge promises. $!\n";
	$unveil_started = 1;

	# Unveil dir paths.
	for (my $idx = 0; $idx <= $#allowed_paths; $idx++) {
	    my $path = $allowed_paths[$idx];
	    my $unveil_path = ($path =~ m{/$}) ? $path : dirname($path);
	    my $sudo = ($sudo_for_paths[$idx] ? 1 : 0);
	    if ($push) {
		do_unveil ($unveil_path, 'r', $sudo);

	    }
	    else {
		do_unveil ($unveil_path, 'rwc', $sudo);
	    }
	}

	# Unveil commands.
	unveil ($RSYNC, 'rx') || die "Cannot unveil $RSYNC: $!\n";
	unveil ($SSH, 'rx') || die "Cannot unveil $SSH: $!\n";
	unveil ($RSYNC_USER_SSHDIR, 'r') || die "Cannot unveil $RSYNC_USER_SSHDIR: $!\n";
	unveil ($CONFIG_FILE, 'r') || die "Cannot unveil $CONFIG_FILE: $!\n";
	unveil ($LOG_FILE, 'rwc') || die "Cannot unveil $LOG_FILE: $!\n";
	unveil ($ZONEINFO_DIR, 'r') || die "Cannot unveil $ZONEINFO_DIR: $!\n";

	foreach $command (@setup_command) {
	    if ($command) {
		foreach my $cmd (split(/\s*;\s*/, $command)) {
		    my $cmd_path = $cmd;
		    $cmd_path =~ s/^(\S+).*$/$1/;
		    do_unveil ($cmd_path, 'rx', 0);
		}
	    }
	}
	foreach $command (@cleanup_command) {
	    if ($command) {
		foreach my $cmd (split(/\s*;\s*/, $command)) {
		    my $cmd_path = $cmd;
		    $cmd_path =~ s/^(\S+).*$/$1/;
		    do_unveil ($cmd_path, 'rx', 0);
		}
	    }
	}

	# doas or sudo, only if a path in this pass needs it.
	if ($need_elevate) {
	    unveil ($ELEVATE, 'rx') || die "Cannot unveil $ELEVATE: $!\n";
	}

	# If both, only lock down AFTER the pull has completed, since
	# pull requires more access on client side. (This could also be
	# a bit better by intentionally removing unneeded paths after
	# the pull is complete.)
	if (!$both || $push) {
	    unveil () || die "Cannot lock unveil: $!\n";
	}
    }

    for ($idx = 0; $idx <= $#source_dirlist; $idx++) {
	my $item = "$source_info$source_dirlist[$idx] -> $destination_info$destination_dirlist[$idx]";
	my $setup_err = '';
	if ($setup_command[$idx]) {
	    print "setup: $setup_command[$idx]\n" if ($DEBUG);
	    $setup_err = exec_command ($setup_command[$idx], $ALLOW_MULTIPLE);
	    if ($setup_err) {
		print STDERR "Setup for $item failed ($setup_err); skipping its rsync.\n";
		$failures++;
	    }
	}
	if (($push && $source_sudo[$idx]) || (!$push && $destination_sudo[$idx])) {
	    @this_command = ($ELEVATE, @rsync_command);
	}
	else {
	    @this_command = (@rsync_command);
	}

	# Do any glob expansion required on client side, don't rely on shell.
	my @sources = ($source_info eq '' && $source_dirlist[$idx] =~ /\*/)
	    ? bsd_glob("$source_info$source_dirlist[$idx]", GLOB_LIMIT|GLOB_NOCHECK|GLOB_BRACE|GLOB_QUOTE)
	    : ("$source_info$source_dirlist[$idx]");
	
	if (!$setup_err) {
	    my @options = $rsync_options[$idx] ? split (' ', $rsync_options[$idx]) : ();
	    print "@this_command @options @sources $destination_info$destination_dirlist[$idx]\n" if ($DEBUG);
	    my ($err, $code) = run_command (@this_command, @options, @sources, "$destination_info$destination_dirlist[$idx]");
	    if ($err && $code == 24) {
		print STDERR "rsync $item: some source files vanished during the transfer (exit 24).\n";
	    }
	    elsif ($err) {
		print STDERR "rsync $item failed: $err.\n";
		$failures++;
	    }
	}

        if ($cleanup_command[$idx]) {
            print "cleanup: $cleanup_command[$idx]\n" if ($DEBUG);
	    my $err = exec_command ($cleanup_command[$idx], $ALLOW_MULTIPLE);
	    if ($err) {
		print STDERR "Cleanup for $item failed ($err).\n";
		$failures++;
	    }
        }
    }
}

# Server function. Returns the exit status for the server process.
sub exec_server {
    my $exit_status = 0;
    # Push.
    if ($push) {
	@allowed_paths = @destination_dirlist;
	@setup_command = @dest_setup;
	@cleanup_command = @dest_cleanup;
    }
    # Pull.
    else {
	@allowed_paths = @source_dirlist;
	@setup_command = @source_setup;
	@cleanup_command = @source_cleanup;
    }

    my $allowed_prefix_re = ($push) ? '--server' : '--server --sender'; # used in regexp
    @allowed_prefix = ($push) ? ('--server') : ('--server', '--sender');

    my @sudo_for_paths = $push ? @destination_sudo : @source_sudo;
    my $need_elevate = grep { $_ } @sudo_for_paths;
    die "This entry needs doas or sudo, but neither $DOAS nor $SUDO is installed.\n"
	if ($need_elevate && !$HAVE_ELEVATE);

    # Use pledge and unveil to restrict access for server. stdio already included.
    if ($^O eq 'openbsd') {
	my ($path, $command);

	pledge ('rpath' , 'wpath', 'cpath', 'unveil', 'exec', 'proc') || die "Cannot pledge promises. $!\n";
	$unveil_started = 1;

	unveil ($RSYNC, 'rx') || die "Cannot unveil $RSYNC: $!\n";
	unveil ($CONFIG_FILE, 'r') || die "Cannot unveil $CONFIG_FILE: $!\n";
	unveil ($LOG_FILE, 'rwc') || die "Cannot unveil $LOG_FILE: $!\n";
	unveil ($ZONEINFO_DIR, 'r') || die "Cannot unveil $ZONEINFO_DIR: $!\n";
	for (my $idx = 0; $idx <= $#allowed_paths; $idx++) {
	    my $path = $allowed_paths[$idx];
	    my $unveil_path = ($path =~ m{/$}) ? $path : dirname($path);
	    my $sudo = ($sudo_for_paths[$idx] ? 1 : 0);
	    if ($push) {
		do_unveil ($unveil_path, 'rwc', $sudo);
	    }
	    else {
		do_unveil ($unveil_path, 'r', $sudo);
	    }
	}

	foreach $command (@setup_command) {
	    if ($command) {
		foreach my $cmd (split(/\s*;\s*/, $command)) {
		    my $cmd_path = $cmd;
		    $cmd_path =~ s/^(\S+).*$/$1/;
		    do_unveil ($cmd_path, 'rx', 0);
		}
	    }
	}
	foreach $command (@cleanup_command) {
	    if ($command) {
		foreach my $cmd (split(/\s*;\s*/, $command)) {
		    my $cmd_path = $cmd;
		    $cmd_path =~ s/^(\S+).*$/$1/;
		    do_unveil ($cmd_path, 'rx', 0);
		}
	    }
	}

	# doas or sudo, only if a path in this entry needs it.
	if ($need_elevate) {
	    unveil ($ELEVATE, 'rx') || die "Cannot unveil $ELEVATE: $!\n";
	}

	unveil () || die "Cannot lock unveil: $!\n";
    }

    $command = $ENV{'SSH_ORIGINAL_COMMAND'};
    die "Uninitialized environment variable SSH_ORIGINAL_COMMAND.\n" if (!defined ($command));
    $time = time();
    $time = localtime ($time);

    my $LOG = open_log_file_secure();

    # Everything from the client is logged through log_safe (no forged lines).
    print $LOG "$time $0 " . log_safe ($ENV{'SSH_CONNECTION'} // '') .
	" ***New command issued: " . log_safe ($command) . "\n";

    if ($command =~ /^rsync $allowed_prefix_re\s*([\s\w\.-]*)\s+\.\s+(.*)$/) {
	$options = $1;
	$path = $2;

	$allowed_this_path = 0;
	for ($idx = 0; $idx <= $#allowed_paths; $idx++) {
	    if ($push) {
		$need_sudo = $destination_sudo[$idx];
	    }
	    else {
		$need_sudo = $source_sudo[$idx];
	    }
	    # Requires strict matching (e.g., can't have dir with terminal slash in client config but not in server config).
	    if ($path eq $allowed_paths[$idx]) {
		$allowed_this_path = 1;
		if (server_options_match ($LOG, $options, $rsync_options[$idx])) {
		    my $setup_err = '';
		    if ($setup_command[$idx]) {
			print $LOG "$time Setup command: $setup_command[$idx]\n";
			$setup_err = exec_command ($setup_command[$idx], $ALLOW_MULTIPLE);
			if ($setup_err) {
			    print $LOG "$time Setup command failed ($setup_err); not running rsync.\n";
			    $exit_status = 1;
			}
		    }

		    $time = time();
		    $time = localtime ($time);
		    if ($need_sudo) {
			@this_command = ($ELEVATE, $RSYNC);
		    }
		    else {
			@this_command = ($RSYNC);
		    }

		    my @paths = ($path =~ /\*/)
			? bsd_glob($path, GLOB_LIMIT|GLOB_NOCHECK|GLOB_BRACE|GLOB_QUOTE)
			: ($path);

		    # Confinement root for this transfer: the directory rsync resolves within.
		    # Same derivation as the unveil path -- the dir itself for a trailing-slash
		    # entry, else the parent of the file/glob pattern. Computed from the pre-glob
		    # $path so a glob confines to its containing directory, not an expanded leaf.
		    my $confine_root = ($path =~ m{/$}) ? $path : dirname($path);

		    my @confine = ();
		    unless (RSYNC_PRE35 || $confine_root eq '/') {
			@confine = ('--confine-root=' . $confine_root);
		    }

		    if (!$setup_err) {
			my $logged = log_safe ("@this_command @allowed_prefix @confine $options . @paths");
			print $LOG "$time Command issued: $logged\n";
			my ($err, $code) = run_command (@this_command, @allowed_prefix, @confine, split (' ', $options), '.', @paths);
			if ($err) {
			    print $LOG "$time Command failed ($err): $logged\n";
			    $exit_status = $code;
			}
			else {
			    print $LOG "$time Command executed: $logged\n";
			}
		    }

		    if ($cleanup_command[$idx]) {
			print $LOG "$time Cleanup command: $cleanup_command[$idx]\n";
			my $err = exec_command ($cleanup_command[$idx], $ALLOW_MULTIPLE);
			if ($err) {
			    print $LOG "$time Cleanup command failed ($err).\n";
			    $exit_status ||= 1;
			}
		    }

		}
		else {
		    print $LOG "$time Disallowed options: " . log_safe ($options) . "\n";
		    $exit_status = 1;
		}
		last;
	    }
	}

	$time = time();
	$time = localtime ($time);
	if (!$allowed_this_path) {
	    print $LOG "$time Disallowed path: " . log_safe ($path) . "\n";
	    $exit_status = 1;
	}
    }
    else { # Doesn't match regexp.
	$exit_status = 1;
	print $LOG "$time Disallowed command: " . log_safe ($command) . "\n";
        print $LOG "    Permitted:   rsync @allowed_prefix <options> . <dir>\n";
	if ($push) {
	    print $LOG "    Running as push.\n";
	}
	else {
	    print $LOG "    Running as pull.\n";
	}
    }

    close ($LOG);
    return ($exit_status);
}

### Utility subroutines.

# Subroutine to run a command without a shell. Returns ('', 0) on success,
# otherwise a description of the failure and an exit code for it: 127 if
# the command could not be run, 128+N if killed by signal N, else its own
# exit status. $? is read on the line after system() (nothing between).
sub run_command {
    my (@cmd) = @_;
    system (@cmd);
    my $status = $?;
    return ('', 0) if ($status == 0);
    return ("could not run $cmd[0]: $!", 127) if ($status == -1);
    return ("$cmd[0] killed by signal " . ($status & 127), 128 + ($status & 127))
	if ($status & 127);
    return ("$cmd[0] exited with status " . ($status >> 8), $status >> 8);
}

# Subroutine to do unveils with error checking while ignoring EPERM and ENOENT with sudo/doas
# (the two ways unveil can fail on paths the unpriv process doesn't have access to).
sub do_unveil {
    my ($path, $perm, $sudo) = @_;
    
    return 1 if unveil ($path, $perm);
    my $err = $!;                    # capture before it's clobbered
    return 1 if $sudo && $!{EPERM};  # already covered by an ancestor; wider perm stands
    return 1 if $sudo && $!{ENOENT}; # sudo path _rsyncu can't resolve; elevated rsync will
    die "Cannot unveil $path ($perm): $err\n";
}

# Escape control characters as \xNN in text from the client before it is
# logged, so a newline cannot forge a log line. Other text is unchanged.
sub log_safe {
    my ($s) = @_;
    $s =~ s/([\x00-\x1f\x7f])/sprintf ("\\x%02x", ord ($1))/ge;
    return $s;
}

# Subroutine to die with security error message and log it.
sub security_die {
    my ($message) = @_;
    
    # Try to log the security event
    eval {
	my $LOG = open_log_file_secure();
	my $timestamp = localtime (time());
	my $remote = log_safe ($ENV{'SSH_CONNECTION'} || 'local');
	print $LOG "$timestamp SECURITY [$remote]: $message\n";
	close($LOG);
    };
    # Ignore errors during logging - still die even if logging fails
    
    die "SECURITY: $message\n";
}

# Subroutine to verify config file ownership and permissions.
sub validate_config_file_security {
    my ($config_dir, $dir_mode, $dir_uid, $dir_gid, $dir_perms);
    my ($uid, $gid, $mode, $perms);
    my ($rsync_gid);

    # Get directory path for config file.
    $config_dir = dirname ($CONFIG_FILE);

    # Directory must exist and be accessible.
    if (!-e $config_dir) {
	security_die ("Config directory $config_dir does not exist.");
    }

    if (!-d $config_dir) {
	security_die ("Config directory path $config_dir is not a directory.");
    }

    # Get rsync user's GID for validation.
    $rsync_gid = getgrnam ($RSYNC_USER);
    if (!defined ($rsync_gid)) {
	security_die ("Cannot determine GID for group $RSYNC_USER.");
    }

    # Check directory ownership and permissions.
    ($dir_mode, $dir_uid, $dir_gid) = (stat ($config_dir))[2,4,5];

    if (!defined ($dir_mode)) {
	security_die ("Cannot stat config directory $config_dir. $!");
    }

    # Config file must be owned by root (uid 0)
    if ($dir_uid != 0) {
        security_die ("Config directory $config_dir must be owned by root (currently uid $dir_uid)");
    }
    
    if ($dir_gid != $rsync_gid) {
        security_die ("Config directory $config_dir must be group-owned by $RSYNC_USER (expected gid $rsync_gid, found $dir_gid)");
    }
    
    $dir_perms = $dir_mode & 07777;
    if ($dir_perms != 0750) {
        security_die (sprintf("Config directory $config_dir has wrong permissions (expected 0750, found %04o)", $dir_perms));
    }

    # Directory validated, now check file
    if (!-e $CONFIG_FILE) {
        security_die ("Config file $CONFIG_FILE does not exist.");
    }

    if (!-f $CONFIG_FILE) {
        security_die ("Config file path $CONFIG_FILE is not a regular file");
    }

    # Check file ownership and permissions.
    ($mode, $uid, $gid) = (stat($CONFIG_FILE))[2,4,5];

    if (!defined($mode)) {
        security_die ("Cannot stat config file $CONFIG_FILE: $!");
    }

    # Config file must be owned by root.
    if ($uid != 0) {
        security_die ("Config file $CONFIG_FILE must be owned by root (currently uid $uid)");
    }
    
    # Config file must be group-owned by rsync group
    if ($gid != $rsync_gid) {
        security_die ("Config file $CONFIG_FILE must be group-owned by $RSYNC_USER (expected gid $rsync_gid, found $gid).");
    }
    
    # Extract permission bits
    $perms = $mode & 07777;
    
    # Must be 0640 (rw-r-----)
    if ($perms != 0640) {
        security_die (sprintf("Config file must have permissions 0640 (currently %04o).", $perms));
    }

}

# Subroutine to open log file and create with 0600 permissions.
sub open_log_file_secure {
    my $log_fh;
    # Create with 0600 permissions (rw-------)
    if (!sysopen($log_fh, $LOG_FILE, O_WRONLY|O_APPEND|O_CREAT, 0600)) {
        die "Cannot open log file $LOG_FILE: $!\n";
    }
    return $log_fh;
}

# Subroutine to complain if we already have one of these.
sub check_arg {
    my ($entry, $arg, $have) = @_;

    if ($have) {
	die "Configuration file has multiple \"$entry\" fields. $arg\n";
    }
}

# Subroutine to return array of directories from a list.
# Also used by command lists, so only validate when requested.
# "" becomes 0.
sub dirlist {
    my ($arg, $validate) = @_;
    my (@dirlist, $item);

    @dirlist = split (/\s*,\s*/, $arg);
    foreach $item (@dirlist) {
	if ($item eq "\"\"") {
	    $item = 0;
	}
	elsif ($validate && !valid_dir ($item)) {
	    die "Configuration file has invalid dir \"$item\" in dirlist \"$arg\".\n";
	}
    }
    return (@dirlist);
}

# Subroutine to do some minimal validation on dirs in dirlist.
sub valid_dir {
    my ($path) = @_;
    my ($dir, $file);

    # No directory traversal.
    if ($path =~ /\.\./) {
	return 0;
    }

    # Must be absolute path.
    if ($path !~ /^\//) {
	return 0;
    }

    $dir = dirname ($path);
    $file = basename ($path);

    # Check dir portion.
    if ($dir !~ /^[A-Za-z0-9\._\-\/]+$/) {
	return 0;
    }

    # If path ends in /, treat file like dir.
    if ($path =~ /\/$/) {
	if ($file !~ /^[A-Za-z0-9\._\-\/]+$/) {
	    return 0;
	}
	return 1;
    }

    # Otherwise, allow *.
    elsif ($file !~ /^[A-Za-z0-9\._\-\/\*]+$/) {
	return 0;
    }

    return 1;
}

# Subroutine to return array of options from rsync_options.
sub optionlist {
    my ($arg) = @_;
    my (@wordlist, $word, @optionlist);

    @wordlist = split (/\s+/, $arg);
    foreach $word (@wordlist) {
	if (substr ($word, 0, 1) eq '-') {
	    push (@optionlist, $word);
	}
	elsif ($#optionlist > -1) {
	    $optionlist[$#optionlist] .= " $word";
	}
	else {
	    push (@optionlist, "$word");
	}
    }
    return (@optionlist);
}

# Subroutine to return "yes" or "no".
sub yes_or_no {
    my ($entry, $arg) = @_;

    return (1) if ($arg eq 'yes');
    return (0) if ($arg eq 'no');

    die "Invalid $entry field in config file.  Must be \"yes\" or \"no\", not \"$arg\".\n";
}

# Subroutine to return array of "yes" or "no" options.
sub yes_or_no_list {
    my ($entry, $arg) = @_;
    my (@in_list, $in, @yn_list);

    @in_list = split (/\s*,\s*/, $arg);
    foreach $in (@in_list) {
	push (@yn_list, yes_or_no ($entry, $in));
    }

    return (@yn_list);
}

# Subroutine to return 1 if server options match.
# All supplied options must be from @POSSIBLE_SERVER_OPTIONS or the entry's
# rsync_options, but not all rsync_options need be in the supplied options.
sub server_options_match {
    my ($log_fh, $supplied_options, $avail_options) = @_;
    my (@split_supplied_options, @split_avail_options, $option);

    @split_supplied_options = optionlist ($supplied_options);

    @split_avail_options = @POSSIBLE_SERVER_OPTIONS;

    push (@split_avail_options, &optionlist ($avail_options)) if (defined ($avail_options));

    foreach $option (@split_supplied_options) {
	if (!grep { $_ eq $option } @split_avail_options) {
	    print $log_fh "$time Disallowed individual option: " . log_safe ($option) . "\n";
	    return 0;
	}
    }

    return 1;
}

# Subroutine to execute a command without invoking shell.
# Note: Arguments cannot contain whitespace. Use scripts for complex commands.
# Returns '' if every command succeeded, else a description of the first
# failure; commands after a failed one in a ";" chain are not run.
sub exec_command {
    my ($command, $allow_multiple) = @_;
    my (@commands, @command);

    if ($allow_multiple && $command =~ /;/) {
	@commands = split (/\s*;\s*/, $command);
    }
    else {
	push (@commands, $command);
    }

    foreach $command (@commands) {
	@command = split (' ', $command);
	my ($err) = run_command (@command);
	return ($err) if ($err);
    }
    return ('');
}
