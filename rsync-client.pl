#!/usr/bin/perl -w

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
# 1. Use an unprivileged rsync user with a passwordless SSH DSA key as the
#    initiator (client side) of the rsync, when possible.
#
# 2. Use an authorized_keys2 file on the server side which specifies a
#    specific command (calling this script with the appropriate arguments)
#    and a specific host (the host expected to be on the other side).
#    Set permissions and ownership on the authorized_keys2 file so that
#    the rsync user cannot modify it or anything else in its .ssh directory.
#    (Manually update its known_hosts file.)
#
# 3. Put the specific needed rsync commands into your sudoers file, which
#    specify the particular dirs or files being rsynced.  These commands
#    are of the following form on the source (server) side when using "pull":
#      $RSYNC_PATH --server --sender -vlogDtprze.[iLf] <rsync options> . <source dir>
#    and of the following form on the destination (server) side when using "push":
#      $RSYNC_PATH --server -vlogDtprze.[iLf] <rsync options> . <dest dir>
#    There is a command of these forms for each source/dest directory; it is recommended
#    that they be put into a command alias such as
#       Cmnd_Alias RSYNC_CMDS = <comma-separated list of commands>
#
#    The format of the commands on the source (client) side when using "push":
#        $RSYNC_PATH -avz <rsync options> <source dir> $RSYNC_USER@<dest host>\:<dest dir>
#    The backslash must appear in front of the colon; that character has special meaning
#    in the sudoers file syntax.
#
#    Finally, the format on the destination (client) side when using "pull":
#        $RSYNC_PATH -avz <rsync options> $SOURCE_HOST\:<source dir> <dest dir>
#
#    In previous versions, for the latter two cases the SSH identity used was root's
#    rather than the rsync user, but now the rsync user is used in all cases.
#
# 4. The server side script will only permit rsync for pathnames that are in the appropriate
#    entry in the config file.  Make sure the ownership and permissions on the config file
#    are restricted to read-only for the rsync user.
#
# NOTE: As of sudo version 1.6.9p4 (the version included with OpenBSD 4.2), sudo filters
# environment variables.  If you do any rsyncs with this script that use sudo, you
# will need to permit the RSYNC_RSH environment variable to be passed by adding
# a line to your sudoers file that says:
#  Default:_rsyncu env_keep +="RSYNC_RSH"

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
# source-dirlist: list,of,dirs,or,files
# destination-dirlist: list,of,dirs,or,files
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
# executed after the rsync.

### Required packages.

use strict;
use Sys::Hostname;

### Global constants.

my $DEBUG = 0;
my $USE_SUDO = 0;

my $RSYNC_USER = '_rsyncu';
my $RSYNC_USER_HOME = "/home/$RSYNC_USER";
my $RSYNC_USER_SSHDIR = "$RSYNC_USER_HOME/.ssh";
my $RSYNC_IDENTITY = "$RSYNC_USER_SSHDIR/id_dsa";
my $RSYNC_ED25519_IDENTITY = "$RSYNC_USER_SSHDIR/id_ed25519";
my $RSYNC_ECDSA_IDENTITY = "$RSYNC_USER_SSHDIR/id_ecdsa";
my $RSYNC_DSA_IDENTITY = "$RSYNC_USER_SSHDIR/id_dsa";
my $RSYNC_RSA_IDENTITY = "$RSYNC_USER_SSHDIR/id_rsa";

my $CONFIG_FILE = '/etc/rsync/rsync.conf';
my $LOG_FILE = "$RSYNC_USER_HOME/rsync.out";

my $DOAS = '/usr/bin/doas';
my $RSYNC = '/usr/local/bin/rsync';
my $SUDO = '/usr/bin/sudo';
my $SSH = '/usr/bin/ssh';

my $HOSTNAME = hostname();
my $DOMAIN = '';
($HOSTNAME, $DOMAIN) = split (/\./, $HOSTNAME, 2);

if (-e $SUDO) {
    $USE_SUDO = 1;
}

my $CLIENT = 0;

if ($0 =~ /rsync-client.pl$/) {
    $CLIENT = 1;
}
elsif ($0 =~ /rsync-server.pl$/) {
    $CLIENT = 0;
}

my @POSSIBLE_SERVER_OPTIONS = ('-vlogDtprz', '-vlogDtpRz', '-vlogDtprze.', '-vlogDtprze.i', '-vlogDtprze.f', '-vlogDtprze.if', '-vlogDtprze.iLf', '-vlogDtprze.iL', '-vlogDtprze.iLfx', '-vlogDtprze.iLfxC', '-vlogDtprze.iLfxCIvu');
# The "R" option is for --relative; the e.[i] options only appear after rsync 3.0.; .f only in rsync 3.0.7+
# I probably haven't made this work for 3.0 uses of --relative.
# The "L" option appeared with rsync 3.0.8.
# The "f" disappears in rsync 3.1.0.
# The "C" option appeared with rsync 3.1.2.

### Variables.

my ($push, $both, $other_host, $source, $destination,
    @source_dirlist, @destination_dirlist, @rsync_options, $ssh_identity,
    @source_sudo, @destination_sudo,
    @source_setup, @source_cleanup, @dest_setup, @dest_cleanup,
    @setup_command, @cleanup_command, $idx);

# Client variables.
my ($source_info, $destination_info);

# Server variables.
my ($allowed_prefix, @allowed_paths, $options, $need_sudo, $command, $this_command, $time,
    $path, $allowed_path, $allowed_this_path);

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
    $push = 1;
    $both = 1;
}
else {
    die "Invalid argument \"$ARGV[0]\".  Must be \"push\" or \"pull\" or \"both\".\n";
}

$other_host = $ARGV[1];

# Parse the config file, then execute client or server functions
# as necessary. If "both" on the client side, execute push, then
# parse the config file again and execute pull. If "both" on the
# server side, look in the SSH_ORIGINAL_COMMAND for --sender -- if
# present, do a pull, if not present, do a push.
if ($CLIENT) {
    # This could be a push or a pull, but if it's "both" it's a push.
    &parse_config;
    &exec_client;
    # And so, with both, we now need to do a pull.
    if ($both) {
	$push = 0;
	&parse_config;
	&exec_client;
    }
}
# server gets invoked twice if "both" is used, need to do what the
# client expects.
else {
    $command = $ENV{'SSH_ORIGINAL_COMMAND'};
    if ($command =~ /--sender/) {
	$push = 0;
    }
    else {
	$push = 1;
    }
    &parse_config;
    &exec_server;
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

    open (CONFIG, $CONFIG_FILE) || die "Cannot open config file. $CONFIG_FILE $!\n";
    while (<CONFIG>) {
	if (/^\s*#|^$/) {
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
	    &check_arg ('destination', $1, $have_destination);
	    $destination = $1;
	    $have_destination = 1;
	}
	elsif (/^\s*source-dirlist:\s+(.*)$/) {
	    &check_arg ('source-dirlist', $1, $have_source_dirlist);
	    @source_dirlist = &dirlist ($1);
	    $have_source_dirlist = 1;
	}
	elsif (/^\s*destination-dirlist:\s+(.*)$/) {
	    &check_arg ('destination-dirlist', $1, $have_destination_dirlist);
	    @destination_dirlist = &dirlist ($1);
	    $have_destination_dirlist = 1;
	}
	elsif (/^\s*rsync-options:\s+(.*)$/) {
	    &check_arg ('rsync-options', $1, $have_rsync_options);
	    @rsync_options = &dirlist ($1);
	    $have_rsync_options = 1;
	}
	elsif (/^\s*ssh-identity:\s+(.*)$/) {
	    &check_arg ('ssh-identity', $1, $have_ssh_identity);
	    $ssh_identity = $1;
	    $have_ssh_identity = 1;
	}
	elsif (/^\s*source-setup:\s+(.*)$/) {
	    &check_arg ('source-setup', $1, $have_source_setup);
	    @source_setup = &dirlist ($1);
	    $have_source_setup = 1;
	}
	elsif (/^\s*source-cleanup:\s+(.*)$/) {
	    &check_arg ('source-cleanup', $1, $have_source_cleanup);
	    @source_cleanup = &dirlist ($1);
	    $have_source_cleanup = 1;
	}
	elsif (/^\s*destination-setup:\s+(.*)$/) {
	    &check_arg ('destination-setup', $1, $have_dest_setup);
	    @dest_setup = &dirlist ($1);
	    $have_dest_setup = 1;
	}
	elsif (/^\s*destination-cleanup:\s+(.*)$/) {
	    &check_arg ('destination-cleanup', $1, $have_dest_cleanup);
	    @dest_cleanup = &dirlist ($1);
	    $have_dest_cleanup = 1;
	}
	elsif (/^\s*source-sudo:\s+(.*)$/) {
	    &check_arg ('source-sudo', $1, $have_source_sudo);
	    @source_sudo = &yes_or_no_list ('source-sudo', $1);
	    $have_source_sudo = 1;
	}
	elsif (/^\s*destination-sudo:\s+(.*)$/) {
	    &check_arg ('destination-sudo', $1, $have_destination_sudo);
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
			die "Configuration file does not have all required fields for antry with source $source and no destination.\n";
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

		open (LOG, ">>$LOG_FILE");

		print LOG "$time $0 hostname=$HOSTNAME, other_host=$other_host, CLIENT=$CLIENT, push=$push, both=$both, No matching entry in config file.\n";
		close (LOG);
	    }
	}
	die "No matching entry in config file. $CONFIG_FILE\n";
    }
}

# Client function.
sub exec_client {
    if ($ssh_identity ne '') {
	if (-e "$ssh_identity") {
	    $RSYNC_IDENTITY = $ssh_identity;
	}
	else {
	    die "Cannot find specified ssh-identity. $ssh_identity\n";
	}
    }
    elsif (-e $RSYNC_ED25519_IDENTITY) {
	$RSYNC_IDENTITY = $RSYNC_ED25519_IDENTITY;
    }
    elsif (-e $RSYNC_ECDSA_IDENTITY) {
	$RSYNC_IDENTITY = $RSYNC_ECDSA_IDENTITY;
    }
    elsif (-e $RSYNC_DSA_IDENTITY) {
	$RSYNC_IDENTITY = $RSYNC_DSA_IDENTITY;
    }
    elsif (-e $RSYNC_RSA_IDENTITY) {
	$RSYNC_IDENTITY = $RSYNC_RSA_IDENTITY;
    }
    else {
	die "Cannot find .ssh/(ed25519 ecdsa dsa rsa)_id.\n"
    }
    $ENV{'RSYNC_RSH'} = "$SSH -i $RSYNC_IDENTITY";
    if ($DEBUG) {
	$ENV{'RSYNC_RSH'} = "$SSH -vv -i $RSYNC_IDENTITY";
    }

    $command = "$RSYNC -avz";

    if ($push) {
	$source_info = "";
	$destination_info = "$RSYNC_USER\@$other_host:"; 
	@setup_command = @source_setup;
	@cleanup_command = @source_cleanup;
    }
    else {
	$source_info = "$RSYNC_USER\@$other_host:";
	$destination_info = "";
	@setup_command = @dest_setup;
	@cleanup_command = @dest_cleanup;
    }

    for ($idx = 0; $idx <= $#source_dirlist; $idx++) {
	if ($setup_command[$idx]) {
	    print "setup: $setup_command[$idx]\n" if ($DEBUG);
	    system ("$setup_command[$idx]");
	}
	if (($push && $source_sudo[$idx]) || (!$push && $destination_sudo[$idx])) {
	    if ($USE_SUDO) {
		$this_command = "$SUDO $command";
	    }
	    else {
		$this_command = "$DOAS $command";
	    }
	}
	else {
	    $this_command = $command;
	}
	if ($rsync_options[$idx]) {
	    print "$this_command $rsync_options[$idx] $source_info$source_dirlist[$idx] $destination_info$destination_dirlist[$idx]\n" if ($DEBUG);
	    system ("$this_command $rsync_options[$idx] $source_info$source_dirlist[$idx] $destination_info$destination_dirlist[$idx]");
	}
	else {
	    print "$this_command $source_info$source_dirlist[$idx] $destination_info$destination_dirlist[$idx]\n" if ($DEBUG);
	    system ("$this_command $source_info$source_dirlist[$idx] $destination_info$destination_dirlist[$idx]");
	}

        if ($cleanup_command[$idx]) {
            print "cleanup: $cleanup_command[$idx]\n" if ($DEBUG);
            system ("$cleanup_command[$idx]");
        }
    }
}

# Server function.
sub exec_server {
    # Push.
    if ($push) {
	$allowed_prefix = '--server';
	@allowed_paths = @destination_dirlist;
	@setup_command = @dest_setup;
	@cleanup_command = @dest_cleanup;
    }
    # Pull.
    else {
	$allowed_prefix = '--server --sender';
	@allowed_paths = @source_dirlist;
	@setup_command = @source_setup;
	@cleanup_command = @source_cleanup;
    }

    $command = $ENV{'SSH_ORIGINAL_COMMAND'};
    $time = time();
    $time = localtime ($time);

    open (LOG, ">>$LOG_FILE");

    print LOG "$time $0 $ENV{'SSH_CONNECTION'} ***New command issued: $command\n";

    if ($command =~ /^rsync $allowed_prefix\s*([\s\w\.-]*)\s+\.\s+(.*)$/) {
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
	    if ($path eq $allowed_paths[$idx]) {
		$allowed_this_path = 1;
		if (&server_options_match ($options, $rsync_options[$idx])) {
#		if (($rsync_options[$idx] && (&server_options_match ($options, $rsync_options[$idx]))) ||
#		    ($options eq "")) {

		    if ($setup_command[$idx]) {
			print LOG "$time Setup command: $setup_command[$idx]\n";
			system ("$setup_command[$idx]");
		    }

		    $time = time();
		    $time = localtime ($time);
		    if ($need_sudo) {
			if ($USE_SUDO) {
			    print LOG "$time Command issued: $SUDO $RSYNC $allowed_prefix $options . $path\n";
			    system ("$SUDO $RSYNC $allowed_prefix $options . $path");
			    print LOG "$time Command executed: $SUDO $RSYNC $allowed_prefix $options . $path\n";
			}
			else {
			    print LOG "$time Command issued: $DOAS $RSYNC $allowed_prefix $options . $path\n";
			    system ("$DOAS $RSYNC $allowed_prefix $options . $path");
			    print LOG "$time Command executed: $DOAS $RSYNC $allowed_prefix $options . $path\n";
			}

		    }
		    else {
			print LOG "$time Command issued: $RSYNC $allowed_prefix $options . $path\n";
			system ("$RSYNC $allowed_prefix $options . $path");
			print LOG "$time Command executed: $RSYNC $allowed_prefix $options . $path\n";
		    }

		    if ($cleanup_command[$idx]) {
			print LOG "$time Cleanup command: $cleanup_command[$idx]\n";
			system ("$cleanup_command[$idx]");
		    }

		}
		else {
		    print LOG "$time Disallowed options: $options\n";
		}
		last;
	    }
	}

	$time = time();
	$time = localtime ($time);
	print LOG "$time Disallowed path: $path\n" if (!$allowed_this_path);
    }
    else { # Doesn't match regexp.
	print LOG "$time Disallowed command: $command\n";
        print LOG "    Permitted:   rsync $allowed_prefix <options> . <dir>\n";
	if ($push) {
	    print LOG "    Running as push.\n";
	}
	else {
	    print LOG "    Running as pull.\n";
	}
    }

    close (LOG);
}

### Utility subroutines.

# Subroutine to complain if we already have one of these.
sub check_arg {
    my ($entry, $arg, $have) = @_;

    if ($have) {
	die "Configuration file has multiple \"$entry\" fields. $arg\n";
    }
}

# Subroutine to return array of directories from a list.
sub dirlist {
    my ($arg) = @_;
    my (@dirlist, $item);

    @dirlist = split (/,\s+/, $arg);
    foreach $item (@dirlist) {
	if ($item eq "\"\"") {
	    $item = 0;
	}
    }
    return (@dirlist);
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

    @in_list = split (/,\s+/, $arg);
    foreach $in (@in_list) {
	push (@yn_list, &yes_or_no ($entry, $in));
    }

    return (@yn_list);
}

# Subroutine to return 1 if server options match.
# All supplied options must be from list of rsync_options, but not all
# rsync_options need be in the supplied options.
# If --relative is in the options, then we allow $RELATIVE_SERVER_OPTIONS,
# otherwise we allow $STANDARD_SERVER_OPTIONS.
sub server_options_match {
    my ($supplied_options, $avail_options) = @_;
    my (@split_supplied_options, @split_avail_options, $option);

    @split_supplied_options = &optionlist ($supplied_options);
#    @split_avail_options = &optionlist ($avail_options);

#    if (grep (/^--relative/, @split_avail_options)) {
#	push (@split_avail_options, $RELATIVE_SERVER_OPTIONS);
#    }
#    else {
#	push (@split_avail_options, $STANDARD_SERVER_OPTIONS);
#    }

    @split_avail_options = @POSSIBLE_SERVER_OPTIONS;

    push (@split_avail_options, &optionlist ($avail_options)) if (defined ($avail_options));

    foreach $option (@split_supplied_options) {
	if (!grep (/^$option$/, @split_avail_options)) {
	    print LOG "$time Disallowed individual option: $option\n";
	    return 0;
	}
    }

    return 1;
}
