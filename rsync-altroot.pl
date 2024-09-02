#!/usr/bin/perl
# Script to rsync filesystems on mirror disk.
# 2002-01-26 Jim Lippard.
# Modified 2006-03-07 by Jim Lippard to not copy root partition
#   and to use separate partition for /usr/local.  Root partition
#   is copied by daily script if desired.
# Modified 2006-03-08 by Jim Lippard to do weekly or monthly rsyncs,
#   to /backup or /altroot/backup.
#  To modify: Don't copy root partition ONLY if doing std. altroot
#     --which doesn't work when using syslevel=2
# Modified 2011-12-23 by Jim Lippard to get device information from
#   commented-out lines in fstab.
# Modified 2011-12-28 by Jim Lippard to do daily backups from /share
#   to /backup/share.
# Modified 2012-05-24 by Jim Lippard to comment out /backup/share stuff.
# Modified 2013-01-07 by Jim Lippard to skip directories that aren't
#   present (e.g., /openbsd) and remove daily, weekly, monthly, and
#   backup options which are no longer relevant. This script now serves
#   just to maintain daily /altroot backups on a separate physical disk.
#   (i.e., it will become useless if I move to real hardware RAID).
# Modified 2013-01-08 by Jim Lippard to rely more on fstab information.
#   Needs an update to pull mount options from fstab, too.
# Modified 2021-10-12 by Jim Lippard to rename to rsync-altroot.pl
# Modified 2024-01-03 by Jim Lippard to use newer perl open format.
# Modified 2024-09-01 by Jim Lippard to use pledge and unveil on OpenBSD.
# Modified 2024-09-02 by Jim Lippard to avoid unveil errors from need for
#   /bin/sh by passing arguments individually in system calls.

# Old removed features (now using rsnapshot):
# Regular rsyncs are from the original files to /altroot (daily),
#    /backup/weekly (weekly), and /backup/monthly (monthly). Also
#    from /share to /backup/share (daily).
# Backup rsyncs are from /backup/weekly to /altroot/backup/weekly (weekly),
#   and from /backup/monthly to /altroot/backup/monthly (monthly).
# The intent is to backup to altroot before backing up to /backup, so
#   that /altroot is always one week/month behind.

# As of 2012-05-24, I'm no longer doing the weekly or monthly backups,
# which are covered by rsnapshot.  I will be freeing up the backup
# partitions in the VMware data stores.

use strict;
use Getopt::Long;
use if $^O eq "openbsd", "OpenBSD::Pledge";
use if $^O eq "openbsd", "OpenBSD::Unveil";

# '' = '/'

my $MOUNT = '/sbin/mount';
my $RSYNC = '/usr/local/bin/rsync';
my $UNMOUNT = '/sbin/umount';

my $FSTAB = '/etc/fstab';

my @FILESYSTEMS = (
		   '',
		   '/var',
		   '/usr',
		   '/usr/local',
		   '/openbsd',
		   '/home'
		   );

my (%device, %fstab, $dir);

# '' = '/'
my %device_map = (
		  '', '/altroot',
		  '/altroot', '/altroot',
		  '/var', '/altroot/var',
		  '/usr', '/altroot/usr',
		  '/usr/local', '/altroot/usr/local',
		  '/openbsd', '/altroot/openbsd',
		  '/home', '/altroot/home'
		  );

my @ROOT_DIRS = (
		 '/bin',
		 '/boot',
		 '/bsd',
		 '/bsd.old',
		 '/etc',
		 '/root',
		 '/sbin',
		 '/stand',
		 '/sys'
		 );

my $ALTROOT = '/altroot';

my $DEBUG = 0;

my ($mount, $rsync, $unmount);

my ($filesystem, $directory, $target, $alt_target, $rsync_target);

$| = 1;

$mount = $rsync = $unmount = 0;

Getopt::Long::Configure ("bundling");
if (!GetOptions ("mount|m" => \$mount,
		 "rsync|r" => \$rsync,
		 "unmount|u" => \$unmount)) {
    # Invalid option.
    exit;
}

if (!$mount && !$rsync && !$unmount) {
    $mount = $rsync = $unmount = 1;
}

if ($#ARGV != -1) {
    die "Usage: rsync-altroot.pl [-mrudwtb]\n--mount, --rsync, --unmount\n";
}

$rsync_target = $ALTROOT;

# Use pledge and unveil on OpenBSD.
if ($^O eq 'openbsd') {
    my @promises = ('rpath', 'exec', 'proc', 'unveil');
    push (@promises, 'wpath', 'cpath') if ($rsync);
    pledge (@promises) || die "Cannot pledge promises. $!\n";
    unveil ('/', 'r');
    unveil ($ALTROOT, 'rwc');
    unveil ($RSYNC, 'rx') if ($rsync);
    unveil ($MOUNT, 'rx') if ($mount);
    unveil ($UNMOUNT, 'rx') if ($unmount);
    unveil ();
}

# Get device names from /etc/fstab.
if (open (FSTAB_HANDLE, '<', $FSTAB)) {
    while (<FSTAB_HANDLE>) {
	chop;
	if (/^[#]*([\S]+)\s+([\S]+)\s*/) {
	       $fstab{$2} = $1;
	} #if
    } #while
} # open
else {
    die "Cannot open $FSTAB.\n";
}
close (FSTAB_HANDLE);

foreach $dir (@FILESYSTEMS) {
    if (defined ($fstab{$device_map{$dir}})) {
	$device{$dir} = $fstab{$device_map{$dir}};
     }
}

if ($mount) {
    foreach $filesystem (@FILESYSTEMS) {
	if (defined ($device{$filesystem}) && (-d $filesystem || $filesystem eq '')) {
	    print "Mounting $device{$filesystem} on /altroot$filesystem\n";
	    system ("$MOUNT", "$device{$filesystem}", "/altroot$filesystem") if (!$DEBUG);
	}
    }
}

if ($rsync) {
# This section code copies from the original directories, to either /altroot or /backup.
# Root filesystem.
    foreach $directory (@ROOT_DIRS) {
	if (-d $directory || $directory eq '') {
	    print "rsync on $directory to $rsync_target\n";
	    if ($directory eq '/etc') {
		system ("$RSYNC", '-avz', '--exclude', "'*scache.*'", '--delete', "$directory", "$rsync_target") if (!$DEBUG);
	    }
	    else {
		system ("$RSYNC", '-avz', '--delete', "$directory", "$rsync_target") if (!$DEBUG);
	    }
	}
    }

# Remaining filesystems, except /usr/local, which is covered by /usr.
    foreach $directory (@FILESYSTEMS) {
	if (defined ($device{$directory}) && (-d $directory || $directory eq '')) {
	    if ($directory ne '' && $directory ne '/usr/local') {
		print "rsync from $directory to $rsync_target\n";
		system ("$RSYNC", '-avz', '--delete', "$directory", "$rsync_target") if (!$DEBUG);
	    }
	}
    }
}

if ($unmount) {
	foreach $filesystem (reverse (@FILESYSTEMS)) {
	    if (defined ($device{$filesystem}) && (-d $filesystem || $filesystem eq '')) {
		print "Unmounting /altroot$filesystem\n";
		system ("$UNMOUNT", "/altroot$filesystem") if (!$DEBUG);
	    }
    }
}
