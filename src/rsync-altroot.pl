#!/usr/bin/perl
# Script to rsync filesystems on mirror disk. Not suitable for Linux without modification.
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
# Modified 2024-11-01 by Jim Lippard to abort if any mount fails.
# Modified 2025-08-28 by Jim Lippard to update / contents and add /share.
# Modified 2025-09-15 by Jim Lippard to support Linux rsync path.
# Modified 2026-01-10 by Jim Lippard to remove unnecessary quotes.
# Modified 2026-04-08 by Jim Lippard to add "use warnings" and remove
#    unneeded /etc special-casing.
# Modified 2026-05-17 by Jim Lippard to not use bareword filehandles.
# Modified 2026-07-01 by Jim Lippard after review by Claude Opus 4.8 to
#    change dir check to existence check in the rsync so that kernels
#    are rsynced, check that /altroot dirs are mounted before doing rsync,
#    minor cleanup.
# Modified 2026-10-15 by Claude Opus 5.5 at the direction of Jim Lippard
#    after a checklist review:
#    - Rsync the root directories only when fstab has an /altroot entry
#      (and it is mounted). The 2026-07-01 mount check covered only the
#      filesystems with an fstab entry, so with no /altroot line the root
#      dirs were rsynced with --delete into /altroot on the root disk. (That
#      check came from a Claude review; this was its gap.)
#    - The mount check skips a filesystem whose source dir does not exist,
#      as the mount and rsync loops already do (it used to abort the run).
#    - Check the exit status of every rsync and umount; report failures and
#      exit 1 at the end. rsync exit 24 (source files vanished during the
#      transfer, normal on a live /var) is reported but is not a failure.
#    - If a mount fails, unmount what this run mounted before dying, so the
#      next run does not fail on "already mounted".
#    - Exit 1 on an invalid option (was 0).
#    - pledge/unveil: drop wpath/cpath and the /altroot rwc unveil. The
#      script itself only reads (rsync, mount and umount are exec'd and are
#      not confined by its unveil); unveil / r covers its reads.

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
use warnings;
use File::Basename qw( dirname );
use Getopt::Long;
use if $^O eq "openbsd", "OpenBSD::Pledge";
use if $^O eq "openbsd", "OpenBSD::Unveil";

# '' = '/'

my $MOUNT = '/sbin/mount';
my $RSYNC = '/usr/local/bin/rsync';
$RSYNC = '/usr/bin/rsync' if ($^O eq 'linux');
my $UNMOUNT = '/sbin/umount';

my $FSTAB = '/etc/fstab';

my @FILESYSTEMS = (
    '',
    '/var',
    '/usr',
    '/usr/local',
    '/home',
    '/share',
    );

my (%device, %fstab, $dir);

# '' = '/'
my %device_map = (
    '', '/altroot',
    '/altroot', '/altroot',
    '/var', '/altroot/var',
    '/usr', '/altroot/usr',
    '/usr/local', '/altroot/usr/local',
    '/home', '/altroot/home',
    '/share', '/altroot/share'
    
		  );

my @ROOT_DIRS = (
    '/bin',
    '/boot',
    '/bsd',
    '/bsd.rd',
    '/etc',
    '/obsd',
    '/root',
    '/sbin',
    '/stand',
    '/sys'
    );

my $ALTROOT = '/altroot';

my $DEBUG = 0;

my ($mount, $rsync, $unmount);

my ($filesystem, $directory, $rsync_target);
my $failures = 0;

$| = 1;

$mount = $rsync = $unmount = 0;

Getopt::Long::Configure ("bundling");
if (!GetOptions ("mount|m" => \$mount,
		 "rsync|r" => \$rsync,
		 "unmount|u" => \$unmount)) {
    # Invalid option.
    die "Usage: rsync-altroot.pl [-mru]\n--mount, --rsync, --unmount\n";
}

if (!$mount && !$rsync && !$unmount) {
    $mount = $rsync = $unmount = 1;
}

if ($#ARGV != -1) {
    # no -d debug, -t target
    die "Usage: rsync-altroot.pl [-mru]\n--mount, --rsync, --unmount\n";
}

$rsync_target = $ALTROOT;

# Use pledge and unveil on OpenBSD. These confine this script only: rsync,
# mount and umount are exec'd and start without its pledge or unveil, so
# the script itself needs only to read (fstab, and stat for -d/is_mounted).
if ($^O eq 'openbsd') {
    my @promises = ('rpath', 'exec', 'proc', 'unveil');
    pledge (@promises) || die "Cannot pledge promises. $!\n";
    unveil ('/', 'r');
    unveil ($RSYNC, 'rx') if ($rsync);
    unveil ($MOUNT, 'rx') if ($mount);
    unveil ($UNMOUNT, 'rx') if ($unmount);
    unveil ();
}

# Get device names from /etc/fstab.
my $fstab_fh;
if (open ($fstab_fh, '<', $FSTAB)) {
    while (<$fstab_fh>) {
	chomp;
	if (/^[#]*\s*([\S]+)\s+([\S]+)\s*/) {
	       $fstab{$2} = $1;
	} #if
    } #while
} # open
else {
    die "Cannot open $FSTAB.\n";
}
close ($fstab_fh);

foreach $dir (@FILESYSTEMS) {
    if (defined ($fstab{$device_map{$dir}})) {
	$device{$dir} = $fstab{$device_map{$dir}};
     }
}

if ($mount) {
    my @mounted;
    foreach $filesystem (@FILESYSTEMS) {
	if (defined ($device{$filesystem}) && (-d $filesystem || $filesystem eq '')) {
	    print "Mounting $device{$filesystem} on /altroot$filesystem\n";
	    if (!$DEBUG) {
		my $status = run_status ($MOUNT, "$device{$filesystem}", "/altroot$filesystem");
		if ($status ne '0') {
		    # Undo this run's mounts, so the next run can mount them again.
		    foreach my $mp (reverse (@mounted)) {
			print "Unmounting $mp\n";
			my $ustatus = run_status ($UNMOUNT, $mp);
			print STDERR "umount $mp failed: $ustatus\n" if ($ustatus ne '0');
		    }
		    die "Aborting due to error mounting $device{$filesystem} on /altroot$filesystem: $status\n";
		}
		push (@mounted, "/altroot$filesystem");
	    }
	}
    }
}

if ($rsync) {
    foreach $filesystem (@FILESYSTEMS) {
        next unless defined ($device{$filesystem}) && (-d $filesystem || $filesystem eq '');
        my $target = "/altroot$filesystem";
        is_mounted ($target)
            or die "Aborting: $target is not mounted (--delete would hit the root disk).\n"
	    unless ($DEBUG);
    }
    # This section code copies from the original directories, to either /altroot or /backup.
    # Root filesystem, only if fstab has an /altroot entry (checked mounted
    # above); otherwise /altroot is a directory on the root disk.
    if (defined ($device{''})) {
	foreach $directory (@ROOT_DIRS) {
	    if (-e $directory) {
		print "rsync on $directory to $rsync_target\n";
		run_rsync ($directory, $rsync_target) if (!$DEBUG);
	    }
	}
    }
    else {
	print "No /altroot entry in $FSTAB, not copying root directories.\n";
    }

# Remaining filesystems, except /usr/local, which is covered by /usr.
    foreach $directory (@FILESYSTEMS) {
	if (defined ($device{$directory}) && (-d $directory || $directory eq '')) {
	    if ($directory ne '' && $directory ne '/usr/local') {
		print "rsync from $directory to $rsync_target\n";
		run_rsync ($directory, $rsync_target) if (!$DEBUG);
	    }
	}
    }
}

if ($unmount) {
	foreach $filesystem (reverse (@FILESYSTEMS)) {
	    if (defined ($device{$filesystem}) && (-d $filesystem || $filesystem eq '')) {
		print "Unmounting /altroot$filesystem\n";
		if (!$DEBUG) {
		    my $status = run_status ($UNMOUNT, "/altroot$filesystem");
		    if ($status ne '0') {
			print STDERR "umount /altroot$filesystem failed: $status\n";
			$failures++;
		    }
		}
	    }
    }
}

if ($failures) {
    print STDERR "$failures operation(s) failed.\n";
    exit 1;
}
exit 0;

### Subroutines.

# Run a command; return '0' on success, otherwise a description of why not.
sub run_status {
    system (@_);
    my $status = $?;
    return "could not run $_[0]: $!" if ($status == -1);
    return "killed by signal " . ($status & 127) if ($status & 127);
    return ($status >> 8) ? "exit status " . ($status >> 8) : '0';
}

# rsync one directory; count a failure (rsync exit 24, files that vanished
# during the transfer, is reported but not counted).
sub run_rsync {
    my ($from, $to) = @_;
    my $status = run_status ($RSYNC, '-avz', '--delete', $from, $to);
    return if ($status eq '0');
    if ($status eq 'exit status 24') {
	print STDERR "rsync $from: some source files vanished during the transfer (exit 24)\n";
	return;
    }
    print STDERR "rsync $from to $to failed: $status\n";
    $failures++;
}

sub is_mounted {
    my ($mp) = @_;
    my $dev        = (stat ($mp))[0];
    my $parent_dev = (stat (dirname ($mp)))[0];
    return defined ($dev) && defined ($parent_dev) && $dev != $parent_dev;
}
