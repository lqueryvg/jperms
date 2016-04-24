#!/usr/bin/perl
#
# Author: John Buxton, 2016

use strict;
use warnings;

use File::Find;
use Getopt::Long;
use Pod::Usage;
use IO::File;
use POSIX;
use File::stat;
use Data::Dumper;

# Globals

my %options = ( # command line options
  verbosity => 0,
  no_change => 0,
);
my %metrics;
my %parse_errors;
my $header_already_printed = 0;

# Subroutines
sub init_metrics {
  for my $name (qw/inspected changed failed pending/) {
    $metrics{$name} = 0;
  }
  return;
}

sub get_options { # Get command line options
  GetOptions(\%options, 'help|?|h', 'file=s',
                        'man', 'verbosity+', 'dir=s', 'no_change');
  pod2usage(1) if $options{help};
  pod2usage(-verbose => 2) if $options{man};
  pod2usage({ -message => q{ERROR: -file is required} }) unless $options{file};
  pod2usage({ -message => q{ERROR: -dir is required} })  unless $options{dir};
  return;
}

sub parse_error {
  my ($str) = @_;
  $parse_errors{$str} = undef;
  return;
}

sub print_parse_errors {
  for my $e (keys %parse_errors) {
    print "PARSE_ERROR: $e\n";
  }
  return;
}

sub parse_permission_rules {
  # Process rules file

  my $fh = IO::File->new($options{file}, q{<})
    or die "ERROR: unable to open rules file $options{file}\n";

  print "rules...\n" if $options{verbosity} > 3;

  my %desired_perms = ();   # indexed by pattern
  my @pattern_list = ();

  while (my $line = <$fh>) {

    chomp $line;
    print "$line\n" if $options{verbosity} > 3;

    my ($pattern, $owner, $group, $dmode, $fmode) = split(' ', $line);

    # skip blank lines and comments
    next if (!defined $pattern || $pattern =~ /^\#/x);

    push @pattern_list, $pattern;

    my %pa;  # pattern attributes
    my @field_names = qw/owner group dmode fmode/;

    # convert owner and group names to numbers
    @pa{@field_names} = (get_uid($owner), get_gid($group), oct($dmode), oct($fmode));

    $desired_perms{$pattern} = \%pa;
  }

  print Dumper \%desired_perms if $options{verbosity} > 5;
  print Dumper \@pattern_list if $options{verbosity} > 5;

  return {
    perms => \%desired_perms,
    patterns => \@pattern_list,
  };
}

sub stat_current_perms {
  my ($file) = @_;
  my $sb = stat($file);
  if (!defined($sb)) {
    print "ERROR: unable to stat $file: $!\n";
    return;
  }
  return {
    owner => $sb->uid,
    group => $sb->gid,
    mode  => $sb->mode,
  };
}

sub _get_id {
  my ($name, $type, $sub) = @_;
  # Safely convert user or group name to a numerical id suitable
  # for use with chown. -1 is returned if user or group not found,
  # which will tell chown to leaving user or group un-altered.
  return -1 if ($name eq '-');
  my $id = $sub->($name);
  return $id if (defined $id);
  parse_error("unable to find $type " . $name);
  return -1;
  # TODO cache for speed ?
}

sub get_uid {
  my ($name) = @_;
  return _get_id($name, 'user', \&POSIX::getpwnam);
}

sub get_gid {
  my ($name) = @_;
  return _get_id($name, 'group', \&POSIX::getgrnam);
}

sub get_name_from_id {
  my ($id, $sub) = @_;
  return '-' if ($id == -1);
  my $name = $sub->($id);
  return $name;
}

sub get_username{
  my ($id) = @_;
  return get_name_from_id($id, \&POSIX::getpwuid);
}

sub get_groupname{
  my ($id) = @_;
  return get_name_from_id($id, \&POSIX::getgrgid);
}

sub file_matches_pattern {
  my ($file, $pattern) = @_;
  print "compare $file against pattern $pattern\n" if $options{verbosity} >= 4;
  if ($file =~ /^${pattern}$/x) {
    print "  rule = $pattern\n" if $options{verbosity} >= 4;
    return 1
  } else {
    return 0
  }
}

sub soct {  # convert number to octal string
  my ($number) = @_;
  return '-' if ($number == 0);
  return sprintf('%04o', $number & oct('777'));
}

sub perms_to_string {
  my ($p) = @_;
  print Dumper $p if $options{verbosity} >= 5;
  return sprintf('o=%s,g=%s,m=%s',
    get_username($p->{owner}),
    get_groupname($p->{group}),
    soct($p->{mode}),
  );
}

sub get_target_perms {
  my ($file, $current_mode, $target_perms) = @_;

  my $target_mode;
  if (S_ISDIR($current_mode)) {
    $target_mode = $target_perms->{dmode};
  } else {
    $target_mode = $target_perms->{fmode};
  }
  return {
    owner => $target_perms->{owner},
    group => $target_perms->{group},
    mode => $target_mode,
  };
}

sub print_csv_header {
  return if $header_already_printed;
  print 'type,path,mode,owner,group' . "\n";
  $header_already_printed = 1;
  return;
}

sub handle_file {
  my ($file, $current_perms, $target_perms_) = @_;

  my $current_owner = $current_perms->{owner};

  # compare current perms with target
  # print changes required
  # make changes
  my $target_perms = get_target_perms(
    $file,
    $current_perms->{mode},
    $target_perms_
  );

  my $file_type = S_ISDIR($current_perms->{mode}) ? 'd' : 'f';

  if ($options{verbosity} >= 3) {
    print '  current ' . perms_to_string($current_perms) . "\n";
    print '  target  ' . perms_to_string($target_perms) . "\n";
  }

  my @changes = ();
  my $change_count = 0;
  my $pending = 0;
  my $changed = 0;
  my $failed = 0;
  my @errors = ();

  # mode
  my $tmode = $target_perms->{mode};
  my $cmode = $current_perms->{mode};

  if ($tmode != 0 && $tmode != ($cmode & oct('777'))) {
    push @changes, sprintf "mode(%s->%s)", soct($cmode), soct($tmode);
    $change_count++;
    print "  chmod $tmode $file\n" if $options{verbosity} >= 3;
    if ($options{no_change}) {
      $pending |= 1;
    } else {
      if (chmod($tmode, $file) == 1) {
        $changed |= 1;
      } else {
        push @errors, sprintf "ERROR: chmod %s $file: $!", soct($tmode);
        $failed |= 1;
        $pending |= 1;
      }
    }
  } else {
    push @changes, '';
  }

  # owner
  my $towner = $target_perms->{owner};
  my $cowner = $current_perms->{owner};

  if ($towner != -1 && $towner != $cowner) {
    push @changes, sprintf "owner(%s->%s)",
      get_username($cowner),
      get_username($towner);
    print "  chown $towner, -1, $file\n" if $options{verbosity} >= 3;
    $change_count++;
    if ($options{no_change}) {
      $pending |= 1;
    } else {
      if (chown($towner, -1, $file) == 1) {
        $changed |= 1;
      } else {
        push @errors, sprintf "ERROR: chown %s $file: $!", get_username($towner);
        $failed |= 1;
        $pending |= 1;
      }
    }
  } else {
    push @changes, '';
  }

  # group
  my $tgroup = $target_perms->{group};
  my $cgroup = $current_perms->{group};

  if ($tgroup != -1 && $tgroup != $cgroup) {
    push @changes, sprintf "group(%s->%s)",
      get_groupname($cgroup),
      get_groupname($tgroup);
    print "  chown -1, $tgroup, $file\n" if $options{verbosity} >= 3;
    $change_count++;
    if ($options{no_change}) {
      $pending |= 1;
    } else {
      if (chown(-1, $tgroup, $file) == 1) {
        $changed |= 1;
      } else {
        push @errors, sprintf "ERROR: chgrp %s $file: $!", get_groupname($tgroup);
        $failed |= 1;
        $pending |= 1;
      }
    }
  } else {
    push @changes, '';
  }

  if (($options{verbosity} == 0 && $options{no_change} && $change_count > 0) ||
      ($options{verbosity} == 1 && $change_count > 0) ||
      ($options{verbosity} >= 2)) {
    print_csv_header();
    print join(',', ($file_type, $file, @changes)) . "\n";
  }

  print map { '  ERROR: ' . $_ . "\n" } @errors;

  $metrics{pending} += $pending;
  $metrics{failed} += $failed;
  $metrics{changed} += $changed;
  return;
}

sub start_descent {
  my ($dir, $rules_href) = @_;

  print "start descent from $dir ...\n" if $options{verbosity} >= 4;

  find({no_chdir => 1, wanted => sub {

    $metrics{inspected}++;

    # get the current file or dir, including dir & filename
    my $f = $File::Find::name;

    print "f = $f\n" if $options{verbosity} >= 4;

    for my $pattern (@{$rules_href->{patterns}}) {
      if (file_matches_pattern($f, $pattern)) {

        my $current_perms = stat_current_perms($f);
        if (!defined($current_perms)) {
          $metrics{failed}++;
          return;
        }
        my $target_perms = $rules_href->{perms}{$pattern};

        handle_file($f, $current_perms, $target_perms);
        
        return;
      }
    }
  }}, $options{dir});
  return;
}

sub print_summary {
  print 'Summary: ' . join(', ', map {
    $_ . '=' . $metrics{$_}
  } (qw/inspected changed failed pending/)) . "\n";
  return;
}

sub main {
  get_options();
  print "verbosity = $options{verbosity}\n" if $options{verbosity} >= 2;
  init_metrics();
  my $rules = parse_permission_rules($options{file});
  print Dumper $rules if $options{verbosity} >= 5;

  print_parse_errors();
  start_descent($options{dir}, $rules);
  print_summary();
  return;
}

main();

exit 0;

__END__

=head1 jperms.pl

recursively set permissions and ownerships according to pattern rules

=head1 OPTIONS

jperms.pl [options]

 Options:
   -dir            directory to descend
   -file           permission rules file
   -no_change      don't make changes, just show what would change
   -verbosity      repeat to increase
   -man            full documentation
   -help|-h|-?     help

=head1 DESCRIPTION

jperms.pl descends the specified directory tree applying permissions and
ownerships to each file or directory found according to a set
of permission rules.

=head1 PERMISSION RULES

Permission rules are specified as lines in a file, optionally preceded by
whitespace.  Lines starting with a '#' are treated as B<comments> and ignored.

Each line consists of 5 fields separated by whitespace:

 pattern   owner   group   dir_mode   file_mode

A value of '-' for any field except pattern means the field should be
ignored and the corresponding attribute for a matching file is to remain
un-altered.

=over

=item pattern

- B<pattern> is a regex (NOT a fileglob!) to be matched against each path
found during the tree descent.

- patterns are automatically surrounded by ^ and $ when matching; a pattern
must match the whole of the current path (not just part of it).

- file paths include the start directory exactly as specified on the
command line, so a pattern to match a I<relative> top level directory (e.g.
"./dir") must also match the dot (".") at the start of the path (e.g. with
"\./dir")

- paths are compared against each pattern in turn (in order) until the first
match is found.  Permissions are then applied to the matchedd path as per the
rule, and process continues with the next file or directory.

=item owner and group

- must be names; numeric ids are not supported

- an B<owner> or B<group> which does not exist on the host will cause an error
message to be printed and the field will have no effect, i.e.  it will be
treated as if it were '-'

- files with numeric owner or group ids (i.e. the user or group does not exist
on the host), are treated like any other file; i.e. new B<owner> and/or
B<group> will be applied as normal if a rules matches.

=item dir_mode and file_mode

- both specify absolute permissions and are not applied through any kind of
mask.

- must be octal; leading zero is not required

- a value of 0 (or any string which evaluates to zero when converted to a
number) is treated as a '-'

- B<dir_mode> is only ever applied to directories, and B<file_mode> is only
applied to files


=back

=head1 OUTPUT

By default jperms.pl prints only a summary upon completion with the following
details:

- inspected: the number of objects (files or directories) inspected

- changed: the number of objects changed. Note: change of owner, group or mode,
or all three counts as a single change

- failed: the number of objects on which a changed failed. Note: failure to chmod or
chown (or both) counts as a single failure

- pending: the number of objects which need to be changed, but weren't changed
either due to error or -no_change mode.

Other output is controlled by the -verbosity level:

  0 summary
  1 objects & changes needed
  2 all objects (even if no change required)
  3 commands used to make changes
  3 permission rules
  4 debug (patterns, current/target perms, filename)
  5 internal data structures

=head1 EXAMPLE

Example rules.txt file:

  # pattern                      owner   group  dmode  fmode

  \./test/data.*/proj/cards      appuser grp2    770   -
  \./test/data.*/proj/r/r_import appuser grp2    770   -
  \./test/data.*/proj/outbound   appuser adm    2770   -
  \./test/data.*/proj/.*/inbox   appuser grp2    770   -
  \./test/data.*/proj/[^/]+      appuser grp2    750   -
  \./test/data[^/]*/proj         appuser adm     750   -
  \./test/data.*/tws/logs        appuser grp2    770   -
  \./test/data.*/tws             appuser grp2    750   -
  \./test/data.*/logs            appuser grp2    770   -
  \./test/data.*/scripts         root    adm     750   -
  \./test/data.*                 appuser grp2    770   660
  \./test/.*                     -       -       -     -
  \./test                        appuser appgrp  775   -

Run the above permission rules recursively to directory ./test
in -no_change mode, i.e. report the changes needed without
making any changes:

  jperms.pl -f patterns.txt -d ./test -n

Sample output (suitable for parsing as CSV):

  type,path,mode,owner,group
  d,./test/data,mode(0775->0770),,
  d,./test/data/scripts,mode(0777->0750),,group(docker->kvm)
  d,./test/data/proj,mode(0776->0750),,
  d,./test/data/proj/r,mode(0777->0750),,
  d,./test/data/proj/r/r_import,mode(0777->0770),,group(john->docker)
  f,./test/data/proj/r/r_import/f1,mode(0777->0660),,
  d,./test/data/tws,mode(0777->0750),,
  d,./test/data/tws/logs,mode(0677->0770),,
  d,./test/data-2,mode(0757->0770),,
  Summary: inspected=11, changed=0, failed=0, pending=9

