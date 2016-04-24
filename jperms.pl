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

# Globals

my %options = ( # command line options
  verbosity => 0,
  no_run => 0,
);
my %metrics;

# Subroutines
sub init_metrics {
  for my $name (qw/inspected changed failed pending/) {
    $metrics{$name} = 0;
  }
}

sub get_options { # Get command line options
  GetOptions(\%options, 'help|?|h', 'file=s',
                        'man', 'verbosity+', 'dir=s', 'no_run');
  pod2usage(1) if $options{help};
  pod2usage(-verbose => 2) if $options{man};
  pod2usage({ -message => q{ERROR: -file is required} }) unless $options{file};
  pod2usage({ -message => q{ERROR: -dir is required} })  unless $options{dir};
}

sub zero_pad_octal_string {
  my ($str) = @_;
  if ($str ne '-' && substr($str, 0, 1) ne '0') {
    $str = '0' . $str;
  }
  #return oct($str);
  return $str;
}

sub get_pattern_rules {
  # Process pattern rules

  my $fh = IO::File->new($options{file}, q{<})
    or die "ERROR: unable to open patterns file $options{file}\n";

  print "rules...\n" if $options{verbosity} > 3;

  my %desired_perms = ();   # indexed by pattern
  my @pattern_list = ();

  while (my $line = <$fh>) {

    chomp $line;
    print "$line\n" if $options{verbosity} > 3;

    my ($pattern, $owner, $group, $dmode, $fmode) = split(' ', $line);

    # skip blank lines and comments
    next if (!defined $pattern || $pattern =~ /^ *#/);

    push @pattern_list, $pattern;

    my %pa;  # pattern attributes
    my @field_names = qw/owner group dmode fmode/;

    # convert owner and group names to numbers
    @pa{@field_names} = (get_uid($owner), get_gid($group), oct($dmode), oct($fmode));

    $desired_perms{$pattern} = \%pa;
  }

  return {
    perms => \%desired_perms,
    patterns => \@pattern_list,
  };
}

sub get_current_perms {
  my ($file) = @_;
  my $sb = stat($file);
  if (!defined($sb)) {
    print "ERROR: unable to stat $file: $!\n";
    return undef;
  }
  return {
    owner => $sb->uid,
    group => $sb->gid,
    mode  => $sb->mode,
  };
}

my %parse_errors;
sub parse_error {
  my ($str) = @_;
  $parse_errors{$str} = undef;
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
  if ($file =~ /^${pattern}$/) {
    print "  rule = $pattern\n" if $options{verbosity} >= 4;
    return 1
  } else {
    return 0
  }
}

sub soct {  # convert number to octal string
  my ($number) = @_;
  return '-' if ($number == 0);
  return sprintf('%04o', $number & 0777);
}

sub perms_to_string {
  my ($p) = @_;
  if ($options{verbosity} >= 4) {
    use Data::Dumper;
    print Dumper $p;
  }
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

  print '  current ' . perms_to_string($current_perms) . "\n" if $options{verbosity} >= 3;
  print '  target  ' . perms_to_string($target_perms) . "\n" if $options{verbosity} >= 3;

  my @changes = ();
  my $change_count = 0;
  my $pending = 0;
  my $changed = 0;
  my $failed = 0;
  my @errors = ();

  # mode
  my $tmode = $target_perms->{mode};
  my $cmode = $current_perms->{mode};

  if ($tmode != 0 && $tmode != ($cmode & 0777)) {
    push @changes, sprintf "mode(%s->%s)", soct($cmode), soct($tmode);
    $change_count++;
    print "  chmod $tmode $file\n" if $options{verbosity} >= 3;
    if ($options{no_run}) {
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
    if ($options{no_run}) {
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
    if ($options{no_run}) {
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

  if (($options{verbosity} == 0 && $options{no_run} && $change_count > 0) ||
      ($options{verbosity} == 1 && $change_count > 0) ||
      ($options{verbosity} >= 2)) {
    print join(',', ($file_type, $file, @changes)) . "\n";
  }

  print map { '  ERROR: ' . $_ . "\n" } @errors;

  $metrics{pending} += $pending;
  $metrics{failed} += $failed;
  $metrics{changed} += $changed;
}

sub start_descent {
  my ($dir, $rules_href) = @_;

  #print "start descent from $dir ...\n" if $options{verbosity} >= 2;

  find({no_chdir => 1, wanted => sub {

    $metrics{inspected}++;

    # get the current file or dir, including dir & filename
    my $f = $File::Find::name;

    print "$f\n" if $options{verbosity} >= 4;

    for my $pattern (@{$rules_href->{patterns}}) {
      if (file_matches_pattern($f, $pattern)) {

        my $current_perms = get_current_perms($f);
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
}

sub print_summary {
  print 'Summary: ' . join(', ', map {
    $_ . '=' . $metrics{$_}
  } (qw/inspected changed failed pending/)) . "\n";
}

sub print_parse_errors {
  for my $e (keys %parse_errors) {
    print "PARSE_ERROR: $e\n";
  }
}

sub main {
  get_options();
  init_metrics();
  my $rules = get_pattern_rules($options{file});
  print_parse_errors();
  start_descent($options{dir}, $rules);
  print_summary();
  print "verbosity = $options{verbosity}\n" if $options{verbosity} >= 2;
}

main();

__END__

=head1 jperms.pl

recursively set permissions and ownerships according to pattern rules

=head1 OPTIONS

jperms.pl [options] [dir ...]

 Options:
   -help|-h|-?     help
   -man            full documentation
   -dir            directory to descend
   -file           patterns file
   -no_run         don't run any commands
   -verbosity      repeat to increase

=head1 DESCRIPTION

jperms.pl descends the specified directory tree applying permissions and
ownerships to each file or directory found according to a set
of pattern rules.

=head1 RULES

Pattern rules are specified as a list of lines.
Each line consists of 5 fields separated by whitespace:

 # pattern   owner   group   dir_mode   file_mode

- pattern is a regex (NOT a fileglob!) to be matched against each path
found during the tree descent.

- Patterns are automatically surrounded by ^ and $ when matching, meaning
that it must match the whole of the current path (not just part of it).

- file paths include the top level path exactly as specified on the command
line, so a pattern to match a *relative* top level directory (e.g.  "./dir")
must also match the dot (".") at the start of each path (e.g. "\./dir")

- The path of each file or directory found during the descent is compared
against each pattern in turn (top to bottom) until a match is found.  Pattern
matching for that path then stops and the owner, group, dir_mode
& file_mode associated with the matching pattern are applied to the file or
directory, where appropriate (see below).

- A value of '-' for any or all of owner, group, dir_mode or file_mode
means that this attribute are to be un-altered when a match is found.

- A dir_mode or file_mode value of 0 (or any string which evaluates to zero
when converted to a number) is treated as a '-'

- file or dir mode must be specified in octal

- A pattern may match both files and directories, but dir_mode are only ever
applied to directories, and file_mode are only applied to files

=head1 OUTPUT

By default jperms.pl prints only a summary upon completion with the following
details:

- inspected: the number of objects (files or directories) inspected

- changed: the number of objects changed. Note: change of owner, group or mode,
or all three counts as a single change

- failed: the number of objects on which a changed failed. Note: failure to chmod or
chown (or both) counts as a single failure

- unchanged: the number of objects which don't need to be changed, i.e.
they already match the pattern rules

- pending: the number of objects which need to be changed, but weren't
either due to error or -no_run mode.

Other output is controlled by the -verbosity level:

  0 summary
  1 objects & changes needed
  2 all objects (even if no change required)
  3 commands used to make changes
  3 pattern rules
  4 pattern debug
  4 current perms
  4 target perms
  4 file
  4 perms debug

=head1 USERS AND GROUPS

- owners and groups must be specified as names; numeric ids
are not supported

- only users & groups which exist are allowed (i.e. in /etc/passwd or
/etc/group)

- specifying a user or group which does not exist will
cause an error message to be printed and the field
will have no effecte, i.e.  it will be treated as if it were '-'

- files found during the descent with numeric owner or group ids
(i.e. the user or group does not exist on the host), are treated
like any other file; i.e. the new ownership/group will be applied
as specified by a matching rule

=head1 COMMENTS

Lines starting with a '#' (optionally preceeded by whitespace)
are treated as comments and ignored.

=head1 EXAMPLE PATTERNS

Example pattern file:

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

=head1 NOTES


