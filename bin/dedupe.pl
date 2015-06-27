#!/usr/bin/perl

use warnings;
use strict;

use FindBin;
use lib $FindBin::Bin.'/../lib';

use File::Find;

my $config = {
    debug           => 0,
    verbose         => 0,

    root_dir        => $FindBin::Bin.'/..',
    rule_paths      => undef,

    exclude         => [],
    include         => [],
};

use Getopt::Long;
{
    my %opts;
    my $result = Getopt::Long::GetOptions(
        'help'                  => \$opts{help},
        'debug'                 => \$opts{debug},
        'verbose'               => \$opts{verbose},
        'exclude=s@'            => \$opts{exclude},
        'include=s@'            => \$opts{include},
    );

    if (defined $opts{debug})     { $config->{debug}    = $opts{debug}   }
    if (defined $opts{verbose})   { $config->{verbose}  = $opts{verbose} }
    if (defined $opts{help})      { $config->{help}     = $opts{help}    }
    if (defined $opts{exclude})   { $config->{exclude}  = $opts{exclude} }
    if (defined $opts{include})   { $config->{include}  = $opts{include} }
}

sub debug   { $config->{debug}   && print STDERR  "[DBG] @_\n" }
sub verbose { $config->{verbose} && print STDERR "[VERB] @_\n" }
sub warn    {                       print STDERR "[WARN] @_\n" }
sub error   {                       print STDERR  "[ERR] @_\n" }

# treat the rest of the command line arguments as file / directory names
$config->{rule_paths} = [ @ARGV ];

if ($config->{help} or (!defined  $config->{rule_paths}) or
                       (!scalar @{$config->{rule_paths}})) {
    usage({ defaults => $config });
    exit 1;
}

# build regular expressions from patterns of files to in- / exclude
my $include_re = undef;
if (scalar @{$config->{include}}) {
    $include_re = '(?:'. (join '|', @{$config->{include}}) .')';
    verbose("[include_re] $include_re");
}
my $exclude_re = undef;
if (scalar @{$config->{exclude}}) {
    $exclude_re = '(?:'. (join '|', @{$config->{exclude}}) .')';
    verbose("[exclude_re] $exclude_re");
}

# create list of files to parse
my $rule_files = [];

foreach my $rule_path (@{$config->{rule_paths}}) {
    if (-f $rule_path) {
        verbose("[path_iterator] $rule_path is a file");
        if (check_filename($rule_path, $include_re, $exclude_re)) {
            push @$rule_files, $rule_path;
        }
    } elsif (-d $rule_path) {
        verbose("[path_iterator] $rule_path is a directory, recursing");
        recurse_dir($rule_path, \$rule_files, $include_re, $exclude_re);
    } else {
        main::warn("[path_iterator] unknown file object:$rule_path");
    }
}
debug(sprintf('found %i files', scalar @$rule_files));

my $parser = YaraParser->new( verbose => $config->{verbose} // 0);
my $dupes = [];
foreach my $file (@$rule_files) {
    local $SIG{__WARN__} = sub {
        my ($w) = @_;  chomp $w;
        ## collect warnings about duplicate rule names
        # 'duplicate rule_id:office_magic_bytes line:(rule office_magic_bytes)'
        if (my ($rule_id) =  $w =~ m{duplicate rule_id:(.*?) line}) {
            push @$dupes, {
                file    => $file,
                rule_id => $rule_id,
            };
            debug("[$file] $w");
            return;
        }
        ## ignore subsequent error messages
        # 'select a new name or try'
        if ($w =~ m{(?:select|pick) a new name or try}) {
            verbose("[$file] $w");
            return;
        }
        if ($w =~ m{already set\.}) {
            verbose("[$file] $w");
            return;
        }

        main::warn("[$file] $w");
    };
    eval {
        parse_file($file, $parser);
    };
}

foreach my $dupe (@$dupes) {
    printf 'duplicate rule:%s file:%s'."\n", $dupe->{rule_id}, $dupe->{file}
}

debug(sprintf('[end] found rules:%i dupes:%i', scalar keys %{$parser->{rules}}, scalar @$dupes));
exit 0;

##################################################################
sub usage {
    my ($args) = @_;
    print STDERR "usage: $0 [options] file [dir ...]\n" .
                 "parses, im- and exports yara rules from different places\n".
                 "\n" .
                 "options:\n" .
                 " --help               this help text\n" .
                 " --debug              show what's going on\n" .
                 " --verbose            even more information\n" .
                 " --include pattern    regular expression of filenames to include\n" . 
                 "                      can be given multiple times\n" .
                 "                      default: include everything\n".
                 " --exclude pattern    regular expression of filenames to exclude\n" . 
                 "                      can be given multiple times\n" .
                 "                      default: exclude nothing\n"
    ;

}

sub check_filename {
    my ($file, $include_re, $exclude_re) = @_;
    if ((defined $include_re) and ($file !~ m{$include_re})) {
        verbose("[check_filename][$file] not included:($include_re)");
        return 0;
    }
    if ((defined $exclude_re) and ($file =~ m{$exclude_re})) {
        verbose("[check_filename][$file] excluded:($exclude_re)");
        return 0;
    }
    return 1;
}

sub recurse_dir {
    my ($dir, $files, $include_re, $exclude_re) = @_;
    File::Find::find( sub {
        # verbose("[recurse_dir][$dir] checking $_");
        return unless -f $_;
        if (check_filename($File::Find::name, $include_re, $exclude_re)) {
            verbose("[recurse_dir][$dir] adding $_");
            push @{$$files}, $File::Find::name;
        }
    }, $dir);
}

sub parse_file {
    my ($file, $parser) = @_;
    verbose("[parse_file][$file]");
    unless (defined $parser) {
        $parser = YaraParser->new( verbose => $config->{verbose} // 0);
    }
    eval {
        $parser->read_file($file);
    };  if ($@) {
        my $e = $@;  chomp $e;
        error(sprintf('[parse_file][%s] can\'t parse (%s)', $file, $e));
        return undef;
    }

#     map {
#         chomp;
#         verbose("[$file] $_");
#     } split /\n/, $parser->as_string();
}

#########################################################################
package YaraParser;
use strict;
use warnings;
use Carp;

use base qw(Parse::YARA);

sub parse {
    my ($self, $rule_string) = @_;
    my $modifier;
    my $rule_id;
    my $tags;
    my $position = 1;
    my $rule_data = {};
    my $knot = tie(%{$rule_data}, 'Tie::IxHash');

    # Strip comments, I have replaced the comments with a newline as otherwise it was stripping the newline, this hasn't broken anything so far.
    # For an explanation, see: http://perldoc.perl.org/perlfaq6.html#How-do-I-use-a-regular-expression-to-strip-C-style-comments-from-a-file%3F
    $rule_string =~ s#/\*[^*]*\*+([^/*][^*]*\*+)*/|//([^\\]|[^\n][\n]?)*?\n|("(\\.|[^"\\])*"|'(\\.|[^'\\])*'|.[^/"'\\]*)#defined $3 ? $3 : "\n"#gse;
    $rule_string =~ s/\n\/\/.*//g;

    # Tidy up any strings that come in with strange formatting
    # Rules with the close brace for previous rule on the same line
    $rule_string =~ s/\n\s*}\s*(rule.*)/\n}\n$1/g;
    # String / Meta names on one line but values on the next
    $rule_string =~ s/\s*(\S+)\s*=\s*\n\s*(\S+)/\n\t\t$1 = $2\n/g;
    # Multiple strings on the same line
    $rule_string =~ s/(\/)(\$\S+\s*=)/$1\n\t\t$2/g;
    $rule_string =~ s/(")(\$\S+\s*=)/$1\n\t\t$2/g;
    $rule_string =~ s/(})(\$\S+\s*=)/$1\n\t\t$2/g;

    # convert 'alien' line feeds into '\n'
    $rule_string =~ s{(\r\n|\r|\n)}{\n}g;

    # Parse the rule line by line
    while($rule_string =~ /([^\n]+\n)?/g) {
        my $line = $1;

        # Need to find a rule_id before we can start
        if($line and $line =~ /^(?:(global|private)\s+)?rule\s+([a-zA-Z0-9_]+)(?:\s*:\s*([^{]*))?\s*({.*})?/) {
            chomp($line);
            $rule_id = $2;
            if (exists $rule_data->{$rule_id}) {
                carp("duplicate rule_id:$rule_id line:($line)");
            }
            $rule_data->{$rule_id}->{modifier} = $1;
            $rule_data->{$rule_id}->{tags} = $3;
            # Make sure we don't set the rule_id to a YARA reserved word
            if($self->_check_reserved($rule_id, 'rule_id')) {
                carp("Cannot use reserved word as rule identifier: $rule_id");
                next;
            } elsif(!$self->_is_valid($rule_id, 'rule_id')) {
                # Or to an invalid one
                next;
            }

            $rule_data->{$rule_id}->{raw} = '';
            # If $4 exists, we have found a single line rule so add all the data to raw
            if($4) {
                $rule_data->{$rule_id}->{raw} = $4;
            }
        # Because their is no rule_id set we can't
        # add the line to the rule_data
        } elsif(!$rule_id) {
            next;
        # Now we have a rule_id, add the current
        # line to the rule_data ready for parsing
        } elsif($line) {
            $rule_data->{$rule_id}->{raw} .= $line;
        }
    }

    # Extract meta, strings and conditions from
    # each rule and add it to the hashref
    foreach my $rule (keys(%{$rule_data})) {
        # Tidy up the raw rule string to make sure we can easily parse this
        # line by line
        $rule_data->{$rule}->{raw} =~ s/(strings:|meta:|condition:)/\n\t$1\n\t\t/g;
        $rule_data->{$rule}->{raw} =~ s/}\s*$/\n}/;
        $self->_parse_meta($rule, $rule_data->{$rule}->{raw});
        $self->_parse_strings($rule, $rule_data->{$rule}->{raw});
        $self->_parse_condition($rule, $rule_data->{$rule}->{raw});
        if($rule_data->{$rule}->{modifier}) {
            $self->set_rule_modifier($rule, $rule_data->{$rule}->{modifier});
        }

        # If we found any tags add each one as an element
        # of an array to the tags key
        if($rule_data->{$rule}->{tags}) {
            foreach(split(/\s+/, $rule_data->{$rule}->{tags})) {
                $self->add_tag($rule, $_);
            }
        }
        # This is useful for testing
        if($self->{verbose}) {
            print "Added rule: $rule";
            if($self->{rules}->{$rule}->{tags} and scalar($self->{rules}->{$rule}->{tags}) > 0) {
                print " :";
                foreach my $tag (@{$self->{rules}->{$rule}->{tags}}) {
                    print " $tag";
                }
            }
            print "\n";
        }
    }
}

