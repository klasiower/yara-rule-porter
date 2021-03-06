#!/usr/bin/perl

use warnings;
use strict;

use FindBin;
use lib $FindBin::Bin.'/../lib';

my $config = {
    _revision_nr    => (sprintf '%s', q$Revision 4:14M$ =~ /(\S+)$/),

    debug           => 0,
    verbose         => 0,

    root_dir        => $FindBin::Bin.'/..',
    rule_paths      => undef,

    exclude         => [],
    include         => [],

    dump_rules      => 0,
    output_format   => 'yara',
    input_format    => 'yara',

    show_dupes      => 0,
};

## reading in configuration given on command line
# and merging with default config
my $command_line_config = get_command_line_config();
$config = { %$config, %$command_line_config };

sub debug   { $config->{debug}   && print STDERR  "[DBG] @_\n" }
sub verbose { $config->{verbose} && print STDERR "[VERB] @_\n" }
sub warn    {                       print STDERR "[WARN] @_\n" }
sub error   {                       print STDERR  "[ERR] @_\n" }

if ($config->{version}) {
    printf '%s revision:%s'."\n", $0, $config->{_revision_nr};
    exit 0;
}

if ($config->{help} or (!defined  $config->{rule_paths}) or
                       (!scalar @{$config->{rule_paths}})) {
    usage({ defaults => $config });
    exit 1;
}

## building file iterator
my $file_iterator = file_iterator->new({
    include => $config->{include},
    exclude => $config->{exclude},
});
# create list of files to parse
$file_iterator->build_file_list($config->{rule_paths});

## creating parser
# which wrapps Parse::YARA
# FIXME support for multiple parser depending on input format
my $parser = parser->new({
    verbose         => $config->{verbose} // 0,
    input_format    => $config->{input_format},
});

## parsing each file
while (my $file = $file_iterator->get_next_file()) {
    $parser->parse_file($file);
}

## show dupes
if ($config->{show_dupes}) {
    while (my $dupe = $parser->get_next_dupe()) {
        printf '// duplicate rule:%s file:%s'."\n", $dupe->{rule_id}, $dupe->{file};
    }
}

## print rules if told so
if ($config->{dump_rules}) {
    if ($config->{output_format} eq 'yara') {
        print $parser->dump_rules()
    } elsif ($config->{output_format} eq 'json') {
        my $hash = $parser->dump_rules_hash();
        # FIXME generalize output formater
        use JSON;
        my $json = JSON->new();
        print $json->pretty->encode($hash);
    } else {
        error("[dump_rules] unknown output-format:$config->{output_format}");
    }
}

debug(sprintf('[end] found files:%i rules:%i dupes:%i', $file_iterator->file_count(), $parser->rule_count(), $parser->dupe_count()));

exit 0;

##################################################################

# FIXME operates intrusively on ARGV
sub get_command_line_config {
    my $command_line_config = {};
    use Getopt::Long;
    my %opts;
    my $result = Getopt::Long::GetOptions(
        'help'                  => \$opts{help},
        'debug'                 => \$opts{debug},
        'verbose'               => \$opts{verbose},
        'version'               => \$opts{version},
        'exclude=s@'            => \$opts{exclude},
        'include=s@'            => \$opts{include},
        'dump-rules'            => \$opts{dump_rules},
        'output-format=s'       => \$opts{output_format},
        'show-dupes'            => \$opts{show_dupes},
    );

    if (defined $opts{debug})         { $command_line_config->{debug}         = $opts{debug}         }
    if (defined $opts{verbose})       { $command_line_config->{verbose}       = $opts{verbose}       }
    if (defined $opts{version})       { $command_line_config->{version}       = $opts{version}       }
    if (defined $opts{help})          { $command_line_config->{help}          = $opts{help}          }
    if (defined $opts{exclude})       { $command_line_config->{exclude}       = $opts{exclude}       }
    if (defined $opts{include})       { $command_line_config->{include}       = $opts{include}       }
    if (defined $opts{dump_rules})    { $command_line_config->{dump_rules}    = $opts{dump_rules}    }
    if (defined $opts{output_format}) { $command_line_config->{output_format} = $opts{output_format} }
    if (defined $opts{show_dupes})    { $command_line_config->{show_dupes}    = $opts{show_dupes}    }

    # treat the rest of the command line arguments as file / directory names
    $command_line_config->{rule_paths} = [ @ARGV ];

    return $command_line_config;
}

sub usage {
    my ($args) = @_;
    print STDERR "usage: $0 [options] file [dir ...]\n" .
                 "parses, im- and exports yara rules from different places\n".
                 "\n" .
                 "options:\n" .
                 " --help                   this help text\n" .
                 " --debug                  show what's going on\n" .
                 " --version                show version / revision\n" .
                 " --verbose                even more information\n" .
                 " --input-format format    valid formats are: yara, json\n" .
                 "                          default: yara\n" .
                 " --include pattern        regular expression of filenames to include\n" . 
                 "                          can be given multiple times\n" .
                 "                          default: include everything\n".
                 " --exclude pattern        regular expression of filenames to exclude\n" . 
                 "                          can be given multiple times\n" .
                 "                          default: exclude nothing\n" .
                 " --dump-rules             print parsed and normalized rules on STDOUT\n" .
                 " --output-format format   valid formats are: yara, json\n" .
                 "                          default: yara\n" .
                 " --show-dupes             print duplicate rules on STDOUT\n" .
    '';

}


#########################################################
package file_iterator;
use warnings;
use strict;

use File::Find;

sub new {
    my ($class, $args) = @_;
    $args //= {};
    my $self = bless $args, $class;

    ## build regular expressions from patterns of files to in- / exclude
    # FIXME getter / setter for *_re:s
    $self->{include_re} = undef;
    if (scalar @{$args->{include}}) {
        $self->{include_re} = '(?:'. (join '|', @{$args->{include}}) .')';
        main::verbose("[new][include_re] $self->{include_re}");
    }
    $self->{exclude_re} = undef;
    if (scalar @{$args->{exclude}}) {
        $self->{exclude_re} = '(?:'. (join '|', @{$args->{exclude}}) .')';
        main::verbose("[new][exclude_re] $self->{exclude_re}");
    }

    ## FIXME generic iterator
    $self->{files}{position}  = undef;
    $self->{files}{items}     = [];
    return $self;
}

sub build_file_list {
    my ($self, $roots) = @_;

    my $rule_files = [];

    foreach my $rule_path (@$roots) {
        if (-f $rule_path) {
            main::verbose("[build_file_list] $rule_path is a file");
            if ($self->check_filename($rule_path)) {
                push @$rule_files, $rule_path;
            }
        } elsif (-d $rule_path) {
            main::verbose("[build_file_list] $rule_path is a directory, recursing");
            $self->recurse_dir($rule_path, \$rule_files);
        } else {
            main::warn("[build_file_list] unknown file object:$rule_path");
        }
    }
    ## joining arrays
    $self->{files}{items} = [ @{$self->{files}{items}}, @$rule_files ];
    main::debug(sprintf('[build_file_list] new files:%i total:%i', scalar @$rule_files, $self->file_count()));
}

sub recurse_dir {
    my ($self, $dir, $files) = @_;
    File::Find::find( sub {
        # verbose("[recurse_dir][$dir] checking $_");
        return unless -f $_;
        if ($self->check_filename($File::Find::name)) {
            main::verbose("[recurse_dir][$dir] adding $_");
            ## FIXME ugly interface
            push @{$$files}, $File::Find::name;
        }
    }, $dir);
}


sub check_filename {
    my ($self, $file) = @_;
    if ((defined $self->{include_re}) and ($file !~ m{$self->{include_re}})) {
        main::verbose("[check_filename][$file] not included:($self->{include_re})");
        return 0;
    }
    if ((defined $self->{exclude_re}) and ($file =~ m{$self->{exclude_re}})) {
        main::verbose("[check_filename][$file] excluded:($self->{exclude_re})");
        return 0;
    }
    return 1;
}

sub get_next_file {
    my ($self) = @_;
    if (! defined $self->{files}{position}) {
        $self->{files}{position} = 0;
    }
    if ((! defined $self->{files}{items}) or (scalar @{$self->{files}{items}} <= $self->{files}{position})) {
        return undef;
    }
    return $self->{files}{items}->[$self->{files}{position} ++]
}

sub file_count {
    my ($self) = @_;
    return scalar @{$self->{files}{items}};
}

1;

#########################################################
package parser;
use warnings;
use strict;

sub new {
    my ($class, $args) = @_;
    $args //= {};
    my $self = bless $args, $class;

    $self->{wrapper} = parser::wrapper->new( verbose => $args->{verbose} // 0);

    ## FIXME generic iterator
    $self->{dupes}{position}  = undef;
    $self->{dupes}{items}     = [];
    return $self;
}


sub wrapper_parse_file {
    my ($self, $file, $context) = @_;
    main::verbose("[parse_file][$file]");
    eval {
        $self->{wrapper}->read_file($file, $context);
    };  if ($@) {
        my $e = $@;  chomp $e;
        main::error(sprintf('[parse_file][%s] can\'t parse (%s)', $file, $e));
        return undef;
    }
}

sub parse_file {
    my ($self, $file, $context) = @_;

    $context //= {};
    $context->{file} //= $file;

    local $SIG{__WARN__} = sub {
        my ($w) = @_;  chomp $w;
        ## collect warnings about duplicate rule names
        # 'duplicate rule_id:office_magic_bytes line:(rule office_magic_bytes)'
        if (my ($rule_id) =  $w =~ m{duplicate rule_id:(.*?) line}) {
            push @{$self->{dupes}{items}}, {
                file    => $file,
                rule_id => $rule_id,
            };
            main::debug("[$file] $w");
            return;
        }
        ## ignore subsequent error messages
        # 'select a new name or try'
        if ($w =~ m{(?:select|pick) a new name or try}) {
            main::verbose("[$file] $w");
            return;
        }
        if ($w =~ m{already set\.}) {
            main::verbose("[$file] $w");
            return;
        }

        main::warn("[$file] $w");
    };
    eval {
        $self->wrapper_parse_file($file, $context);
    };
}

sub wrapper_dump_rules {
    my ($self) = @_;
    return $self->{wrapper}->as_string();
}

sub dump_rules {
    my ($self) = @_;
    return $self->wrapper_dump_rules();
}

sub dump_rules_hash {
    my ($self) = @_;
    return $self->wrapper_dump_rules_hash();
}

sub wrapper_dump_rules_hash {
    my ($self) = @_;
    return $self->{wrapper}->as_hash();
}


sub rule_count {
    my ($self) = @_;
    return $self->wrapper_rule_count();
}

sub wrapper_rule_count {
    my ($self) = @_;
    return scalar keys %{$self->{wrapper}{rules}};
}

sub get_next_dupe {
    my ($self) = @_;
    if (! defined $self->{dupes}{position}) {
        $self->{dupes}{position} = 0;
    }
    if ((! defined $self->{dupes}{items}) or (scalar @{$self->{dupes}{items}} <= $self->{dupes}{position})) {
        return undef;
    }
    return $self->{dupes}{items}->[$self->{dupes}{position} ++]
}

sub dupe_count {
    my ($self) = @_;
    return scalar @{$self->{dupes}{items}};
}


1;
#########################################################################
package parser::wrapper;
use strict;
use warnings;
use Carp;

use base qw(Parse::YARA);

sub parse {
    my ($self, $rule_string, $context) = @_;
    my $modifier;
    my $rule_id;
    my $tags;
    my $position = 1;
    my $rule_data = {};
    my $knot = tie(%{$rule_data}, 'Tie::IxHash');


    # convert 'alien' line feeds into '\n'
    $rule_string =~ s#(\r\n|\r|\n)#\n#g;

    # Strip comments, I have replaced the comments with a newline as otherwise it was stripping the newline, this hasn't broken anything so far.
    # For an explanation, see: http://perldoc.perl.org/perlfaq6.html#How-do-I-use-a-regular-expression-to-strip-C-style-comments-from-a-file%3F
    $rule_string =~ s#/\*[^*]*\*+([^/*][^*]*\*+)*/|//([^\\]|[^\n][\n]?)*?\n|("(\\.|[^"\\])*"|'(\\.|[^'\\])*'|.[^/"'\\]*)#defined $3 ? $3 : "\n"#gse;
    $rule_string =~ s#\n\s*//.*##g;

    # stripping comments at line endings
    # $rule_string =~ s#//.*$##g;

    # Tidy up any strings that come in with strange formatting
    # Rules with the close brace for previous rule on the same line
    $rule_string =~ s#\n\s*}\s*(rule.*)#}\n$1#g;
    # String / Meta names on one line but values on the next
    $rule_string =~ s#\s*(\S+)\s*=\s*\n\s*(\S+)#\n\t\t$1 = $2\n#g;
    # Multiple strings on the same line
    $rule_string =~ s#(\/)(\$\S+\s*=)#$1\n\t\t$2#g;
    $rule_string =~ s#(")(\$\S+\s*=)#$1\n\t\t$2#g;
    $rule_string =~ s#(})(\$\S+\s*=)#$1\n\t\t$2#g;

    # main::verbose("[parse] rule string:($rule_string)");

    # Parse the rule line by line
    while($rule_string =~ /([^\n]+\n)?/g) {
        my $line = $1;

        # Need to find a rule_id before we can start
        if($line and $line =~ /^(?:(global|private)\s+)?rule\s+([a-zA-Z0-9_]+)(?:\s*:\s*([^{]*))?\s*({.*})?/) {
            chomp($line);
            $rule_id = $2;
            if (exists $rule_data->{$rule_id} or exists $self->{rules}->{$rule_id}) {
                carp("duplicate rule_id:$rule_id file:$context->{file} line:($line)");
                # FIXME make handling of duplicate rule_ids configurable
                $rule_id = undef;
                next;
            }
            $rule_data->{$rule_id}->{_context} = { %$context };
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
        $rule_data->{$rule}->{raw} =~ s|}\s*(?:/\s*/.*)?$|\n}|;
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

sub read_file {
    my ($self, $file, $context) = @_;
    my $rules = "";
    my @include_files;
    $context //= {};
    $context->{file} = $file;

    if($self->{verbose}) { print STDERR "Parsing file: $file\n" };

    open(RULESFILE, "<", $file) or die $!;
    # Loop through rules file and find all YARA rules
    while(<RULESFILE>) {
        # If we are including files, push to an array so we can
        # read them all in later
        if($self->{include} and /^include\s+"(.*?)"/) {
            push(@include_files, File::Basename::dirname($file) . "/" . $1);
        } elsif(!/^include\s+"(.*?)"/) {
            $rules .= $_;
        }
    }
    close(RULESFILE);

    $self->parse($rules, $context);

    # Parse any include's we found earlier on
    foreach my $include_file (@include_files) {
        $self->read_file($include_file, $context);
    }

}

# _rule_as_hash
# Parses the rule hash(es) contained within $self or if a $rule_id is provided parses that rule.
# Returns a string of the rule printed in YARA format.

sub _rule_as_hash {
    my ($self, $rule_id) = @_;
    my $ret = {};
    my @missing;

    # Check for condition, if not the rule is invalid
    if(!exists($self->{rules}->{$rule_id}->{condition})) {
        carp("$rule_id does not contain a condition.");
    } else {
        if($self->{rules}->{$rule_id}->{modifier}) {
            # $ret .= $self->{rules}->{$rule_id}->{modifier} . " ";
            $ret->{modifier} = $self->{rules}->{$rule_id}->{modifier};
        }

        # $ret .= "rule $rule_id";
        $ret->{rule_id} = $rule_id;

        # If tags are set, add a : after the rule_id and then space separate each tag
        if($self->{rules}->{$rule_id}->{tags}) {
            # $ret .= " :";
            foreach my $tag (@{$self->{rules}->{$rule_id}->{tags}}) {
                # $ret .= " $tag";
                push @{$ret->{tags}}, $tag;
            }
        }

        # Now add the opening brace on a new line
        # $ret .= "\n{";

        # If their is a meta element, loop through each entry and add to the rule string
        if($self->{rules}->{$rule_id}->{meta}) {
            # $ret .= "\n";
            # $ret .= "\tmeta:\n";
            foreach my $meta_name (keys(%{$self->{rules}->{$rule_id}->{meta}})) {
                my $meta_val;
                if($self->{rules}->{$rule_id}->{meta}->{$meta_name} =~ /^(\d+|true|false)$/) {
                    $meta_val = $self->{rules}->{$rule_id}->{meta}->{$meta_name};
                } else {
                    $meta_val = "\"$self->{rules}->{$rule_id}->{meta}->{$meta_name}\"";
                }
                # $ret .= "\t\t$meta_name = $meta_val\n";
                push @{$ret->{meta}}, { key => $meta_name, value => $meta_val };
            }
        }

        # If their is a strings element, loop through each entry and add to the rule string
        if($self->{rules}->{$rule_id}->{strings}) {
            # $ret .= "\n";
            # $ret .= "\tstrings:\n";
            foreach my $string_name (keys(%{$self->{rules}->{$rule_id}->{strings}})) {
                my $string_struct = {};
                my $display_name = $string_name;
                my $display_val;
                if($string_name =~ /^\$+$/) {
                    $display_name = '$';
                }
                if($self->{rules}->{$rule_id}->{strings}->{$string_name}->{type} eq "text") {
                    $display_val = "\"$self->{rules}->{$rule_id}->{strings}->{$string_name}->{value}\"";
                    foreach my $str_mod (@{$self->{rules}->{$rule_id}->{strings}->{$string_name}->{modifier}}) {
                        # $display_val .= " $str_mod";
                        push @{$string_struct->{modifier}}, $str_mod;
                    }
                } elsif($self->{rules}->{$rule_id}->{strings}->{$string_name}->{type} eq "hex") {
                    $display_val = $self->{rules}->{$rule_id}->{strings}->{$string_name}->{value};
                } elsif($self->{rules}->{$rule_id}->{strings}->{$string_name}->{type} eq "regex") {
                    $display_val = $self->{rules}->{$rule_id}->{strings}->{$string_name}->{value};
                }
                # $ret .= "\t\t$display_name = $display_val\n";
                $string_struct->{key}   = $display_name;
                $string_struct->{value} = $display_val;
                push @{$ret->{strings}}, $string_struct;
            }
        }

        # Add the condition and closing brace
        # $ret .= "\n";
        # $ret .= "\tcondition:\n";
        # $ret .= "\t\t$self->{rules}->{$rule_id}->{condition}\n";
        # $ret .= "}";
        $ret->{condition} = $self->{rules}->{$rule_id}->{condition};
    }

    return $ret;
}

sub as_hash {
    my ($self, $rule_id) = @_;
    my $ret = {};

    # Check to see if their is a rule_id and return that rule as a string
    if($rule_id) {
        $ret = $self->_rule_as_hash($rule_id);
    } else {
        # Otherwise loop through the hash and return all rules as a string
        foreach my $rule_id (keys(%{$self->{rules}})) { 
            $ret->{rules}{$rule_id} = $self->_rule_as_hash($rule_id);
        }
    }

    return $ret;
}


1;
