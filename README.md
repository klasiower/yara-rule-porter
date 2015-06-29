# yara-rule-porter

yara-rule-porter is a package to transform yara rules.

It reads in yara rules from files or databases, parses them and applies a set of normalization or transformation scripts.

After that it will export the rules to files or databases again.

It is written in Perl and uses the Yara Parser [Parse::YARA](http://search.cpan.org/~moofu/Parse-YARA-0.02/lib/Parse/YARA.pm) written by Leigh Thompson.

# Installation

download the source and unpack it into a directory of your choice.  There are no external dependencies (Parse::YARA is already included in the package).

# Usage
    usage: bin/dedupe.pl [options] file [dir ...]
    parses, im- and exports yara rules from different places

    options:
     --help                   this help text
     --debug                  show what's going on
     --version                show version / revision
     --verbose                even more information
     --input-format format    valid formats are: yara, json
                              default: yara
     --include pattern        regular expression of filenames to include
                              can be given multiple times
                              default: include everything
     --exclude pattern        regular expression of filenames to exclude
                              can be given multiple times
                              default: exclude nothing
     --dump-rules             print parsed and normalized rules on STDOUT
     --output-format format   valid formats are: yara, json
                              default: yara
     --show-dupes             print duplicate rules on STDOUT


# Examples

### reading in a directory tree of yara rules and report duplicate rule names

    $ perl bin/dedupe.pl --include '\.yar$' --show-dupes  tests/
    // duplicate rule:abc file:tests/02_dupes_02.yar
    // duplicate rule:abc file:tests/02_dupes_02.yar

### reading in a directory tree of yara rules, parse and de-duplicate them, print result into a file

    $ perl bin/dedupe.pl --include '\.yar$' --dump-rules  tests/ > all_rules.yar

### same as above but uses json as serialization format

    $ perl bin/dedupe.pl --include '\.yar$' --dump-rules --output-format json tests/ > all_rules.json


# TODOs
* database im-/export
* pre-/post normalization scripts
* fix string modifier bug
* use generic iterator
* multiple input sources, formats and parser
