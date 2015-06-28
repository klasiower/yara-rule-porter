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
	--help                this help text
	--debug               show what's going on
	--verbose             even more information
	--include pattern     regular expression of filenames to include
	                      can be given multiple times
	                      default: include everything
	 --exclude pattern    regular expression of filenames to exclude
	                      can be given multiple times
	                      default: exclude nothing

# Examples

### reading in a directory tree of yara rules and report duplicate rule names

    $ bin/dedupe.pl --include '\.yar$' ../data/test/
    duplicate rule:magic_bytes file:../data/test/magic.yar

# TODOs
* implement database im-/export
* implement pre-/post normalization scripts
* fix string modifier bug
