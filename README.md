# yara-rule-porter
Im- / Exporter for yara rules

# usage
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

