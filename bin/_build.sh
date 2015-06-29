#!/bin/sh

REVISION=$(/usr/bin/svnversion -n trunk)

/bin/sed -i 's/^\(.*\)\$Revision[^$]*\$\(.*\)$/\1$Revision '"${REVISION}"'$\2/' trunk/bin/dedupe.pl
