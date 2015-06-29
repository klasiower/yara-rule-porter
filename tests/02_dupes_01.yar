rule abc {
	meta:
		description = "rule abc 01 A"
	strings:
        $ = "a"
        $ = "b"
        $ = "c"
	condition:
		all of them
}
rule abc {
	meta:
		description = "rule abc 01 B"
	strings:
        $ = "a"
        $ = "b"
        $ = "c"
	condition:
		all of them
}
