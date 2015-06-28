
rule rtf
{
	meta:
        author = "tester"
	strings:
		
		$k3 = /ln\\\'[0-9A-F]{2}/
		$rtf = {7B 5C 72 74 (66|7B)} // {\rtf

	condition:
		$rtf at 0
}

rule abc {
	meta:
		description = "look mam, there is an apostrophe -> ' <- in the description!"
	strings:
        $ = "a"
        $ = "b"
        $ = "c"
	condition:
		all of them
}
