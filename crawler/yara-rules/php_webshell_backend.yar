rule php_webshell_backend : notifier
{
  meta:
    description = "PHP webshell backend used by the attacker"
    author = "HP Threat Research @HPSecurity"
    filetype = "PHP"
    maltype = "notifier"
    date = "2021-06-08"

  strings:
    $a1 = "__construct"
	$a2 = "ord"
	$a3 = "chr"
	$a4 = "class"
	$a5 = "strpos"
	$a6 = "strlen"
	
	$b = "array"
	$c = "function"
	$d = "var"
	
	$e = /\$\w+\s*\=\s*(\$\w+->\w+\[\d+\]\.?)+;/
	$f = /var\s*\$\w+\s*\=\s*['\"][\w\/\+\=\n\t]+/
	
  condition:
    all of ($a*) and #b >= 5 and #c == 9 and #d >= 9 and #e >= 5 and $f and filesize < 1MB
}
