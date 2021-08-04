rule js_webshell_tracking_script : notifier
{
  meta:
    description = "JavaScript which notifies the attacker when the webshell becomes active"
    author = "HP Threat Research @HPSecurity"
    filetype = "JavaScript"
    maltype = "notifier"
    date = "2021-06-08"

  strings:
    $a1 = "ndsj===undefined"
	$a2 = "ndsw===undefined"
	
	$b = "function"
	
	$c = "HttpClient"
	
	$d1 = "XMLHttpRequest"
	$d2 = "Math"
	$d3 = "undefined"
	
	$e1 = "onreadystatechange"
	$e2 = "responseText"
	$e3 = "random"
	$e4 = "ndsx"
	$e5 = "GET"
	$e6 = "open"
	$e7 = "send"
	
	$f1 = "parseInt"
	$f2 = /var\s*\w+\s*\=\s*\[(['\"][\w\.\?\/\:]+['\"][,\]\s]+)+/
	$g = "0x"

  condition:
    any of ($a*) and #b > 5 and #c >= 2 and all of ($d*) and (all of ($e*) or (all of ($f*) and #g > 50)) and filesize < 1MB
}
