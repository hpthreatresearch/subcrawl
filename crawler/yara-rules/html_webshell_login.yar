rule protected_webshell
{
  meta:
    description = "Protected Webshell Login"
    author = "HP Threat Research @HPSecurity"
    filetype = "PHP"
    maltype = "notifier"
    date = "2021-06-08"

  strings:
    $a1 = /actions*=\s*\"\"/
    $a2 = /methods*=\s*\"post\"/
    $a3 = /type\s*=\s*\"submit\"/
    $a4 = /name\s*=\s*\"[_{1}a-z]{3,4}\"/
	
    $b1 = /type\s*=\s*\"input\"/
    $b2 = /type\s*=\s*\"text\"/
   
    $c1 = /value\s*=\s*\"(\s*>\s*){1,2}\"/
    $c2 = /value\s*=\s*\"(\s?&gt;\s?){1,2}\"/
	
  condition:
    all of ($a*) and any of ($b*) and any of ($c*) and filesize < 1000
}
