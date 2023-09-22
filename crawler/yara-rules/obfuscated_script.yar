rule obfuscated_script
{
  meta:
    description = "Looks for common functions and patterns to deobfuscate scripts"
    author = "josh@m9cyber.com"
    date = "2022-02-27"
 strings:
    $eval = "eval(" nocase
    $hex = "hex(" nocase
    $split = "split(" nocase
    $exec = "execute" nocase
    $char ="char(" nocase
    $from_hex = /([\d]{2,3}[^\d]{1,10}){200,}/
 condition:
    ($hex or $split or $char or $from_hex) and ($eval or $exec)
}
