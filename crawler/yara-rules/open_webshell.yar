rule open_webshell
{
  meta:
    description = "Open Webshell Detection"
    author = "patrick.schlapfer@hp.com"
    date = "2021-04-19"

  strings:
    $a = "file manager"
    $b = "uname"

  condition:
    all of them
}
