rule pony_panel_login
{
  meta:
    description = "Pony stealer panel login"
    author = "Josh Stroschein josh@m9cyber.com"
    date = "2022-04-03"
 strings:
    $title = "authorization</title>" nocase
    $form_action = "action=\"/panel/admin.php\"" nocase
    $lock = "lock_open.png" nocase
    $pass = "name=\"password\"" nocase
 condition:
    all of them
}
