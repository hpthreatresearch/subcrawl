rule mars_panel_login
{
  meta:
    description = "Mars stealer panel login"
    author = "Josh Stroschein josh@m9cyber.com"
    date = "2022-03-28"
    resources = "https://isc.sans.edu/diary/Arkei+Variants%3A+From+Vidar+to+Mars+Stealer/28468"
 strings:
    $title = "dashboard</title>" nocase
    $form_action = "action=\"login.php\"" nocase
    $login_btn = "name=\"do_login\"" nocase
    $pass = "name=\"password\"" nocase
 condition:
    all of them
}
