rule webpanel_origin_login
{
  meta:
    description = "Origin (AgentTesla) Webpanel"
    author = "josh@m9cyber.com"
    date = "2022-02-21"
 strings:
    $title = "Login</title>"
    $form = "action=\"login.php\""
    $signin = "box-title m-b-20\">Sign In"
    $style = "margin: auto;margin-top:100px;}"
 condition:
    all of them
}