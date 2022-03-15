rule unk_webpanel_login
{
  meta:
    description = "Unsure of panel, login page"
    author = "josh@m9cyber.com"
    date = "2022-03-10"
 strings:
    $title = "web panel | login</title>" nocase
    $form_action = "action=\"login.php\"" nocase
    $pass = "name=\"password\"" nocase
    $user = "name=\"username\"" nocase

 condition:
    all of them
}
