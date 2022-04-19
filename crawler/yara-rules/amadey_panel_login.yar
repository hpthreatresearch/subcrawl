rule amadey_panel_login
{
  meta:
    description = "Amadey panel login"
    author = "Josh Stroschein josh@m9cyber.com"
    date = "2022-04-08"
 strings:
    $title = "authorization</title>" nocase
    $form_action = "action=\"Login.php\""
    $bg_img = "images\\bg_1.png"
    $pass = "name=\"password\"" nocase
 condition:
    all of them
}
