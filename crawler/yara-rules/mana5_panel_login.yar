rule mana5_panel_login
{
  meta:
    description = "Mana Tools Panel 5.0"
    author = "josh@m9cyber.com"
    date = "2022-03-17"
 strings:
    $title = "login</title>" nocase
    $banner = "lone wolf version 5.0" nocase
    $back_img = "background-image: url('1.jpg')"
    $html_title = "<h3 class=\"box-title m-b-20\">Log-In</h3>"
    $user = "name=\"username\"" nocase
    $pass = "name=\"password\"" nocase
    $button = "Log In"
 condition:
    all of them
}
