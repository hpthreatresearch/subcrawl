rule mana_tools_panel
{
  meta:
    description = "Mana Tools Panel"
    author = "patrick.schlapfer@hp.com"
    date = "2022-01-06"
 strings:
    $c = "background-image: url('1.jpg')"
    $d = "<title>Login</title>"
    $e = "id=\"loginform\" action=\"login.php\""
    $f = "<h3 class=\"box-title m-b-20\">Log-In</h3>"
    $g = "Username"
    $h = "Password"
    $ih = "Log In"
 condition:
    all of them
}
