rule wells_fargo_phish
{
  meta:
    description = "Wells Fargo Phish"
    author = "Josh Stroschein josh@m9cyber.com"
    date = "2022-04-18"
 strings:
    $title = "Wells Fargo</title>" nocase
    $form_action = "action=\"./parse.php\""
    $user = "name=\"j_username\"" nocase
    $pass = "name=\"j_password\"" nocase
 condition:
    all of them
}
