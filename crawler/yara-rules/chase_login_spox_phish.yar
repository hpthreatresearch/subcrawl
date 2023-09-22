rule chase_login_spox_phish
{
  meta:
    description = "Chase Bank Login"
    author = "josh@m9cyber.com"
    date = "2022-02-27"
 strings:
    $title = "Online enrollement</title>"
    $form = "action=\"regex.php\""
    $user = "name=\"id\""
    $pass = "name=\"password\""
 condition:
    all of them
}
