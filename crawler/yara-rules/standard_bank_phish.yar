rule standard_bank_phish
{
  meta:
    description = "Standard Bank Login Phish"
    author = "josh@m9cyber.com"
    date = "2022-03-06"
 strings:
    $title = "sign in</title>" nocase
    $form_submit = "send_login.php" nocase
    $user = "name=\"email\"" nocase
    $password = "name=\"password\"" nocase
    $register = "standard bank id?" nocase
 condition:
    all of them
}
