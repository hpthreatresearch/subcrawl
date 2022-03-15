rule microsoft_phish
{
  meta:
    description = "Microsoft login"
    author = "josh@m9cyber.com"
    date = "2022-03-01"
 strings:
    $form = "office/login.php" nocase
    $title = "sign in to your microsoft account</title>" nocase
    $user = "id=\"user\""
    $redirect = "pass.php" nocase
 condition:
    all of them
}
