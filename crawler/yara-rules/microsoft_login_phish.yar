rule microsoft_login_phish
{
  meta:
    description = "Microsoft login"
    author = "josh@m9cyber.com"
    date = "2022-10-19"
 strings:
    $form = "<form id=\"contact\"" nocase
    $title = "Microsoft | Login</title>" nocase
    $user = "name=\"ai\""
    $submit  = "bmV4dC5waHA=" //next.php
    $forget = "Forget password?" nocase
 condition:
    all of them
}
