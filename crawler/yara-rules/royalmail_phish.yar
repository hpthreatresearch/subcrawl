rule royal_mail_phish
{
  meta:
    description = "Royal Mail phish"
    author = "Josh Stroschein josh@m9cyber.com"
    date = "2022-04-18"
 strings:
    $title = "royal mail group ltd</title>" nocase
    $form_action = "action=\"login.php\""
    $pass = "name=\"pass\"" nocase
 condition:
    all of them
}
