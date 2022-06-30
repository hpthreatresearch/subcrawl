rule outlook_phish
{
  meta:
    description = "Outlook login"
    author = "josh@m9cyber.com"
    date = "2022-06-29"
 strings:
    $form = "class=\"boxtext\"" nocase
    $title = "microsoft | login</title>" nocase
    $pass = "id=\"pr\""
    $header = "OUTLOOK</h2>"
 condition:
    all of them
}
