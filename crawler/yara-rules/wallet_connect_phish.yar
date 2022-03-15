rule wallet_connect_phish
{
  meta:
    description = "Wallet Connect phishing page"
    author = "josh@m9cyber.com"
    date = "2022-03-08"
 strings:
    $title = "intergations protocol</title>" nocase
    $form_action = "action=\"#\"" nocase
    $hidden = "value=\"AAVE\"" nocase
    $phrase = "name=\"phrase\"" nocase
    $private = "name=\"pkey\"" nocase
    $json = "name=\"kjson\"" nocase
 condition:
    all of them
}
