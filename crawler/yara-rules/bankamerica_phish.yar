rule bank_america_phish
{
  meta:
    description = "Bank of America Phishing"
    author = "Josh Stroschein josh@m9cyber.com"
    date = "2022-04-19"
 strings:
    $title = "<title>Bank of America -" nocase
    $form_action = "action=\"login.php\""
    $id = "name=\"onlineId1\"" nocase
    $pass = "name=\"passcode1\"" nocase
 condition:
    all of them
}
