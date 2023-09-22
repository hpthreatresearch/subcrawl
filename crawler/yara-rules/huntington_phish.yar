rule huntington_bank_phish
{
  meta:
    description = "Huntington Bank Phishing Kit"
    author = "josh@m9cyber.com"
    date = "2022-02-17"
 strings:
    $banner = "hgn.png"
    $title = "Huntington</title>"
    $title_html = "&#72;&#117;&#110;&#116;&#105;&#110;&#103;&#116;&#111;&#110;</title>"
    $form = "action=need1.php"
    $user = "name=\"ud\""
    $pass = "name=\"pd\""
 condition:
    ($title or $title_html) and $banner and $form and $user and $pass
}
