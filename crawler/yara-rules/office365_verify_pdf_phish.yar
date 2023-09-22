rule office365_verify_pdf_phish
{
  meta:
    description = "Office365/OneDrive Verify Yourself PDF phish"
    author = "josh@m9cyber.com"
    date = "2022-07-25"
 strings:
    $title = "Files - OneDrive"
    $form = "action=\"link.php\""
    $user = "id=\"txtTOAAEmail\""
    $verify = "Verify Yourself"

 condition:
    all of them
}
