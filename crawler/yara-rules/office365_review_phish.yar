rule office365_review__phish
{
  meta:
    description = "Office 365 Review Document phish"
    author = "josh@m9cyber.com"
    date = "2022-07-12"
 strings:
    $form = "post.php" nocase
    $title = "Office 365</title>"
    $user = "id=\"email\""
    $placeholder = "Office 365 Email" nocase
 condition:
    all of them
}
