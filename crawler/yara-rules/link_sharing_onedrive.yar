rule link_sharing_onedrive
{
  meta:
    description = "OneDrive Link Sharing Phish"
    author = "josh@m9cyber.com"
    date = "2022-02-17"
 strings:
    $modified = "new injection"
    $title = /link.{0,10}validation<\/title>/ nocase
    $form = "bmV4dC5waHA=" //next.php
    $user = "id=\"ai\""
    $pass = "id=\"pr\""
 condition:
    all of them
}
