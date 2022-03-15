rule attachments_onedrive_phish
{
  meta:
    description = "OneDrive Attachments Phish"
    author = "josh@m9cyber.com"
    date = "2022-03-02"
 strings:
    $title = "attachments - onedrive</title>" nocase
    $post_out = "loginout.php" nocase
    $post_365 = "login365.php" nocase
    $class = "class=\"login-form\"" nocase
 condition:
    all of them
}
