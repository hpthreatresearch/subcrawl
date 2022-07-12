rule sharepoint_dropbox_online_phish
{
  meta:
    description = "Sharepoint Online Multiple Logins with Dropbox login theme"
    author = "josh@m9cyber.com"
    date = "2022-07-11"
 strings:
    $title = "share point online</title>" nocase
    $user = "id=\"email\""
    $post_url = "next.php" nocase
    $dropbox = "DropBox Buisness"
 condition:
    all of them
}
