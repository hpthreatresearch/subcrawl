rule sharepoint_online_phish
{
  meta:
    description = "Sharepoint Online Multiple Logins"
    author = "josh@m9cyber.com"
    date = "2022-03-02"
 strings:
    $title = "share point online</title>" nocase
    $user = "id=\"email\""
    $post_url = "next.php" nocase
 condition:
    all of them
}
