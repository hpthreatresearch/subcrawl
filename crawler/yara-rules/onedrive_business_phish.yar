rule onedrive_business_phish
{
  meta:
    description = "OneDrive Business phishing page w/ multiple sign-in options"
    author = "josh@m9cyber.com"
    date = "2022-02-25"
 strings:
    $injection = "/new injection/"
    $title = "OnDrive | Login</title>"
    $form = "id=\"contact\""
    $user = "id=\"email\""
    $pass = "name=\"password\""
 condition:
    all of them
}
