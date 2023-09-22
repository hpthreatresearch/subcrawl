rule default_page_xampp_windows
{
  meta:
    description = "Default page for XAMPP"
    author = "josh@m9cyber.com"
    date = "2022-02-27"
 strings:
    $title = "Welcome to XAMPP</title>" nocase
    $platform = "welcome to xampp for windows" nocase
 condition:
    all of them
}
