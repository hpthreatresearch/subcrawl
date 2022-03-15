rule default_page_apache
{
  meta:
    description = "Default page for Apache2"
    author = "josh@m9cyber.com"
    date = "2022-03-02"
 strings:
    $title = /apache2.{,10}default page/ nocase
    $apache = "apache2" nocase
    $default = "default page" nocase
 condition:
    all of them
}
