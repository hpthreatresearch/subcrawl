rule bapr_phish_phish
{
  meta:
    description = "BAPR Online banking phishing page"
    author = "josh@m9cyber.com"
    date = "2022-03-09"
 strings:
    $title = "personal internet banking</title>" nocase
    $form = "name=\"login.loginform\"" nocase
    $pass = "id=\"passcrypt\"" nocase
 condition:
    all of them
}
