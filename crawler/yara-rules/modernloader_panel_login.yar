rule modernloader_panel_login {
    meta:
        date = "2022-11-30"
        author = "@jstrosch"

    strings:
        $s1 = "<title>Panel - Login</title>" nocase
        $s2 = "class=\"login__form\"" nocase
        $s3 = "url = \"control.php\"" nocase
        $s4 = "Welcome</h3>" nocase

    condition:
        all of them
}