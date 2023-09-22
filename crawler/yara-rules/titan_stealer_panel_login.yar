rule titan_stealer_panel_login {
    meta:
        date = "2022-11-30"

    strings:
        $s1 = "<title>Titan Stealer</title>" nocase
        $s2 = "class=\"auth__form\"" nocase 
        $s3 = "Sign in" nocase
        $s4 = "id=\"floatingPassword\"" nocase

    condition:
        all of them
}