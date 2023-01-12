rule aurora_stealer_panel_login {
    meta:
        date = "2022-11-30"
        author = "@jstrosch"

    strings:
        $s1 = "<title>Auth</title>" nocase
        $s2 = "AURORA STEALER" nocase
        $s3 = "placeholder=\"YOU PASSWORD\"" nocase
        $s4 = "id=\"email-2ee9\"" nocase

    condition:
        all of them
}