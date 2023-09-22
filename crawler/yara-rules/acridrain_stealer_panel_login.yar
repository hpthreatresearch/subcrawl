rule acridrain_stealer_panel_login {
    meta:
        description = "AcridRain Stealer panel login"
        author = "Josh Stroschein josh@m9cyber.com"
        date = "2022-12-29"

    strings:
        $r1 = "<title>Acrid -" nocase
        $r2 = "AcridRain Stealer" nocase
        $s1 = "/Account/Login" nocase
        $s2 = "name=\"Email\"" nocase
        $s3 = "name=\"Password\"" nocase

    condition:
        $r1 and $r2 and 1 of ($s*)
}