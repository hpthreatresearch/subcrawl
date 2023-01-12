rule grandamisha_panel_login {
    meta:
        description = "Granda Misha panel login"
        author = "Josh Stroschein josh@m9cyber.com"
        date = "2022-12-29"

    strings:
        $r1 = "misha" nocase
        $r2 = "granda misha" nocase
        $s1 = "placeholdler=\"Jabber ID\"" nocase
        $s2 = "name=\"password\"" nocase
        $s3 = "users_signin" nocase

    condition:
        $r1 and $r2 and 1 of ($s*)
}