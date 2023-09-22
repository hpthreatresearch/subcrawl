rule unam_webpanel_login {
    meta:
        description = "Detects Unam web panel login page"
        author = "@jstrosch"
        date = "2022-01-12"

    strings:
        $s1 = "Unam Web Panel &mdash; Login</title>" nocase 
        $s2 = "unamLogin'>" nocase
        $s3 = "name='password'" nocase
        $s4 = "Login" nocase

    condition:
        all of them
}
