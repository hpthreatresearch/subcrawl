rule collector_stealer_panel_login {
    meta:
        date = "2022-11-30"

    strings:
        $s1 = "<title>login</title>" nocase
        $s2 = "Collector Stealer panel" nocase
        $s3 = "action=\"/index.php?auth\"" nocase
        $s4 = "id=\"sendlogin\"" nocase 

    condition:
        all of them
}