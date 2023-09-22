rule erbium_discord_panel_login {
    meta:
        data = "2022-11-28"

    strings:
        $x1 = "https://erbium_support.t.me"
        $x2 = "<title>Discord"
        $s1 = "id=\"username\""
        $s2 = "id=\"password\""

    condition:
        all of them
}
