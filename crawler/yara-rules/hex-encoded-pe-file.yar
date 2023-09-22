rule hexencoded_pe_file {
    meta:
        desc = "Detects hex-encoded pe file"
        author = "@jstrosch"
        date = "2022 Oct 24"

    strings:
        $mz = { 34 44 35 41 } //4D 5A -> MZ
        $pe = { 35 30 34 35 30 30 30 30 } // 50 45 00 00 -> PE00 

    condition:
        $mz at 0 and $pe in (@mz[1]..0x200)
}
