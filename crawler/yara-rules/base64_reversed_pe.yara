rule pe_base64encoded_reverse {

    meta:
        desc = "Detects base64 encoded PE files, reversed"
        author = "@jstrosch"
    
    strings:
        $tail = /={0,4}A{10,}/
        $mz_header = /(uUFpVT|QRSpTV|gUBpVT|QqVT)/
        $this_program = "tFmcn9mcwBycphGV"
        $null_bytes = "AAAAA"
    condition:
        $tail in (0..100) and $this_program and $mz_header and (#null_bytes > 2)
}
