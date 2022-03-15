rule base64_pe
{
  meta:
    description = "Detects base64 encoded PE files, often used with Powershell."
    author = "josh@m9cyber.com"
    date = "2022-02-25"
 strings:
    $mz_header = /(TVqQ|QqVT)/
    $this_program = /(VGhpcyBwcm9ncmFt|tFmcn9mcwBycphGV)/
    $null_bytes = "AAAAA"
 condition:
    $mz_header and $this_program and #null_bytes > 2
}
