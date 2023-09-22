rule php_file_manager_login {

	meta:
		date = "2022-11-29"

	strings:
		$s1 = "<title>File Manager"
		$s2 = "content=\"Web based File Manager"
		$s3 = "class=\"form-signin\""
		$s4 = "File Manager</h1>"

	condition:
		all of them
}
