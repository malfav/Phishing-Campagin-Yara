rule APT__PISHING_Malicious_Strings{
	meta:
		author = "Diyar Saadi"
	strings:
		$header = "[Content_Types]" //Header
		$header_version = "version=1.0" //Header_Version
		$powershell_code = "powershell -enc $e"
		$path_pshell = "Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
		$path_pshell2 = "Windows\\\\\\\\System32\\\\\\\\WindowsPowerShell\\\\\\\\v1.0\\\\\\\\powershell.exe"
		$path_pshell3 = "Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
		$winword_office ="MSWord.exe\\\\..\\\\..\\\\..\\\\..\\\\"
		$sys_pth = "\\\\..\\\\..\\\\..\\\\..\\\\Windows\\\\System32"
		$ps_downloader = "(New-Object System.Net.WebClient).DownloadString('http://"
		$time_date = "2017-10-27T22:25:00Z"
		$time_date1 = "2017-10-27T22:23:00Z"
	condition:
		($header and $header_version and
		$header (0..50) //Header String Range (0 to 50)
		and 2 of (path_pshell*)and 
		$winword_office and
		$sys_pth and $ps_downloader and 1 of ($time_date*)
	) 
}

rule is_not_same_campagin{
	condition:
		not APT__PISHING_Malicious_Strings
}

rule is_same_campagin{
	condition:
		APT__PISHING_Malicious_Strings
}