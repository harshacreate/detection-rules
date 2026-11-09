rule suspicious_powershell_strings {
    meta:
        description = "Finds a narrow combination of download and execution strings in text fixtures"
        author = "Harsha Malepati"
        date = "2026-11-10"
    strings:
        $download = "DownloadString" nocase
        $execute = "Invoke-Expression" nocase
    condition:
        all of them
}
