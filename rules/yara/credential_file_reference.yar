rule credential_file_reference {
    meta:
        description = "Finds a literal reference to a common Unix credential file in text"
        author = "Harsha Malepati"
        date = "2026-11-10"
    strings:
        $credential_path = "/etc/shadow"
    condition:
        $credential_path
}
