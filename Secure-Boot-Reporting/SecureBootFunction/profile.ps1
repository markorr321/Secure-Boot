if ($env:MSI_SECRET -or $env:IDENTITY_ENDPOINT) {
    Disable-AzContextAutosave -Scope Process | Out-Null
    Connect-AzAccount -Identity | Out-Null
}
