<#
    Import the PKCS#12 bundle a `format: pkcs12` pair is published as, on a
    Windows receiver, and bind it where it is used. Fetched first with one of
    the scripts beside this one - the bundle and its password file are two more
    files in the same directory.

    The password is made once per pair and kept across renewals, so this script
    does not have to be run again when the certificate is renewed: it is the
    same password, and a run that finds the same thumbprint already installed
    does nothing.

    The directory must be readable by Administrators and SYSTEM only: the
    bundle and its password are the key. The commands the interface shows set
    that up.

    Names are placeholders.
#>
param(
    [string]$Bundle   = "C:\certs\app.example.net\app.example.net.pfx",
    [string]$PasswordFile = "C:\certs\app.example.net\app.example.net.password",
    [string]$Store    = "Cert:\LocalMachine\My",
    [string]$SiteName = "Default Web Site"
)

$ErrorActionPreference = "Stop"

$secured = ConvertTo-SecureString (Get-Content -Raw $PasswordFile).Trim() -AsPlainText -Force
$incoming = Get-PfxData -FilePath $Bundle -Password $secured
$thumbprint = $incoming.EndEntityCertificates[0].Thumbprint

if (Get-ChildItem $Store | Where-Object { $_.Thumbprint -eq $thumbprint }) {
    Write-Host "already installed: $thumbprint"
    exit 0
}

Import-PfxCertificate -FilePath $Bundle -CertStoreLocation $Store -Password $secured | Out-Null
Write-Host "imported: $thumbprint"

# Bind it. IIS keeps the binding by thumbprint, so this is what the renewal
# actually changes.
#
# -SslFlags 0 binds the certificate to the address: one site per IP and port.
# For several sites on one address the binding needs SNI, made with the
# site's host name and -SslFlags 1 instead:
#
#     New-WebBinding -Name $SiteName -Protocol https -Port 443 `
#         -HostHeader app.example.net -SslFlags 1
#
# and the certificate must carry that name.
Import-Module WebAdministration
$binding = Get-WebBinding -Name $SiteName -Protocol https
if ($null -eq $binding) {
    New-WebBinding -Name $SiteName -Protocol https -Port 443 -SslFlags 0
    $binding = Get-WebBinding -Name $SiteName -Protocol https
}
$binding.AddSslCertificate($thumbprint, "My")
Write-Host "bound to $SiteName"
