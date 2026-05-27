<#
TECHMENTOR CONSULTING
www.techmentor.com.pe

Script: Review-AdminCount_TechMentor.ps1
Versión: 2026.05.25-FIX02

Objetivo:
- Revisar objetos usuarios, grupos y equipos con adminCount=1.
- Identificar si aún pertenecen a grupos protegidos.
- Generar reporte CSV y log de ejecución.
- Remediar únicamente objetos no protegidos, limpiando adminCount y habilitando herencia ACL.

AVISO DE RESPONSABILIDAD:
Este script es entregado por TECHMENTOR CONSULTING como herramienta de apoyo técnico.
Debe ser validado previamente en un ambiente de pruebas y ejecutado por personal autorizado.
TECHMENTOR CONSULTING no se hace responsable por impactos, pérdida de configuración, interrupciones,
modificaciones no deseadas o cualquier consecuencia derivada de su uso sin validación, respaldo o control de cambios.
#>

param(
    [ValidateSet("Report","Remediate")]
    [string]$Mode = "Report",

    [string]$OutputPath = "C:\Temp\AdminCount_Review"
)

Import-Module ActiveDirectory -ErrorAction Stop

if (!(Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

$Date = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportFile = Join-Path $OutputPath "Reporte_AdminCount_$Date.csv"
$LogFile    = Join-Path $OutputPath "Log_AdminCount_$Date.log"

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )

    $Line = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Add-Content -Path $LogFile -Value $Line

    switch ($Level) {
        "OK"    { Write-Host $Line -ForegroundColor Green }
        "WARN"  { Write-Host $Line -ForegroundColor Yellow }
        "ERROR" { Write-Host $Line -ForegroundColor Red }
        default { Write-Host $Line -ForegroundColor Cyan }
    }
}

function Convert-SidToName {
    param([string]$Sid)

    try {
        return ([System.Security.Principal.SecurityIdentifier]$Sid).Translate([System.Security.Principal.NTAccount]).Value
    }
    catch {
        return $Sid
    }
}

function Get-ObjectSidValue {
    param($Object)

    try {
        if ($null -ne $Object.objectSid) {
            return (New-Object System.Security.Principal.SecurityIdentifier($Object.objectSid, 0)).Value
        }
    }
    catch {
        try { return $Object.objectSid.Value } catch {}
    }

    return ""
}

function Get-ObjectTokenGroupSIDs {
    param(
        [string]$DistinguishedName,
        [string]$Server
    )

    try {
        $DE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server/$DistinguishedName")
        $DE.RefreshCache(@("tokenGroups"))

        $Sids = foreach ($Token in $DE.Properties["tokenGroups"]) {
            try {
                (New-Object System.Security.Principal.SecurityIdentifier($Token, 0)).Value
            }
            catch {}
        }

        if (!$Sids -or $Sids.Count -eq 0) {
            throw "No se pudo obtener tokenGroups."
        }

        return @{
            Success = $true
            SIDs    = @($Sids | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            Error   = $null
        }
    }
    catch {
        $PrimaryError = $_.Exception.Message

        try {
            $PrincipalGroups = Get-ADPrincipalGroupMembership -Identity $DistinguishedName -Server $Server -ErrorAction Stop

            $GroupSids = foreach ($Group in $PrincipalGroups) {
                try { $Group.SID.Value } catch {}
            }

            return @{
                Success = $true
                SIDs    = @($GroupSids | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                Error   = $null
            }
        }
        catch {
            return @{
                Success = $false
                SIDs    = @()
                Error   = "$PrimaryError / Fallback Get-ADPrincipalGroupMembership: $($_.Exception.Message)"
            }
        }
    }
}

# ==========================
# Datos del dominio
# ==========================

$Domain = Get-ADDomain
$DomainSID = $Domain.DomainSID.Value

$DCObj = Get-ADDomainController -Discover -Writable
$DC = [string]$DCObj.HostName

if ([string]::IsNullOrWhiteSpace($DC)) {
    throw "No se pudo obtener un controlador de dominio válido."
}

Write-Log "Script TECHMENTOR CONSULTING versión 2026.05.25-FIX02"
Write-Log "Modo de ejecución: $Mode"
Write-Log "Dominio: $($Domain.DNSRoot)"
Write-Log "Domain SID: $DomainSID"
Write-Log "DC utilizado: $DC"

# ==========================
# SIDs protegidos oficiales
# ==========================

$ProtectedSIDs = @(
    "$DomainSID-500", # Administrator
    "$DomainSID-502", # krbtgt
    "$DomainSID-512", # Domain Admins
    "$DomainSID-516", # Domain Controllers
    "$DomainSID-518", # Schema Admins
    "$DomainSID-519", # Enterprise Admins
    "$DomainSID-521", # Read-only Domain Controllers
    "$DomainSID-526", # Key Admins
    "$DomainSID-527", # Enterprise Key Admins

    "S-1-5-32-544",   # BUILTIN\Administrators
    "S-1-5-32-548",   # BUILTIN\Account Operators
    "S-1-5-32-549",   # BUILTIN\Server Operators
    "S-1-5-32-550",   # BUILTIN\Print Operators
    "S-1-5-32-551",   # BUILTIN\Backup Operators
    "S-1-5-32-552"    # BUILTIN\Replicator
)

# ==========================
# Obtener objetos
# IMPORTANTE:
# No usar -Properties SID. En Get-ADObject la propiedad válida es objectSid.
# ==========================

$Objects = Get-ADObject `
    -LDAPFilter "(&(adminCount=1)(|(objectClass=user)(objectClass=group)(objectClass=computer)))" `
    -Server $DC `
    -Properties adminCount,distinguishedName,sAMAccountName,name,objectSid,objectClass,userAccountControl `
    -ErrorAction Stop

Write-Log "Objetos encontrados con adminCount=1: $($Objects.Count)"

# ==========================
# Procesamiento
# ==========================

$Results = foreach ($Object in $Objects) {

    $ObjectSID = ""
    $ObjectEnabled = "N/A"
    $InheritanceDisabled = "N/A"
    $Action = ""

    try {
        Write-Log "Procesando objeto [$($Object.ObjectClass)]: $($Object.sAMAccountName)"

        $ObjectSID = Get-ObjectSidValue -Object $Object

        if ($Object.ObjectClass -in @("user","computer")) {
            if (($Object.userAccountControl -band 2) -eq 2) {
                $ObjectEnabled = $false
            }
            else {
                $ObjectEnabled = $true
            }
        }

        $Acl = Get-Acl -Path "AD:\$($Object.DistinguishedName)"
        $InheritanceDisabled = $Acl.AreAccessRulesProtected

        $TokenResult = Get-ObjectTokenGroupSIDs `
            -DistinguishedName $Object.DistinguishedName `
            -Server $DC

        if ($TokenResult.Success -ne $true) {

            $Action = "NO REMEDIAR - Validación de tokenGroups incompleta"

            Write-Log "$($Object.sAMAccountName): $Action. Error: $($TokenResult.Error)" "ERROR"

            [PSCustomObject]@{
                SamAccountName      = $Object.sAMAccountName
                Name                = $Object.Name
                ObjectClass         = $Object.ObjectClass
                Enabled             = $ObjectEnabled
                DistinguishedName   = $Object.DistinguishedName
                ObjectSID           = $ObjectSID
                AdminCount          = $Object.adminCount
                ValidationStatus    = "ERROR"
                IsProtected         = "UNKNOWN"
                ProtectedBy         = ""
                InheritanceDisabled = $InheritanceDisabled
                Action              = $Action
                Error               = $TokenResult.Error
            }

            continue
        }

        $EffectiveSIDs = @($ObjectSID) + @($TokenResult.SIDs) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

        $MatchedProtectedSIDs = $EffectiveSIDs |
            Where-Object { $ProtectedSIDs -contains $_ } |
            Select-Object -Unique

        $MatchedProtectedNames = $MatchedProtectedSIDs | ForEach-Object {
            Convert-SidToName $_
        }

        $IsProtected = $MatchedProtectedSIDs.Count -gt 0

        if ($IsProtected) {

            $Action = "NO REMEDIADO - El objeto pertenece o corresponde a un objeto protegido"

            Write-Log "$($Object.sAMAccountName) protegido por: $($MatchedProtectedNames -join '; ')" "WARN"
        }
        else {

            if ($Mode -eq "Report") {

                $Action = "CANDIDATO A REMEDIACIÓN - No pertenece a objetos protegidos"

                Write-Log "$($Object.sAMAccountName) candidato a remediación." "WARN"
            }

            if ($Mode -eq "Remediate") {

                Write-Log "Remediando objeto [$($Object.ObjectClass)]: $($Object.sAMAccountName)"

                Set-ADObject `
                    -Identity $Object.DistinguishedName `
                    -Server $DC `
                    -Clear adminCount `
                    -ErrorAction Stop

                if ($InheritanceDisabled -eq $true) {

                    $Acl.SetAccessRuleProtection($false, $true)

                    Set-Acl `
                        -Path "AD:\$($Object.DistinguishedName)" `
                        -AclObject $Acl `
                        -ErrorAction Stop

                    $Action = "REMEDIADO - adminCount limpiado y herencia habilitada"
                }
                else {
                    $Action = "REMEDIADO - adminCount limpiado; herencia ya estaba habilitada"
                }

                Write-Log "$($Object.sAMAccountName): $Action" "OK"
            }
        }

        [PSCustomObject]@{
            SamAccountName      = $Object.sAMAccountName
            Name                = $Object.Name
            ObjectClass         = $Object.ObjectClass
            Enabled             = $ObjectEnabled
            DistinguishedName   = $Object.DistinguishedName
            ObjectSID           = $ObjectSID
            AdminCount          = $Object.adminCount
            ValidationStatus    = "OK"
            IsProtected         = $IsProtected
            ProtectedBy         = if ($MatchedProtectedNames) { $MatchedProtectedNames -join "; " } else { "" }
            InheritanceDisabled = $InheritanceDisabled
            Action              = $Action
            Error               = ""
        }
    }
    catch {

        Write-Log "Error procesando $($Object.sAMAccountName): $($_.Exception.Message)" "ERROR"

        [PSCustomObject]@{
            SamAccountName      = $Object.sAMAccountName
            Name                = $Object.Name
            ObjectClass         = $Object.ObjectClass
            Enabled             = $ObjectEnabled
            DistinguishedName   = $Object.DistinguishedName
            ObjectSID           = $ObjectSID
            AdminCount          = $Object.adminCount
            ValidationStatus    = "ERROR"
            IsProtected         = "UNKNOWN"
            ProtectedBy         = ""
            InheritanceDisabled = $InheritanceDisabled
            Action              = "NO REMEDIAR - Error durante validación"
            Error               = $_.Exception.Message
        }
    }
}

$Results | Export-Csv -Path $ReportFile -NoTypeInformation -Encoding UTF8

Write-Log "Reporte generado: $ReportFile" "OK"
Write-Log "Log generado: $LogFile" "OK"
Write-Log "Proceso finalizado." "OK"
