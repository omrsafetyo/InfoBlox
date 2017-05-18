#Requires -Version 3.0
<#
    .SYNOPSIS
    Commandlets for interfacing with the InfoBlox WAPI Release 2.3
    
    .NOTES
    Author: omrsafetyo
    Email:    omrsafetyo@gmail.com
    Date:    4/7/2017
    PSVer:    3.0
    Change Log: 
        5/15/2017    -    NWK   Added Set-TrustAllCertsPolicy
                                Completed New-InfoBloxSession
        5/16/2017    -    NWK   Added Get-InfoBloxResourceRecordSet
                                Added New-InfoBloxResourceRecord

#>

# private functions
$PrivateDirectory = Join-Path -Path $PSScriptRoot -ChildPath private
$PrivateFiles = Get-ChildItem -Path $PrivateDirectory -Filter "*.ps1" 
ForEach ( $PrivateFile in $PrivateFiles ) {
	. $PrivateFile.FullName
}

#public functions
$PublicDirectory = Join-Path -Path $PSScriptRoot -ChildPath Public
$PublicFiles = Get-ChildItem -Path $PublicDirectory -Filter "*.ps1" 
ForEach ( $PublicFile in $PublicFiles ) {
	try {
		. $PublicFile.FullName
		Export-ModuleMember -Function $PublicFile.BaseName
	}
	catch {
		Write-Error -Message "Failed to import function $($PublicFile.fullname): $_"
	}
}

# There is an error trying to reference [Microsoft.PowerShell.Commands.WebRequestSession] in a fresh session.
# creating a dummy session, loading this type prevents the error.
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

#Create / Read config
if(-not (Test-Path -Path "$PSScriptRoot\public\Infoblox.xml" -ErrorAction SilentlyContinue)) {
    Try {
        Write-Warning "Did not find config file $PSScriptRoot\public\Infoblox.xml, attempting to create"
        [pscustomobject]@{
            Uri = $null
            IBVersion = "2.3"
        } | Export-Clixml -Path "$PSScriptRoot\public\Infoblox.xml" -Force -ErrorAction Stop
    }
    Catch {
        Write-Warning "Failed to create config file $PSScriptRoot\public\Infoblox.xml: $_"
    }
}
    
#Initialize the config variable.
Try {
    #Import the config
    $IBConfig = $null
    $IBConfig = Get-InfoBloxConfig -Source Infoblox.xml -ErrorAction Stop | Select -Property Uri, IBVersion, IBSession

}
Catch {   
    Write-Warning "Error importing IBConfig: $_"
}

<# 
Get-Variable -Scope:Script | ForEach-Object {
	Export-ModuleMember -Variable $_.Name
}
#>