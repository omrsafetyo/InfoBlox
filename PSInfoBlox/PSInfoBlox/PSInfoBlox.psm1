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

<# 
Get-Variable -Scope:Script | ForEach-Object {
	Export-ModuleMember -Variable $_.Name
}
#>