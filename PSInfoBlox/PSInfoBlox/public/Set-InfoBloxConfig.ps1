Function Set-InfoBloxConfig {
    <#
    .SYNOPSIS
        Set Infoblox module configuration.
    .DESCRIPTION
        Set Infoblox module configuration, and module $IBConfig variable.
        This data is used as the default for most commands.
    .PARAMETER Uri
        Specify a Uri to use
    .PARAMETER IBVersion
        Specify an Infoblox version (v1.6 is the default)
    .PARAMETER IBSession
        Specify an Infoblox session.  This is not written to the XML, it is used in $IBConfig only.
    .Example
        Set-InfoBloxConfig -Uri "https://grid.contoso.com"
    .FUNCTIONALITY
        Infoblox
    #>
    [cmdletbinding()]
    param(
        [string]
		$Uri,

        [string]
		$IBVersion,

		[string]
		$IBServer,

        $IBSession
    )

    if ($PSBoundParameters.ContainsKey('IBVersion')) {
		if ( -not($Script:IBConfig.PSObject.Properties.Name -contains "IBVersion") ) {
			Add-Member -InputObject $Script:IBConfig -NotePropertyName IBVersion -NotePropertyValue $IBVersion
		}
		else {
			$Script:IBConfig.IBVersion = $IBVersion
		}
    }
	
    if ($PSBoundParameters.ContainsKey('Uri')) {
		if ( -not($Script:IBConfig.PSObject.Properties.Name -contains "Uri") ) {
			Add-Member -InputObject $Script:IBConfig -NotePropertyName Uri -NotePropertyValue $Uri
		}
		else {
			$Script:IBConfig.Uri = $Uri
		}
    }
	
    if ($PSBoundParameters.ContainsKey('IBSession')) {
		if ( -not($Script:IBConfig.PSObject.Properties.Name -contains "IBSession") ) {
			Add-Member -InputObject $Script:IBConfig -NotePropertyName IBSession -NotePropertyValue $IBSession
		}
		else {
			$Script:IBConfig.IBSession = $IBSession
		}
    }
	
	if ($PSBoundParameters.ContainsKey('IBServer')) {
		if ( -not($Script:IBConfig.PSObject.Properties.Name -contains "IBServer") ) {
			Add-Member -InputObject $Script:IBConfig -NotePropertyName IBServer -NotePropertyValue $IBServer
		}
		else {
			$Script:IBConfig.IBServer = $IBServer
		}
    }

    $Script:IBConfig | Select -Property * -ExcludeProperty IBSession | Export-Clixml -Path "$PSScriptRoot\Infoblox.xml" -force

}