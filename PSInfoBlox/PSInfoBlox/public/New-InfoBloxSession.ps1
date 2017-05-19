Function New-InfoBloxSession {
    <#
        .SYNOPSIS
            Starts a session to the Infoblox server.
            
        .DESCRIPTION
            https://github.com/RamblingCookieMonster
            
        .PARAMETER IBServer
            IP Address or FQDN/Hostname of the Infoblox server. If not IP, this must be DNS resolvable.
            
        .PARAMETER Version
            Version of the InfoBlox server. This changes the REST API version that is used to build the URL.
            Example: 1.0
            Default is 2.3
            
        .PARAMETER Credential
            Credentials for the InfoBlox server. Should be in format <username> - not domain\username or username@domain

    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$True)]
        [string]
        $IBServer,
        
        [Parameter(Mandatory=$False)]
        [string]
        $IBVersion = $Script:IBConfig.IBVersion,
        
        [Parameter(Mandatory=$True)]
        [System.Management.Automation.PSCredential]
        $Credential,
        
        [switch]
        $PassThru,

		[switch]
		$NoConfigChange
    )
    
    BEGIN {
        Set-TrustAllCertsPolicy
    }
    
    PROCESS {
        $GridUri = "https://{0}/wapi/v{1}/grid" -f $IBServer, $IBVersion
        
		Write-Host "GridUri is $GridUri"
        
        $Params = @{
            Uri = $GridUri
            Method = 'Get'
            Credential = $Credential
            SessionVariable = 'TempSession'
            ErrorAction = 'Stop'
        }
        
        try {
            #Run the command
            $Grid = Invoke-RestMethod @Params
            $GridName = ( $Grid._ref -split ":" )[-1]
            Write-Verbose "Connected to grid '$GridName'"
        }
        catch {
            $_
        }
        
        if ( $PassThru ) {
            $TempSession
        }

        if ( -not $NoConfigChange ) {
			$Uri = "https://{0}/wapi/v{1}" -f $IBServer, $IBVersion

			Set-InfoBloxConfig -Uri $Uri -IBVersion $IBVersion -IBServer $IBServer
            $Script:IBConfig.IBSession = $TempSession
			$Script:IBConfig.Uri = $Uri
			$Script:IBConfig.IBVersion = $IBVersion
			$Script:IBConfig.IBServer = $IBServer
        }
    }
    
    END {}
}