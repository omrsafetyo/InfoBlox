Function New-InfoBloxSession {
    <#
        .SYNOPSIS
            Starts a session to the Infoblox server.
            
        .DESCRIPTION
            https://github.com/RamblingCookieMonster
            
        .PARAMETER InfoBloxServer
            IP Address or FQDN/Hostname of the Infoblox server. If not IP, this must be DNS resolvable.
            
        .PARAMETER Version
            Version of the InfoBlox server. This changes the REST API version that is used to build the URL.
            Example: 1.0
            Default is 2.3
            
        .PARAMETER Credential
            Credentials for the InfoBlox server. Should be in format username@domain.com 
    #>
    [CmdletBinding()]
    PARAM (
        [Parameter(Mandatory=$True)]
        [string]
        $InfoBloxServer,
        
        [Parameter(Mandatory=$False)]
        [string]
        $Version = "2.3",
        
        [Parameter(Mandatory=$True)]
        [System.Management.Automation.PSCredential]
        $Credential,
        
        [switch]
        $PassThru
    )
    
    BEGIN {
        Set-TrustAllCertsPolicy
        $Script:InfoBloxServer = $InfoBloxServer
        $Script:InfoBloxVersion = $InfoBloxVersion
    }
    
    PROCESS {
        $BaseUri = "https://{0}/wapi/v{1}/grid" -f $InfoBloxServer, $Version
        $Script:InfoBloxBaseUri = "https://{0}/wapi/v{1}" -f $InfoBloxServer, $Version
        
        $Params = @{
            Uri = $BaseUri
            Method = 'Get'
            Credential = $Credential
            SessionVariable = 'TempSession'
            ErrorAction = 'Stop'
        }
        
        try {
            #Run the command
            $Grid = Invoke-RestMethod @Params
            $Script:GridName = ( $Grid._ref -split ":" )[-1]
            Write-Verbose "Connected to grid '$GridName'"
        }
        catch {
            $_
        }
        
        if ( $PassThru ) {
            $TempSession
        }
        else {
            $Script:InfoBloxSession = $TempSession
        }
    }
    
    END {}
}