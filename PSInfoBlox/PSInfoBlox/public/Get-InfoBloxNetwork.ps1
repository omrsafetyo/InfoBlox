Function Get-InfoBloxNetwork {
    <#
        .SYNOPSIS
        Retrieves Network records from the InfoBlox server.
              
        .PARAMETER Uri
        Specifies the InfoBlox REST server Base Uri. Not required if you are using sessions, and will default based on the default
        specified in New-InfoBloxSession if not specified.
        
        .PARAMETER IBVersion
        Specifies InfoBlox version. This is used for crafting the BaseUri in the New-InfoBloxSession function if 
        Credentials are specified instead of a session.
        
        .PARAMETER IBSession
        Created with the New-InfoBloxSession function. This commandlet will be run anyway if the credentials only are specified, 
        in the begin block.
        
        .PARAMETER Credential
        Credential object with user Id and password for creating an InfoBlox Grid session.
        
        .PARAMETER IBServer
        Passed to the New-InfoBlox session function if a Credential is specified instead of a session.
        
        .PARAMETER Passthru
        If specified, this switch will cause the IBSession created in this function to be pased to the pipeline in the output object, 
        so it can be utilized, and not recreated in subsequent function calls.

		.PARAMETER Network
		This is the network string for searching, in standard subnet/mask format.  Example: 192.168.0.0/24

		.PARAMETER Reference

		.PARAMETER GetNextIPAddress
		Switch parameter that includes the next available IP Address in the output

		.PARAMETER Next
		This sets the GetNextIPAddress equal to true, but also allows you to specify how many next IP Addresses should be returned.  If 
		Next is set to 5, this will return the next 5 available addresses in the network as part of the output.

		.PARAMETER IncludeUsedAddresses
		This returns the network information, and all ipv4address records for that network.
        
        https://github.com/AWahlqvist/Infoblox-PowerShell-Module/blob/master/cmdlets/Get-IBResourceRecord.ps1
        https://github.com/AWahlqvist/Infoblox-PowerShell-Module/tree/master/cmdlets
        https://github.com/RamblingCookieMonster/Infoblox/blob/master/Infoblox/Get-IBRecord.ps1
        https://github.com/Infoblox-API/PowerShell/tree/master/examples

		https://github.com/slchorne/apibrowser/blob/master/apiguide/README.md
    #>
    [CmdletBinding(DefaultParameterSetName="Session")]
    param(    
		[Parameter(Mandatory=$False,ParameterSetName="Session")]
		[Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [string]
        $Network,

		[Parameter(Mandatory=$False,ParameterSetName="Session")]
		[Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [string]
        $Reference,

        [Parameter(Mandatory=$False,ParameterSetName="Session")]
        [Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [string]
        $Uri =  $Script:IBConfig.Uri,
        
        [Parameter(Mandatory=$False,ParameterSetName="Session")]
        [Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [string]
        $IBVersion = $Script:IBConfig.IBVersion,
        
        [Parameter(Mandatory=$False,ParameterSetName="Session")]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $IBSession = $Script:IBConfig.IBSession,
        
        [Parameter(Mandatory=$True,ParameterSetName="Credential")]
        [System.Management.Automation.PSCredential]
        $Credential,
        
        [Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [string]
        $IBServer,

		[Parameter(Mandatory=$False,ParameterSetName="Session")]
		[Parameter(Mandatory=$False,ParameterSetName="Credential")]
		[int]
		$Next,

		[switch]
        $GetNextIPAddress,

		[switch]
        $IncludeUsedAddresses,
        
        [switch]
        $PassThru
    )
    
    BEGIN {
        
    }
    
    PROCESS {
        $msg = "ParameterSetName is {0}" -f $PSCmdlet.ParameterSetName
        Write-Verbose $msg
        Write-Verbose "Uri is $Uri"
        $BaseUri = "{0}/network" -f $Uri
        
		if ( $PSBoundParameters.ContainsKey("Network") ) {
			$ReqUri = "{0}?network={1}" -f $BaseUri, $Network
		}
		elseif ($PSBoundParameters.ContainsKey("Reference")) {
			$ReqUri = $Uri, $Reference -join "/"
		}
		else {
			$ReqUri = $BaseUri
		}
        
		if ( $PSCmdlet.ParameterSetName -eq "Session") {
			$IRMParams = @{
				Uri = $ReqUri
				Method = 'Get'
				WebSession = $IBSession
			}
		}
		else {
			$IRMParams = @{
				Uri = $ReqUri
				Method = 'Get'
				Credential = $Credential
			}
		}
        
        Write-Verbose $ReqUri

		try {
            $TempResult = Invoke-RestMethod @IRMParams
        }
        catch {
            Throw "Error retrieving record: $_"
        }


		if ( $PSBoundParameters.ContainsKey("Next") ) {
			$GetNextIPAddress = $True
		}

		if ( $GetNextIPAddress ) {
			$ReqUri = "{0}/{1}" -f $Uri, $TempResult._ref
			$ReqUri = $ReqUri, "_function=next_available_ip" -join "?"
			$IRMParams["Uri"] = $ReqUri
			$IRMParams["Method"] = "POST"
			if ( $PSBoundParameters.ContainsKey("Next") ) {
				$Num = @{
					num = $Next
				}
				$Body = ConvertTo-Json -InputObject $Num
				[void]$IRMParams.Add("Body",$Body)
				[void]$IRMParams.Add('ContentType',"application/json")
			}
			
			$NextIPResult = Invoke-RestMethod @IRMParams
			$TempResult | Add-Member -Type NoteProperty -Name NextIPAddresses -Value $NextIPResult.ips
			[void]$IRMParams.Remove("Body")
			[void]$IRMParams.Remove("ContentType")
		}

		if ($IncludeUsedAddresses) {
			$ReqUri = "{0}/ipv4address?network={1}" -f $Uri, $TempResult.Network
			$IRMParams["Uri"] = $ReqUri
			$IRMParams["Method"] = "GET"
			$ipv4addressResult = Invoke-RestMethod @IRMParams
			$TempResult | Add-Member -Type NoteProperty -Name CurrentRecords -Value $ipv4addressResult
		}

		if ( $PassThru ) {
            $TempResult | Add-Member -Type NoteProperty -Name IBSession -Value $IBSession
        }

        $TempResult
    }
    
    END {}
}