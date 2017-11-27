Function Get-InfoBloxFixedAddressReservation {
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
		[Alias('IPAddress','IP','ipv4Address')]
        [string]
        $ipv4addr,

		[Parameter(Mandatory=$False,ParameterSetName="Session")]
		[Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [string]
        $Reference,

		[Parameter(Mandatory=$False,ParameterSetName="Session")]
        [Parameter(Mandatory=$False,ParameterSetName="Credential")]
		[Alias("MaxRecords","Records","Count","RecordCount","MaxResults")]
        [int]
        $PageSize = 1000,

		[Parameter(Mandatory=$False,ParameterSetName="Session")]
        [Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [string[]]
        $Properties,

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
       
        [switch]
        $PassThru
    )
    
    BEGIN {
		Set-TrustAllCertsPolicy
    }
    
    PROCESS {
        $msg = "ParameterSetName is {0}" -f $PSCmdlet.ParameterSetName
        Write-Verbose $msg
        Write-Verbose "Uri is $Uri"
        $ReqUri = "{0}/fixedaddress" -f $Uri
		$NextPageID = "NotStarted"

		if ( $PSBoundParameters.ContainsKey("Network") ) {
			$ReqUri = "{0}?network={1}" -f $ReqUri, $Network
			$ReqUri = $ReqUri, "_paging=1&_max_results=$PageSize&_return_as_object=1" -join "&"
		}

		if ( $PSBoundParameters.ContainsKey("ipv4addr") ) {
			$ReqUri = "{0}?ipv4addr={1}" -f $ReqUri, $ipv4addr
			$ReqUri = $ReqUri, "_paging=1&_max_results=$PageSize&_return_as_object=1" -join "&"
		}

		if ($PSBoundParameters.ContainsKey("Reference")) {
			$ReqUri = $Uri, $Reference -join "/"
			$ReqUri = $ReqUri, "_return_as_object=1" -join "?"
		}


		if ( $PSBoundParameters.ContainsKey("Properties") ) {
            $ReqUri = "{0}&_return_fields={1}" -f $ReqUri, ($Properties -Join ",").Replace(" ","").ToLower()
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
        
		if ( $ReqUri -notmatch '\?') {
			$ReqUri = $ReqUri, "_paging=1&_max_results=$PageSize&_return_as_object=1" -join "?"
		}
	
        Write-Verbose $ReqUri

		do {
            if($NextPageID -ne "NotStarted") {
				Write-Verbose "Page --$NextPageID--"
				$IRMParams.Uri = $IRMParams.Uri, "_page_id=$NextPageID" -join "&"
            }

            try {
                $TempResult = Invoke-RestMethod @IRMParams
            }
            catch {
                Throw "Error retrieving record: $_"
            }

			if ( @($TempResult.psobject.properties | select-object -expandProperty Name) -contains "next_page_id" ) {
				$NextPageID = $TempResult.next_page_id
			}
			else {
				$NextPageID = $null
			}
            
            if ( $PassThru ) {
                $TempResult | Add-Member -Type NoteProperty -Name IBSession -Value $IBSession
				$TempResult
            }
            else {
				if ( [string]::IsNullOrEmpty($NextPageId) ) {
					$TempResult
				}
				else {
					$TempResult.result
				}
            }

        }
        until ([string]::IsNullOrEmpty($NextPageID))
    }
    
    END {}
}