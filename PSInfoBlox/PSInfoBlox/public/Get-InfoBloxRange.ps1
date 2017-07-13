Function Get-InfoBloxRange {
    <#
        .SYNOPSIS
		Retrieves range records from the InfoBlox server.

		.PARAMETER Network
        Limit the results to addresses within a specific network (defined as x.x.x.x/xx, e.g. 10.0.0.1/24)

		.PARAMETER StartAddress
        The start address of the specified range.

		.PARAMETER EndAddress
        The end address of the specified range.

		.PARAMETER NetworkView
		The network view of the range.
              
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

		.PARAMETER Reference
		The _ref attribute of a ResourceRecord.

		.PARAMETER GetNextIPAddress
		Switch parameter that includes the next available IP Address in the output

		.PARAMETER Next
		This sets the GetNextIPAddress equal to true, but also allows you to specify how many next IP Addresses should be returned.  If 
		Next is set to 5, this will return the next 5 available addresses in the network as part of the output.
    #>
    [CmdletBinding(DefaultParameterSetName="Session")]
    param(    
		[Parameter(Mandatory=$False,ParameterSetName="Session")]
		[Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [string]
        $Network,

		[Parameter(Mandatory=$False,ParameterSetName="Session")]
		[Parameter(Mandatory=$False,ParameterSetName="Credential")]
		[ValidateScript({$_ -match [IPAddress]$_ })] 
        [string]
        $StartAddress,

		[Parameter(Mandatory=$False,ParameterSetName="Session")]
		[Parameter(Mandatory=$False,ParameterSetName="Credential")]
		[ValidateScript({$_ -match [IPAddress]$_ })] 
        [string]
        $EndAddress,

		[Parameter(Mandatory=$False,ParameterSetName="Session")]
		[Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [string]
        $NetworkView,

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
        $PassThru
    )
    
    BEGIN {
        $AvailableUriOptions = @{
			"Network" = "network"
			"StartAddress" = "start_addr"
			"EndAddress" = "end_addr"
			"NetworkView" = "network_view"
		}
    }
    
    PROCESS {
        $msg = "ParameterSetName is {0}" -f $PSCmdlet.ParameterSetName
        Write-Verbose $msg
        Write-Verbose "Uri is $Uri"
        $BaseUri = "{0}/range" -f $Uri
        
		if ($PSBoundParameters.ContainsKey("Reference")) {
			$ReqUri = $Uri, $Reference -join "/"
		}
		else {
			$ReqUri = $BaseUri
		}

		$ConcatString = ""
		ForEach ( $item in $AvailableUriOptions.Keys ) {
			if ( $PSBoundParameters.ContainsKey($item) ) {
				if ( [string]::IsNullOrEmpty($ConcatString) ) {
					$ConcatString = "{0}?{1}={2}" -f $ConcatString, $AvailableUriOptions.$($item), $PSBoundParameters.$($item)
				}
				else {
					$ConcatString = "{0}&{1}={2}" -f $ConcatString, $AvailableUriOptions.$($item), $PSBoundParameters.$($item)
				}
			}
		}
		$ReqUri = "{0}{1}" -f $ReqUri, $ConcatString
        
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
			# Note:  With range, a .0 is valid as long as the subnet is a 31 bit mask.
			# in all other cases, the .0 is silently discarded, or used as a broadcast.  
			# But a /31 is only valid as a network - direct host-to-host connections, not as a range. RFC 3021
			# so for the next available, I will always exclude .0 for a range - the range next_available_ip function
			# will return a .0 from the API, but I don't think this is valid.
			$ReqUri = "{0}/{1}" -f $Uri, $TempResult._ref
			$ReqUri = $ReqUri, "_function=next_available_ip" -join "?"
			$IRMParams["Uri"] = $ReqUri
			$IRMParams["Method"] = "POST"
			if ( $PSBoundParameters.ContainsKey("Next") ) {
				$Num = @{
					num = $Next
				}
				# This is to exclude the start address from the next available function, if the last octet = 0
				if ( $TempResult.start_addr.split(".")[3] -eq 0 ) {
					[void]$Num.Add("exclude",[array]$TempResult.start_addr)
				}
				$Body = ConvertTo-Json -InputObject $Num
				[void]$IRMParams.Add("Body",$Body)
				[void]$IRMParams.Add('ContentType',"application/json")
				Write-Verbose $Body
			}
			else {
				# if no Next was passed, we're going to add the parameters anyway, and set the num to 1
				# so we can add the exclude parameter.
				if ( $TempResult.start_addr.split(".")[3] -eq 0 ) {
					$Num = @{
						num = 1
						exclude = [array]$TempResult.start_addr
					}
					$Body = ConvertTo-Json -InputObject $Num
					[void]$IRMParams.Add("Body",$Body)
					[void]$IRMParams.Add('ContentType',"application/json")
					Write-Verbose $Body
				}
			}
			Write-Verbose $ReqUri
			$NextIPResult = Invoke-RestMethod @IRMParams
			$TempResult | Add-Member -Type NoteProperty -Name NextIPAddresses -Value $NextIPResult.ips
			[void]$IRMParams.Remove("Body")
			[void]$IRMParams.Remove("ContentType")
		}

		if ( $PassThru ) {
            $TempResult | Add-Member -Type NoteProperty -Name IBSession -Value $IBSession
        }

        $TempResult
    }
    
    END {}
}