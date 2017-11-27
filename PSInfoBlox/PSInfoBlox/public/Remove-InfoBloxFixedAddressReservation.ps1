#
# Remove_InfoBloxResourceRecord.ps1
Function Remove-InfoBloxFixedAddressReservation {
    <#
        .SYNOPSIS
        Deletes a fixed address reservation from the InfoBlox server.
        
        .DESCRIPTION
		Deletes a fixed address reservation from the InfoBlox server.
        
        .PARAMETER Reference
        The reference Uri to the record.
        
        .PARAMETER Uri
        Specifies the InfoBlox REST server Base Uri. Not required if you are using sessions, and will default based on the default
        specified in New-InfoBloxSession if not specified.
        
        .PARAMETER IBVersion
        Specifies InfoBlox version. This is used for crafting the BaseUri if Credentials are specified instead of a session.
        
        .PARAMETER IBSession
        Created with the New-InfoBloxSession function.
        
        .PARAMETER Credential
        Credential object with user Id and password for creating an InfoBlox Grid session.
        
        .PARAMETER IBServer
        Passed to the New-InfoBlox session function if a Credential is specified instead of a session.
               
        .PARAMETER Passthru
        If specified, this switch will cause the IBSession created in this function to be pased to the pipeline in the output object, 
        so it can be utilized, and not recreated in subsequent function calls.
    #>
    [CmdletBinding(DefaultParameterSetName="Session")]
    param( 
		[Parameter(Mandatory=$True,ParameterSetName="Session")]
        [Parameter(Mandatory=$True,ParameterSetName="CredentialUri")]
		[Parameter(Mandatory=$True,ParameterSetName="CredentiaNolUri")]
		[Alias('_ref','ref')]
        [string]
        $Reference =  $Script:IBConfig.Uri,

        [Parameter(Mandatory=$False,ParameterSetName="Session")]
        [Parameter(Mandatory=$False,ParameterSetName="CredentialUri")]
        [string]
        $Uri =  $Script:IBConfig.Uri,
        
        [Parameter(Mandatory=$False,ParameterSetName="Session")]
        [Parameter(Mandatory=$False,ParameterSetName="CredentialNoUri")]
        [string]
        $IBVersion = $Script:IBConfig.IBVersion,

		[Parameter(Mandatory=$False,ParameterSetName="CredentialNoUri")]
        [string]
        $IBServer,
        
        [Parameter(Mandatory=$False,ParameterSetName="Session")]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $IBSession = $Script:IBConfig.IBSession,
        
        [Parameter(Mandatory=$True,ParameterSetName="CredentialNoUri")]
		[Parameter(Mandatory=$True,ParameterSetName="CredentialUri")]
        [System.Management.Automation.PSCredential]
        $Credential,
        
        [switch]
        $PassThru
    )
    
    BEGIN {
		if (-not($PSBoundParameters.ContainsKey("Uri")) ) {
			if ( [string]::IsNullOrEmpty($Uri) -and $PSCmdlet.ParameterSetName -match "Credential" ) {
				if ([string]::IsNullOrEmpty($IBServer) -or [string]::IsNullOrEmpty($IBVersion) ) {
					throw "Unable to determine Uri for IBServer. Specify Uri, or IBVersion and IBServer."
				}
				$Uri = "https://{0}/wapi/v{1}" -f $IBServer, $IBVersion
			}
		}
        Set-TrustAllCertsPolicy
    }
    
    PROCESS {
		$msg = "ParameterSetName is {0}" -f $PSCmdlet.ParameterSetName
		Write-Verbose $msg
		Write-Verbose "baseUri is $Uri"

        $ReqUri = "{0}/{1}" -f $Uri, $Reference
        
		if ( $PSCmdlet.ParameterSetName -match "Credential") {
			$IRMParams = @{
				Uri = $ReqUri
				Method = 'Delete'
				Credential = $Credential
			}
		}
		else {
			$IRMParams = @{
				Uri = $ReqUri
				Method = 'Delete'
				WebSession = $IBSession
			}
		}
        
        Write-Verbose $ReqUri
        
        try {
            $TempResult = Invoke-RestMethod @IRMParams
        }
        catch {
            Throw "Error retrieving record: $_"
        }

        if ( $PassThru ) {
            $TempResult | Add-Member -Type NoteProperty -Name IBSession -Value $IBSession
        }
        else 
        {
            $TempResult.result
        }
    }
    
    END {}
}