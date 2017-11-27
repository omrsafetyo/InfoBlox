Function Get-InfoBloxResourceRecord {
    <#
        .SYNOPSIS
        Retrieves a single Resource Record from the InfoBlox server from the reference URL.
              
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

    #>
    [CmdletBinding(DefaultParameterSetName="Session")]
    param(    
		[Parameter(Mandatory=$True,ParameterSetName="Session")]
		[Parameter(Mandatory=$True,ParameterSetName="Credential")]
        [string]
        $Reference,

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

		$ReqUri = $Uri, $Reference -join "/"
		$ReqUri = $ReqUri, "_return_as_object=1" -join "?"

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
        
        Write-Verbose $ReqUri


        try {
            $TempResult = Invoke-RestMethod @IRMParams
        }
        catch {
            Throw "Error retrieving record: $_"
        }
        $NextPageID = $TempResult.next_page_id
            
        Write-Verbose "Page $NextPageID"
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