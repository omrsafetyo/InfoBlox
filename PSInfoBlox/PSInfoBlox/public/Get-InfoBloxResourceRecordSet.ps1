Function Get-InfoBloxResourceRecordSet {
    <#
        .SYNOPSIS
        Retrieves resource records from the InfoBlox server.
        
        .DESCRIPTION
        Returns resource record objects from the InfoBlox server based on the record type, and search parameters specified.
        Can be used with a InfoBlox Session created with New-InfoBloxSession, or the Url to the InfoBlox server, and credentials
        can be passed directly to this function.
        
        .PARAMETER RecordType
        Specifies the type of record to return (A record, CNAME, etc,.)
        
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
        
        .PARAMETER PageSize
        How many results per page to retrieve from the InfoBlox server.
        
        .PARAMETER SearchField
        Specifies a ResourceRecord property to filter on
        
        .PARAMETER SearchValue
        Specifies the value to search for in the SearchField
        
        .PARAMETER Properties
        Properties to be included in the record set
        
        .PARAMETER Passthru
        If specified, this switch will cause the IBSession created in this function to be pased to the pipeline in the output object, 
        so it can be utilized, and not recreated in subsequent function calls.
        
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
        [ValidateSet("A","AAAA","CName","DName","DNSKEY","DS","Host","LBDN","MX","NAPTR","NS","NSEC","NSEC3","NSEC3PARAM","PTR","RRSIG","SRV","TXT")]
        [string]
        $RecordType = "A",
        
        [Parameter(Mandatory=$False,ParameterSetName="Session")]
        [Parameter(Mandatory=$False,ParameterSetName="Credential")]
		[Alias("MaxRecords","Records","Count","RecordCount","MaxResults")]
        [int]
        $PageSize = 1000,
        
        [Parameter(Mandatory=$False,ParameterSetName="Session")]
        [Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [string]
        $SearchField = 'name',
        
        [Parameter(Mandatory=$False,ParameterSetName="Session")]
        [Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [Alias("eq", "ceq", "neq", "like", "ge", "le")] # -eq, -ne, -gt, -lt, -le, -ge		# = ~= := <= >=  clike ?
        [string]
        $SearchValue = '',
        
        [Parameter(Mandatory=$False,ParameterSetName="Session")]
        [Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [string]
        $Properties = '',

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
        # If Credential was specified, we can use that to initiate the InfoBlox session. 
        # build a params hashtable to splat to the New-InfoBloxSession function
        if ( $PSCmdlet.ParameterSetName -eq "Credential" ) {
            $Params = @{
                Credential = $Credential
                PassThru = $True
            }
            
            if ( $PSBoundParameters.ContainsKey("IBVersion")) {
                 $Params.Add('IBVersion',$IBVersion) 
            }
            
            if ( $PSBoundParameters.ContainsKey("IBServer")) {
                 $Params.Add('IBServer',$IBServer) 
            }

            Write-Host "Building session since Credentials were specified."
            $IBSession = New-InfoBloxSession @Params
			$Script:IBConfig = Get-InfoBloxConfig
			$Uri = $Script:IBConfig.Uri
        }
		
		# "eq", "ceq", "like", "clike", "ge", "le"
        $exactQualityArr = @("text","creator","reclaimable","port")                # =
        $regexArr = @("zone","view","target")                                    # ~=, =
        $caseInsensitiveArr = @("name","ddns_principal","comment")                # := , ~=, =
        $equalityArr = @("weight","priority")                                    # =, <=, >=
        $notSearchableArr = @("use_ttl","ttl","forbid_reclamation","dns_name","disable","ddns_protected","creation_time","cloud_info","aws_rte53_record_info")
        # creation_time = epochseconds format
        # extattrs    

		$CommandLine = $MyInvocation.Line
		# This accounts for when variables are passed to the -SearchValue parameter when an Alias is used.
		$varPattern = '\$\w+'	# variable regex pattern
		filter Matches($pattern) {	# find all instances
			$_ | Select-String -AllMatches $pattern |
			Select-Object -ExpandProperty Matches |
			Select-Object -ExpandProperty Value
		}
		# when we re-use them in the regex below, we need to look for \$varname
		# so this will look for -like "zonename" or -like $ZoneName
		$VariablesInCommandLine = $CommandLine | Matches $varPattern | ForEach-Object { $_ -replace '\$','\$'}

		if ( $PSBoundParameters.ContainsKey("SearchValue") ) {
			Write-Verbose "Checking to see if equality operator alias used"
			if ( -not($CommandLine -match " -SearchValue ") ) {
				Write-Verbose "Equality operator alias used."
				# The Actual variable name was not used, which alias was?
				# $SearchValueAliasUsed = $CommandLine -match "\s-($($MyInvocation.MyCommand.Parameters['SearchValue'].Aliases -join '|'))\s" | % { $Matches[1] }
				$Aliases = $MyInvocation.MyCommand.Parameters['SearchValue'].Aliases -join '|'
				$Quotes = "'" + '"'
				$Regex = '\s-({0})[\s:]+?[{3}]??({1}|{2})[{3}]??' -f $Aliases, $PSBoundParameters["SearchValue"], ($VariablesInCommandLine -join '|'), $Quotes
				$SearchValueAliasUsed = $CommandLine -match $Regex | ForEach-Object { $Matches[1] }
				Write-Verbose "Alias used is $SearchValueAliasUsed"
			}
		}
    }
    
    PROCESS {
        $msg = "ParameterSetName is {0}" -f $PSCmdlet.ParameterSetName
        Write-Verbose $msg
        Write-Verbose "Uri is $Uri"
        $BaseUri = "{0}/record:{1}" -f $Uri, $RecordType.ToLower()
        $NextPageID = "NotStarted"
        
        $ReqUri = $BaseUri, "_paging=1&_max_results=$PageSize&_return_as_object=1" -join "?"
        
        <# 
        if ( $PSBoundParameters.ContainsKey("SearchValue") ) {
            $ReqUri = "{0}&{1}~={2}" -f $ReqUri, $SearchField, $SearchValue
        }
        #>
        
        # TODO: Refine this so it works a bit better. This shouldn't be a 1:many ratio - it should be many:many. Need to parameterize the options.
        if ( $PSBoundParameters.ContainsKey("SearchValue") ) {
			# 6/2/2017
			if ( $SearchValueAliasUsed ) {
				Write-Verbose "Using equality operator"
				switch ( $SearchValueAliasUsed ) {
					"eq" {
						$EqualityOperator = ":="
					}
					"ceq" {
						$EqualityOperator = "="
					}
					"neq" {
						$EqualityOperator = "!="
					}
					"like" {
						$EqualityOperator = "~="
					}
					"ge" {
						$EqualityOperator = ">="
					}
					"le" {
						$EqualityOperator = "<="
					}
				}
				Write-Verbose "Using $EqualityOperator"
				$ReqUri = "{0}&{1}{2}{3}" -f $ReqUri, $SearchField, $EqualityOperator, $SearchValue
			}
			else {
				Write-Verbose "Not using specific equality operator"
				switch ( $SearchField ) {
					{$exactQualityArr -contains $_} {$ReqUri = "{0}&{1}={2}" -f $ReqUri, $SearchField, $SearchValue}
					{$regexArr -contains $_} {$ReqUri = "{0}&{1}~={2}" -f $ReqUri, $SearchField, $SearchValue}
					{$caseInsensitiveArr -contains $_} {$ReqUri = "{0}&{1}:={2}" -f $ReqUri, $SearchField, $SearchValue}
				}
			}
        }
        
        if ( $PSBoundParameters.ContainsKey("Properties") ) {
            $ReqUri = "{0}&return_fields={1}" -f $ReqUri, $Properties.Join(",").Replace(" ","").ToLower()
        }
        
        $IRMParams = @{
            Uri = $ReqUri
            Method = 'Get'
            WebSession = $IBSession
        }
        
        Write-Verbose $ReqUri
        
        do {
            if($NextPageID -notlike "NotStarted") {
                $IRMParams.Uri = $BaseUri, "_page_id=$NextPageID" -join "?"
            }

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
        until (-not $TempResult.next_page_id)
    }
    
    END {}
}