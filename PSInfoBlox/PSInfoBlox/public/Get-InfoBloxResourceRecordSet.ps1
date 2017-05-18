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
        
        .PARAMETER InfoBloxServer
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
    #>
    [CmdletBinding(DefaultParameterSetName="Session")]
    param(
        [Parameter(Mandatory=$False,ParameterSetName="Session")]
        [Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [ValidateSet("A","AAAA","CName","DName","DNSKEY","DS","Host","LBDN","MX","NAPTR","NS","NSEC","NSEC3","NSEC3PARAM","PTR","RRSIG","SRV","TXT")]
        [string]
        $RecordType = "A",
        
        [Parameter(Mandatory=$False,ParameterSetName="Session")]
        [Parameter(Mandatory=$True,ParameterSetName="Credential")]
        [string]
        $Uri = $Script:InfobloxBaseUri,
        
        [Parameter(Mandatory=$False,ParameterSetName="Session")]
        [Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [string]
        $IBVersion = $Script:InfoBloxVersion,
        
        [Parameter(Mandatory=$False,ParameterSetName="Session")]
        [Microsoft.PowerShell.Commands.WebRequestSession]
        $IBSession = $Script:InfoBloxSession,
        
        [Parameter(Mandatory=$True,ParameterSetName="Credential")]
        [System.Management.Automation.PSCredential]
        $Credential,
        
        [Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [string]
        $InfoBloxServer,
        
        [Parameter(Mandatory=$False,ParameterSetName="Session")]
        [Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [int]
        $PageSize = 1000,
        
        [Parameter(Mandatory=$False,ParameterSetName="Session")]
        [Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [string]
        $SearchField = 'name',
        
        [Parameter(Mandatory=$False,ParameterSetName="Session")]
        [Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [string]
        $SearchValue = '',
        
        [Parameter(Mandatory=$False,ParameterSetName="Session")]
        [Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [string]
        $Properties = '',
        
        [switch]
        $PassThru
    )
    
    BEGIN {
        # If Credential was specified, we can use that to initiate the InfoBlox session. 
        # build a params hashtable to splat to the New-InfoBloxSession function
        if ( $PSCmldet.ParameterSetName -eq "Credential" ) {
            $Params = @{
                Credential = $Credential
                PassThru = $True
            }
            
            if ( $PSBoundParameters.ContainsKey("IBVersion")) {
                 $Params.Add('Version',$IBVersion) 
            }
            
            if ( $PSBoundParameters.ContainsKey("InfoBloxServer")) {
                 $Params.Add('InfoBloxServer',$InfoBloxServer) 
            }
            
            $IBSession = New-InfoBloxSession @Params
        }
        
        $exactQualityArr = @("text","creator","reclaimable","port")                # =
        $regexArr = @("zone","view","target")                                    # ~=, =
        $caseInsensitiveArr = @("name","ddns_principal","comment")                # := , ~=, =
        $equalityArr = @("weight","priority")                                    # =, <=, >=
        $notSearchableArr = @("use_ttl","ttl","forbid_reclamation","dns_name","disable","ddns_protected","creation_time","cloud_info","aws_rte53_record_info")
        # creation_time = epochseconds format
        # extattrs    
    }
    
    PROCESS {
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
            switch ( $SearchField) {
                {$exactQualityArr -contains $_} {$ReqUri = "{0}&{1}={2}" -f $ReqUri, $SearchField, $SearchValue}
                {$regexArr -contains $_} {$ReqUri = "{0}&{1}~={2}" -f $ReqUri, $SearchField, $SearchValue}
                {$caseInsensitiveArr -contains $_} {$ReqUri = "{0}&{1}:={2}" -f $ReqUri, $SearchField, $SearchValue}
            }
        }
        
        if ( $PSBoundParameters.ContainsKey("Properties") ) {
            $ReqUri = "{0}&return_fileds={1}" -f $ReqUri, $Properties.Join(",").Replace(" ","").ToLower()
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