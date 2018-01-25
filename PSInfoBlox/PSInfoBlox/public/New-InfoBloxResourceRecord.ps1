Function New-InfoBloxResourceRecord {
    <#
        .SYNOPSIS
        Creats a new Resource Record in Infoblox.
        
        .DESCRIPTION
        INSERT DESCRIPTION
        
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
        
        .PARAMETER Passthru
        If specified, this switch will cause the IBSession created in this function to be pased to the pipeline in the output object, 
        so it can be utilized, and not recreated in subsequent function calls.
        
        https://github.com/AWahlqvist/Infoblox-PowerShell-Module/blob/master/cmdlets/Get-IBResourceRecord.ps1
        https://github.com/AWahlqvist/Infoblox-PowerShell-Module/tree/master/cmdlets
        https://github.com/RamblingCookieMonster/Infoblox/blob/master/Infoblox/Get-IBRecord.ps1
        https://github.com/Infoblox-API/PowerShell/tree/master/examples

		https://community.infoblox.com/t5/API-Integration/The-definitive-list-of-REST-examples/td-p/1214
		https://ipam.illinois.edu/wapidoc/additional/sample.html
    #>
    [CmdletBinding(DefaultParameterSetName="Session")]
    param(
        <#
            
        #>
        [Parameter(Mandatory=$False,ParameterSetName="IBSession")]
        [Parameter(Mandatory=$False,ParameterSetName="Credential")]
        #[ValidateSet("A","AAAA","CName","DName","DNSKEY","DS","Host","LBDN","MX","NAPTR","NS","NSEC","NSEC3","NSEC3PARAM","PTR","RRSIG","SRV","TXT")]
        [ValidateSet("A","AAAA","CName","Host","Host_ipv4addr","Host_ipv6addr","LBDN","MX","NAPTR","PTR","SRV","TXT")]
        [string]
        $RecordType = "Host",
        
        [Parameter(Mandatory=$False,ParameterSetName="IBSession")]
        [Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [string]
        $Uri = $Script:IBConfig.Uri,
        
        [Parameter(Mandatory=$False,ParameterSetName="IBSession")]
        [Parameter(Mandatory=$False,ParameterSetName="Credential")]
        [string]
        $IBVersion = $Script:IBConfig.IBVersion,
        
        [Parameter(Mandatory=$False,ParameterSetName="IBSession")]
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
    
    DynamicParam {
		# https://github.com/RamblingCookieMonster/PowerShell/blob/master/New-DynamicParam.ps1 

        # this array holds a list of the parameter names that are added to the parm block. This is they can 
        # be looped through when creating the JSON object for the body
        $DynamicParamList = New-Object System.Collections.ArrayList

        # Dictionary to add to the param block
        $paramDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
        
        # Previously I had each dynamic parameter attribute duplicated in each record type.
        # I think it would be smarter to define these up front, and then simply add them to
        # the attribute collections, and param dictionaries in the individual case blocks.
        
        #region parameter attribute definitions
        $pHostName = New-Object System.Management.Automation.ParameterAttribute
        $pHostName.Mandatory = $true
        $pHostName.HelpMessage = "HostName of the record"
        
        $pCanonical = New-Object System.Management.Automation.ParameterAttribute
        $pCanonical.Mandatory = $true
        $pCanonical.HelpMessage = "Canonical name in FQDN format."
        
        $pipv4Address = New-Object System.Management.Automation.ParameterAttribute
        $pipv4Address.Mandatory = $true
        $pipv4Address.HelpMessage = "IPv4 address of the new A record"
        # http://www.powershelladmin.com/wiki/PowerShell_regex_to_accurately_match_IPv4_address_(0-255_only)
        $ipv4Regex = '((?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d))'
        $ipv4ValidatePatternAttribute = New-Object System.Management.Automation.ValidatePatternAttribute($ipv4Regex)

        $pipv6Address = New-Object System.Management.Automation.ParameterAttribute
        $pipv6Address.Mandatory = $true
        $pipv6Address.HelpMessage = "IPv6 address of the new A record"    
        # IPv6 RegEx - http://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
        $ipv6Regex = "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
        $ipv6ValidatePatternAttribute = New-Object System.Management.Automation.ValidatePatternAttribute($ipv6Regex)

        $pText = New-Object System.Management.Automation.ParameterAttribute
        $pText.Mandatory = $true
        $pText.HelpMessage = "Text associated with the record. It can contain up to 255 bytes per substring, up to a total of 512 bytes."
        
        $pPort = New-Object System.Management.Automation.ParameterAttribute
        $pPort.Mandatory = $true
        $pPort.HelpMessage = "The port of the record. Valid values are from 0 to 65535 (inclusive), in 32-bit unsigned integer format."
        
        $pPriority = New-Object System.Management.Automation.ParameterAttribute
        $pPriority.Mandatory = $true
        $pPriority.HelpMessage = "The priority of the record. Valid values are from 0 to 65535 (inclusive), in 32-bit unsigned integer format."
        
        $pTarget = New-Object System.Management.Automation.ParameterAttribute
        $pTarget.Mandatory = $true
        $pTarget.HelpMessage = "The target of the record in FQDN format."
        
        $pWeight = New-Object System.Management.Automation.ParameterAttribute
        $pWeight.Mandatory = $true
        $pWeight.HelpMessage = "The weight of the record. Valid values are from 0 to 65535 (inclusive), in 32-bit unsigned integer format."
        
        $pPTRDName = New-Object System.Management.Automation.ParameterAttribute
        $pPTRDName.Mandatory = $true
        $pPTRDName.HelpMessage = "The domain name of the DNS PTR record in FQDN format."
        
        $pMailExchanger = New-Object System.Management.Automation.ParameterAttribute
        $pMailExchanger.Mandatory = $true
        $pMailExchanger.HelpMessage = "Mail exchanger name in FQDN format."
        
        $pPreference = New-Object System.Management.Automation.ParameterAttribute
        $pPreference.Mandatory = $true
        $pPreference.HelpMessage = "Preference value, 0 to 65535 (inclusive) in 32-bit unsigned integer format."
        
        $pOrder = New-Object System.Management.Automation.ParameterAttribute
        $pOrder.Mandatory = $true
        $pOrder.HelpMessage = "The order parameter of the NAPTR records. Specifies the order in which NAPTR rules are applied when multiple rules are present (0-65535 inclusive, 32 bit unsigned int)"
        
        $pReplacement = New-Object System.Management.Automation.ParameterAttribute
        $pReplacement.Mandatory = $true
        $pReplacement.HelpMessage = "For nonterminal NAPTR records, this field specifies the next domain name to look up."
        
        $pComment = New-Object System.Management.Automation.ParameterAttribute
        $pComment.Mandatory = $false
        $pComment.HelpMessage = "For nonterminal NAPTR records, this field specifies the next domain name to look up."
        
        $pDisable = New-Object System.Management.Automation.ParameterAttribute
        $pDisable.Mandatory = $false
        $pDisable.HelpMessage = "For nonterminal NAPTR records, this field specifies the next domain name to look up."

		$pExclude = New-Object System.Management.Automation.ParameterAttribute
        $pExclude.Mandatory = $false
        $pExclude.HelpMessage = "An array or range of IP addresses to exclude. (Single IP address, or e.g. 192.168.1.1-192.168.1.10)"
        
        #endregion parameter attribute definitions
        
        switch ( $RecordType ) {
            # "A","AAAA","CName","Host","Host_ipv4addr","Host_ipv6addr","LBDN","MX","NAPTR","PTR","SRV","TXT"
            "A"            {
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pipv4Address)
                $attributeCollection.Add($ipv4ValidatePatternAttribute)
                $pipv4Param = New-Object System.Management.Automation.RuntimeDefinedParameter('IPv4Addr', [string], $attributeCollection)
                $paramDictionary.Add('IPv4Addr', $ipv4Param)
                [void]$DynamicParamList.Add("IPv4Addr")
                
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pHostName)
                $HostNameParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Name', [string], $attributeCollection)
                $paramDictionary.Add('Name', $HostNameParam)
                [void]$DynamicParamList.Add("Name")
                
                
                # TODO:  Move the declaration of NextAvailableIP up with the rest of the decalarations
                $pNextAvailableIp = New-Object System.Management.Automation.ParameterAttribute
                $pNextAvailableIp.Mandatory = $false
                $pNextAvailableIp.HelpMessage = "Determines if the ipv4Address should be the next available address in the network"
				$pNextAvailableIpAliases = New-Object System.Management.Automation.AliasAttribute -ArgumentList @("NextAvailable", "UseNextAvailable", "NextIP", "NextIPAddress")
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pNextAvailableIp)
				$attributeCollection.Add($NextAvailableIpAliases)
                $NextAvailableIpParam = New-Object System.Management.Automation.RuntimeDefinedParameter('UseNextAvailableIp', [switch], $attributeCollection)
                $paramDictionary.Add('UseNextAvailableIp', $NextAvailableIpParam)
				[void]$DynamicParamList.Add("UseNextAvailableIp")

                <# 
                    # Examples:
                    # func:nextavailableip:network/ZG54dfgsrDFEFfsfsLzA:10.0.0.0/8/default
                    # func:nextavailableip:10.0.0.0/8
                    # func:nextavailableip:10.0.0.0/8,external
                    # func:nextavailableip:10.0.0.3-10.0.0.10

					    { "name":"wapi.test.org",
						  "ipv4addrs":[
							  {
								 "ipv4addr":"func:nextavailableip:10.1.1.0/24"
							  }
							]
						}
                #>

				# TODO:  Move the declaration of Network up with the rest of the decalarations
                $pNetwork = New-Object System.Management.Automation.ParameterAttribute
                $pNetwork.Mandatory = $false
                $pNetwork.HelpMessage = "Determines the network for the next available address"
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pNetwork)
                $NetworkParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Network', [string], $attributeCollection)
                $paramDictionary.Add('Network', $NetworkParam)
				[void]$DynamicParamList.Add("Network")

				$pRange = New-Object System.Management.Automation.ParameterAttribute
                $pRange.Mandatory = $false
                $pRange.HelpMessage = "Determines the range for the next available address"
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pRange)
                $RangeParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Range', [string], $attributeCollection)
                $paramDictionary.Add('Range', $RangeParam)
				[void]$DynamicParamList.Add("Range")
            } #A
            "AAAA"        {
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pipv6Address)
                $attributeCollection.Add($ipv6ValidatePatternAttribute)
                $ipv6Param = New-Object System.Management.Automation.RuntimeDefinedParameter('IPv6Addr', [string], $attributeCollection)
                $paramDictionary.Add('IPv6Addr', $ipv6Param)
                [void]$DynamicParamList.Add("IPv6Addr")
                
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pHostName)
                $HostNameParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Name', [string], $attributeCollection)
                $paramDictionary.Add('Name', $HostNameParam)
                [void]$DynamicParamList.Add("Name")
            } #AAAA
            "CName"        {
                <#
                    A CNAME record maps an alias to a canonical name. You can use CNAME records in both forward and IPv4 reverse-mapping zones to serve
                    two different purposes. (At this time you cannot use CNAME records with IPv6 reverse-mapping zones.)
                    In a forward-mapping zone, a CNAME record maps an alias to a canonical (or offical) name. CNAME records are often more convenient
                    to use than canonical names because they can be shorter or more descriptive.
                    
                    -Name This is the name this record is referenced by
                    -Canonical this is the FQDN of the A (AAAA, etc) record
                #>
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pHostName)
                $HostNameParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Name', [string], $attributeCollection)
                $paramDictionary.Add('Name', $HostNameParam)
                [void]$DynamicParamList.Add("Name")
                
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pCanonical)
                $CanonicalParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Canonical', [string], $attributeCollection)
                $paramDictionary.Add('Canonical', $CanonicalParam)
                [void]$DynamicParamList.Add("Canonical")
            } #CNAME
            "Host"        {
                <#
                    A host record defines attributes for a node, such as the name-to-address and address-to-name mapping. This alleviates
                    having to specify an A record and a PTR record separately for the same node. A host can also define aliases and DHCP
                    fixed address nodes. The zone must be created first before adding a host record for the zone.
                #>

				#[string] $IPv4Addr
				$attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $pipv4Address.Mandatory = $false        # set this to false, since IPv6 is allowed too
                $attributeCollection.Add($pipv4Address)
                $attributeCollection.Add($ipv4ValidatePatternAttribute)
                $ipv4Param = New-Object System.Management.Automation.RuntimeDefinedParameter('IPv4Addr', [string], $attributeCollection)
                $paramDictionary.Add('IPv4Addr', $ipv4Param)
                [void]$DynamicParamList.Add("IPv4Addr")
                
				#[string] $IPv6Addr
				$attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $pipv6Address.Mandatory = $false        # set this to false, since IPv4 is allowed too
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($ipv6Address)
                $attributeCollection.Add($ipv6ValidatePatternAttribute)
                $ipv6Param = New-Object System.Management.Automation.RuntimeDefinedParameter('IPv6Addr', [string], $attributeCollection)
                $paramDictionary.Add('IPv6Addr', $ipv6Param)
                [void]$DynamicParamList.Add("IPv6Addr")
                
				#[string] $Name
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pHostName)
                $HostNameParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Name', [string], $attributeCollection)
                $paramDictionary.Add('Name', $HostNameParam)
                [void]$DynamicParamList.Add("Name")

				 # TODO:  Move the declaration of NextAvailableIP up with the rest of the decalarations
				#[switch] $NextAvailableIp
                $pNextAvailableIp = New-Object System.Management.Automation.ParameterAttribute
                $pNextAvailableIp.Mandatory = $false
                $pNextAvailableIp.HelpMessage = "Determines if the ipv4Address should be the next available address in the network"
				$NextAvailableIpAliases = New-Object System.Management.Automation.AliasAttribute -ArgumentList @("NextAvailable", "UseNextAvailable", "NextIP", "NextIPAddress")
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pNextAvailableIp)
				$attributeCollection.Add($NextAvailableIpAliases)
                $NextAvailableIpParam = New-Object System.Management.Automation.RuntimeDefinedParameter('UseNextAvailableIp', [switch], $attributeCollection)
                $paramDictionary.Add('UseNextAvailableIp', $NextAvailableIpParam)
				[void]$DynamicParamList.Add("UseNextAvailableIp")

 				# TODO:  Move the declaration of Network up with the rest of the decalarations
				#[string] $Network
                $pNetwork = New-Object System.Management.Automation.ParameterAttribute
                $pNetwork.Mandatory = $false
                $pNetwork.HelpMessage = "Specifies the network to insert the next available address into."
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pNetwork)
                $NetworkParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Network', [string], $attributeCollection)
                $paramDictionary.Add('Network', $NetworkParam)
				[void]$DynamicParamList.Add("Network")

				#[string] $Range
				$pRange = New-Object System.Management.Automation.ParameterAttribute
                $pRange.Mandatory = $false
                $pRange.HelpMessage = "Specifies the range to insert the next available address into."
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pRange)
                $RangeParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Range', [string], $attributeCollection)
                $paramDictionary.Add('Range', $RangeParam)
				[void]$DynamicParamList.Add("Range")

				#[switch] $ConfigureDHCP
				$pConfigureDHCP = New-Object System.Management.Automation.ParameterAttribute
                $pConfigureDHCP.Mandatory = $false
                $pConfigureDHCP.HelpMessage = "Specifies that the record should be created with DHCP enabled (MAC address must be on the record, or specified)."
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pConfigureDHCP)
                $ConfigureDHCPParam = New-Object System.Management.Automation.RuntimeDefinedParameter('ConfigureDHCP', [switch], $attributeCollection)
                $paramDictionary.Add('ConfigureDHCP', $ConfigureDHCPParam)
				[void]$DynamicParamList.Add("ConfigureDHCP")

				#[string] $MacAddress
				$pMacAddress = New-Object System.Management.Automation.ParameterAttribute
                $pMacAddress.Mandatory = $false
                $pMacAddress.HelpMessage = "Specifies that the record should be created with DHCP enabled (MAC address must be on the record, or specified)."
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pMacAddress)
                $MacAddressParam = New-Object System.Management.Automation.RuntimeDefinedParameter('MacAddress', [string], $attributeCollection)
                $paramDictionary.Add('MacAddress', $MacAddressParam)
				[void]$DynamicParamList.Add("MacAddress")

				#[string[]] $Exclude
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pExclude)
                $ExcludeParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Exclude', [string[]], $attributeCollection)
                $paramDictionary.Add('Exclude', $ExcludeParam)
				[void]$DynamicParamList.Add("Exclude")
            } #Host
            "Host_ipv4addr"        {
                #    A Host address in an object used to specify addresses in the record.host object
                $attributeCollection.Add($pipv4Address)
                $attributeCollection.Add($ipv4ValidatePatternAttribute)
                $ipv4Param = New-Object System.Management.Automation.RuntimeDefinedParameter('IPv4Addr', [string], $attributeCollection)
                $paramDictionary.Add('IPv4Addr', $ipv4Param)
                [void]$DynamicParamList.Add("IPv4Addr")
            } #Host_ipv4addr
            "Host_ipv6addr"        {
                #    A Host address in an object used to specify addresses in the record.host object
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pipv6Address)
                $attributeCollection.Add($ipv6ValidatePatternAttribute)
                $ipv6Param = New-Object System.Management.Automation.RuntimeDefinedParameter('IPv6Addr', [string], $attributeCollection)
                $paramDictionary.Add('IPv6Addr', $ipv6Param)
                [void]$DynamicParamList.Add("IPv6Addr")
            } #Host_ipv6addr
            "LBDN"        {
                <#
                    A Load Balanced Domain Name Record object
                    Note: no required fields in this object type. Adding optional fields that are not read-only.
                #>
                # not mandatory ever, no need to declare false
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pComment)
                $CommentParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Comment', [string], $attributeCollection)
                $paramDictionary.Add('Comment', $CommentParam)
                [void]$DynamicParamList.Add("Comment")
                
                # not mandatory ever, no need to declare false
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($Disable)
                $DisableParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Disable', [bool], $attributeCollection)
                $paramDictionary.Add('Disable', $DisableParam)
                [void]$DynamicParamList.Add("Disable")
            } #LBDN
            "MX"        {
                <#
                    An MX (mail exchanger) record maps a domain name to a mail exchanger. A mail exchanger is a server that either
                    delivers or forwards mail. You can specify one or more mail exchangers for a zone, as well as the preference for 
                    using each mail exchanger. A standard MX record applies to a particular domain or subdomain.
                #>
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pHostName)
                $HostNameParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Name', [string], $attributeCollection)
                $paramDictionary.Add('Name', $HostNameParam)
                [void]$DynamicParamList.Add("Name")
                
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pMailExchanger)
                $MailExchangerParam = New-Object System.Management.Automation.RuntimeDefinedParameter('mail_exchanger', [string], $attributeCollection)
                $paramDictionary.Add('mail_exchanger', $ipv6Param)
                [void]$DynamicParamList.Add("mail_exchanger")
                
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pPreference)
                $PreferenceParam = New-Object System.Management.Automation.RuntimeDefinedParameter('preference', [int], $attributeCollection)
                $paramDictionary.Add('preference', $PreferenceParam)
                [void]$DynamicParamList.Add("preference")
            } #MX
            "NAPTR"        {
                <#
                    a DNS NAPTR object represents a Naming Authority Pointer (NAPTR) resource record. This resource record specifies 
                    a regular expression=based rewrite rule that, when applied to an existing string, produces a new domain name or URI.
                #>
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pHostName)
                $HostNameParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Name', [string], $attributeCollection)
                $paramDictionary.Add('Name', $HostNameParam)
                [void]$DynamicParamList.Add("Name")
                
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pOrder)
                $OrderParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Order', [int], $attributeCollection)
                $paramDictionary.Add('Order', $OrderParam)
                [void]$DynamicParamList.Add("Order")
                
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pPreference)
                $PreferenceParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Preference', [int], $attributeCollection)
                $paramDictionary.Add('Preference', $PreferenceParam)
                [void]$DynamicParamList.Add("Preference")
                
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pReplacement)
                $ReplacementParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Replacement', [string], $attributeCollection)
                $paramDictionary.Add('Replacement', $ReplacementParam)
                [void]$DynamicParamList.Add("Replacement")
            } #NAPTR
            "PTR"        {
                <#
                    In a forward-mapping zone, a PTR (pointer) record maps a domain name to another domain name. In a reverse-mapping
                    zone, PTR record maps an address to a domain name. To define a specific addresss-to-name mapping, add a PTR record
                    to a previously defined authoritative reverse-mapping zone.
                #>
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pHostName)
                $HostNameParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Name', [string], $attributeCollection)
                $paramDictionary.Add('Name', $HostNameParam)
                [void]$DynamicParamList.Add("Name")
                
                # records can be ipv6 or ipv4, so we need to set mandatory=$false for this parameter
                $ipv4Address.Mandatory = $false
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pipv4Address)
                $attributeCollection.Add($ipv4ValidatePatternAttribute)
                $ipv4Param = New-Object System.Management.Automation.RuntimeDefinedParameter('IPv4Addr', [string], $attributeCollection)
                $paramDictionary.Add('IPv4Addr', $ipv4Param)
                [void]$DynamicParamList.Add("IPv4Addr")
                
                $ipv6Address.Mandatory = $false
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pipv6Address)
                $attributeCollection.Add($ipv6ValidatePatternAttribute)
                $ipv6Param = New-Object System.Management.Automation.RuntimeDefinedParameter('IPv6Addr', [string], $attributeCollection)
                $paramDictionary.Add('IPv6Addr', $ipv6Param)
                [void]$DynamicParamList.Add("IPv6Addr")
                
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pPTRDName)
                $PTRDNameParam = New-Object System.Management.Automation.RuntimeDefinedParameter('PTRDName', [string], $attributeCollection)
                $paramDictionary.Add('PTRDName', $PTRDNameParam)
                [void]$DynamicParamList.Add("PTRDName")
            } #PTR
            "SRV"        {
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pHostName)
                $HostNameParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Name', [string], $attributeCollection)
                $paramDictionary.Add('Name', $HostNameParam)
                [void]$DynamicParamList.Add("Name")
                
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pPort)
                $PortParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Port', [int], $attributeCollection)
                $paramDictionary.Add('Port', $PortParam)
                [void]$DynamicParamList.Add("Port")
                
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pPriority)
                $PriorityParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Priority', [int], $attributeCollection)
                $paramDictionary.Add('Priority', $PriorityParam)
                [void]$DynamicParamList.Add("Priority")
                
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pTarget)
                $TargetParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Target', [string], $attributeCollection)
                $paramDictionary.Add('Target', $TargetParam)
                [void]$DynamicParamList.Add("Target")
                
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pWeight)
                $WeightParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Weight', [int], $attributeCollection)
                $paramDictionary.Add('Weight', $WeightParam)
                [void]$DynamicParamList.Add("Weight")
            } #SRV
            "TXT"        {
                <# 
                    3.127 record:txt : DNS TXT record object.
                    A TXT (text record) record contains supplemental information for a host. For example, if you have a sales server that
                    serves only North America, you can create a text record stating this fact. You can create more than one text record for
                    a domain name.
                #>
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pHostName)
                $HostNameParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Name', [string], $attributeCollection)
                $paramDictionary.Add('Name', $HostNameParam)
                [void]$DynamicParamList.Add("Name")
                
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($pText)
                $TextParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Text', [string], $attributeCollection)
                $paramDictionary.Add('Text', $TextParam)
                [void]$DynamicParamList.Add("Text")
            } #TXT
        } #switch
        
        return $paramDictionary
    } #DynamicParam
    
    BEGIN {
        # If Credential was specified, we can use that to initiate the InfoBlox session. 
        # build a params hashtable to splat to the New-InfoBloxSession function
		<#
        if ( $PSCmldet.ParameterSetName -eq "Credential" ) {
            $Params = @{
                Credential = $Credential
                PassThru = $True
            }
            
            if ( $PSBoundParameters.ContainsKey("IBVersion")) {
                 $Params.Add('Version',$IBVersion) 
            }
            
            if ( $PSBoundParameters.ContainsKey("IBServer")) {
                 $Params.Add('IBServer',$IBServer) 
            }
            
            $IBSession = New-InfoBloxSession @Params -PassThru
            
        }
		#>
		if (-not($PSBoundParameters.ContainsKey("Uri")) ) {
			if ( [string]::IsNullOrEmpty($Uri) -and $PSCmdlet.ParameterSetName -eq "Credential" ) {
				if ([string]::IsNullOrEmpty($IBServer) -or [string]::IsNullOrEmpty($IBVersion) ) {
					throw "Unable to determine Uri for IBServer. Specify Uri, or IBVersion and IBServer."
				} #if
				$Uri = "https://{0}/wapi/v{1}" -f $IBServer, $IBVersion
			} #if
		} #if
		Set-TrustAllCertsPolicy
		$arrays = @("ipv4addr","ipv6addr","aliases")
		$SpecialProcessingParams = @("Network","Range","ConfigureDHCP","MacAddress","Exclude")
		$ExcludeExpanded = New-Object System.Collections.ArrayList
    } #BEGIN
    
    PROCESS {
        # build Url based on the record type
        $ReqUri = "{0}/record:{1}?_return_fields%2b=name,zone,extattrs" -f $Uri, $RecordType.ToLower()    # %2b in place of +

		if ( $PSBoundParameters.ContainsKey("Exclude")) {
			ForEach ($item in $PSBoundParameters["Exclude"]) {
				$Expanded = Get-IPsInRange -ipaddress $item
				ForEach ( $expandedItem in $Expanded ) {
					[void]$ExcludeExpanded.Add($expandedItem)
				} #ForEach
			} #ForEach
		} #if

		#IPv4Addr - assign this value to either the passed in value for ipv4addr (else) or, if the UseNextAvailableIp switch was used, set it to the next
		# available IPv4Address in the specified network
		if ( $PSBoundParameters.ContainsKey("UseNextAvailableIp") ) {
			# If UseNextAvailableIp switch was specified, we also need the network or range
			Write-Verbose "Using next available IP"
			if ($PSBoundParameters.ContainsKey("Network")) {
				$IPAddressString = "func:nextavailableip:{0}" -f $PSBoundParameters["Network"]
			} # if 
			elseif ($PSBoundParameters.ContainsKey("Range")) {
				try { 
					[void][ipaddress]::Parse($PSBoundParameters["Range"])
					# This is an IP Address.  Assume it is a start address of the range - lets try to find the range.
					$RangeObj = Get-InfoBloxRange -StartAddress $PSBoundParameters["Range"] -Credential $Credential
					if ( $null -eq $RangeObj ) {
						throw "UseNextAvailableIp switch was specified, valid IP address was passed, but was not a valid range or network."
						return
					} # if 
					if ( $RangeObj.start_addr.Split(".")[3] -eq 0 ) {
						<#
						How to create a network in a specified RANGE, and skip/exclude a specified IP address - in the even the next available IP
						Has a last octet of 0, we do want to skip that address, unless this is a /31.
						{
						"name":  "myrecord.mydomain.com",
						"ipv4addrs":  [
							{
								"ipv4addr":  {
								"_object_function" : "next_available_ip",
								"_object_field" : "ips",
								"_object" : "range",
								"_result_field": "ips", 
								"_parameters" : {
									"num" : 1,
									"exclude" : ["192.168.1.0"]
								},
								"mac":"aa:bb:cc:11:22:21",
								"configure_for_dhcp": true,
								"_object_parameters" : {
									"start_addr" : "192.168.1.0"
								}
								}
							}
						]
						}
						#> 

						$IPAddressString = @{
							"_object_function" = "next_available_ip"
                            "_object_field" = "ips"
                            "_object" = "range"
                            "_result_field" = "ips"
						} #hash ipv4addr
						# Embdedded hashtable _parameters

						[void]$ExcludeExpanded.Add($RangeObj.start_addr)
						$_parameters = @{
							num = 1
							exclude = $ExcludeExpanded
						} #hash

						# Embdedded hashtable _object_parameters
						$_object_parameters = @{
							start_addr = $RangeObj.start_addr
						} #hash

						#Add the embedded hashtables to the parent
						$IPAddressString.Add("_parameters",$_parameters)
						$IPAddressString.Add("_object_parameters",$_object_parameters)
					} #if
					else {
						$IPAddressString = "func:nextavailableip:{0}-{1}" -f $RangeObj.start_addr, $RangeObj.end_addr
					} #else
				} #try
				catch {
					# not an IP Address
					$IPAddressString = "func:nextavailableip:{0}" -f $PSBoundParameters["Range"]
				} #catch
			} # if 
			else {
				throw "UseNextAvailableIp switch was specified, but no network or range was specified."
				return
			} # else
		}
		elseIf ($RecordType -eq "Host" -and $PSBoundParameters.ContainsKey("ipv4addr")) {
			Write-Verbose "Using passed ipv4addr"
			Write-Verbose $PSBoundParameters["ipv4addr"]
			$IPAddressString = $PSBoundParameters["ipv4addr"]
		}
		Write-Verbose "ipv4addr is $IPAddressString"
        
        # We need to build the JSON Body from the Dynamic Parameters
        $ParamHash = @{}
		if ( $PSBoundParameters.ContainsKey("Exclude") -and $PSBoundParameters.ContainsKey("UseNextAvailableIp") -and $RecordType -eq "Host" -and $PSBoundParameters.ContainsKey("Network")) {
			<#
			# JSON for advanced function with excluded IP Addresses.
			{
				"name": "myrecord.mydomain.com", 
				"ipv4addrs": [
				{
				"ipv4addr": {
					"_object_function": "next_available_ip", 
					"_object": "network", 
					"_object_parameters": {
					"network": "192.168.1.0/23"
					}, "_result_field": "ips", 
					"_parameters": {
					"num": 1, 
					"exclude": ["192.169.1.3"]
					}
				}
				}
				]
			}
			#>
			$_parameters = @{
				num = 1
				exclude = [array]$ExcludeExpanded
			} #hash
			$_object_parameters = @{
				network = $PSBoundParameters["Network"]
			} #hash
			$ipv4addrHash = @{
				"_object_function" = "next_available_ip"
				"_object" = "network"
				"_object_parameters" = $_object_parameters
			} #hash
			$ipv4addrHash.Add("_parameters",$_parameters)
			$ipv4addrHash.Add("_result_field","ips")
			
			
			$ipv4addrshash = @{}
			$ipv4addrsHash.Add("ipv4addr",$ipv4addrHash)
			if ( $PSBoundParameters.ContainsKey("MacAddress")) {
				$ipv4addrsHash.Add("mac",$PSBoundParameters["MacAddress"])
				if ($PSBoundParameters.ContainsKey("ConfigureDHCP")) {
					$ipv4addrsHash.Add("configure_for_dhcp",$true)
				} #if 
			} #if

			$Paramhash.Add("name", $PSBoundParameters["Name"])
			$ParamHash.Add("ipv4addrs",[array]$ipv4addrshash)

		} #if $PSBoundParameters.ContainsKey("Exclude")
		else {
			ForEach ( $DynamicParam in $DynamicParamList ) {
				$Value = $PSBoundParameters[$DynamicParam]
				if ( $PSBoundParameters.ContainsKey($DynamicParam) ) {
					# if Host, ip4addr = ipv4addrs array, etc.
					if ( $arrays -contains $DynamicParam -and $RecordType -eq "Host" ) {
						$Parent = "{0}s" -f $DynamicParam.ToLower()
						$SubHash = @{
							$DynamicParam.ToLower() = $Value
						}
						if ( $DynamicParam -eq "ipv4addr") {
							if ( $PSBoundParameters.ContainsKey("MacAddress")) {
								$SubHash.Add("mac",$PSBoundParameters["MacAddress"])
								if ($PSBoundParameters.ContainsKey("ConfigureDHCP")) {
									$SubHash.Add("configure_for_dhcp",$true)
								} #if 
							} #if 
						} #if
						$ParamHash.Add($Parent,[array]$SubHash)  # cast subhash as array, so it has the proper format.
					} #if
					elseif ($DynamicParam -eq "UseNextAvailableIp") {
						$Parent = "ipv4addrs"
						$SubHash = @{
							ipv4addr = $IPAddressString
						} #hash

						if ( $DynamicParam -eq "ipv4addr") {
							if ( $PSBoundParameters.ContainsKey("MacAddress")) {
								$SubHash.Add("mac",$PSBoundParameters["MacAddress"])
								if ($PSBoundParameters.ContainsKey("ConfigureDHCP")) {
									$SubHash.Add("configure_for_dhcp",$true)
								} #if
							} #if
						} #if

						$ParamHash.Add($Parent,[array]$SubHash)  # cast subhash as array, so it has the proper format.
					} #elseif
					elseif ($SpecialProcessingParams -contains $DynamicParam ) {
						continue
					} #elseif
					else {
						$ParamHash.Add($DynamicParam.ToLower(),$PSBoundParameters[$DynamicParam])
					} #else
				} #id
			} #ForEach
        } #else
        $JSON = $ParamHash | ConvertTo-Json -Depth 10
        if ($PSCmdlet.ParameterSetName -eq "Credential" ) {
			$IRMParams = @{
				Uri = $ReqUri
				Method = 'Post'
				Credential = $Credential
				Body = $JSON
				ContentType = "application/json"
			} #IRMParams Hash
		} #if
		else {
			$IRMParams = @{
				Uri = $ReqUri
				Method = 'Post'
				WebSession = $IBSession
				Body = $JSON
				ContentType = "application/json"
			} #IRMParams Hash
		} #else

		$UsingParameterSet = "Using {0}" -f $PSCmdlet.ParameterSetName
        Write-Verbose $UsingParameterSet
        Write-Verbose $ReqUri
		Write-Verbose $JSON
        
        try {
            $TempResult = Invoke-RestMethod @IRMParams
        } #try
        catch {
			# Compliments to JBOSS https://community.infoblox.com/t5/API-Integration/How-to-create-static-DHCP-record-with-API/td-p/4746
			$error = $_
			 if ($error.Exception.Response) {
				$InfobloxError = $error.Exception.Response.GetResponseStream()
				$reader = New-Object System.IO.StreamReader($InfobloxError)
				$responseBody = $reader.ReadToEnd();
				throw $responseBody
			}
        } #catch
        

        
        if ( $PassThru ) {
            $TempResult | Add-Member -Type NoteProperty -Name IBSession -Value $IBSession
        } #if
        else {
            $TempResult
        } #else
    } # PROCESS
    
    END {}
}