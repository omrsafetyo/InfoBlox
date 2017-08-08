Function Set-InfoBloxResourceRecord {
    <#
        .SYNOPSIS
        Creats a new Resource Record in Infoblox.
        
        .DESCRIPTION
        INSERT DESCRIPTION
        
        .PARAMETER Reference
        Specifies the _ref for the object in InfoBlox Grid.
        
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
        [Parameter(Mandatory=$True,ParameterSetName="IBSession")]
        [Parameter(Mandatory=$True,ParameterSetName="Credential")]
        [Alias('_ref','ref')]
        [string]
        $Reference,
        
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
        # this array holds a list of the parameter names that are added to the parm block. This is they can 
        # be looped through when creating the JSON object for the body
        $DynamicParamList = New-Object System.Collections.ArrayList
        # Dictionary to add to the param block
        $paramDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

		# Once reference is defined, we can load that value in.
		if ( $Reference ) {
			# If its a variable, we need to expand that variable out.
			if ( $Reference.SubString(0,1) -eq '$' ) {
				# If we are referencing a property of a variable - for instance, if we did a GET on a record, and saved
				# the output 
				if ( $Reference.Split(".").Count -gt 1 ) {
					$Variable = $Reference.Split(".")[0].Substring(1)
					$Property = $Reference.Split(".")[1]
					$OrigVariable = (Get-Variable $Variable).Value
					$ReferenceExpand = $OrigVariable.$($Property)
				}
				else {
					# if the variable has no properties being referenced, just expand the variable
					$ReferenceExpand = (Get-Variable $Reference).Value
				}
				# Finally, substring the value on : and / and grab the 2nd item
				# record:cname/BuncHoFLetters:recordname/view
				# we want cname
				$RecordType = $ReferenceExpand.Split(":/")[1]
			}
			else {
				# if a string was passed, just split the string.
				$RecordType = $Reference.Split(":/")[1]
			}
			Write-Host "Record type os $RecordType"
		}
		else {
			Write-Host "Record type not found"
			return
		}
        
        # Previously I had each dynamic parameter attribute duplicated in each record type.
        # I think it would be smarter to define these up front, and then simply add them to
        # the attribute collections, and param dictionaries in the individual case blocks.
        
        #region parameter attribute definitions
		# all Mandatory attributes are set to false, because this is a Put operation and all options are optional
        $HostName = New-Object System.Management.Automation.ParameterAttribute
        $HostName.Mandatory = $false
        $HostName.HelpMessage = "HostName of the record"
        
        $Canonical = New-Object System.Management.Automation.ParameterAttribute
        $Canonical.Mandatory = $false
        $Canonical.HelpMessage = "Canonical name in FQDN format."
        
        $ipv4Address = New-Object System.Management.Automation.ParameterAttribute
        $ipv4Address.Mandatory = $false
        $ipv4Address.HelpMessage = "IPv4 address of the new A record"
        # http://www.powershelladmin.com/wiki/PowerShell_regex_to_accurately_match_IPv4_address_(0-255_only)
        $ipv4Regex = '((?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d))'
        $ipv4ValidatePatternAttribute = New-Object System.Management.Automation.ValidatePatternAttribute($ipv4Regex)

        $ipv6Address = New-Object System.Management.Automation.ParameterAttribute
        $ipv6Address.Mandatory = $false
        $ipv6Address.HelpMessage = "IPv6 address of the new A record"    
        # IPv6 RegEx - http://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
        $ipv6Regex = "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
        $ipv6ValidatePatternAttribute = New-Object System.Management.Automation.ValidatePatternAttribute($ipv6Regex)

        $Text = New-Object System.Management.Automation.ParameterAttribute
        $Text.Mandatory = $false
        $Text.HelpMessage = "Text associated with the record. It can contain up to 255 bytes per substring, up to a total of 512 bytes."
        
        $Port = New-Object System.Management.Automation.ParameterAttribute
        $Port.Mandatory = $false
        $Port.HelpMessage = "The port of the record. Valid values are from 0 to 65535 (inclusive), in 32-bit unsigned integer format."
        
        $Priority = New-Object System.Management.Automation.ParameterAttribute
        $Priority.Mandatory = $false
        $Priority.HelpMessage = "The priority of the record. Valid values are from 0 to 65535 (inclusive), in 32-bit unsigned integer format."
        
        $Target = New-Object System.Management.Automation.ParameterAttribute
        $Target.Mandatory = $false
        $Target.HelpMessage = "The target of the record in FQDN format."
        
        $Weight = New-Object System.Management.Automation.ParameterAttribute
        $Weight.Mandatory = $false
        $Weight.HelpMessage = "The weight of the record. Valid values are from 0 to 65535 (inclusive), in 32-bit unsigned integer format."
        
        $PTRDName = New-Object System.Management.Automation.ParameterAttribute
        $PTRDName.Mandatory = $false
        $PTRDName.HelpMessage = "The domain name of the DNS PTR record in FQDN format."
        
        $MailExchanger = New-Object System.Management.Automation.ParameterAttribute
        $MailExchanger.Mandatory = $false
        $MailExchanger.HelpMessage = "Mail exchanger name in FQDN format."
        
        $Preference = New-Object System.Management.Automation.ParameterAttribute
        $Preference.Mandatory = $false
        $Preference.HelpMessage = "Preference value, 0 to 65535 (inclusive) in 32-bit unsigned integer format."
        
        $Order = New-Object System.Management.Automation.ParameterAttribute
        $Order.Mandatory = $false
        $Order.HelpMessage = "The order parameter of the NAPTR records. Specifies the order in which NAPTR rules are applied when multiple rules are present (0-65535 inclusive, 32 bit unsigned int)"
        
        $Replacement = New-Object System.Management.Automation.ParameterAttribute
        $Replacement.Mandatory = $false
        $Replacement.HelpMessage = "For nonterminal NAPTR records, this field specifies the next domain name to look up."
        
        $Comment = New-Object System.Management.Automation.ParameterAttribute
        $Comment.Mandatory = $false
        $Comment.HelpMessage = "For nonterminal NAPTR records, this field specifies the next domain name to look up."
        
        $Disable = New-Object System.Management.Automation.ParameterAttribute
        $Disable.Mandatory = $false
        $Disable.HelpMessage = "For nonterminal NAPTR records, this field specifies the next domain name to look up."
        
        #endregion parameter attribute definitions
        
        switch ( $RecordType ) {
            # "A","AAAA","CName","Host","Host_ipv4addr","Host_ipv6addr","LBDN","MX","NAPTR","PTR","SRV","TXT"
            "A"            {
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($ipv4Address)
                $attributeCollection.Add($ipv4ValidatePatternAttribute)
                $ipv4Param = New-Object System.Management.Automation.RuntimeDefinedParameter('IPv4Addr', [string], $attributeCollection)
                $paramDictionary.Add('IPv4Addr', $ipv4Param)
                [void]$DynamicParamList.Add("IPv4Addr")
                
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($HostName)
                $HostNameParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Name', [string], $attributeCollection)
                $paramDictionary.Add('Name', $HostNameParam)
                [void]$DynamicParamList.Add("Name")
                
                <# 
                # TODO:
                $NextAvailableIp = New-Object System.Management.Automation.ParameterAttribute
                $NextAvailableIp.Mandatory = $false
                $NextAvailableIp.HelpMessage = "Determines if the ipv4Address should be the next available address in the network"
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($NextAvailableIp)
                $NextAvailableIpParam = New-Object System.Management.Automation.RuntimeDefinedParameter('UseNextAvailableIp', [switch], $attributeCollection)
                $paramDictionary.Add('UseNextAvailableIp', $NextAvailableIpParam)
                
                    # Examples:
                    # func:nextavailableip:network/ZG54dfgsrDFEFfsfsLzA:10.0.0.0/8/default
                    # func:nextavailableip:10.0.0.0/8
                    # func:nextavailableip:10.0.0.0/8,external
                    # func:nextavailableip:10.0.0.3-10.0.0.10
                    
                    
                #>
            }
            "AAAA"        {
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($ipv6Address)
                $attributeCollection.Add($ipv6ValidatePatternAttribute)
                $ipv6Param = New-Object System.Management.Automation.RuntimeDefinedParameter('IPv6Addr', [string], $attributeCollection)
                $paramDictionary.Add('IPv6Addr', $ipv6Param)
                [void]$DynamicParamList.Add("IPv6Addr")
                
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($HostName)
                $HostNameParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Name', [string], $attributeCollection)
                $paramDictionary.Add('Name', $HostNameParam)
                [void]$DynamicParamList.Add("Name")
            }
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
                $attributeCollection.Add($HostName)
                $HostNameParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Name', [string], $attributeCollection)
                $paramDictionary.Add('Name', $HostNameParam)
                [void]$DynamicParamList.Add("Name")
                
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($Canonical)
                $CanonicalParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Canonical', [string], $attributeCollection)
                $paramDictionary.Add('Canonical', $CanonicalParam)
                [void]$DynamicParamList.Add("Canonical")
            }
            "Host"        {
                <#
                    A host record defines attributes for a node, such as the name-to-address and address-to-name mapping. This alleviates
                    having to specify an A record and a PTR record separately for the same node. A host can also define aliases and DHCP
                    fixed address nodes. The zone must be created first before adding a host record for the zone.
                #>
				$attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $ipv4Address.Mandatory = $false        # set this to false, since IPv6 is allowed too
                $attributeCollection.Add($ipv4Address)
                $attributeCollection.Add($ipv4ValidatePatternAttribute)
                $ipv4Param = New-Object System.Management.Automation.RuntimeDefinedParameter('IPv4Addr', [string], $attributeCollection)
                $paramDictionary.Add('IPv4Addr', $ipv4Param)
                [void]$DynamicParamList.Add("IPv4Addr")
                
				$attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $ipv6Address.Mandatory = $false        # set this to false, since IPv4 is allowed too
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($ipv6Address)
                $attributeCollection.Add($ipv6ValidatePatternAttribute)
                $ipv6Param = New-Object System.Management.Automation.RuntimeDefinedParameter('IPv6Addr', [string], $attributeCollection)
                $paramDictionary.Add('IPv6Addr', $ipv6Param)
                [void]$DynamicParamList.Add("IPv6Addr")
                
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($HostName)
                $HostNameParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Name', [string], $attributeCollection)
                $paramDictionary.Add('Name', $HostNameParam)
                [void]$DynamicParamList.Add("Name")
            }
            "Host_ipv4addr"        {
                #    A Host address in an object used to specify addresses in the record.host object
                $attributeCollection.Add($ipv4Address)
                $attributeCollection.Add($ipv4ValidatePatternAttribute)
                $ipv4Param = New-Object System.Management.Automation.RuntimeDefinedParameter('IPv4Addr', [string], $attributeCollection)
                $paramDictionary.Add('IPv4Addr', $ipv4Param)
                [void]$DynamicParamList.Add("IPv4Addr")
            }
            "Host_ipv6addr"        {
                #    A Host address in an object used to specify addresses in the record.host object
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($ipv6Address)
                $attributeCollection.Add($ipv6ValidatePatternAttribute)
                $ipv6Param = New-Object System.Management.Automation.RuntimeDefinedParameter('IPv6Addr', [string], $attributeCollection)
                $paramDictionary.Add('IPv6Addr', $ipv6Param)
                [void]$DynamicParamList.Add("IPv6Addr")
            }
            "LBDN"        {
                <#
                    A Load Balanced Domain Name Record object
                    Note: no required fields in this object type. Adding optional fields that are not read-only.
                #>
                # not mandatory ever, no need to declare false
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($Comment)
                $CommentParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Comment', [string], $attributeCollection)
                $paramDictionary.Add('Comment', $CommentParam)
                [void]$DynamicParamList.Add("Comment")
                
                # not mandatory ever, no need to declare false
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($Disable)
                $DisableParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Disable', [bool], $attributeCollection)
                $paramDictionary.Add('Disable', $DisableParam)
                [void]$DynamicParamList.Add("Disable")
            }
            "MX"        {
                <#
                    An MX (mail exchanger) record maps a domain name to a mail exchanger. A mail exchanger is a server that either
                    delivers or forwards mail. You can specify one or more mail exchangers for a zone, as well as the preference for 
                    using each mail exchanger. A standard MX record applies to a particular domain or subdomain.
                #>
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($HostName)
                $HostNameParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Name', [string], $attributeCollection)
                $paramDictionary.Add('Name', $HostNameParam)
                [void]$DynamicParamList.Add("Name")
                
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($MailExchanger)
                $MailExchangerParam = New-Object System.Management.Automation.RuntimeDefinedParameter('mail_exchanger', [string], $attributeCollection)
                $paramDictionary.Add('mail_exchanger', $ipv6Param)
                [void]$DynamicParamList.Add("mail_exchanger")
                
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($Preference)
                $PreferenceParam = New-Object System.Management.Automation.RuntimeDefinedParameter('preference', [int], $attributeCollection)
                $paramDictionary.Add('preference', $PreferenceParam)
                [void]$DynamicParamList.Add("preference")
            }
            "NAPTR"        {
                <#
                    a DNS NAPTR object represents a Naming Authority Pointer (NAPTR) resource record. This resource record specifies 
                    a regular expression=based rewrite rule that, when applied to an existing string, produces a new domain name or URI.
                #>
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($HostName)
                $HostNameParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Name', [string], $attributeCollection)
                $paramDictionary.Add('Name', $HostNameParam)
                [void]$DynamicParamList.Add("Name")
                
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($Order)
                $OrderParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Order', [int], $attributeCollection)
                $paramDictionary.Add('Order', $OrderParam)
                [void]$DynamicParamList.Add("Order")
                
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($Preference)
                $PreferenceParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Preference', [int], $attributeCollection)
                $paramDictionary.Add('Preference', $PreferenceParam)
                [void]$DynamicParamList.Add("Preference")
                
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($Replacement)
                $ReplacementParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Replacement', [string], $attributeCollection)
                $paramDictionary.Add('Replacement', $ReplacementParam)
                [void]$DynamicParamList.Add("Replacement")
            }
            "PTR"        {
                <#
                    In a forward-mapping zone, a PTR (pointer) record maps a domain name to another domain name. In a reverse-mapping
                    zone, PTR record maps an address to a domain name. To define a specific addresss-to-name mapping, add a PTR record
                    to a previously defined authoritative reverse-mapping zone.
                #>
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($HostName)
                $HostNameParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Name', [string], $attributeCollection)
                $paramDictionary.Add('Name', $HostNameParam)
                [void]$DynamicParamList.Add("Name")
                
                # records can be ipv6 or ipv4, so we need to set mandatory=$false for this parameter
                $ipv4Address.Mandatory = $false
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($ipv4Address)
                $attributeCollection.Add($ipv4ValidatePatternAttribute)
                $ipv4Param = New-Object System.Management.Automation.RuntimeDefinedParameter('IPv4Addr', [string], $attributeCollection)
                $paramDictionary.Add('IPv4Addr', $ipv4Param)
                [void]$DynamicParamList.Add("IPv4Addr")
                
                $ipv6Address.Mandatory = $false
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($ipv6Address)
                $attributeCollection.Add($ipv6ValidatePatternAttribute)
                $ipv6Param = New-Object System.Management.Automation.RuntimeDefinedParameter('IPv6Addr', [string], $attributeCollection)
                $paramDictionary.Add('IPv6Addr', $ipv6Param)
                [void]$DynamicParamList.Add("IPv6Addr")
                
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($PTRDName)
                $PTRDNameParam = New-Object System.Management.Automation.RuntimeDefinedParameter('PTRDName', [string], $attributeCollection)
                $paramDictionary.Add('PTRDName', $PTRDNameParam)
                [void]$DynamicParamList.Add("PTRDName")
            }
            "SRV"        {
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($HostName)
                $HostNameParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Name', [string], $attributeCollection)
                $paramDictionary.Add('Name', $HostNameParam)
                [void]$DynamicParamList.Add("Name")
                
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($Port)
                $PortParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Port', [int], $attributeCollection)
                $paramDictionary.Add('Port', $PortParam)
                [void]$DynamicParamList.Add("Port")
                
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($Priority)
                $PriorityParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Priority', [int], $attributeCollection)
                $paramDictionary.Add('Priority', $PriorityParam)
                [void]$DynamicParamList.Add("Priority")
                
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($Target)
                $TargetParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Target', [string], $attributeCollection)
                $paramDictionary.Add('Target', $TargetParam)
                [void]$DynamicParamList.Add("Target")
                
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($Weight)
                $WeightParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Weight', [int], $attributeCollection)
                $paramDictionary.Add('Weight', $WeightParam)
                [void]$DynamicParamList.Add("Weight")
            }
            "TXT"        {
                <# 
                    3.127 record:txt : DNS TXT record object.
                    A TXT (text record) record contains supplemental information for a host. For example, if you have a sales server that
                    serves only North America, you can create a text record stating this fact. You can create more than one text record for
                    a domain name.
                #>
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($HostName)
                $HostNameParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Name', [string], $attributeCollection)
                $paramDictionary.Add('Name', $HostNameParam)
                [void]$DynamicParamList.Add("Name")
                
                $attributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
                $attributeCollection.Add($Text)
                $TextParam = New-Object System.Management.Automation.RuntimeDefinedParameter('Text', [string], $attributeCollection)
                $paramDictionary.Add('Text', $TextParam)
                [void]$DynamicParamList.Add("Text")
            }
        }
        
        return $paramDictionary
    }
    
    BEGIN {
		if (-not($PSBoundParameters.ContainsKey("Uri")) ) {
			if ( [string]::IsNullOrEmpty($Uri) -and $PSCmdlet.ParameterSetName -eq "Credential" ) {
				if ([string]::IsNullOrEmpty($IBServer) -or [string]::IsNullOrEmpty($IBVersion) ) {
					throw "Unable to determine Uri for IBServer. Specify Uri, or IBVersion and IBServer."
				}
				$Uri = "https://{0}/wapi/v{1}" -f $IBServer, $IBVersion
			}
		}
		Set-TrustAllCertsPolicy
		$arrays = @("ipv4addr","ipv6addr","aliases")
    }
    
    PROCESS {
        # build Url based on the record type
        $ReqUri = "{0}/{1}" -f $Uri, $Reference
        
        # We need to build the JSON Body from the Dynamic Parameters
        $ParamHash = @{}
        ForEach ( $DynamicParam in $DynamicParamList ) {
            if ( $PSBoundParameters.ContainsKey($DynamicParam) ) {
                # if Host, ip4addr = ipv4addrs array, etc.
				if ( $arrays -contains $DynamicParam -and $RecordType -eq "Host" ) {
					$Parent = "{0}s" -f $DynamicParam.ToLower()
					$SubHash = @{
						$DynamicParam.ToLower() = $PSBoundParameters[$DynamicParam]
					}
					$ParamHash.Add($Parent,[array]$SubHash)  # cast subhash as array, so it has the proper format.
				}
				else {
					$ParamHash.Add($DynamicParam.ToLower(),$PSBoundParameters[$DynamicParam])
				}
            }
        }
        
        $JSON = $ParamHash | ConvertTo-Json
        if ($PSCmdlet.ParameterSetName -eq "Credential" ) {
			$IRMParams = @{
				Uri = $ReqUri
				Method = 'Put'
				Credential = $Credential
				Body = $JSON
				ContentType = "application/json"
			}
		}
		else {
			$IRMParams = @{
				Uri = $ReqUri
				Method = 'Put'
				WebSession = $IBSession
				Body = $JSON
				ContentType = "application/json"
			}
		}

		$UsingParameterSet = "Using {0}" -f $PSCmdlet.ParameterSetName
        Write-Verbose $UsingParameterSet
        Write-Verbose $ReqUri
		Write-Verbose $JSON
        
        try {
            $TempResult = Invoke-RestMethod @IRMParams
        }
        catch {
            Throw "Error retrieving record: $_"
        }
        

        
        if ( $PassThru ) {
            $TempResult | Add-Member -Type NoteProperty -Name IBSession -Value $IBSession
        }
        else {
            $TempResult
        }
    }
    
    END {}
}