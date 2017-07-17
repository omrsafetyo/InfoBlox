#requires -version 3.0
#requires -module ActiveDirectory

Function Get-WmiDNSZone  {
	[CmdletBinding()]
	PARAM (
		[Parameter()]
		[string]
		$Computername = $ENV:COMPUTERNAME,
		
		[Parameter()]
		[string[]]
		$ZoneName,
		
		$Credential
	)
	
	BEGIN {
		# https://learn-powershell.net/2013/08/03/quick-hits-set-the-default-property-display-in-powershell-on-custom-objects/
		# http://blogs.microsoft.co.il/scriptfanatic/2012/04/13/custom-objects-default-display-in-powershell-30/
		$defaultDisplaySet = 'ZoneName','ZoneType','IsAutoCreated','IsDsIntegrated','IsReverseLookupZone','IsSigned'
		$defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet',[string[]]$defaultDisplaySet)
		$PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)
	}
	
	PROCESS {
		$param = @{}
		ForEach ($Parameter in $PSBoundParameters.Keys) {
			if ( $Parameter -eq "ZoneName" ) {continue}
			[void]$param.Add($Parameter,$PSBoundParameters.Item($Parameter))
		}
		
		$ScriptBlock = [scriptblock]::Create("Get-WmiObject -Namespace root\MicrosoftDNS -Class MicrosoftDNS_Zone")
		[void]$param.Add("ScriptBlock",$ScriptBlock)
		try {
			$ZoneInfo = Invoke-Command @param -ErrorAction Stop
		}
		catch [System.Management.Automation.Remoting.PSRemotingTransportException]{
			Write-Host "System.Management.Automation.Remoting.PSRemotingTransportException encountered.  You may need to enable WSManCredSSP" -foregroundcolor Yellow
			Write-Host "Try running the following.  On the client (where you run the script):" -foregroundcolor Yellow
			Write-Host "Enable-WSManCredSSP -Role Client -DelegateComputer $Computername" -foregroundcolor Green
			Write-Host "Set-Item wsman:localhost\client\trustedhosts -value $Computername" -foregroundcolor Green
			Write-Host "On the server ($Computername):" -foregroundcolor Yellow
			Write-Host "Enable-WSManCredSSP -Role Server" -foregroundcolor Green
			Throw $_
		}
		
		if ( $PSBoundParameters.ContainsKey("ZoneName") ) {
			$ZoneInfo = $ZoneInfo | Where-Object {$ZoneName -contains $_.Name}
		}
		# https://msdn.microsoft.com/en-us/library/windows/desktop/ms682757(v=vs.85).aspx
		switch($ZoneInfo.ZoneType) {
			0 {$ZoneType = "Integrated"}
			1 {$ZoneType = "Primary"}
			2 {$ZoneType = "Secondary"}
			3 {$ZoneType = "Stub"}
			3 {$ZoneType = "Forwarder"}
			default {$ZoneType = "Unknown"}
		}
		
		switch($zoneInfo.Notify) {
			0 {$Notify = "DoNotNotify"}
			1 {$Notify = "NotifyNameServers"}
			2 {$Notify = "Notify"}
			default {$Notify = "Unknown"}
		}
		
		switch ($ZoneInfo.SecureSecondaries) {
			0 {$SecureSecondaries = "TransferToAnyHost"}
			1 {$SecureSecondaries = "TransferToNameServers"}
			2 {$SecureSecondaries = "TransferToSecondaryServers"}
			3 { $SecureSecondaries = "TransferToSecureServers"}
			default {$SecureSecondaries = "Unknown"}
		}
		$OutputObject = [PSCustomObject] @{
			NotifyServers						=	$ZoneInfo.NotifyServers
			SecondaryServers					=	$ZoneInfo.SecondaryServers
			AllowedDcForNsRecordsAutoCreation	=	""
			DistinguishedName					=	""	#Cim path
			IsAutoCreated						=	$ZoneInfo.AutoCreated
			IsDsIntegrated						=	$ZoneInfo.DsIntegrated
			IsPaused							=	$ZoneInfo.Paused
			IsReadOnly							=	""
			IsReverseLookupZone					=	$ZoneInfo.Reverse
			IsShutdown							=	$ZoneInfo.Shutdown
			ZoneName							=	$ZoneInfo.Name
			ZoneType							=	$ZoneType
			DirectoryPartitionName				=	""
			DynamicUpdate						=	""
			IsPluginEnabled						=	""
			IsSigned							=	""
			IsWinsEnabled						=	$ZoneInfo.UseWins
			Notify								=	$Notify
			ReplicationScope					=	""
			SecureSecondaries					=	$SecureSecondaries
			ZoneFile							=	$ZoneInfo.DataFile
			PSComputerName						= 	$Computername
		}
		
		$OutputObject.PSObject.TypeNames.Insert(0,"DNS.Information")
		$OutputObject | Add-Member MemberSet PSStandardMembers $PSStandardMembers
		$OutputObject
	}
}

Function Get-WmiDNSResourceRecordSet  {
	[CmdletBinding()]
	PARAM (
		[Parameter()]
		[string]
		$Computername = $ENV:COMPUTERNAME,
		
		[Parameter(Mandatory=$False)]
		[string]
		$ZoneName,
		
		[Parameter(Mandatory=$True)]
		[string]
		[Alias("RRType","Type")]
		[ValidateSet("MG","X25","AFSDB","PTR","KEY","SRV","MD","MB","AAAA","ISDN","MINFO","RP","SIG","MF","A","WKS","WINSR","SOA","MX","WINS","ATMA","NS","NXT","RT","CNAME","TXT","HINFO","MR")]
		$RecordType = 'A',
		
		$Credential
	)
	
	BEGIN {
		# https://learn-powershell.net/2013/08/03/quick-hits-set-the-default-property-display-in-powershell-on-custom-objects/
		# http://blogs.microsoft.co.il/scriptfanatic/2012/04/13/custom-objects-default-display-in-powershell-30/
		$defaultDisplaySet = 'Name','HostName','RecordType','Timestamp','TimeToLive','RecordData'
		$defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet',[string[]]$defaultDisplaySet)
		$PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)
	}
	
	PROCESS {
		$WmiQuery = "Get-WmiObject -Namespace root\MicrosoftDNS -Class MicrosoftDNS_{0}Type" -f $RecordType
		if ( $PSBoundParameters.ContainsKey("ZoneName") ) {
			$WmiQuery = '{0} -Filter "ContainerName = {2}{1}{2}"' -f $WmiQuery, $ZoneName, "'"
		}
		
		$ScriptBlock = [scriptBlock]::Create($WmiQuery)
		$param = @{}
		ForEach ($Parameter in $PSBoundParameters.Keys) {
			if ( $Parameter -eq "ZoneName" -or $Parameter -eq "RecordType") {continue}
			[void]$param.Add($Parameter,$PSBoundParameters.Item($Parameter))
		}
		[void]$param.Add("ScriptBlock",$ScriptBlock)
		
		try {
			$ResourceRecordSet = Invoke-Command @param -ErrorAction Stop
		}
		catch [System.Management.Automation.Remoting.PSRemotingTransportException]{
			Write-Host "System.Management.Automation.Remoting.PSRemotingTransportException encountered.  You may need to enable WSManCredSSP" -foregroundcolor Yellow
			Write-Host "Try running the following.  On the client (where you run the script):" -foregroundcolor Yellow
			Write-Host "Enable-WSManCredSSP -Role Client -DelegateComputer $Computername" -foregroundcolor Green
			Write-Host "Set-Item wsman:localhost\client\trustedhosts -value $Computername" -foregroundcolor Green
			Write-Host "On the server ($Computername):" -foregroundcolor Yellow
			Write-Host "Enable-WSManCredSSP -Role Server" -foregroundcolor Green
			Throw $_
		}
		
		ForEach ($ResourceRecord in $ResourceRecordSet) {
			# https://msdn.microsoft.com/en-us/library/windows/desktop/ms682713(v=vs.85).aspx
			switch ($ResourceRecord.RecordClass) {
				1 {$RecordClass = "IN"}
				2 {$RecordClass = "CS"}
				3 {$RecordClass = "CH"}
				4 {$RecordClass = "HS"}
				default {$RecordClass = "IN"}
			}
			$OutputObject = [PSCustomObject] @{
				DistinguishedName	=	""
				Name				=	$ResourceRecord.OwnerName
				HostName			=	$ResourceRecord.OwnerName.Split(".")[0]
				RecordClass			=	$RecordClass
				RecordData			=	$ResourceRecord.RecordData
				RecordType			=	$RecordType
				Timestamp			=	([datetime]"1.1.1601").AddHours($ResourceRecord.TimeStamp)
				TimeToLive			=	$ResourceRecord.TTL
				PSComputerName		=	$Computername
			}
		
			$OutputObject.PSObject.TypeNames.Insert(0,"DNS.Information")
			$OutputObject | Add-Member MemberSet PSStandardMembers $PSStandardMembers
			$OutputObject
			
		}
	}
}

Function Get-WmiDNSAdapterSettings {
[CmdletBinding()]
PARAM (
		[Parameter(Mandatory=$False)]
		[string]
		$Computername = $ENV:COMPUTERNAME,
		
		[Parameter(Mandatory=$False)]
		$Credential
	)
	BEGIN {
		$defaultDisplaySet = 'Name','InterfaceDescription','Index','Timestamp','TimeToLive','RecordData'
		$defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet',[string[]]$defaultDisplaySet)
		$PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)
	}
	
	PROCESS {
		$param = @{
			Class = "Win32_NetworkAdapterConfiguration"
			Filter = "ipenabled = 'true'"
		}
		
		ForEach ($Parameter in $PSBoundParameters.Keys) {
			[void]$param.Add($Parameter,$PSBoundParameters.Item($Parameter))
		}
		
		$AdapterConfigs = Get-WmiObject @param
		
		$param.Class = "Win32_NetworkAdapter"
		
		# $Adapters = Get-WmiObject @param
		
		ForEach ( $AdapterConfig in $AdapterConfigs ) {
			$Index = $AdapterConfig.InterfaceIndex
			$param.Filter = "InterfaceIndex = $Index"
			# $Adapter = $Adapters | Where-Object { $_.InterfaceIndex -eq  }
			$Adapter = Get-WmiObject @param
			$AdapterConfig | Add-Member -NotePropertyName Name -NotePropertyValue $Adapter.NetConnectionID
			$AdapterConfig | Add-Member -NotePropertyName InterfaceDescription -NotePropertyValue $Adapter.Description
			$AdapterConfig | Add-Member -NotePropertyName ifIndex -NotePropertyValue $Adapter.InterfaceIndex
			$AdapterConfig | Add-Member -NotePropertyName MediaType -NotePropertyValue $Adapter.AdapterType
			$AdapterConfig
		}
	}
	
	END {}
}

Function Get-WmiDNSNetworkAdapterSettings {
    [CmdletBinding()]
    PARAM(
		[Parameter(Mandatory=$False)]
		[string[]]
		$Computername
	)

    BEGIN {
        Import-Module $PSScriptRoot\TestConnectionAsync.psm1
    }

    PROCESS {
		$OutputResults = New-Object System.Collections.ArrayList
        Write-Verbose "Retrieving AD Computer list"
		if ( $PSBoundParameters.ContainsKey("Computername")) {
			$ADComputers = $Computername
		}
		else {
			$ADComputers = Get-ADComputer -Properties LastLogonDate, IPv4Address, OperatingSystem, ServicePrincipalName -Filter * | Where-Object {
				$_.ServicePrincipalName -notmatch "MSClusterVirtualServer" -and -NOT([string]::IsNullOrEmpty($_.IPv4Address)) -and $_.OperatingSystem -match "Windows"
			} | Select-Object -expandproperty Name 
        }
        $ScriptBlock = {
            $NetAdapterConfig = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "ipenabled = 'true'"
            ForEach ( $Adapter in $NetAdapterConfig ) {
                [PSCustomObject] @{
                    Computername         = $ENV:COMPUTERNAME
                    IPAddress            = $Adapter.IPAddress
                    DefaultIPGateway     = $Adapter.DefaultIPGateway
                    DNSServerSearchOrder = $Adapter.DNSServerSearchOrder
                    Description          = $Adapter.Description
                    Index                = $Adapter.Index
                    SuccessStage         = 1
                    Error                = ""
                }
            }
        }
        $msg = "Running initial pass.  {0} computers to scan." -f $ADComputers.Count
        Write-Verbose $msg
		
		# This returns a deserialized hashtable
        $Results = Invoke-Command -Computername $ADComputers -ScriptBlock $ScriptBlock -ErrorAction SilentlyContinue
        
        $RetryComputers = $ADComputers | Where-Object { ($Results | Select-Object -ExpandProperty PSComputerName) -notcontains $_ }
		
		# Convert the deserialized hashtable back into an object
		ForEach ( $item in $Results) {
			$Output = [PSCustomObject] @{
				Computername         = $item.Computername
				IPAddress            = $item.IPAddress
				DefaultIPGateway     = $item.DefaultIPGateway
				DNSServerSearchOrder = $item.DNSServerSearchOrder
				Description          = $item.Description
				Index                = $item.Index
				SuccessStage         = $item.SuccessStage
				Error                = $item.Error
			}
			#Add the results to our output array
			[void]$OutputResults.Add($Output)
		}
        
        $msg = "Checking {0} failed computers to re-scan." -f $RetryComputers.Count
        Write-Verbose $msg
        
        $RetryResults = Test-ConnectionAsync -ComputerName $RetryComputers -Quiet
        ForEach ( $RetryComputer in $RetryResults ) {
            if ( $RetryComputer.Success -eq $True ) {
                $Computer = $RetryComputer.ComputerName
                Write-Verbose "Retrying $Computer"
                try {
                    $NetAdapterConfig = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "ipenabled = 'true'" -ComputerName $Computer -ErrorAction Stop
                    ForEach ( $Adapter in $NetAdapterConfig ) {
                        $Output = [PSCustomObject] @{
                            Computername          = $Computer
                            IPAddress             = $Adapter.IPAddress
                            DefaultIPGateway      = $Adapter.DefaultIPGateway
                            DNSServerSearchOrder  = $Adapter.DNSServerSearchOrder
                            Description           = $Adapter.Description
                            Index                 = $Adapter.Index
                            SuccessStage          = 2
                            Error                 = ""
                        }
                        [void]$OutputResults.Add($Output)
                    }
                }
                catch {
                    $ErrorMessage = $_.Exception.Message
                    $Output = [PSCustomObject] @{
                        Computername          = $Computer
                        IPAddress             = ""
                        DefaultIPGateway      = ""
                        DNSServerSearchOrder  = ""
                        Description           = ""
                        Index                 = ""
                        SuccessStage          = 0
                        Error                 = "Failed WMI connection - $ErrorMessage"
                    }
                    [void]$OutputResults.Add($Output)
                }
            }
            else {
                $Output = [PSCustomObject] @{
                    Computername          = $Computer
                    IPAddress             = ""
                    DefaultIPGateway      = ""
                    DNSServerSearchOrder  = ""
                    Description           = ""
                    Index                 = ""
                    SuccessStage          = 0
                    Error                 = "Failed ping to $Computer"
                }
                [void]$OutputResults.Add($Output)
            }
        }
        $OutputResults
    }

    END {}
}

Function Set-WmiDNSNetworkAdapterDNSSearchOrder {
    [CmdletBinding()]
    PARAM(
		[Parameter(Mandatory=$False)]
		[string[]]
		$Computername,
		
		[Parameter(Mandatory=$True)]
		[string[]]
		$SearchOrder,
		
		[Parameter(Mandatory=$False)]
		[string[]]
		$ReplaceSearchOrder
	)

    BEGIN {
        Import-Module $PSScriptRoot\TestConnectionAsync.psm1
    }

    PROCESS {
		$OutputResults = New-Object System.Collections.ArrayList
        Write-Verbose "Retrieving AD Computer list"
		if ( $PSBoundParameters.ContainsKey("Computername")) {
			$ADComputers = $Computername
		}
		else {
			$ADComputers = Get-ADComputer -Properties LastLogonDate, IPv4Address, OperatingSystem, ServicePrincipalName -Filter * | Where-Object {
				$_.ServicePrincipalName -notmatch "MSClusterVirtualServer" -and -NOT([string]::IsNullOrEmpty($_.IPv4Address)) -and $_.OperatingSystem -match "Windows"
			} | Select-Object -expandproperty Name 
		}
		
		$SearchOrderString = $(($SearchOrder -Join ",") -replace ",", '","')
		$SearchOrderString = '@("{0}")' -f $SearchOrderString
		
		$sbText = @'
	$NetAdapterConfig = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "ipenabled = 'true'"
	ForEach ( $Adapter in $NetAdapterConfig ) {
		$DNSSearchOrder = $Adapter.DNSServerSearchOrder
		$AdapterIndex = $Adapter.Index
		
'@
		if ( $PSBoundParameters.ContainsKey("ReplaceSearchOrder") ) {
			$ReplaceDNSString = $(($ReplaceSearchOrder -Join ",") -replace ",", '","')
			$sbText += 'ForEach ( $DNSServer in @({0}{1}{2}) ) {3}{4}' -f '"', $ReplaceDNSString, '"', '{', "`n"
			$sbText += '			if ( $DNSSearchOrder -contains $DNSServer ) {0}{1}' -f "{","`n"
			$sbText += '				$Adapter.SetDnsServerSearchOrder({0}){1}' -f $SearchOrderString, "`n"
			$sbText += '				break{0}' -f "`n"
			$sbText += '			{0}{1}' -f "}","`n"
			$sbText += '		{0}{1}' -f "}","`n"
		}
		else {
			$sbText += '$Adapter.SetDnsServerSearchOrder({0})' -f $SearchOrderString
		}
		
		$sbText += @'
		
		$NewConfig = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "Index = $AdapterIndex"
		[PSCustomObject] @{
			Computername         = $ENV:COMPUTERNAME
			IPAddress            = $Adapter.IPAddress
			DNSServerSearchOrder = $NewConfig.DNSServerSearchOrder
			OldDNSServerSearchOrder = $DNSSearchOrder
			Description          = $Adapter.Description
			Index                = $Adapter.Index
			SuccessStage         = 1
			Error                = ""
		}
		Get-Service Netlogon | Restart-Service
	}
		
'@

		Write-Verbose $sbText
        $ScriptBlock = [ScriptBlock]::Create($sbText)
        $msg = "Running initial pass.  {0} computers to scan." -f $ADComputers.Count
        Write-Verbose $msg
		
		# This returns a deserialized hashtable
        $Results = Invoke-Command -Computername $ADComputers -ScriptBlock $ScriptBlock -ErrorAction SilentlyContinue 
        $RetryComputers = @($ADComputers | Where-Object { ($Results | Select-Object -ExpandProperty PSComputerName) -notcontains $_ })
		
		# $Results
		
		# Convert the deserialized hashtable back into an object
		ForEach ( $item in $Results) {
			if ( $null -eq $item.Computername ) {continue}
			Write-verbose "Deserializing item..."
			$Output = [PSCustomObject] @{
				Computername         = $item.Computername
				IPAddress            = $item.IPAddress
				DNSServerSearchOrder = $item.DNSServerSearchOrder
				OldDNSServerSearchOrder = $item.OldDNSServerSearchOrder
				Description          = $item.Description
				Index                = $item.Index
				SuccessStage         = $item.SuccessStage
				Error                = $item.Error
			}
			#Add the results to our output array
			[void]$OutputResults.Add($Output)
		}

		#
		# Invoke-Command won't always work.  This requires PSRemoting to be enabled, and the user to have permissions. 
		# So just in case, we've keep track of all the computers where Invoke-Command failed.  For those computers,
		# we will try again using remote-WMI.
		#
        
        $msg = "Checking {0} failed computers to re-scan." -f $RetryComputers.Count
        Write-Verbose $msg

		# 
		# First, ping the computers Async.  We'll only try to hit WMI on computers we can ping.
		#
        if ( $RetryComputers.Count -gt 0 ) {
			$RetryResults = Test-ConnectionAsync -ComputerName $RetryComputers -Quiet
		}
		else {
			$RetryResults = $null
		}
        ForEach ( $RetryComputer in $RetryResults ) {
            if ( $RetryComputer.Success -eq $True ) {
                $Computer = $RetryComputer.ComputerName
                Write-Verbose "Retrying $Computer"
                try {
                    $NetAdapterConfig = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "ipenabled = 'true'" -Computername $Computer
					ForEach ( $Adapter in $NetAdapterConfig ) {
						$DNSSearchOrder = $Adapter.DNSServerSearchOrder
						$AdapterIndex = $Adapter.Index
						if ($PSBoundParameters.ContainsKey("ReplaceSearchOrder") ) {
							ForEach ( $DNSServer in $ReplaceSearchOrder) {
								if ( $DNSSearchOrder -contains $DNSServer ) {
									$Adapter.SetDnsServerSearchOrder($SearchOrderString)
									break
								}
							}
						}
						else {
							$Adapter.SetDnsServerSearchOrder($SearchOrderString)
						}

						$NewConfig = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "Index = $AdapterIndex" -Computername $Computer
						[PSCustomObject] @{
								Computername         = $ENV:COMPUTERNAME
								IPAddress            = $Adapter.IPAddress
								DNSServerSearchOrder = $NewConfig.DNSServerSearchOrder
								OldDNSServerSearchOrder = $DNSSearchOrder
								Description          = $Adapter.Description
								Index                = $Adapter.Index
								SuccessStage         = 1
								Error                = ""
						}
						$svc = Get-Service Netlogon -Computername $Computer
						Restart-Service -InputObject $svc
                        [void]$OutputResults.Add($Output)
						Write-Verbose "Completed $Computer with success."
                    }
                }
                catch {
                    $ErrorMessage = $_.Exception.Message
                    $Output = [PSCustomObject] @{
                        Computername          = $Computer
                        IPAddress             = ""
                        DNSServerSearchOrder  = ""
						OldDNSServerSearchOrder = ""
                        Description           = ""
                        Index                 = ""
                        SuccessStage          = 0
                        Error                 = "Failed WMI connection - $ErrorMessage"
                    }
                    [void]$OutputResults.Add($Output)
					Write-Verbose "Failed to connect to WMI on $Computer"
                }
            }
            else {
                $Output = [PSCustomObject] @{
                    Computername          = $Computer
                    IPAddress             = ""
                    DNSServerSearchOrder  = ""
					OldDNSServerSearchOrder = ""
                    Description           = ""
                    Index                 = ""
                    SuccessStage          = 0
                    Error                 = "Failed ping to $Computer"
                }
                [void]$OutputResults.Add($Output)
				Write-Verbose "Failed ping to $Computer"
            }
			
        }
        $OutputResults
    }

    END {}
}	# Set-NetworkAdapterDNSSearchOrder


Export-ModuleMember -Function Get-WmiDNSZone
Export-ModuleMember -Function Get-WmiDNSResourceRecordSet
Export-ModuleMember -Function Get-WmiDNSAdapterSettings
Export-ModuleMember -Function Get-WmiDNSNetworkAdapterSettings
Export-ModuleMember -Function Set-WmiDNSNetworkAdapterDNSSearchOrder