#requires -version 3.0
#requires -modules PSInfoBlox
<#
	.EXAMPLE
	$IBCred = Get-Credential
	Import-Module DnsServer
	$DatacenterResourceRecords = Get-DnsServerResourceRecord -ZoneName myzone.local -RRType A -ComputerName DC01
	$DatacenterResourceRecords | % {
		$_ | Add-Member -MemberType Noteproperty -Name Name -Value $("{0}.{1}" -f $_.HostName, "myzone.local")
	}
	
	Compare-DNSZoneToInfoBlox -ResourceRecordSet $DatacenterResourceRecords -InfoBloxServer $IBServer -InfoBloxCredential $IBCred -ZoneName myzone.local

#>
[CmdletBinding()]
param(
	[Parameter(Mandatory=$True)]
	[PSObject[]]
	$ResourceRecordSet,
	
	[Parameter(Mandatory=$True)]
	[string]
	$InfoBloxServer,
	
	[Parameter(Mandatory=$True)]
	[string]
	$ZoneName,
	
	[Parameter(Mandatory=$True)]
	$InfoBloxCredential
)

BEGIN {
	$RecordTypes = $ResourceRecordSet[0].RecordType
	if ( $RecordTypes -eq "A" ) {
		$RecordTypes = @("A","Host")
	}
	
	$PropertyNames = $ResourceRecordSet[0] | Get-Member | Where-Object { $_.MemberType -eq "Property" -or $_.MemberType -eq "NoteProperty" } | Select-Object -ExpandProperty Name
	if (-NOT($PropertyNames -contains "Name")) {
		$ResourceRecordSet | ForEach-Object {
			$_ | Add-Member -MemberType Noteproperty -Name Name -Value $("{0}.{1}" -f $_.HostName, $ZoneName)
		}
	}
}

PROCESS {
	$RecordsToCheck = $ResourceRecordSet | Where-Object { -not( @('ForestDnsZones','DomainDnsZones',$ZoneName) -contains $_.HostName)}
	$IBSession = New-InfoBloxSession -IBServer $InfoBloxServer -Credential $InfoBloxCredential
	
	$IBResourceRecords = New-Object System.Collections.ArrayList
	
	ForEach ( $RecordType in $RecordTypes ) {
		$IBRR = Get-InfoBloxResourceRecordSet -RecordType $RecordType -SearchField name -like $ZoneName -Verbose
		if ( $IBRR.Count -gt 1 ) {
			[void]$IBResourceRecords.AddRange($IBRR)
		}
		elseif ( $IBRR.Count -eq 1 ) {
			[void]$IBResourceRecords.Add($IBRR)
		}
	}
	
	ForEach ( $ResourceRecord in $RecordsToCheck ) {
		$ReturnObject = [PSCustomObject] @{
			Name = $ResourceRecord.Name
			SourceRecordData = ""
			IBRecordData = ""
			Found = $False
			IPMatch = $False
		}
		switch ($RecordType) {
			"A" 	{
				if ( $ResourceRecord.GetType().Name -eq "CimInstance" ) {
					# DNSServer module object
					$ReturnObject.SourceRecordData = $ResourceRecord.RecordData.IPv4Address.IPAddressToString 
				}
				else {
					# WMIDNSServer object
					$ReturnObject.SourceRecordData = $ResourceRecord.RecordData
				}
			}
			"Host" 	{ 
				if ( $ResourceRecord.GetType().Name -eq "CimInstance" ) {
					$ReturnObject.SourceRecordData = $ResourceRecord.RecordData.IPv4Address.IPAddressToString 
				}
				else {
					$ReturnObject.SourceRecordData = $ResourceRecord.RecordData
				}
			}
			"CNAME"	{ 
				if ( $ResourceRecord.GetType().Name -eq "CimInstance" ) {
					$ReturnObject.SourceRecordData = $ResourceRecord.RecordData.HostNameAlias 
				}
				else {
					$ReturnObject.SourceRecordData = $ResourceRecord.RecordData
				}
			}
		}
		$IBResourceRecord = $IBResourceRecords | Where-Object { $_.Name -eq $ResourceRecord.Name }
		if ( $null -ne $IBResourceRecord ) {
			$ReturnObject.Found = $True
			ForEach ( $Record in $IBResourceRecord ) {
				switch ($RecordType) {
					"A" 	{$ReturnObject.IBRecordData = ($IBResourceRecord.ipv4addrs.ipv4addr)}
					"Host" 	{$ReturnObject.IBRecordData = ($IBResourceRecord.ipv4addrs.ipv4addr)}
					"CNAME" {$ReturnObject.IBRecordData = ($IBResourceRecord.name)}
				}
				if ( $ReturnObject.IBRecordData -is [array] -and $ReturnObject.IBRecordData -contains $ReturnObject.SourceRecordData ) {
					$ReturnObject.IBRecordData = $ReturnObject.IBRecordData | Where-Object { $_ -match $ReturnObject.SourceRecordData }
					$ReturnObject.IPMatch = $True
				}
				elseif ( $ReturnObject.IBRecordData -is [array]) {
					$ReturnObject.IBRecordData = ($ReturnObject.IBRecordData -join ",")
				}
				elseif ($ReturnObject.IBRecordData -is [string] -and $ReturnObject.IBRecordData -eq $ReturnObject.SourceRecordData) {
					$ReturnObject.IPMatch = $True
				}
				$ReturnObject
			}
		}
		else {
			$ReturnObject
		}
	}
}

END {}