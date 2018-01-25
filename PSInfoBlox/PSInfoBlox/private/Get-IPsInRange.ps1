function ConvertFrom-IPToInt64 () { 
	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)]
		[string]
		$ip
	) 
	
	PROCESS {
		$octets = $ip.split(".") 
		[int64]([int64]$octets[0]*16777216 +[int64]$octets[1]*65536 +[int64]$octets[2]*256 +[int64]$octets[3])
	}
} 
 
function ConvertFrom-Int64ToIP() { 
  [CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)]
		[int64]
		$int
	) 
	PROCESS {
		(([math]::truncate($int/16777216)).tostring()+"."+([math]::truncate(($int%16777216)/65536)).tostring()+"."+([math]::truncate(($int%65536)/256)).tostring()+"."+([math]::truncate($int%256)).tostring() )
		# ([ipaddress]$int).IPAddressToString
	}
}

Function Get-IPsInRange {
	[CmdletBinding(DefaultParameterSetName="IPAddress")]
	PARAM (
		[Parameter(ParameterSetName="IPAddress",Mandatory=$True)]
		[string]
		$IPAddress,
		
		[Parameter(ParameterSetName="IPAddress",Mandatory=$False)]
		[string]
		$Mask,
		
		[Parameter(ParameterSetName="StartEnd",Mandatory=$True)]
		[string]
		$Start,
		
		[Parameter(ParameterSetName="StartEnd",Mandatory=$True)]
		[string]
		$End
	)
	
	BEGIN {
		# Pure IPv4 Address
		$IPv4Regex = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
		$RangeRegex = "({0})-({1})" -f $IPv4Regex.Replace('$',''), $IPv4Regex.Replace('^','')
		if ($IPAddress -match $IPv4Regex) {
			# IP is Fine as is
		} #if
		elseif ($IPAddress -match "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))$") {
			# IP Address with CIDR block
			$cidr = $matches[5]
			# Write-Host "Cidr is $cidr"
			$temp = $IPAddress -match "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
			$IPAddress = $matches[0]
			# Write-Host "IP is $IPAddress"
		} #elseif
		elseif ($IPAddress -match $RangeRegex) {
			$startaddr = ConvertFrom-IPToInt64 -ip $matches[1]
			$endaddr = ConvertFrom-IPToInt64 -ip $matches[5]
		} #elseif
	} #BEGIN
	
	PROCESS {
		if ( [string]::IsNullOrEmpty($startaddr) -or [string]::IsNullOrEmpty($endaddr) ) {
			if ($PSBoundParameters.ContainsKey("IPAddress")) {
				$ipaddr = [Net.IPAddress]::Parse($IPAddress)
			} #if
			
			if ($PSBoundParameters.ContainsKey("mask")) {
				$maskaddr = [Net.IPAddress]::Parse($mask)
			} #if
			elseif (-Not([string]::IsNullOrEmpty($CIDR))) {
				$maskaddr = [Net.IPAddress]::Parse((ConvertFrom-Int64ToIP -int ([convert]::ToInt64(("1"*$cidr+"0"*(32-$cidr)),2))))
			} #elseif
			else {
				$mask = "255.255.255.255"
				$maskaddr = [Net.IPAddress]::Parse($mask)
			} #else
			
			if ($PSBoundParameters.ContainsKey("IPAddress")) {
				$networkaddr = new-object net.ipaddress ($maskaddr.address -band $ipaddr.address)
			} #if
			
			if ($PSBoundParameters.ContainsKey("IPAddress")) {
				$broadcastaddr = new-object net.ipaddress (([system.net.ipaddress]::parse("255.255.255.255").address -bxor $maskaddr.address -bor $networkaddr.address))
			} #if
			 
			if ($PSBoundParameters.ContainsKey("IPAddress")) { 
				$startaddr = ConvertFrom-IPToInt64 -ip $networkaddr.ipaddresstostring 
				$endaddr = ConvertFrom-IPToInt64 -ip $broadcastaddr.ipaddresstostring 
			} #if
			else { 
				$startaddr = ConvertFrom-IPToInt64 -ip $start 
				$endaddr = ConvertFrom-IPToInt64 -ip $end 
			} #else
		} #if
		 
		for ($i = $startaddr; $i -le $endaddr; $i++) { 
			ConvertFrom-Int64ToIP -int $i 
		} # for
	}
}