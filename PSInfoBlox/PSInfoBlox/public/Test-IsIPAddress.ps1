#
# Test_IsIPAddress.ps1
#

Function Test-IsIPAddress {
	param(
		[Parameter(Mandatory=$True)]
		[string]
		$InputString
	)
	BEGIN {}
	PROCESS {
		try {
		   $Check = [ipaddress]::Parse($inputString)
		   return $true
		}
		catch {
		   return $false
		}
	}
	END {}
}