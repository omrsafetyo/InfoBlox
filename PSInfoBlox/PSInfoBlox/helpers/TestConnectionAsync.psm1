#requires -Version 2

function Test-ConnectionAsync
{    
    <# 
    .Synopsis 
       Proxy function for Test-Connection that pings multiple hosts at a time. 
    .DESCRIPTION 
       Proxy function for Test-Connection that pings multiple hosts at a time, using the -AsJob parameter of Test-Connection. The Test-Connection cmdlet performs these jobs in multiple threads of a single process, unlike Start-Job. 
    .PARAMETER MaxConcurrent 
       Specifies the maximum number of Test-Connection commands to run at a time. 
    .EXAMPLE 
       Get-Content .\IPAddresses.txt | Test-ConnectionAsync -MaxConcurrent 250 -Quiet 
 
       Pings the devices listed in the IPAddresses.txt file, up to 250 at a time. 
    .INPUTS 
       Either an array of strings, or of objects containing a property named one of: 
       ComputerName, CN, IPAddress, __SERVER, Server, or Destination. 
    .OUTPUTS 
       If the -Quiet parameter is not specified, the function outputs a collection of Win32_PingStatus objects, one for each ping result. 
    
       If the -Quiet parameter is specified, the function outputs a collection of PSCustomObjects containing the properties "ComputerName" (a string with the address that was pinged) and "Success" (a boolean value indicating whether the computer responded to at least one ping successfully). 
    .NOTES 
       If found, this function makes use of Get-CallerPreference from http://gallery.technet.microsoft.com/Inherit-Preference-82343b9d . This can be useful if you want to place Test-ConnectionAsync in a Script Module (psm1 file), and have it behave according to the caller's settings for variables like $ErrorActionPreference. 
       Other than the MaxConcurrent and Quiet parameters, all other parameters behave identically to the Test-Connection cmdlet; refer to its help file for more details. 
       Unlike Test-Connection, Test-ConnectionAsync does not have an AsJob parameter. 
    .LINK 
       Test-Connection 
    #>
    
    [CmdletBinding(DefaultParameterSetName='Default')]
    param(
        [System.Management.AuthenticationLevel]
        ${Authentication},

        [Alias('Size','Bytes','BS')]
        [ValidateRange(0, 65500)]
        [System.Int32]
        ${BufferSize},

        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('CN','IPAddress','__SERVER','Server','Destination')]
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        ${ComputerName},

        [ValidateRange(1, 4294967295)]
        [System.Int32]
        ${Count},

        [Parameter(ParameterSetName='Source')]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        ${Credential},

        [Parameter(ParameterSetName='Source', Mandatory=$true, Position=1)]
        [Alias('FCN','SRC')]
        [ValidateNotNullOrEmpty()]
        [System.String[]]
        ${Source},

        [System.Management.ImpersonationLevel]
        ${Impersonation},

        [Parameter(ParameterSetName='Default')]
        [Parameter(ParameterSetName='Source')]
        [ValidateRange(-2147483648, 1000)]
        [System.Int32]
        ${ThrottleLimit},

        [Alias('TTL')]
        [ValidateRange(1, 255)]
        [System.Int32]
        ${TimeToLive},

        [ValidateRange(1, 60)]
        [System.Int32]
        ${Delay},

        [ValidateScript({$_ -ge 1})]
        [System.UInt32]
        $MaxConcurrent = 20,

        [Parameter(ParameterSetName='Quiet')]
        [Switch]
        $Quiet
    )

    begin
    {
        if ($null -ne ${function:Get-CallerPreference})
        {
            Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        }

        $null = $PSBoundParameters.Remove('MaxConcurrent')
        $null = $PSBoundParameters.Remove('Quiet')
        
        $jobs = @{}
        $i = -1

        function ProcessCompletedJob
        {
            [CmdletBinding()]
            param (
                [Parameter(Mandatory = $true)]
                [hashtable]
                $Jobs,

                [Parameter(Mandatory = $true)]
                [int]
                $Index,

                [switch]
                $Quiet
            )

            $quietStatus = New-Object psobject -Property @{ComputerName = $Jobs[$Index].Target; Success = $false}
                    
            if ($Jobs[$Index].Job.HasMoreData)
            {
                foreach ($ping in (Receive-Job $Jobs[$Index].Job))
                {
                    if ($Quiet)
                    {
                        $quietStatus.ComputerName = $ping.Address
                        if ($ping.StatusCode -eq 0)
                        {
                            $quietStatus.Success = $true
                            break
                        }
                    }
                            
                    else
                    {
                        Write-Output $ping
                    }
                }
            }

            if ($Quiet)
            {
                Write-Output $quietStatus
            }

            Remove-Job -Job $Jobs[$Index].Job -Force
            $Jobs[$Index] = $null

        } # function ProcessCompletedJob

    } # begin

    process
    {
        $null = $PSBoundParameters.Remove('ComputerName')

        foreach ($target in $ComputerName)
        {
            while ($true)
            {
                if (++$i -eq $MaxConcurrent)
                {
                    Start-Sleep -Milliseconds 100
                    $i = 0
                }

                if ($null -ne $jobs[$i] -and $jobs[$i].Job.JobStateInfo.State -ne [System.Management.Automation.JobState]::Running)
                {
                    ProcessCompletedJob -Jobs $jobs -Index $i -Quiet:$Quiet
                }

                if ($null -eq $jobs[$i])
                {
                    Write-Verbose "Job ${i}: Pinging ${target}."

                    $job = Test-Connection -ComputerName $target -AsJob @PSBoundParameters
                    $jobs[$i] = New-Object psobject -Property @{Target = $target; Job = $job}

                    break
                }
            }
        }
    }

    end
    {
        while ($true)
        {
            $foundActive = $false

            for ($i = 0; $i -lt $MaxConcurrent; $i++)
            {
                if ($null -ne $jobs[$i])
                {
                    if ($jobs[$i].Job.JobStateInfo.State -ne [System.Management.Automation.JobState]::Running)
                    {
                        ProcessCompletedJob -Jobs $jobs -Index $i -Quiet:$Quiet
                    }                    
                    else
                    {
                        $foundActive = $true
                    }
                }
            }

            if (-not $foundActive)
            {
                break
            }

            Start-Sleep -Milliseconds 100
        }
    }

} # function Test-ConnectionAsync

New-Variable -Scope Script -Force -Option ReadOnly -Name "PingQuickSelectPropertyList" -Value 'PSComputerName',
    'Address','BufferSize','NoFragmentation','PrimaryAddressResolutionStatus',
    'ProtocolAddress','ProtocolAddressResolved','RecordRoute','ReplyInconsistency','ReplySize','ResolveAddressNames',
    'ResponseTime','ResponseTimeToLive','RouteRecord','RouteRecordResolved','SourceRoute','SourceRouteType','StatusCode',
    'Timeout','TimeStampRecord','TimeStampRecordAddress','TimeStampRecordAddressResolved','TimestampRoute','TimeToLive',
    'TypeofService','__CLASS','__DERIVATION','__DYNASTY','__GENUS','__NAMESPACE','__PATH','__PROPERTY_COUNT','__RELPATH',
    '__SERVER','__SUPERCLASS'

New-Variable -Scope Script -Force -Option ReadOnly -Name "PingQuickFormatPropertyList" -Value @{"Name"="Source";"Expression"={$_.__SERVER}},
    @{"Name"="Destination";"Expression"={$_.Address}},@{"Name"="Bytes";"Expression"={$_.ReplySize}},
    @{"Name"="Time(ms)";Expression={$_.ResponseTime}}

Export-ModuleMember -Function Test-ConnectionAsync -Variable 'PingQuickSelectPropertyList', 'PingQuickFormatPropertyList'
# SIG # Begin signature block
# MIIhfgYJKoZIhvcNAQcCoIIhbzCCIWsCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUSw+wWAscyXWM4ODOxLItN1oT
# Ci+gghywMIIDtzCCAp+gAwIBAgIQDOfg5RfYRv6P5WD8G/AwOTANBgkqhkiG9w0B
# AQUFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVk
# IElEIFJvb3QgQ0EwHhcNMDYxMTEwMDAwMDAwWhcNMzExMTEwMDAwMDAwWjBlMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3Qg
# Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtDhXO5EOAXLGH87dg
# +XESpa7cJpSIqvTO9SA5KFhgDPiA2qkVlTJhPLWxKISKityfCgyDF3qPkKyK53lT
# XDGEKvYPmDI2dsze3Tyoou9q+yHyUmHfnyDXH+Kx2f4YZNISW1/5WBg1vEfNoTb5
# a3/UsDg+wRvDjDPZ2C8Y/igPs6eD1sNuRMBhNZYW/lmci3Zt1/GiSw0r/wty2p5g
# 0I6QNcZ4VYcgoc/lbQrISXwxmDNsIumH0DJaoroTghHtORedmTpyoeb6pNnVFzF1
# roV9Iq4/AUaG9ih5yLHa5FcXxH4cDrC0kqZWs72yl+2qp/C3xag/lRbQ/6GW6whf
# GHdPAgMBAAGjYzBhMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0G
# A1UdDgQWBBRF66Kv9JLLgjEtUYunpyGd823IDzAfBgNVHSMEGDAWgBRF66Kv9JLL
# gjEtUYunpyGd823IDzANBgkqhkiG9w0BAQUFAAOCAQEAog683+Lt8ONyc3pklL/3
# cmbYMuRCdWKuh+vy1dneVrOfzM4UKLkNl2BcEkxY5NM9g0lFWJc1aRqoR+pWxnmr
# EthngYTffwk8lOa4JiwgvT2zKIn3X/8i4peEH+ll74fg38FnSbNd67IJKusm7Xi+
# fT8r87cmNW1fiQG2SVufAQWbqz0lwcy2f8Lxb4bG+mRo64EtlOtCt/qMHt1i8b5Q
# Z7dsvfPxH2sMNgcWfzd8qVttevESRmCD1ycEvkvOl77DZypoEd+A5wwzZr8TDRRu
# 838fYxAe+o0bJW1sj6W3YQGx0qMmoRBxna3iw/nDmVG3KwcIzi7mULKn+gpFL6Lw
# 8jCCBQswggPzoAMCAQICEAOiV15N2F/TLPzy+oVrWjMwDQYJKoZIhvcNAQEFBQAw
# bzELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEuMCwGA1UEAxMlRGlnaUNlcnQgQXNzdXJlZCBJRCBD
# b2RlIFNpZ25pbmcgQ0EtMTAeFw0xNDA1MDUwMDAwMDBaFw0xNTA1MTMxMjAwMDBa
# MGExCzAJBgNVBAYTAkNBMQswCQYDVQQIEwJPTjERMA8GA1UEBxMIQnJhbXB0b24x
# GDAWBgNVBAoTD0RhdmlkIExlZSBXeWF0dDEYMBYGA1UEAxMPRGF2aWQgTGVlIFd5
# YXR0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvcX51YAyViQE16mg
# +IVQCQ0O8QC/wXBzTMPirnoGK9TThmxQIYgtcekZ5Xa/dWpW0xKKjaS6dRwYYXET
# pzozoMWZbFDVrgKaqtuZNu9TD6rqK/QKf4iL/eikr0NIUL4CoSEQDeGLXDw7ntzZ
# XKM86RuPw6MlDapfFQQFIMjsT7YaoqQNTOxhbiFoHVHqP7xL3JTS7TApa/RnNYyl
# O7SQ7TSNsekiXGwUNxPqt6UGuOP0nyR+GtNiBcPfeUi+XaqjjBmpqgDbkEIMLDuf
# fDO54VKvDLl8D2TxTFOcKZv61IcToOs+8z1sWTpMWI2MBuLhRR3A6iIhvilTYRBI
# iX5FZQIDAQABo4IBrzCCAaswHwYDVR0jBBgwFoAUe2jOKarAF75JeuHlP9an90WP
# NTIwHQYDVR0OBBYEFDS4+PmyUp+SmK2GR+NCMiLd+DpvMA4GA1UdDwEB/wQEAwIH
# gDATBgNVHSUEDDAKBggrBgEFBQcDAzBtBgNVHR8EZjBkMDCgLqAshipodHRwOi8v
# Y3JsMy5kaWdpY2VydC5jb20vYXNzdXJlZC1jcy1nMS5jcmwwMKAuoCyGKmh0dHA6
# Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9hc3N1cmVkLWNzLWcxLmNybDBCBgNVHSAEOzA5
# MDcGCWCGSAGG/WwDATAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2Vy
# dC5jb20vQ1BTMIGCBggrBgEFBQcBAQR2MHQwJAYIKwYBBQUHMAGGGGh0dHA6Ly9v
# Y3NwLmRpZ2ljZXJ0LmNvbTBMBggrBgEFBQcwAoZAaHR0cDovL2NhY2VydHMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEQ29kZVNpZ25pbmdDQS0xLmNydDAM
# BgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBBQUAA4IBAQBbzAp8wys0A5LcuENslW0E
# oz7rc0A8h+XgjJWdJOFRohE1mZRFpdkVxM0SRqw7IzlSFtTMCsVVPNwU6O7y9rCY
# x5agx3CJBkJVDR/Y7DcOQTmmHy1zpcrKAgTznZuKUQZLpoYz/bA+Uh+bvXB9woCA
# IRbchos1oxC+7/gjuxBMKh4NM+9NIvWs6qpnH5JeBidQDQXp3flPkla+MKrPTL/T
# /amgna5E+9WHWnXbMFCpZ5n1bI1OvgNVZlYC/JTa4fjPEk8d16jYVP4GlRz/QUYI
# y6IAGc/z6xpkdtpXWVCbW0dCd5ybfUYTaeCJumGpS/HSJ7JcTZj694QDOKNvhfrm
# MIIGajCCBVKgAwIBAgIQA5/t7ct5W43tMgyJGfA2iTANBgkqhkiG9w0BAQUFADBi
# MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
# d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBBc3N1cmVkIElEIENB
# LTEwHhcNMTMwNTIxMDAwMDAwWhcNMTQwNjA0MDAwMDAwWjBHMQswCQYDVQQGEwJV
# UzERMA8GA1UEChMIRGlnaUNlcnQxJTAjBgNVBAMTHERpZ2lDZXJ0IFRpbWVzdGFt
# cCBSZXNwb25kZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6aUqB
# TW+lFBaqis1nvku/xmmPWBzgeegenVgmmNpc1Hyj+dsrjBI2w/z5ZAaxu8KomAoX
# DeGV60C065ZtmL+mj3nPvIqSe22cGAZR2KUYUzIBJxlh6IRB38bw6Mr+d61f2J57
# jGBvhVxGvWvnD4DO5wPDfDHPt2VVxvvgmQjkc1r7l9rQTL60tsYPfyaSqbj8OO60
# 5DqkSNBM6qlGJ1vPkhGTnBan/tKtHyLFHqzBce+8StsBCUTfmBwtZ7qoigMzyVG1
# 9wJNCaRN/oBexddFw30IqgEzzDPYTzAW5P8iMi7rfjvw+R4y65Ul0vL+bVSEutXl
# 1NHdG6+9WXuUhTABAgMBAAGjggM1MIIDMTAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0T
# AQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDCCAb8GA1UdIASCAbYwggGy
# MIIBoQYJYIZIAYb9bAcBMIIBkjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGln
# aWNlcnQuY29tL0NQUzCCAWQGCCsGAQUFBwICMIIBVh6CAVIAQQBuAHkAIAB1AHMA
# ZQAgAG8AZgAgAHQAaABpAHMAIABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABjAG8A
# bgBzAHQAaQB0AHUAdABlAHMAIABhAGMAYwBlAHAAdABhAG4AYwBlACAAbwBmACAA
# dABoAGUAIABEAGkAZwBpAEMAZQByAHQAIABDAFAALwBDAFAAUwAgAGEAbgBkACAA
# dABoAGUAIABSAGUAbAB5AGkAbgBnACAAUABhAHIAdAB5ACAAQQBnAHIAZQBlAG0A
# ZQBuAHQAIAB3AGgAaQBjAGgAIABsAGkAbQBpAHQAIABsAGkAYQBiAGkAbABpAHQA
# eQAgAGEAbgBkACAAYQByAGUAIABpAG4AYwBvAHIAcABvAHIAYQB0AGUAZAAgAGgA
# ZQByAGUAaQBuACAAYgB5ACAAcgBlAGYAZQByAGUAbgBjAGUALjALBglghkgBhv1s
# AxUwHwYDVR0jBBgwFoAUFQASKxOYspkH7R7for5XDStnAs0wHQYDVR0OBBYEFGMv
# yd95knu1I8q74aTuM37j4p36MH0GA1UdHwR2MHQwOKA2oDSGMmh0dHA6Ly9jcmwz
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRENBLTEuY3JsMDigNqA0hjJo
# dHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURDQS0xLmNy
# bDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2lj
# ZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0QXNzdXJlZElEQ0EtMS5jcnQwDQYJKoZIhvcNAQEFBQADggEBAKt0
# vUAATHYVJVc90xwD/31FyEUSZucoZWDY3zuz+g3BrDOP9IG5YfGd+5hV195HQ7qA
# PfFIzD9nMFYfzvTQTIS9h6SexeEPqAZd0C9uXtwZ6PCH6uBOrz1sII5zb37Whxjg
# htOa/J7qjHLpQQ+4cbU4LPgpstUcop0b7F8quNw3IOHLu/DQbGyls8ufSvZU4yY0
# PS64wSsct/bDPf7RLR5Q9JTI+P3uc9tJtRv09f+lkME5FBvY7XEbapj7+kCaRKkp
# DlVeeLi3pIPDcAHwZkDlrnk04StNA6Et5ttUYhjt1QmLoqrWDMhPGr6ZJXhpmYnU
# WYne34jw02dedKWdpkQwggajMIIFi6ADAgECAhAPqEkGFdcAoL4hdv3F7G29MA0G
# CSqGSIb3DQEBBQUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJ
# bmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0
# IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0xMTAyMTExMjAwMDBaFw0yNjAyMTAxMjAw
# MDBaMG8xCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNV
# BAsTEHd3dy5kaWdpY2VydC5jb20xLjAsBgNVBAMTJURpZ2lDZXJ0IEFzc3VyZWQg
# SUQgQ29kZSBTaWduaW5nIENBLTEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
# AoIBAQCcfPmgjwrKiUtTmjzsGSJ/DMv3SETQPyJumk/6zt/G0ySR/6hSk+dy+PFG
# hpTFqxf0eH/Ler6QJhx8Uy/lg+e7agUozKAXEUsYIPO3vfLcy7iGQEUfT/k5mNM7
# 629ppFwBLrFm6aa43Abero1i/kQngqkDw/7mJguTSXHlOG1O/oBcZ3e11W9mZJRr
# u4hJaNjR9H4hwebFHsnglrgJlflLnq7MMb1qWkKnxAVHfWAr2aFdvftWk+8b/HL5
# 3z4y/d0qLDJG2l5jvNC4y0wQNfxQX6xDRHz+hERQtIwqPXQM9HqLckvgVrUTtmPp
# P05JI+cGFvAlqwH4KEHmx9RkO12rAgMBAAGjggNDMIIDPzAOBgNVHQ8BAf8EBAMC
# AYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwggHDBgNVHSAEggG6MIIBtjCCAbIGCGCG
# SAGG/WwDMIIBpDA6BggrBgEFBQcCARYuaHR0cDovL3d3dy5kaWdpY2VydC5jb20v
# c3NsLWNwcy1yZXBvc2l0b3J5Lmh0bTCCAWQGCCsGAQUFBwICMIIBVh6CAVIAQQBu
# AHkAIAB1AHMAZQAgAG8AZgAgAHQAaABpAHMAIABDAGUAcgB0AGkAZgBpAGMAYQB0
# AGUAIABjAG8AbgBzAHQAaQB0AHUAdABlAHMAIABhAGMAYwBlAHAAdABhAG4AYwBl
# ACAAbwBmACAAdABoAGUAIABEAGkAZwBpAEMAZQByAHQAIABDAFAALwBDAFAAUwAg
# AGEAbgBkACAAdABoAGUAIABSAGUAbAB5AGkAbgBnACAAUABhAHIAdAB5ACAAQQBn
# AHIAZQBlAG0AZQBuAHQAIAB3AGgAaQBjAGgAIABsAGkAbQBpAHQAIABsAGkAYQBi
# AGkAbABpAHQAeQAgAGEAbgBkACAAYQByAGUAIABpAG4AYwBvAHIAcABvAHIAYQB0
# AGUAZAAgAGgAZQByAGUAaQBuACAAYgB5ACAAcgBlAGYAZQByAGUAbgBjAGUALjAS
# BgNVHRMBAf8ECDAGAQH/AgEAMHkGCCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYY
# aHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2Fj
# ZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MIGB
# BgNVHR8EejB4MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNl
# cnRBc3N1cmVkSURSb290Q0EuY3JsMDqgOKA2hjRodHRwOi8vY3JsNC5kaWdpY2Vy
# dC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMB0GA1UdDgQWBBR7aM4p
# qsAXvkl64eU/1qf3RY81MjAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823I
# DzANBgkqhkiG9w0BAQUFAAOCAQEAe3IdZP+IyDrBt+nnqcSHu9uUkteQWTP6K4fe
# qFuAJT8Tj5uDG3xDxOaM3zk+wxXssNo7ISV7JMFyXbhHkYETRvqcP2pRON60Jcvw
# q9/FKAFUeRBGJNE4DyahYZBNur0o5j/xxKqb9to1U0/J8j3TbNwj7aqgTWcJ8zqA
# PTz7NkyQ53ak3fI6v1Y1L6JMZejg1NrRx8iRai0jTzc7GZQY1NWcEDzVsRwZ/4/I
# a5ue+K6cmZZ40c2cURVbQiZyWo0KSiOSQOiG3iLCkzrUm2im3yl/Brk8Dr2fxIac
# gkdCcTKGCZlyCXlLnXFp9UH/fzl3ZPGEjb6LHrJ9aKOlkLEM/zCCBs0wggW1oAMC
# AQICEAb9+QOWA63qAArrPye7uhswDQYJKoZIhvcNAQEFBQAwZTELMAkGA1UEBhMC
# VVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0
# LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBSb290IENBMB4XDTA2
# MTExMDAwMDAwMFoXDTIxMTExMDAwMDAwMFowYjELMAkGA1UEBhMCVVMxFTATBgNV
# BAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8G
# A1UEAxMYRGlnaUNlcnQgQXNzdXJlZCBJRCBDQS0xMIIBIjANBgkqhkiG9w0BAQEF
# AAOCAQ8AMIIBCgKCAQEA6IItmfnKwkKVpYBzQHDSnlZUXKnE0kEGj8kz/E1FkVyB
# n+0snPgWWd+etSQVwpi5tHdJ3InECtqvy15r7a2wcTHrzzpADEZNk+yLejYIA6sM
# NP4YSYL+x8cxSIB8HqIPkg5QycaH6zY/2DDD/6b3+6LNb3Mj/qxWBZDwMiEWicZw
# iPkFl32jx0PdAug7Pe2xQaPtP77blUjE7h6z8rwMK5nQxl0SQoHhg26Ccz8mSxSQ
# rllmCsSNvtLOBq6thG9IhJtPQLnxTPKvmPv2zkBdXPao8S+v7Iki8msYZbHBc63X
# 8djPHgp0XEK4aH631XcKJ1Z8D2KkPzIUYJX9BwSiCQIDAQABo4IDejCCA3YwDgYD
# VR0PAQH/BAQDAgGGMDsGA1UdJQQ0MDIGCCsGAQUFBwMBBggrBgEFBQcDAgYIKwYB
# BQUHAwMGCCsGAQUFBwMEBggrBgEFBQcDCDCCAdIGA1UdIASCAckwggHFMIIBtAYK
# YIZIAYb9bAABBDCCAaQwOgYIKwYBBQUHAgEWLmh0dHA6Ly93d3cuZGlnaWNlcnQu
# Y29tL3NzbC1jcHMtcmVwb3NpdG9yeS5odG0wggFkBggrBgEFBQcCAjCCAVYeggFS
# AEEAbgB5ACAAdQBzAGUAIABvAGYAIAB0AGgAaQBzACAAQwBlAHIAdABpAGYAaQBj
# AGEAdABlACAAYwBvAG4AcwB0AGkAdAB1AHQAZQBzACAAYQBjAGMAZQBwAHQAYQBu
# AGMAZQAgAG8AZgAgAHQAaABlACAARABpAGcAaQBDAGUAcgB0ACAAQwBQAC8AQwBQ
# AFMAIABhAG4AZAAgAHQAaABlACAAUgBlAGwAeQBpAG4AZwAgAFAAYQByAHQAeQAg
# AEEAZwByAGUAZQBtAGUAbgB0ACAAdwBoAGkAYwBoACAAbABpAG0AaQB0ACAAbABp
# AGEAYgBpAGwAaQB0AHkAIABhAG4AZAAgAGEAcgBlACAAaQBuAGMAbwByAHAAbwBy
# AGEAdABlAGQAIABoAGUAcgBlAGkAbgAgAGIAeQAgAHIAZQBmAGUAcgBlAG4AYwBl
# AC4wCwYJYIZIAYb9bAMVMBIGA1UdEwEB/wQIMAYBAf8CAQAweQYIKwYBBQUHAQEE
# bTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYB
# BQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3Vy
# ZWRJRFJvb3RDQS5jcnQwgYEGA1UdHwR6MHgwOqA4oDaGNGh0dHA6Ly9jcmwzLmRp
# Z2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwOqA4oDaGNGh0
# dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5j
# cmwwHQYDVR0OBBYEFBUAEisTmLKZB+0e36K+Vw0rZwLNMB8GA1UdIwQYMBaAFEXr
# oq/0ksuCMS1Ri6enIZ3zbcgPMA0GCSqGSIb3DQEBBQUAA4IBAQBGUD7Jtygkpzgd
# tlspr1LPUukxR6tWXHvVDQtBs+/sdR90OPKyXGGinJXDUOSCuSPRujqGcq04eKx1
# XRcXNHJHhZRW0eu7NoR3zCSl8wQZVann4+erYs37iy2QwsDStZS9Xk+xBdIOPRqp
# FFumhjFiqKgz5Js5p8T1zh14dpQlc+Qqq8+cdkvtX8JLFuRLcEwAiR78xXm8TBJX
# /l/hHrwCXaj++wc4Tw3GXZG5D2dFzdaD7eeSDY2xaYxP+1ngIw/Sqq4AfO6cQg7P
# kdcntxbuD8O9fAqg7iwIVYUiuOsYGk38KiGtSTGDR5V3cdyxG0tLHBCcdxTBnU8v
# WpUIKRAmMYIEODCCBDQCAQEwgYMwbzELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERp
# Z2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEuMCwGA1UEAxMl
# RGlnaUNlcnQgQXNzdXJlZCBJRCBDb2RlIFNpZ25pbmcgQ0EtMQIQA6JXXk3YX9Ms
# /PL6hWtaMzAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZ
# BgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYB
# BAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUNRLXHioCV2u8A4XfTS/0SEGceKIwDQYJ
# KoZIhvcNAQEBBQAEggEANKTCLwkds+ujmEB9cAKer0ud3AUQ2+lZgRz1Te9ZTXPG
# 5fUq382jETwEJ3pgVQ4PJ39C6tjHRwsoDPaqnYfKU87K1fx7pX3wpkbM39gRUK1z
# nm4zx6K1sZbR/rYL61KevoS+Y9N/d4JYWqOMprfikhAld2cCY4oBbYPYekB0d3rz
# 2SZu/lIGmQhMyosUlHEKhb4mu+1feACXM7dZi8NT1mrcj3C+JKKBmcGteqVBrVcp
# PLIMzM/nrn4vogKaT17Npi4W+63nAwo2lO6Dz1fapIwRmqQ3n+lfNrtyTl4cZUr6
# j/vUzqvQ/I8/QNoLeZrZdoAiZONLUapK8PTIFc7SMqGCAg8wggILBgkqhkiG9w0B
# CQYxggH8MIIB+AIBATB2MGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IEFzc3VyZWQgSUQgQ0EtMQIQA5/t7ct5W43tMgyJGfA2iTAJBgUrDgMCGgUA
# oF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTQw
# NTA4MTczODI1WjAjBgkqhkiG9w0BCQQxFgQUPpHPdsJO8K5ycH9mbvbvB87MTeUw
# DQYJKoZIhvcNAQEBBQAEggEAFOLTkvOEViTUvlcxIGHoaaWh6lWOLM/ickziBPWH
# allvc+dDPBEDCpdq7S8sKoR7isR3hQpqW72PDKrvmu4/A2nccNaWPNXbwSvhbob8
# NYHpQRpKJqNA++sN7vmVNykHErdQDDwLL24N4RZ0cC92mB0wrKQ56JOfujaFGckJ
# RwhLKYaWS+LeYHdOlvZ87PZF/HQhNqiS6noThKRd87N3oUmlkQZPHXIr8x976tP/
# 5RsvdVtPdhf/kO7ANXh5WlT7pHOqPvxdO1l0bDCzdBASqMSro9J8s9nPihiFlh+i
# LWqZ77rjP2B7TV5n2ejSTzG+6iviKiVwf/5aw83TyQ9ujQ==
# SIG # End signature block