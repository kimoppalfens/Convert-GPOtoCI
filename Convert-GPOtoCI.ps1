[CmdletBinding(DefaultParameterSetName = "GpoMode")]
Param(
    [Parameter(
		ParameterSetName = "GpoMode",
		Mandatory=$true)]
		[string]$GpoTarget,    # Name of Group policy
	[Parameter(
		Mandatory=$true)]
		[string]$DomainTarget,    # Domain name
	[Parameter(
		Mandatory=$true)]
		[string]$SiteCode,    # ConfigMgr Site code
	[Parameter(
		Mandatory=$false)]
		[switch]$ExportOnly,    # Switch to disable the creation of CIs and only export to a CAB file
	[Parameter(
		Mandatory=$false)]
		[switch]$Remediate,    # Set remediate non-compliant settings
	[Parameter(
        Mandatory=$false)]
        [ValidateSet('None', 'Informational', 'Warning', 'Critical')]
		[string]$Severity='Informational',    # Rule severity
	[Parameter(
        ParameterSetName = "RsopMode",
		Mandatory=$false)]
		[switch]$ResultantSetOfPolicy,    # Uses Resultant Set of Policy instead of specific GPO for values
	[Parameter(
		ParameterSetName = "GpoMode",
		Mandatory = $false)]
		[switch]$GroupPolicy,    #  Uses a single GPO for values
	[Parameter(
        ParameterSetName = "RsopMode",
		Mandatory=$true)]
		[string]$ComputerName,    # Computer name to be used for RSOP
	[Parameter(
        ParameterSetName = "RsopMode",
		Mandatory=$false)]
		[switch]$LocalPolicy,    # Switch to enable capturing local group policy when using RSOP mode
	[Parameter(
		Mandatory=$false)]
		[switch]$Log    # Switch to enable logging all registry keys and their GPOs to a file
)

# Constants
$MAX_NAME_LENGTH= 255

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$scriptDir = Split-Path -Parent $scriptPath
$startingDrive = (Get-Location).Drive.Name + ":"
$Global:ouPath = $null

if (($GroupPolicy -eq $false) -and ($ResultantSetOfPolicy -eq $false))
{
	$GroupPolicy = $true
}

<#
	Utilizes native GroupPolicy module to query for registry keys assocaited with a given Group Policy
#>
function Get-GPOKeys
{
    param(
        [string]$PolicyName,    # Name of group policy
        [string]$Domain    # Domain name
    )

	If ((Get-Module).Name -contains 'GroupPolicy')
	{
		Write-Verbose "GroupPolicy module already imported."
	}
	Else
	{
		Try
		{
			Import-Module GroupPolicy    # Imports native GroupPolicy PowerShell module
		}
		Catch [Exception]
		{
			Write-Host "Error trying to import GroupPolicy module." -ForegroundColor Red
			Write-Host "Script will exit." -ForegroundColor Red
			pause
			Exit
		}
	}

    Write-Host "Querying for registry keys associated with $PolicyName..."

    $gpoKeys = @("HKLM\Software", "HKLM\System", "HKCU\Software", "HKCU\System")    # Sets registry hives to extract from Group Policy
    $values = @()    
    $keyList = @()
    $newKeyList = @()
    $keyCount = 0
    $prevCount = 0
    $countUp = $true

	# While key count does not increment up
    while ($countUp)
    {
            $prevCount = $keyCount
            $newKeyList = @()
            foreach ($gpoKey in $gpoKeys)
            {
                try
                {
                    $newKeys = (Get-GPRegistryValue -Name $PolicyName -Domain $Domain -Key $gpoKey -ErrorAction Stop).FullKeyPath    # Gets registry keys
                } catch [Exception]
                {
					If ($_.Exception.Message -notlike "*The following Group Policy registry setting was not found:*")
					{
						Write-Host $_.Exception.Message -ForegroundColor Red					
						Break
					}
                }
				# For each key in list of registry keys
                foreach ($nKey in $newKeys)
                {               
					# If key is not already in list
                    if ($keyList -notcontains $nKey)
                    {
                        #Write-Verbose $nKey
                        $keyList += $nKey
                        $keyCount++						
                    }
                    if ($newKeyList -notcontains $nKey)
                    {
                        $newKeyList += $nKey
                    }
                }
            }
            [array]$gpoKeys = $newKeyList
			# If previous key count equals current key count.  (No new keys found; end of list)
            if ($prevCount -eq $keyCount)
            {
                $countUp = $false
            }
    }
    
	If ($newKeys -ne $null)
	{
		foreach ($key in $keyList)
		{
			$values += Get-GPRegistryValue -Name $PolicyName -Domain $Domain -Key $key -ErrorAction SilentlyContinue | select FullKeyPath, ValueName, Value, Type | Where-Object {($_.Value -ne $null) -and ($_.Value.Length -gt 0)} 
		}
		if ($Log)
		{
			foreach ($value in $values)
			{
				Write-Log -RegistryKey $value -GPOName $PolicyName
			}
		}
	}

    $valueCount = $values.Count

    Write-Host "`t$keyCount keys found."
    Write-Host "`t$valueCount values found."

    $values    
}

<#
	Utilizes the ConfigurationManager PowerShell module to create Configuration Item settings based on registry keys
#>
function New-SCCMConfigurationItemSetting
{
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory=$true)]
            [string]$DisplayName,
        [Parameter(
            Mandatory=$false)]
            [string]$Description = "",
        [Parameter(
            Mandatory=$true)]
        [ValidateSet('Int64', 'Double', 'String', 'DateTime', 'Version', 'StringArray')]
            [string]$DataType,
        [Parameter(
            Mandatory=$true)]
        [ValidateSet('HKEY_CLASSES_ROOT', 'HKEY_CURRENT_USER', 'HKEY_LOCAL_MACHINE', 'HKEY_USERS')]
            [string]$Hive,
        [Parameter(
            Mandatory=$true)]
            [bool]$Is64Bit,
        [Parameter(
            Mandatory=$true)]
            [string]$Key,
        [Parameter(
            Mandatory=$true)]
            [string]$ValueName,
        [Parameter(
            Mandatory=$true)]
            [string]$LogicalName
    )

	If ($DisplayName.Length -gt $MAX_NAME_LENGTH)
	{
		$DisplayName = $DisplayName.Substring(0,$MAX_NAME_LENGTH)
	}

    Write-Verbose "`tCreating setting $DisplayName..."

    $templatePath = "$scriptPath\xmlTemplates"

    $settingXml = [xml](Get-Content $templatePath\setting.xml)
    $settingXml.SimpleSetting.LogicalName = $LogicalName
    $settingXml.SimpleSetting.DataType = $DataType
    $settingXml.SimpleSetting.Annotation.DisplayName.Text = $DisplayName
    $settingXml.SimpleSetting.Annotation.Description.Text = $Description
    $settingXml.SimpleSetting.RegistryDiscoverySource.Hive = $Hive
    $settingXml.SimpleSetting.RegistryDiscoverySource.Is64Bit = $Is64Bit.ToString().ToLower()
    $settingXml.SimpleSetting.RegistryDiscoverySource.Key = $Key
    $settingXml.SimpleSetting.RegistryDiscoverySource.ValueName = $ValueName

    $settingXml.Save("c:\users\public\test1.xml")
    $settingXml    
}

<#
	Utilizes the ConfigurationManager PowerShell module to create Configuration Item rules for previously created CI settings
#>
function New-SCCMConfigurationItemRule
{
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory=$true)]
            [string]$DisplayName,
        [Parameter(
            Mandatory=$false)]
            [string]$Description = "",
        [Parameter(
            Mandatory=$true)]
        [ValidateSet('None', 'Informational', 'Warning', 'Critical')]
            [string]$Severity,
        [Parameter(
            Mandatory=$true)]
        [ValidateSet('Equals', 'NotEquals', 'GreaterThan', 'LessThan', 'Between', 'GreaterEquals', 'LessEquals', 'BeginsWith', `
            'NotBeginsWith', 'EndsWith', 'NotEndsWith', 'Contains', 'NotContains', 'AllOf', 'OneOf', 'NoneOf')]
            [string]$Operator,
        [Parameter(
            Mandatory=$true)]
        [ValidateSet('Registry', 'IisMetabase', 'WqlQuery', 'Script', 'XPathQuery', 'ADQuery', 'File', 'Folder', 'RegistryKey', 'Assembly')]
            [string]$SettingSourceType, 
        [Parameter(
            Mandatory=$true)]
        [ValidateSet('String', 'Boolean', 'DateTime', 'Double', 'Int64', 'Version', 'FileSystemAccessControl', 'RegistryAccessControl', `
            'FileSystemAttribute', 'StringArray', 'Int64Array', 'FileSystemAccessControlArray', 'RegistryAccessControlArray', 'FileSystemAttributeArray')]
            [string]$DataType,
        [Parameter(
            Mandatory=$true)]
        [ValidateSet('Value', 'Count')]
            [string]$Method,
        [Parameter(
            Mandatory=$true)]
            [bool]$Changeable,
        [Parameter(
            Mandatory=$true)]
            $Value,
        [Parameter(
            Mandatory=$true)]
        [ValidateSet('String', 'Boolean', 'DateTime', 'Double', 'Int64', 'Version', 'FileSystemAccessControl', 'RegistryAccessControl', `
            'FileSystemAttribute', 'StringArray', 'Int64Array', 'FileSystemAccessControlArray', 'RegistryAccessControlArray', 'FileSystemAttributeArray')]
            [string]$ValueDataType,
        [Parameter(
            Mandatory=$true)]
            [string]$AuthoringScope,
        [Parameter(
            Mandatory=$true)]
            [string]$SettingLogicalName,
        [Parameter(
            Mandatory=$true)]
            [string]$LogicalName
    )

	If ($DisplayName.Length -gt $MAX_NAME_LENGTH)
	{
		$DisplayName = $DisplayName.Substring(0,$MAX_NAME_LENGTH)
	}

    Write-Verbose "`tCreating rule $DisplayName..."

    $templatePath = "$scriptPath\xmlTemplates"
    $id = "Rule_$([guid]::NewGuid())"
    $resourceID = "ID-$([guid]::NewGuid())"
    #$logicalName = "OperatingSystem_$([guid]::NewGuid())"

    if ($DataType -eq "StringArray")
    {
         $ruleXml = [xml](Get-Content $templatePath\ruleSA.xml)
    }
    else
    {
        $ruleXml = [xml](Get-Content $templatePath\rule.xml)
    }

    $ruleXml.Rule.Id = $id
    $ruleXml.Rule.Severity = $Severity
    $ruleXml.Rule.Annotation.DisplayName.Text = $DisplayName
    $ruleXml.Rule.Annotation.Description.Text = $Description
    $ruleXml.Rule.Expression.Operator = $Operator
    $ruleXml.Rule.Expression.Operands.SettingReference.AuthoringScopeId = $AuthoringScope
    $ruleXml.Rule.Expression.Operands.SettingReference.LogicalName = $LogicalName
    $ruleXml.Rule.Expression.Operands.SettingReference.SettingLogicalName = $SettingLogicalName
    $ruleXml.Rule.Expression.Operands.SettingReference.SettingSourceType = $SettingSourceType
    $ruleXml.Rule.Expression.Operands.SettingReference.DataType = $ValueDataType
    $ruleXml.Rule.Expression.Operands.SettingReference.Method = $Method
    $ruleXml.Rule.Expression.Operands.SettingReference.Changeable = $Changeable.ToString().ToLower()
    
    # If registry value type is StringArray
    if ($DataType -eq "StringArray")
    {
        $ruleXml.Rule.Expression.Operands.ConstantValueList.DataType = "StringArray"  
        $valueIndex = 0
        # For each value in array of values
        foreach ($v in $Value)
        {
            # if not first value in array add new nodes; else just set the one value
            if ($valueIndex -gt 0)
            {
                # if only one index do not specifiy index to copy; else specify the index to copy
                if ($valueIndex -le 1)
                {
                    $newNode = $ruleXml.Rule.Expression.Operands.ConstantValueList.ConstantValue.Clone()                    
                }
                else
                {
                    $newNode = $ruleXml.Rule.Expression.Operands.ConstantValueList.ConstantValue[0].Clone()
                }
                $ruleXml.Rule.Expression.Operands.ConstantValueList.AppendChild($newNode)
                $ruleXml.Rule.Expression.Operands.ConstantValueList.ConstantValue[$valueIndex].DataType = "String"
                $ruleXml.Rule.Expression.Operands.ConstantValueList.ConstantValue[$valueIndex].Value = $v
                
            }
            else
            {
                $ruleXml.Rule.Expression.Operands.ConstantValueList.ConstantValue.DataType = "String"
                $ruleXml.Rule.Expression.Operands.ConstantValueList.ConstantValue.Value = $v
            }    
            $valueIndex++
        }
    }
    else
    {
        $ruleXml.Rule.Expression.Operands.ConstantValue.DataType = $ValueDataType
        $ruleXml.Rule.Expression.Operands.ConstantValue.Value = $Value
    }
    $ruleXml
}

<#
	Utilizes the ConfigurationManager PowerShell module to create Configuration Items based on previously created settings and rules
#>
function New-SCCMConfigurationItems
{
    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory=$true)]
            [string]$Name,
        [Parameter(
            Mandatory=$false)]
            [string]$Description="",
        [Parameter(
            Mandatory=$true)]
        [ValidateSet('MacOS', 'MobileDevice', 'None', 'WindowsApplication', 'WindowsOS')]
        [string]$CreationType,
        [Parameter(
            Mandatory=$true)]
            [array]$RegistryKeys,
		[Parameter(
            Mandatory=$false)]
        [ValidateSet('None', 'Informational', 'Warning', 'Critical')]
		[string]$Severity='Informational'    # Rule severity
    )
    
	If ((Get-Module).Name -contains 'ConfigurationManager')
	{
		Write-Verbose "ConfigurationManager module already loaded."
	}
	Else
	{
		Try
		{
			Import-Module "$(Split-Path $env:SMS_ADMIN_UI_PATH)\ConfigurationManager"    # Imports ConfigMgr PowerShell module
		}
		Catch [Exception]
		{
			Write-Host "Error trying to import ConfigurationManager module." -ForegroundColor Red
			Write-Host "Script will exit." -ForegroundColor Red
			pause
			Exit
		}
	}

	If ($Name.Length -gt $MAX_NAME_LENGTH)
	{
		$Name = $Name.Substring(0,$MAX_NAME_LENGTH)
	}

    Write-Host "Creating Configuration Item..."

    Set-Location "$SiteCode`:"

    $origName = $Name
    #$tmpFileCi = [System.IO.Path]::GetTempFileName()
	# If ResultantSetOfPolicy option is used use the OU path to name the CI xml
	if ($ResultantSetOfPolicy)
	{
		$ouNoSpace = $Global:ouPath.Replace(" ", "_")
		$ouNoSpace = $ouNoSpace.Replace("/", "_")
		$ciFile = "$scriptPath\$ouNoSpace.xml"
	}
	# If ResultantSetOfPolicy option is not used use the GPO nane to name the CI xml
	else
	{
		$gpoNoSpace = $GpoTarget.Replace(" ", "_")
		$ciFile = "$scriptPath\$gpoNoSpace.xml"
	}

    
    for ($i = 1; $i -le 99; $i++)
    {
        $testCI = Get-CMConfigurationItem -Name $Name -Fast
        if ($testCI -eq $null)
        {
            break   
        }
        else
        {
            $Name = $origName + " ($i)"
        }
    }

    $ci = New-CMConfigurationItem -Name $Name -Description $Description -CreationType $CreationType
    $ciXml = [xml]($ci.SDMPackageXML.Replace('<RootComplexSetting/></Settings>', '<RootComplexSetting><SimpleSetting></SimpleSetting></RootComplexSetting></Settings><Rules><Rule></Rule></Rules>'))

    $ciXml.Save($ciFile)

    foreach ($Key in $RegistryKeys)
    {
        $len = ($Key.FullKeyPath.Split("\")).Length
        $keyName = ($Key.FullKeyPath.Split("\"))[$len - 1]
        $valueName = $Key.ValueName
        $value = $Key.Value
        $value = $value -replace "[^\u0030-\u0039\u0041-\u005A\u0061-\u007A]\Z", ""
        $type = $Key.Type
        $dName = $keyName + " - " + $valueName
        $hive = ($Key.FullKeyPath.Split("\"))[0]
        $subKey = ($Key.FullKeyPath).Replace("$hive\","")
        $logicalNameS = "RegSetting_$([guid]::NewGuid())"
        $ruleLogName = $ciXml.DesiredConfigurationDigest.OperatingSystem.LogicalName
        $authScope = $ciXml.DesiredConfigurationDigest.OperatingSystem.AuthoringScopeId
        
		if ($Key.Type -eq "Binary")
		{
			continue
		}
		if ($Key.Type -eq "ExpandString")
        {
            $dataType = "String"
        } elseif ($Key.Type -eq "MultiString")
        {
            $dataType = "StringArray"
        } elseif ($Key.Type -eq "DWord")
        {
            $dataType = "Int64"
        } else
        {
            $dataType = $Key.Type
        }

        if ($value.Length -gt 0)
        {
            $settingXml = New-SCCMConfigurationItemSetting -DisplayName $dName -Description ("$keyName - $valueName") -DataType $dataType -Hive $hive -Is64Bit $false `
                -Key $subKey -ValueName $valueName -LogicalName $logicalNameS

            if ($dataType -eq "StringArray")
            {
                $operator = "AllOf"
            }
            else
            {
                $operator = "Equals"
            }
            
            $ruleXml = New-SCCMConfigurationItemRule -DisplayName ("$valueName - $value - $type") -Description "" -Severity $Severity -Operator $operator -SettingSourceType Registry -DataType $dataType -Method Value -Changeable $Remediate `
                -Value $value -ValueDataType $dataType -AuthoringScope $authScope -SettingLogicalName $logicalNameS -LogicalName $ruleLogName
            
            # If array returned search arrary for XmlDocument
            if ($ruleXml.count -gt 1)
            {
                for ($i = 0; $i -lt ($ruleXml.Count); $i++)
                {
                    if ($ruleXml[$i].GetType().ToString() -eq "System.Xml.XmlDocument")
                    {
                        $ruleXml = $ruleXml[$i]
                        continue
                    }
                }
            }
            $importS = $ciXml.ImportNode($settingXml.SimpleSetting, $true)
            $ciXml.DesiredConfigurationDigest.OperatingSystem.Settings.RootComplexSetting.AppendChild($importS) | Out-Null
            $importR = $ciXml.ImportNode($ruleXml.Rule, $true)

            $ciXml.DesiredConfigurationDigest.OperatingSystem.Rules.AppendChild($importR) | Out-Null
            $ciXml = [xml] $ciXml.OuterXml.Replace(" xmlns=`"`"", "")
            $ciXml.Save($ciFile)
        }
    }

	If ($ExportOnly)
	{
		Write-Host "Deleting Empty Configuration Item..."
		Remove-CMConfigurationItem -Id $ci.CI_ID -Force
		Write-Host "Creating CAB File..."
		if ($ResultantSetOfPolicy)
		{
			Export-CAB -Name $Global:ouPath -Path $ciFile
		}
		else
		{
			Export-CAB -Name $GpoTarget -Path $ciFile
		}
	}
	Else
	{
		Write-Host "Setting DCM Digest..."
		Set-CMConfigurationItem -DesiredConfigurationDigestPath $ciFile -Id $ci.CI_ID
		Remove-Item -Path $ciFile -Force
	}
}

function Export-CAB
{
	Param(
		[string]$Name,
		[string]$Path
	)

	$fileName = $Name.Replace(" ", "_")
	$fileName = $fileName.Replace("/", "_")
	$ddfFile = Join-Path -Path $scriptPath -ChildPath temp.ddf

	$ddfHeader =@"
;*** MakeCAB Directive file
;
.OPTION EXPLICIT      
.Set CabinetNameTemplate=$fileName.cab
.set DiskDirectory1=$scriptPath
.Set MaxDiskSize=CDROM
.Set Cabinet=on
.Set Compress=on
"$Path"
"@

	$ddfHeader | Out-File -filepath $ddfFile -force -encoding ASCII
	makecab /f $ddfFile | Out-Null

	#Remove temporary files
	Remove-Item ($scriptPath + '\temp.ddf') -ErrorAction SilentlyContinue
	Remove-Item ($scriptPath + '\setup.inf') -ErrorAction SilentlyContinue
	Remove-Item ($scriptPath + '\setup.rpt') -ErrorAction SilentlyContinue
	Remove-Item ($scriptPath + '\' + $fileName + '.xml') -ErrorAction SilentlyContinue
}

function Get-RSOP
{
	[CmdletBinding()]
	Param(
		[Parameter(
			Mandatory=$true)]
		[string]$ComputerName
	)

	$tmpXmlFile = [System.IO.Path]::GetTempFileName()    # Creates temp file for rsop results

	try
	{
		Write-Host "Processing Resultant Set of Policy for $ComputerName"
		Get-GPResultantSetOfPolicy -Computer $ComputerName -ReportType xml -Path $tmpXmlFile
	}
	catch [Exception]
	{
		Write-Host "Unable to process Resultant Set of Policy" -ForegroundColor Red
		Pause
		Exit
	}

	$rsop = [xml](Get-Content -Path $tmpXmlFile)
	$domainName = $rsop.Rsop.ComputerResults.Domain
	$rsopKeys = @()
	
	# Loop through all applied GPOs starting with the last applied
	for ($x = $rsop.Rsop.ComputerResults.Gpo.Name.Count; $x -ge 1; $x--)
	{
		$rsopTemp = @()
		# Get GPO name
		$gpoResults = ($rsop.Rsop.ComputerResults.Gpo | Where-Object {($_.Link.AppliedOrder -eq $x) -and ($_.Name -ne "Local Group Policy")} | select Name).Name
		If ($gpoResults -ne $null)
		{
			# If name is not null gets registry keys for that GPO and assign to temp value
			$rsopTemp = Get-GPOKeys -PolicyName $gpoResults -Domain $domainName			
			if ($Global:ouPath -eq $null)
			{
				$Global:ouPath = ($rsop.Rsop.ComputerResults.SearchedSom | Where-Object {$_.Order -eq $x} | select Path).path
			}
		}
		# foreach registry key value in gpo results
		foreach ($key in $rsopTemp)
		{
			# if a value is not already stored with that FullKeyPath and ValueName store that value
			if (($rsopKeys | Where-Object {($_.FullKeyPath -eq $key.FullKeyPath) -and ($_.ValueName -eq $key.ValueName)}) -eq $null)
			{
				$rsopKeys += $key
			}
		}
	}

	Remove-Item -Path $tmpXmlFile -Force   # Deletes temp file

	$rsopKeys
}

function Write-Log
{
	[CmdletBinding()]
	Param(
		[Parameter(
			Mandatory=$true)]
			[array]$RegistryKey,
		[Parameter(
			Mandatory=$true)]
			[string]$GPOName
	)

	[string]$logPath = 'gpo_registry_discovery_' + (Get-Date -Format MMddyyyy) + '.log'
	[string]$outString = $GPOName + "`t" + $RegistryKey.FullKeyPath + "`t" + $RegistryKey.ValueName + "`t" + $RegistryKey.Value + "`t" + $RegistryKey.Type
	Out-File -FilePath .\$logPath -InputObject $outString -Force -Append
}

function WriteXmlToScreen ([xml]$xml)
{
    $StringWriter = New-Object System.IO.StringWriter;
    $XmlWriter = New-Object System.Xml.XmlTextWriter $StringWriter;
    $XmlWriter.Formatting = "indented";
    $xml.WriteTo($XmlWriter);
    $XmlWriter.Flush();
    $StringWriter.Flush();
    Write-Output $StringWriter.ToString();
}

if ($GroupPolicy)
{
	$gpo = Get-GPOKeys -PolicyName $GpoTarget -Domain $DomainTarget
}
# If ResultantSetOfPolicy option is used remove the first index of the array that contains RSOP information
if ($ResultantSetOfPolicy)
{
	$gpo = Get-RSOP -ComputerName $ComputerName
	if ($gpo[0].RsopMode -ne $null)
	{
		$gpo = $gpo[1..($gpo.Length - 1)]
	}
}

If ($gpo -ne $null)
{
	# If ResultantSetOfPolicy option is used use the OU path to name the CI
	if ($ResultantSetOfPolicy -eq $true)
	{
		$ciName = $Global:ouPath
	}
	# If ResultantSetOfPolicy option is not used use the target GPO to name the CI
	elseif ($GroupPolicy -eq $true)
	{
		$ciName = $GpoTarget
	}

	New-SCCMConfigurationItems -Name $ciName -Description "This is a GPO compliance settings that was automatically created via PowerShell." -CreationType "WindowsOS" -Severity $Severity -RegistryKeys $gpo

	Set-Location $startingDrive

	Write-Host "Complete"
}
Else
{
	Write-Host "** ERROR! The script will terminate. **" -ForegroundColor Red 
}
# SIG # Begin signature block
# MIIm/wYJKoZIhvcNAQcCoIIm8DCCJuwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDmQYZa7DOT81gB
# HbUFIrjpYppV9ruijMBr1LHRZA8iS6CCIIIwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggauMIIElqADAgECAhAHNje3JFR82Ees/ShmKl5bMA0GCSqG
# SIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yMjAzMjMwMDAwMDBaFw0zNzAzMjIyMzU5NTlaMGMx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMy
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcg
# Q0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDGhjUGSbPBPXJJUVXH
# JQPE8pE3qZdRodbSg9GeTKJtoLDMg/la9hGhRBVCX6SI82j6ffOciQt/nR+eDzMf
# UBMLJnOWbfhXqAJ9/UO0hNoR8XOxs+4rgISKIhjf69o9xBd/qxkrPkLcZ47qUT3w
# 1lbU5ygt69OxtXXnHwZljZQp09nsad/ZkIdGAHvbREGJ3HxqV3rwN3mfXazL6IRk
# tFLydkf3YYMZ3V+0VAshaG43IbtArF+y3kp9zvU5EmfvDqVjbOSmxR3NNg1c1eYb
# qMFkdECnwHLFuk4fsbVYTXn+149zk6wsOeKlSNbwsDETqVcplicu9Yemj052FVUm
# cJgmf6AaRyBD40NjgHt1biclkJg6OBGz9vae5jtb7IHeIhTZgirHkr+g3uM+onP6
# 5x9abJTyUpURK1h0QCirc0PO30qhHGs4xSnzyqqWc0Jon7ZGs506o9UD4L/wojzK
# QtwYSH8UNM/STKvvmz3+DrhkKvp1KCRB7UK/BZxmSVJQ9FHzNklNiyDSLFc1eSuo
# 80VgvCONWPfcYd6T/jnA+bIwpUzX6ZhKWD7TA4j+s4/TXkt2ElGTyYwMO1uKIqjB
# Jgj5FBASA31fI7tk42PgpuE+9sJ0sj8eCXbsq11GdeJgo1gJASgADoRU7s7pXche
# MBK9Rp6103a50g5rmQzSM7TNsQIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB
# /wIBADAdBgNVHQ4EFgQUuhbZbU2FL3MpdpovdYxqII+eyG8wHwYDVR0jBBgwFoAU
# 7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoG
# CCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDig
# NqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZI
# hvcNAQELBQADggIBAH1ZjsCTtm+YqUQiAX5m1tghQuGwGC4QTRPPMFPOvxj7x1Bd
# 4ksp+3CKDaopafxpwc8dB+k+YMjYC+VcW9dth/qEICU0MWfNthKWb8RQTGIdDAiC
# qBa9qVbPFXONASIlzpVpP0d3+3J0FNf/q0+KLHqrhc1DX+1gtqpPkWaeLJ7giqzl
# /Yy8ZCaHbJK9nXzQcAp876i8dU+6WvepELJd6f8oVInw1YpxdmXazPByoyP6wCeC
# RK6ZJxurJB4mwbfeKuv2nrF5mYGjVoarCkXJ38SNoOeY+/umnXKvxMfBwWpx2cYT
# gAnEtp/Nh4cku0+jSbl3ZpHxcpzpSwJSpzd+k1OsOx0ISQ+UzTl63f8lY5knLD0/
# a6fxZsNBzU+2QJshIUDQtxMkzdwdeDrknq3lNHGS1yZr5Dhzq6YBT70/O3itTK37
# xJV77QpfMzmHQXh6OOmc4d0j/R0o08f56PGYX/sr2H7yRp11LB4nLCbbbxV7HhmL
# NriT1ObyF5lZynDwN7+YAN8gFk8n+2BnFqFmut1VwDophrCYoCvtlUG3OtUVmDG0
# YgkPCr2B2RP+v6TR81fZvAT6gt4y3wSJ8ADNXcL50CN/AAvkdgIm2fBldkKmKYcJ
# RyvmfxqkhQ/8mJb2VVQrH4D6wPIOK+XW+6kvRBVK5xMOHds3OBqhK/bt1nz8MIIG
# sDCCBJigAwIBAgIQCK1AsmDSnEyfXs2pvZOu2TANBgkqhkiG9w0BAQwFADBiMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQw
# HhcNMjEwNDI5MDAwMDAwWhcNMzYwNDI4MjM1OTU5WjBpMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0
# ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExMIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1bQvQtAorXi3XdU5WRuxiEL1M4zr
# PYGXcMW7xIUmMJ+kjmjYXPXrNCQH4UtP03hD9BfXHtr50tVnGlJPDqFX/IiZwZHM
# gQM+TXAkZLON4gh9NH1MgFcSa0OamfLFOx/y78tHWhOmTLMBICXzENOLsvsI8Irg
# nQnAZaf6mIBJNYc9URnokCF4RS6hnyzhGMIazMXuk0lwQjKP+8bqHPNlaJGiTUyC
# EUhSaN4QvRRXXegYE2XFf7JPhSxIpFaENdb5LpyqABXRN/4aBpTCfMjqGzLmysL0
# p6MDDnSlrzm2q2AS4+jWufcx4dyt5Big2MEjR0ezoQ9uo6ttmAaDG7dqZy3SvUQa
# khCBj7A7CdfHmzJawv9qYFSLScGT7eG0XOBv6yb5jNWy+TgQ5urOkfW+0/tvk2E0
# XLyTRSiDNipmKF+wc86LJiUGsoPUXPYVGUztYuBeM/Lo6OwKp7ADK5GyNnm+960I
# HnWmZcy740hQ83eRGv7bUKJGyGFYmPV8AhY8gyitOYbs1LcNU9D4R+Z1MI3sMJN2
# FKZbS110YU0/EpF23r9Yy3IQKUHw1cVtJnZoEUETWJrcJisB9IlNWdt4z4FKPkBH
# X8mBUHOFECMhWWCKZFTBzCEa6DgZfGYczXg4RTCZT/9jT0y7qg0IU0F8WD1Hs/q2
# 7IwyCQLMbDwMVhECAwEAAaOCAVkwggFVMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYD
# VR0OBBYEFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB8GA1UdIwQYMBaAFOzX44LScV1k
# TN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcD
# AzB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2lj
# ZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0
# cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmww
# HAYDVR0gBBUwEzAHBgVngQwBAzAIBgZngQwBBAEwDQYJKoZIhvcNAQEMBQADggIB
# ADojRD2NCHbuj7w6mdNW4AIapfhINPMstuZ0ZveUcrEAyq9sMCcTEp6QRJ9L/Z6j
# fCbVN7w6XUhtldU/SfQnuxaBRVD9nL22heB2fjdxyyL3WqqQz/WTauPrINHVUHmI
# moqKwba9oUgYftzYgBoRGRjNYZmBVvbJ43bnxOQbX0P4PpT/djk9ntSZz0rdKOtf
# JqGVWEjVGv7XJz/9kNF2ht0csGBc8w2o7uCJob054ThO2m67Np375SFTWsPK6Wrx
# oj7bQ7gzyE84FJKZ9d3OVG3ZXQIUH0AzfAPilbLCIXVzUstG2MQ0HKKlS43Nb3Y3
# LIU/Gs4m6Ri+kAewQ3+ViCCCcPDMyu/9KTVcH4k4Vfc3iosJocsL6TEa/y4ZXDlx
# 4b6cpwoG1iZnt5LmTl/eeqxJzy6kdJKt2zyknIYf48FWGysj/4+16oh7cGvmoLr9
# Oj9FpsToFpFSi0HASIRLlk2rREDjjfAVKM7t8RhWByovEMQMCGQ8M4+uKIw8y4+I
# Cw2/O/TOHnuO77Xry7fwdxPm5yg/rBKupS8ibEH5glwVZsxsDsrFhsP2JjMMB0ug
# 0wcCampAMEhLNKhRILutG4UI4lkNbcoFUCvqShyepf2gpx8GdOfy1lKQ/a+FSCH5
# Vzu0nAPthkX0tGFuv2jiJmCG6sivqf6UHedjGzqGVnhOMIIGwTCCBKmgAwIBAgIQ
# C0zaPDGbCk5IRTb7noNKwDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0
# ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExMB4XDTIy
# MDMyMzAwMDAwMFoXDTI1MDMyNTIzNTk1OVowRjELMAkGA1UEBhMCQkUxDzANBgNV
# BAcTBkhlcmVudDESMBAGA1UEChMJT1NDQyBCVkJBMRIwEAYDVQQDEwlPU0NDIEJW
# QkEwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDYLbYpAWOgnChRRARP
# XrCfzNVGKQF7olwgDdGcr0MpE0Mh5y0wURbg7l5iY1n/qoltb/fGP6LF/FkAEEOK
# 4Z5W7xZ6QOgH/TQkdu/f1Y9GTA+V+E9tUz+Hq0BtGia3XlBc5oIXhUHu6r4uIin8
# Djvorssk6X4Q8eidvGk7rMeK7PPDajMXL+UF25cxSe1CKjE2W7YPuun++pxJdBxx
# 33qBkhOxAWlGmkpQiaZlMCaVd955p4zGwFwy4HN2qb43XSGBfVXTdpRsU2xS9kBI
# 3SfU0MjV6VxvC8MByqIte6zUVsfGZOri0PiEyjSsHylxs8Dq4is2IAxbuJz7XL6/
# YgbXehs9+6En2pUi0P6VmjGZkGhj7NhuRlVxyaEUREtFRtcTLzi02G/+HNGFeG1q
# MHAQIaEEk7Lq/pCI43kogXM9WaBiG5xQOZoBFjHjVaGXZmyqW/dGZZMQ2HnPwtbr
# 2PxlyMb19spjNv5LxT4xxpSObMWNkcsn3ioRTudBB0w2w9UCAwEAAaOCAgYwggIC
# MB8GA1UdIwQYMBaAFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB0GA1UdDgQWBBQFykiU
# R44B4I4Fw5s9IT7jevJw4TAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYB
# BQUHAwMwgbUGA1UdHwSBrTCBqjBToFGgT4ZNaHR0cDovL2NybDMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAy
# MUNBMS5jcmwwU6BRoE+GTWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dFRydXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3JsMD4G
# A1UdIAQ3MDUwMwYGZ4EMAQQBMCkwJwYIKwYBBQUHAgEWG2h0dHA6Ly93d3cuZGln
# aWNlcnQuY29tL0NQUzCBlAYIKwYBBQUHAQEEgYcwgYQwJAYIKwYBBQUHMAGGGGh0
# dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBcBggrBgEFBQcwAoZQaHR0cDovL2NhY2Vy
# dHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0
# MDk2U0hBMzg0MjAyMUNBMS5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsF
# AAOCAgEAd5emY3HikoSs9iSxWRDnkMr7eAvFljY/oc83+UkHKhwWt7AoV6kIGdF9
# DOPn6QB2JxQ+HtnapC+k4yn0nEuB7veDEsk8i9jXMcj/Pg6MQOP9Bz0tao+e46gE
# Iol/dZfTBHLS5pHREF6d4FU3UQJ2C6y+jx6JlpCGsrAh1NfRrvNJ2L4dMAwkYwKy
# Vds8zaAGym78u98O3I2m6bNyTcECOqzxS/EEco3Ydr6cpi5Hq/+PHGza61Lkp/Z7
# ziuBSthzqZxd4mbSr58VhGnE7zerIySnFX8oKerFeFwj9Rnan2Pr1AXPEp++mxD4
# vk76QCJkd3VLDDxUoiuFPkW/OsbnZogd2HmJwlMUSDCWVeBP9HAL+QHbR2mcpfgv
# WRy04JnMyr4CEkuL/sdq6RfRAqPB78+SmZ/Eog/hr0yC6MqnsTh4gjq4sE7kv3X2
# +Lr/b8WKUIUCqlFdtGpxx3MD6X/F0qADJpBMtArJZwpbB9Nore3pBlhVU96ndP8b
# zW98rhbQqMaYudGAtoJM56gCTym/YTJpllGP0y7vR73UpwRhr6Z1XKRTfjPFcJK6
# M7Qve/0zU5+S1WnlOcOGU/BgWVav2UK4DLhtPlFHmpX+H+j9PKmf/SiGc0kiFDjJ
# SDwY6PL38/396sSXq5PPM0J4VBIW7sRqPf9rROCcoytXcT1u8dowggbCMIIEqqAD
# AgECAhAFRK/zlJ0IOaa/2z9f5WEWMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYT
# AlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQg
# VHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMjMw
# NzE0MDAwMDAwWhcNMzQxMDEzMjM1OTU5WjBIMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xIDAeBgNVBAMTF0RpZ2lDZXJ0IFRpbWVzdGFtcCAy
# MDIzMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAo1NFhx2DjlusPlSz
# I+DPn9fl0uddoQ4J3C9Io5d6OyqcZ9xiFVjBqZMRp82qsmrdECmKHmJjadNYnDVx
# vzqX65RQjxwg6seaOy+WZuNp52n+W8PWKyAcwZeUtKVQgfLPywemMGjKg0La/H8J
# JJSkghraarrYO8pd3hkYhftF6g1hbJ3+cV7EBpo88MUueQ8bZlLjyNY+X9pD04T1
# 0Mf2SC1eRXWWdf7dEKEbg8G45lKVtUfXeCk5a+B4WZfjRCtK1ZXO7wgX6oJkTf8j
# 48qG7rSkIWRw69XloNpjsy7pBe6q9iT1HbybHLK3X9/w7nZ9MZllR1WdSiQvrCuX
# vp/k/XtzPjLuUjT71Lvr1KAsNJvj3m5kGQc3AZEPHLVRzapMZoOIaGK7vEEbeBlt
# 5NkP4FhB+9ixLOFRr7StFQYU6mIIE9NpHnxkTZ0P387RXoyqq1AVybPKvNfEO2hE
# o6U7Qv1zfe7dCv95NBB+plwKWEwAPoVpdceDZNZ1zY8SdlalJPrXxGshuugfNJgv
# OuprAbD3+yqG7HtSOKmYCaFxsmxxrz64b5bV4RAT/mFHCoz+8LbH1cfebCTwv0KC
# yqBxPZySkwS0aXAnDU+3tTbRyV8IpHCj7ArxES5k4MsiK8rxKBMhSVF+BmbTO776
# 65E42FEHypS34lCh8zrTioPLQHsCAwEAAaOCAYswggGHMA4GA1UdDwEB/wQEAwIH
# gDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMCAGA1UdIAQZ
# MBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATAfBgNVHSMEGDAWgBS6FtltTYUvcyl2
# mi91jGogj57IbzAdBgNVHQ4EFgQUpbbvE+fvzdBkodVWqWUxo97V40kwWgYDVR0f
# BFMwUTBPoE2gS4ZJaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFtcGluZ0NBLmNybDCBkAYIKwYBBQUH
# AQEEgYMwgYAwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBY
# BggrBgEFBQcwAoZMaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFtcGluZ0NBLmNydDANBgkqhkiG
# 9w0BAQsFAAOCAgEAgRrW3qCptZgXvHCNT4o8aJzYJf/LLOTN6l0ikuyMIgKpuM+A
# qNnn48XtJoKKcS8Y3U623mzX4WCcK+3tPUiOuGu6fF29wmE3aEl3o+uQqhLXJ4Xz
# jh6S2sJAOJ9dyKAuJXglnSoFeoQpmLZXeY/bJlYrsPOnvTcM2Jh2T1a5UsK2nTip
# gedtQVyMadG5K8TGe8+c+njikxp2oml101DkRBK+IA2eqUTQ+OVJdwhaIcW0z5iV
# GlS6ubzBaRm6zxbygzc0brBBJt3eWpdPM43UjXd9dUWhpVgmagNF3tlQtVCMr1a9
# TMXhRsUo063nQwBw3syYnhmJA+rUkTfvTVLzyWAhxFZH7doRS4wyw4jmWOK22z75
# X7BC1o/jF5HRqsBV44a/rCcsQdCaM0qoNtS5cpZ+l3k4SF/Kwtw9Mt911jZnWon4
# 9qfH5U81PAC9vpwqbHkB3NpE5jreODsHXjlY9HxzMVWggBHLFAx+rrz+pOt5Zapo
# 1iLKO+uagjVXKBbLafIymrLS2Dq4sUaGa7oX/cR3bBVsrquvczroSUa31X/MtjjA
# 2Owc9bahuEMs305MfR5ocMB3CtQC4Fxguyj/OOVSWtasFyIjTvTs0xf7UGv/B3cf
# cZdEQcm4RtNsMnxYL2dHZeUbc7aZ+WssBkbvQR7w8F/g29mtkIBEr4AQQYoxggXT
# MIIFzwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5j
# LjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNB
# NDA5NiBTSEEzODQgMjAyMSBDQTECEAtM2jwxmwpOSEU2+56DSsAwDQYJYIZIAWUD
# BAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMx
# DAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkq
# hkiG9w0BCQQxIgQgmk/l3pdNVF4sSJS2oARjeETs2U6Oqv6JfZ7LKlgmtP8wDQYJ
# KoZIhvcNAQEBBQAEggGAP4RJO0Hfj+SQCpEzdnuKdlJ6SdwKRSD70AcbIDvGza60
# m8oIbs9Hw3x9iD681NE/s/cc9IkNKvY89xSHwxpZeuYfV+CdY7Qn0NvwEKBGncEu
# PTxaqsvG6u+Ej3jz4wM5f/B4BT4m7pfRxqBKx+fira+hOJEc0uuyRgCgZr5jisB5
# ZTv5NA3fSTdFTJoMoMmckVgmwICg+LbjR+wyHJmq1y2j/BReDU/cDNz/iMK0lPG5
# lGgKDsoEEp0K/PHn3Cv30gqxMEJbLKNxMjlJTYh0pEKNZF9e+EYk57BDqytlmWEF
# gUblvJieJZVjs0umcEHwF/7ON3wnUz49GXinIjb0RYU4troS2pHbFzaKAtX2lQqS
# W/N/fv0FAHQQ5TKg1Xl+06etg/JxaMdtxuRDQnQ2jskE+NUBtJTh6WP9mgH9inJt
# eJOdL2rhfV36NcUkx96CavZwSvxz0dUbek3PTV5NcB1HIvRk0xuxoPxUzlcmS2gW
# 3GmirNWQqy1llGPIaDP+oYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcw
# YzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQD
# EzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGlu
# ZyBDQQIQBUSv85SdCDmmv9s/X+VhFjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3
# DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIzMDgyMzE4MTEzM1ow
# LwYJKoZIhvcNAQkEMSIEIKTKjEFWpa5ATzmiitZcpyve+AmujvtC40xmsOkVHEFC
# MA0GCSqGSIb3DQEBAQUABIICAItkwoD52Z5NGHe8ibpvZTlkZSVrb5N+Q7fHRybN
# UQ6LMKd12CrKEHj0av9R14Xkm3aZ6M0g0+OGGfSCxPvd9KliTbOZYf3PQ2SUi/4O
# zsmEEMztK0WrGIyq/PmGgsbbe+yGeNnBVDJ41C00usanWkmH1qpv+A1tPJV18sI/
# L//U3gOMLVsmCq83trFT0/WwiN0CuORcT959oXzLz6mWnGRynphnM/kmyHJIr0aR
# KTVx74AHE3vk03FYZ9WE059Of+IP0S7ymtBYV6fI9gGUeWMfaXkfJ0sBIitHUIZy
# hc4Mbk5Sy9oN2JFGGiDz5eKr/+fBocmwaeKElgmvNCKBPXO+PbIBUv/BSJoVJiMZ
# Ib5IFffeH3bNBdKwwlJ8RPjvn/hyPZKoUkVdmOTiYXxbMhMydivlGjnBiyv04O0X
# ez7ibkbYAQBqgGviad7NHA20YudHqdvftU4hxvgjsh/spBXuVWFAo/Jq8HyBnw1H
# JRt8vtYpMbMWMHPxXGzr13ay9YlhWEO+IUyOlCjUWcwbOoE47mn32zKs61e3qKJc
# 4WJ2v1JZcDvtkInFatmbppfJk4Dm3ZIjFgDezxoTvGso+jkuWHGpqGAjHYqu+xx5
# Ey4Rh1NJ4PIHxh6Jw1GS0llqYfwxZZzREpvxPnCNVixCXPLeOQPOGdSDLKwDxYvk
# gCPg
# SIG # End signature block
