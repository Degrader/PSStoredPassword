﻿<#	
	===========================================================================
	 Created on:   	2/19/2019 11:56 AM
	 Created by:   	Jordan Colton
	 Organization: 	InterMountain ESD
	 Filename:     	PSStoredPassword
	-------------------------------------------------------------------------
	 Module Name: PSStoredPassword
	===========================================================================
#>

function Set-StoredPassword
{
<#
	.SYNOPSIS
		Accepts a plaintext password and stores it as a "secure credential" on disk as type [System.Security.Cryptography.ProtectedData].
	.DESCRIPTION
		Accepts a plaintext password and stores it as a "secure credential" on disk as type [System.Security.Cryptography.ProtectedData]. Scoping (CurrentUser, LocalMachine)
		and output paths are user changeable.
	.PARAMETER Password
		Plain text password to be secured on disk
	.PARAMETER Path
		Output path for secured password. Defaults to "$env:USERPROFILE\Desktop\secure.bin"
	.PARAMETER EntropyPath
		Output path for entropy data. Defaults to "$env:USERPROFILE\Desktop\ent.bin"
	.PARAMETER Scope
		Scope of ProtectedData type. CurrentUser or LocalMachine are the two accepted values. CurrentUser is the default value.
	.EXAMPLE
		PS C:\> Set-StoredPassword "My awesome password!"
	.EXAMPLE
		PS C:\> Set-StoredPassword "My awesome password!" -Scope "LocalMachine"
	.EXAMPLE
		PS C:\> Set-StoredPassword -Password "My awesome password!" -Path "D:\Scripts\EpicScript\secure.bin" -EntropyPath "D:\Scripts\EpicScript\ent.bin"
	.EXAMPLE
		PS C:\> Set-StoredPassword -Password "My awesome password!" -Path "D:\Scripts\EpicScript\secure.bin" -EntropyPath "D:\Scripts\EpicScript\ent.bin" -Scope "LocalMachine"
	.INPUTS
	.OUTPUTS
		Secured password stored as type byte, entropy data stored as type byte.
	.NOTES
		For more information about advanced functions, call Get-Help with any
		of the topics in the links listed below.
	.LINK
		about_modules
	.LINK
		about_functions_advanced
	.LINK
		about_comment_based_help
	.LINK
		about_functions_advanced_parameters
	.LINK
		about_functions_advanced_methods
#>
	[CmdletBinding()]
	param (
		[Parameter(Position = 0, Mandatory = $true)][System.String]$Password,
		[Parameter(Position = 1, Mandatory = $false)][System.String]$Path = "$env:USERPROFILE\Desktop\secure.bin",
		[Parameter(Position = 2, Mandatory = $false)][System.String]$EntropyPath = "$env:USERPROFILE\Desktop\ent.bin",
		[Parameter(Position = 3, Mandatory = $false)][System.String]$Scope = "CurrentUser"
	)
	begin
	{
		try
		{
			#Validate Parameters
			if ($Password -eq $null -or $Password -eq "")
			{
				Write-Verbose "Checking for null or empty password"
				Write-Error "Password cannot be empty/null." -ErrorAction Stop -Category InvalidArgument
			}
			if ($Scope -ne "CurrentUser" -or $Scope -ne "LocalMachine")
			{
				Write-Verbose "Checking for null or empty scope"
				Write-Error "Invalid scope specified. Please specify `"CurrentUser`" or `"LocalMachine`". Default is `"CurrentUser`"." -Category InvalidArgument -ErrorAction Stop
			}
		}
		catch
		{ }
	}
	process
	{
		try
		{
			Add-Type -assembly System.Security
			
			Write-Verbose "Generating entropy data"
			#randomize entropy
			$entropy = [byte[]]((Get-Random -Minimum 1 -Maximum 9), (Get-Random -Minimum 1 -Maximum 9), (Get-Random -Minimum 1 -Maximum 9), (Get-Random -Minimum 1 -Maximum 9), (Get-Random -Minimum 1 -Maximum 9))
			Write-Verbose "Storing entropy data in file on disk"
			Write-Verbose "OutputPath: $EntropyPath"
			$entropy | Set-Content -Path $EntropyPath -Encoding Byte -Force
			
			#convert password to bytes for encryption
			Write-Verbose "Converting plaintext password into bytes"
			$passwordBytes = [System.Text.Encoding]::Unicode.GetBytes("$Password")
			#set proper scope data type based on supplied string
			Write-Verbose "Scope: $Scope"
			if ($Scope -eq "CurrentUser")
			{
				Write-Verbose "Setting scope to [System.Security.Cryptography.DataProtectionScope]::CurrentUser"
				$dataProtectionScope = [System.Security.Cryptography.DataProtectionScope]::CurrentUser
			}
			if ($Scope -eq "LocalMachine")
			{
				Write-Verbose "Setting scope to [System.Security.Cryptography.DataProtectionScope]::LocalMachine"
				$dataProtectionScope = [System.Security.Cryptography.DataProtectionScope]::LocalMachine
			}
			
			#encrypt data
			Write-Verbose "Encrypting password"
			$encrytpedData = [System.Security.Cryptography.ProtectedData]::Protect($passwordBytes, $entropy, $dataProtectionScope)
			#store encrypted data on disk
			Write-Verbose "Storing encrypted password on disk"
			Write-Verbose "OutputPath: $Path"
			$encrytpedData | Set-Content -Path $Path -Encoding Byte -Force
		}
		catch
		{ }
	}
	end
	{
		try
		{
			
		}
		catch
		{ }
	}
}
Export-ModuleMember -Function Set-StoredPassword

function Get-StoredPassword
{
<#
	.SYNOPSIS
		Gets a stored password (typically using Set-StoredPassword), applies entropy and unprotects the data.
	.DESCRIPTION
		Gets a stored password (typically using Set-StoredPassword), applies entropy and unprotects the data.
		Returns password as [System.String]
	.PARAMETER Path
		Input path for secured password.
	.PARAMETER EntropyPath
		Input path for entropy data.
	.PARAMETER Scope
		Scope of ProtectedData type. CurrentUser or LocalMachine are the two accepted values. CurrentUser is the default value.
	.EXAMPLE
		PS C:\> Get-StoredPassword -Path "D:\Scripts\EpicScript\secure.bin" -EntropyPath "D:\Scripts\EpicScript\ent.bin"
	.INPUTS
		Two files, both of type byte, one containing protected password data, the other containing the entropy data used for protection.
	.OUTPUTS
		Returns stored password as [System.String]
	.NOTES
		For more information about advanced functions, call Get-Help with any
		of the topics in the links listed below.
	.LINK
		about_modules
	.LINK
		about_functions_advanced
	.LINK
		about_comment_based_help
	.LINK
		about_functions_advanced_parameters
	.LINK
		about_functions_advanced_methods
#>
	[CmdletBinding()]
	param (
		[Parameter(Position = 0, Mandatory = $true)][System.String]$Path,
		[Parameter(Position = 1, Mandatory = $true)][System.String]$EntropyPath,
		[Parameter(Position = 2, Mandatory = $false)][System.String]$Scope = "CurrentUser",
		[Parameter(Position = 3, Mandatory = $false)][system.Boolean]$AsPlainText = $false
	)
	begin
	{
		try
		{
			#Validate parameters
			if ((Test-Path $Path) -eq $false)
			{
				Write-Error "Provided path is invalid. No file exists at $Path" -Category InvalidArgument -ErrorAction Stop
			}
			if ((Test-Path $EntropyPath) -eq $false)
			{
				Write-Error "Provided entropy path is invalid. No file exists at $EntropyPath" -Category InvalidArgument -ErrorAction Stop
			}
			if ($Scope -notlike "CurrentUser" -or $Scope -notlike "LocalMachine")
			{
				Write-Error "Invalid scope specified. Please specify `"CurrentUser`" or `"LocalMachine`". Default is `"CurrentUser`"." -Category InvalidArgument -ErrorAction Stop
			}
		}
		catch
		{ }
	}
	process
	{
		try
		{
			if ($Scope -eq "CurrentUser")
			{
				Write-Verbose "Setting scope to [System.Security.Cryptography.DataProtectionScope]::CurrentUser"
				$dataProtectionScope = [System.Security.Cryptography.DataProtectionScope]::CurrentUser
			}
			if ($Scope -eq "LocalMachine")
			{
				Write-Verbose "Setting scope to [System.Security.Cryptography.DataProtectionScope]::LocalMachine"
				$dataProtectionScope = [System.Security.Cryptography.DataProtectionScope]::LocalMachine
			}
			
			Write-Verbose "Getting encrypted data from file"
			Write-Verbose "InputPath: $Path"
			$protectedData = Get-Content -Encoding Byte $Path
			Write-Verbose "Getting entropy data from file"
			Write-Verbose "EntropyPath: $EntropyPath"
			$entropy = Get-Content -Encoding Byte $EntropyPath
			Write-Verbose "Decrypting data"
			$unprotectedData = [System.Security.Cryptography.ProtectedData]::Unprotect($protectedData, $entropy, "$dataProtectionScope")
			$password = [System.Text.Encoding]::Unicode.GetString($unprotectedData)
		}
		catch
		{ }
	}
	end
	{
		try
		{
			$password
		}
		catch
		{ }
	}
}
Export-ModuleMember -Function Get-StoredPassword
