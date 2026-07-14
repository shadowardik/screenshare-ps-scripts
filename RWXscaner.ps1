param(
    [Parameter(Mandatory = $true)]
    [int]$ProcessId
)

Add-Type @"
using System;
using System.Runtime.InteropServices;

public static class Native
{
    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
    public const uint PROCESS_VM_READ = 0x0010;

    public const uint MEM_COMMIT = 0x1000;

    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint PAGE_GUARD = 0x100;
    public const uint PAGE_NOCACHE = 0x200;
    public const uint PAGE_WRITECOMBINE = 0x400;

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION64
    {
        public ulong BaseAddress;
        public ulong AllocationBase;
        public uint AllocationProtect;
        public uint __alignment1;
        public ulong RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
        public uint __alignment2;
    }

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(
        uint dwDesiredAccess,
        bool bInheritHandle,
        uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern int VirtualQueryEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        out MEMORY_BASIC_INFORMATION64 lpBuffer,
        uint dwLength);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@

$PROCESS_ACCESS = [Native]::PROCESS_QUERY_INFORMATION -bor [Native]::PROCESS_VM_READ

$hProcess = [Native]::OpenProcess($PROCESS_ACCESS, $false, [uint32]$ProcessId)

if ($hProcess -eq [IntPtr]::Zero) {
    Write-Error "Failed to open process PID $ProcessId"
    exit 1
}

$mbi = New-Object Native+MEMORY_BASIC_INFORMATION64
$mbiSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type]"Native+MEMORY_BASIC_INFORMATION64")

[UInt64]$address = 0
[UInt64]$total = 0
$count = 0

Write-Host ""
Write-Host ("{0,-18} {1,15} {2,12}" -f "Adress", "Size", "MB")
Write-Host ("-" * 50)

while ($true)
{
$result = [Native]::VirtualQueryEx(
    $hProcess,
    [IntPtr]::new([Int64]$address),
    [ref]$mbi,
    [uint32]$mbiSize)

    if ($result -eq 0) {
        break
    }

    $prot = $mbi.Protect -band (-bnot (
        [Native]::PAGE_GUARD `
        -bor [Native]::PAGE_NOCACHE `
        -bor [Native]::PAGE_WRITECOMBINE))

    if (($mbi.State -eq [Native]::MEM_COMMIT) -and
        ($prot -eq [Native]::PAGE_EXECUTE_READWRITE))
    {
        $count++
        $total += $mbi.RegionSize

        "{0,-18} {1,15:N0} {2,12:N2}" -f `
            ("0x{0:X16}" -f $mbi.BaseAddress),
            $mbi.RegionSize,
            ($mbi.RegionSize / 1MB)
    }

    if ($mbi.RegionSize -eq 0) {
        break
    }

    [UInt64]$next = [UInt64]$mbi.BaseAddress + [UInt64]$mbi.RegionSize

    if ($next -le $address) {
        break
    }

    $address = $next
}

Write-Host ("-" * 50)
Write-Host ("Total : {0}" -f $count)

[Native]::CloseHandle($hProcess) | Out-Null
