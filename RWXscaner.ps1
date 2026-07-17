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

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(
        IntPtr hProcess,
        ulong lpBaseAddress,
        byte[] lpBuffer,
        uint nSize,
        out uint lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@

$PROCESS_ACCESS = [Native]::PROCESS_QUERY_INFORMATION -bor [Native]::PROCESS_VM_READ

$hProcess = [Native]::OpenProcess($PROCESS_ACCESS, $false, [uint32]$ProcessId)

if ($hProcess -eq [IntPtr]::Zero) {
    Write-Error "Failed to open process PID $ProcessId. Запущен ли скрипт от Администратора?"
    exit 1
}

$mbi = New-Object Native+MEMORY_BASIC_INFORMATION64
$mbiSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type]"Native+MEMORY_BASIC_INFORMATION64")

[UInt64]$address = 0
[UInt64]$total = 0
$count = 0
$regionsList = @()

Write-Host ""
Write-Host ("{0,-4} {1,-18} {2,15} {3,12}" -f "#", "Address", "Size", "MB")
Write-Host ("-" * 54)

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

        $regionInfo = [PSCustomObject]@{
            Index       = $count
            BaseAddress = $mbi.BaseAddress
            Size        = $mbi.RegionSize
        }
        $regionsList += $regionInfo

        Write-Host ("[{0,2}] {1,-18} {2,15:N0} {3,12:N2}" -f `
            $count,
            ("0x{0:X16}" -f $mbi.BaseAddress),
            $mbi.RegionSize,
            ($mbi.RegionSize / 1MB))
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

Write-Host ("-" * 54)
Write-Host ("Total : {0}" -f $count)
Write-Host ""

if ($count -gt 0) {
    Write-Host "Нажмите Ctrl+C для выхода." -ForegroundColor DarkGray
    $inputStr = Read-Host "Введите номер региона для дампа (из столбца #)"

    if ([int]::TryParse($inputStr, [ref]$null)) {
        $selectedIndex = [int]$inputStr
        
        if ($selectedIndex -ge 1 -and $selectedIndex -le $count) {
            $target = $regionsList[$selectedIndex - 1]
            
            $defaultName = "dump_pid$($ProcessId)_0x$($target.BaseAddress.ToString('X16')).bin"
            Write-Host ""
            Write-Host "Путь по умолчанию: $PWD\$defaultName" -ForegroundColor DarkGray
            $customPath = Read-Host "Куда сохранить дамп? (нажмите Enter для пути по умолчанию)"

            if ([string]::IsNullOrWhiteSpace($customPath)) {
                $savePath = Join-Path $PWD $defaultName
            } else {
                if ([System.IO.Path]::IsPathRooted($customPath)) {
                    $savePath = $customPath
                } else {
                    $savePath = Join-Path $PWD $customPath
                }
            }

            $sizeU32 = [uint32]$target.Size
            $buffer = New-Object byte[] $sizeU32
            $bytesRead = 0

            Write-Host ""
            Write-Host "Дампинг 0x$($sizeU32.ToString('X')) байт по адресу 0x$($target.BaseAddress.ToString('X16'))..." -ForegroundColor Cyan
            
            $success = [Native]::ReadProcessMemory($hProcess, $target.BaseAddress, $buffer, $sizeU32, [ref]$bytesRead)

            if ($success -and $bytesRead -gt 0) {
                if ($bytesRead -lt $buffer.Length) {
                    [Array]::Resize([ref]$buffer, $bytesRead)
                }
                
                try {
                    [System.IO.File]::WriteAllBytes($savePath, $buffer)
                    Write-Host "Успешно! Сохранено $bytesRead байт в: $savePath" -ForegroundColor Green
                } catch {
                    Write-Error "Не удалось сохранить файл. Ошибка: $_"
                }
            } else {
                $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Error "Сбой чтения памяти. Код ошибки (Win32): $err"
            }
        } else {
            Write-Warning "Регион с номером $selectedIndex не найден."
        }
    } elseif (-not [string]::IsNullOrWhiteSpace($inputStr)) {
        Write-Warning "Неверный ввод. Ожидалось число."
    }
} else {
    Write-Host "RWX регионы не найдены." -ForegroundColor Yellow
}

[Native]::CloseHandle($hProcess) | Out-Null