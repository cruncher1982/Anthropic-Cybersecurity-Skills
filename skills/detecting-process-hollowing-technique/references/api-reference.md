# API Reference: Process Hollowing Detection

## MITRE ATT&CK Mapping
- **Technique**: T1055.012 — Process Hollowing
- **Tactic**: Defense Evasion, Privilege Escalation

## Windows API Functions Used in Hollowing

### CreateProcessA/W (kernel32.dll)
```c
BOOL CreateProcessW(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,       // CREATE_SUSPENDED = 0x4
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);
```

### NtUnmapViewOfSection (ntdll.dll)
```c
NTSTATUS NtUnmapViewOfSection(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);
```

### VirtualAllocEx (kernel32.dll)
```c
LPVOID VirtualAllocEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect          // PAGE_EXECUTE_READWRITE = 0x40
);
```

### WriteProcessMemory (kernel32.dll)
```c
BOOL WriteProcessMemory(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T *lpNumberOfBytesWritten
);
```

### ResumeThread (kernel32.dll)
```c
DWORD ResumeThread(HANDLE hThread);
```

## Detection via Linux /proc Filesystem

### /proc/[pid]/exe
Symlink to the actual executable. If deleted or replaced, shows `(deleted)`.

### /proc/[pid]/maps
```
address           perms offset  dev   inode   pathname
00400000-00452000 r-xp 00000000 08:02 173521 /usr/bin/target
```

### /proc/[pid]/status
```
Name:   svchost
Pid:    1234
PPid:   567
VmExe:  512 kB
```

## Sysmon Event IDs for Detection

| Event ID | Description |
|----------|-------------|
| 1 | Process Create (check CREATE_SUSPENDED flag) |
| 8 | CreateRemoteThread |
| 10 | ProcessAccess (PROCESS_VM_WRITE + PROCESS_VM_OPERATION) |
| 25 | ProcessTampering (image replaced) |

## PowerShell Detection Queries

### Get process with module mismatch
```powershell
Get-Process | Where-Object {
    $_.Path -and $_.MainModule.FileName -and
    ($_.Path -ne $_.MainModule.FileName)
}
```

### Check for suspended child processes
```powershell
Get-CimInstance Win32_Process | Where-Object {
    $_.ExecutionState -eq 'Suspended'
} | Select-Object ProcessId, Name, ParentProcessId, CommandLine
```
