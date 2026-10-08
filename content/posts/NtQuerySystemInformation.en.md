---
title: Process Enumeration-2
date: 2026-10-05
draft: false
author: 0xGently
tags:
  - enumeration
---
## Process Enumeration 
### Finding the Target's PID Value (NtQuerySystemInformation)

During malware development ,we generally need a legitimate process that already exists on the system (such as notepad.exe, explorer.exe, or svchost.exe) to hide our payload in memory or to execute various techniques in a stable manner.

This is exactly where we refer to the practice of listing the currently active processes on the system to extract our target's PID value or to collect telemetry about processes, generally known as Process Enumeration. In our previous article, we looked step-by-step at how to perform this operation from scratch using Windows’ standard `EnumProcesses` API. However, in the cybersecurity world, there are always more complex and harder-to-learn ways...

In this article, we are diving much deeper and shifting our focus directly to the undocumented `NtQuerySystemInformation` function hidden within `ntdll.dll`. The reason we do this is due to security mechanisms like AV and EDR. Modern security products monitor Windows' high-level DLL files and APIs very strictly by hooking into them. They don't just stop at monitoring; they can manipulate calls they deem suspicious and sabotage our operation before it even begins. That is why, in order to avoid getting caught by these hooks and to fly under the detection radars, the more low-level we operate, the better.

**The first step** is getting the handle of the ntdll module:

```c
HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
```

We don't use `LoadLibrary` here because `ntdll.dll` is already loaded into memory in every process. No process on Windows can start without it. `GetModuleHandle` only returns a reference to a module that is already loaded, so no extra loading is needed.

**In the second step**, we resolve the address of the function:

```c
PFN_NtQuerySystemInformation NtQuerySystemInformation =
    (PFN_NtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
```

This function is not officially documented by Microsoft, so it can't be linked statically. Its name exists in `ntdll.lib`, but its prototype is missing (or completely absent) in the header files. That is why we have to resolve it at runtime, using a function pointer type that we define ourselves:

```c
typedef NTSTATUS (NTAPI *PFN_NtQuerySystemInformation)(
    ULONG, PVOID, ULONG, PULONG);
```

In this line, we teach the compiler the **template** of a function that it doesn't officially know yet. Let's look at what each part does:

- **`typedef NTSTATUS (NTAPI *PFN_NtQuerySystemInformation)`**: Tells the compiler that we are defining a new function type called `PFN_NtQuerySystemInformation`, which returns an `NTSTATUS` (an error/success code).
- **1st parameter (`ULONG`)**: A number that tells which type of system information we want from the kernel. To get the process list, we will send `SystemProcessInformation`, which is `5`.
- **2nd parameter (`PVOID`)**: The address of the empty memory area (buffer) that we allocated beforehand, where the kernel will write the system information.
- **3rd parameter (`ULONG`)**: The size of this memory area in bytes.
- **4th parameter (`PULONG`)**: The address of a variable. If the memory we gave is not enough, the Windows kernel writes the real size it needs ("I actually need this many bytes") into this variable and returns it to us.

If `GetProcAddress` fails (for example, if it can't find `ntdll.dll`, can't find the target function, or any other problem happens), we exit directly without using the function.

```c
if (!NtQuerySystemInformation) return FALSE;
```

In practice, this check almost never triggers, because ntdll and this function exist in every version of Windows. But it is a step that should not be skipped from the defensive programming point of view.

The first problem we face before calling `NtQuerySystemInformation` is this: we don't know in advance how big the buffer should be to hold the information of all processes in the system. The number of running processes changes all the time, so we can't think "there are N processes right now, so let me allocate N times the struct size". Moreover, new processes can even start while we are still creating the buffer.

To solve this problem, we build a loop that works with a try-grow-retry logic. First, we choose a reasonable starting size:

```c
ULONG size = 1 << 16; // 64 KB initial estimate
PVOID buffer = NULL;
NTSTATUS status;
```

In each step of the loop, we first free the previous buffer and then allocate a new one:

```c
do {
    if (buffer) HeapFree(GetProcessHeap(), 0, buffer);
    buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (!buffer) return FALSE;
```

We use `HeapAlloc`, not `malloc`, because we work directly on the process heap. We also use the `HEAP_ZERO_MEMORY` flag to zero the allocated memory, which prevents unused fields in the struct from holding random values.

Then we make the main call:

```c
    status = NtQuerySystemInformation(SystemProcessInformation, buffer, size, &size);
    if (status == STATUS_INFO_LENGTH_MISMATCH) size += (1 << 14);
} while (status == STATUS_INFO_LENGTH_MISMATCH);
```

There are two critical points here. The first one is that the `size` parameter is used as both input and output: we send it to the function as "I have this much space" (3rd parameter), and the function writes "I actually needed this much space" into the same variable (4th parameter).  
The second one is that when we get `STATUS_INFO_LENGTH_MISMATCH`, we don't only use the size reported by the function, we also add an extra 16 KB on top of it. The reason is this: new processes may start in the system even within a few milliseconds while our loop is running, so even if we give the exact size that was needed, the next call may still fail because of insufficient space. This extra margin largely prevents a second mismatch round.

The loop ends when `STATUS_INFO_LENGTH_MISMATCH` is no longer returned. Finally, we check for a real error:

```c
if (!NT_SUCCESS(status)) {
    HeapFree(GetProcessHeap(), 0, buffer);
    return FALSE;
}
```

The `NT_SUCCESS` macro checks whether the NTSTATUS value is in the success range. Of course, if an error is returned here, we don't forget to free the memory we allocated before.

At this point, we have a correctly sized memory area in `buffer` that holds the information of all system processes.

The data returned from `NtQuerySystemInformation` is not a classic array. Each `SYSTEM_PROCESS_INFORMATION` record carries the offset (in bytes) to the next record inside itself. So what we actually have is a linked-list-like structure, but laid out one after another in memory. We start by pointing to the first element:

```c
PSYSTEM_PROCESS_INFORMATION entry = (PSYSTEM_PROCESS_INFORMATION)buffer;
```

And inside an infinite loop, we move forward using the `NextEntryOffset` field:

```c
if (entry->NextEntryOffset == 0) break;
entry = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)entry + entry->NextEntryOffset);
```

When `NextEntryOffset` is zero, it means we reached the last element of the list, so we exit the loop. Here we do the pointer arithmetic by casting to `PBYTE`, because the offset is given in bytes. If we did pointer arithmetic on the `entry` type, we would jump by the size of the struct, which would be wrong.

In each record, the name of the process is kept in the `ImageName` field as a `UNICODE_STRING`. Before doing the comparison, we need a safety check, because this field can be empty for some special processes like Idle and System:

```c
if (entry->ImageName.Buffer && _wcsicmp(entry->ImageName.Buffer, target_name) == 0) {
```

We use `_wcsicmp` because the comparison must be case-insensitive. The Windows file system is not case-sensitive, so `System.exe` and `system.exe` will be treated as the same process.

A name match alone is not enough. If someone puts a binary with exactly the same name as a system process in a place like `C:\Users\Public\notepad.exe`, a check that looks only at the name would think it is a legitimate service. That is why we also verify the real disk path for every matching PID.

First, we get the PID from the struct:

```c
DWORD pid = (DWORD)(ULONG_PTR)entry->UniqueProcessId;
```

`UniqueProcessId` is actually defined as a `HANDLE` type, but in reality it carries a PID value. That is why we first cast it to `ULONG_PTR`, then to `DWORD`.

To get the path information, we need to open the process, but here we come to one of the most critical rules: we never ask for `PROCESS_ALL_ACCESS`.

```c
HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
```

`PROCESS_QUERY_LIMITED_INFORMATION` came with Windows Vista. It is the lowest-level access right, only for querying, and it gives no permission to interfere with the process. It is enough for functions like `QueryFullProcessImageNameW`. Asking for `PROCESS_ALL_ACCESS` is both unnecessary and raises suspicion about why a normal program needs such wide permissions, which should not happen.

If the handle was opened successfully, we query the real disk path:

```c
WCHAR path[MAX_PATH];
DWORD len = MAX_PATH;
if (QueryFullProcessImageNameW(hProc, 0, path, &len) &&
    _wcsnicmp(path, sysDir, sysDirLen) == 0 && path[sysDirLen] == L'\\') {
    *out_pid = pid;
    found = TRUE;
}
```

Here we look for two conditions at the same time: First, with the `_wcsnicmp` function, we check whether the beginning of the file path matches `sysDir` (that is, `C:\Windows\System32`). Right after that, we check whether there is a `\` character at the position `path[sysDirLen]`.

If we don't do this second check, paths like `C:\Windows\System32Config\update.exe` or `C:\Windows\System32-Drivers\update.exe`, which are created to fool a simple string match, can pass this filter because of the prefix match. Finding a `\` right at the point where the string ends guarantees that the process is running inside that system directory itself, not in another folder with a similar name.

We close the handle as soon as we are done with it, and we don't carry it into the rest of the loop:

```c
CloseHandle(hProc);
```

If you want, you can find the full code at https://github.com/0xGently/Malware-Dev-Analysis-Library/blob/main/Enumeration/NtQuerySystemInformation/NtQuerySystemInformation.c address. That was our topic, thank you for reading.

