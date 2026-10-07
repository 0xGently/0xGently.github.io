---
tags:
  - Enumeration
date: 2026-10-08
author: 0xGently
title: " Process Enumeration"
draft:
---
## Process Enumeration
### Finding the Target's PID Value (EnumProcesses)
When developing malware, we often need a legitimate running process (e.g., notepad.exe or explorer.exe) on the system to execute techniques like hiding or running our payload. We need to speak Windows' language and find the PID (Process ID) value of that process.

This process of listing the active processes on the system to find our target's PID or gather similar information about processes is generally called Process Enumeration. In this article, we will look step-by-step at how to do this from scratch using the standard Windows EnumProcesses API.

First, let's take a look at our function that brings the whole operation under one roof:

```c
BOOL FindSystem32Process(const wchar_t* target_name, DWORD* out_pid)
```

As you can see, it is a BOOL type function. It takes 2 parameters within itself.
1st requires the name of our target process (e.g., svchost.exe).
2nd exports the PID of the process we designated as the target.

Further down in the function, there is this part:
```c
DWORD pids[2048], bytes;
if (!EnumProcesses(pids, sizeof(pids), &bytes)) return FALSE;
```

Here, we create an array named `pids`. The EnumProcesses API retrieves all active PIDs on the system and populates this array. The `bytes` variable holds how much data was written into this array. We now have a massive pool containing the PIDs of all processes on the system.

Now we need to iterate through the PIDs in this pool one by one to find our actual target process. To do this, we start a loop:
```c
for (DWORD i = 0; i < bytes / sizeof(DWORD); i++) {
    if (!pids[i]) continue;

    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pids[i]);
    if (!h) continue;
```

With each iteration of the loop, we take the next PID and attempt to open it using the OpenProcess API. There is a very important point you need to pay attention to here: the privileges we request when opening the target process. Since we only need to read the process's name, we request the `PROCESS_QUERY_LIMITED_INFORMATION` privilege. If we unnecessarily requested `PROCESS_ALL_ACCESS` (full access), it would be a highly suspicious action for security solutions (EDR/AV). If the handle (`h`) is successfully acquired, we can now look inside that process.
Handle in hand, it's now time to find out which application is running behind this PID.
```c
wchar_t path[MAX_PATH];
DWORD size = MAX_PATH;
```

`wchar_t`: Because we are using Windows APIs that end with `W` (Wide), we must use `wchar_t` (2-byte wide character) which supports Unicode, instead of the standard `char` (1 byte).

`MAX_PATH`: This is a standard macro defined in the Windows operating system header files, and its value is 260. It specifies the maximum character limit a classic file path can take in Windows. So, we create an empty array (box) named `path` that can hold a maximum of 260 characters.

`size`: To be able to tell the API, "I have 260 characters of space available", we assign this value to a variable of type `DWORD` (32-bit unsigned integer).

```c
if (QueryFullProcessImageNameW(h, 0, path, &size)) {
```

This function takes the process handle (`h`) and writes the full file path into the `path` array we just created.

The miraculous event here is the `&size` part. We pass the `size` variable not directly, but by memory address (as a reference) by placing an `&` in front of it. Why? Because when the API finishes its job, it essentially says, "You gave me 260 characters of space, but I only used 35 characters of it," and writes the actual length of that process path directly back into this variable (In/Out parameter logic).

If this operation completes without error, the function returns `TRUE` (1), and we enter the `if` block.
```c
    wchar_t* name = wcsrchr(path, L'\\');
```

`wcsrchr` (Wide Character String Reverse Character): It is a string search function in the C standard library. Its purpose is to scan a string not from left to right, but from right to left (from end to beginning).

`L'\\'`: The character we are looking for is a backslash. Since `\` is an escape character in C, it is written twice as `\\` to represent itself. The `L` at the beginning indicates that this is a wide character (Unicode).

Let's say the data inside `path` is this: `C:\Windows\System32\notepad.exe`. `wcsrchr` starts from the far right, goes e, x, e, ., d... and stops at the first `\` sign it sees.
It does not return a string, but rather the memory address (pointer) of the exact point where that backslash is located. So, the `name` pointer is now pointing exactly to the `\notepad.exe` part.
```c
    name = name ? name + 1 : path;
```
This line contains C's famous ternary operator (`condition ? if_true : if_false`) and pointer arithmetic.
`name ?`: This means "If `name` is not null (i.e., if we managed to find a backslash)".

`name + 1`: This is where the real action happens. The `name` pointer was pointing to the `\` sign at the beginning of the `\notepad.exe` string. By saying `+ 1`, we shift the memory address one character to the right. This way, we skip that initial slash, and the pointer starts pointing only to the `notepad.exe` part. This is how we isolate the pure file name.

`: path`: If `wcsrchr` cannot find any backslash (this is technically highly unlikely but it's a rule of safe coding), the `name` pointer returns `NULL`. In this case, the condition is evaluated as false, and the operation after the colon (`:`) is executed: Treat whatever we have (the original `path`) as the pure name.

In the final stage, we check whether the name we found matches the target we are looking for.
```c
        if (_wcsicmp(name, target_name) == 0) {
            *out_pid = pids[i];
            CloseHandle(h);
            return TRUE;
        }
    }
    CloseHandle(h);
}
```
With `_wcsicmp`, we compare the name we have with our `target_name` without worrying about case sensitivity. If it matches, it means we found the target! It exports the PID value (`*out_pid = pids[i]`), cleans up the open handle (`CloseHandle`), and successfully finishes our search. If it doesn't match, the loop continues to examine the next PID.

Note: You can find the complete code described in this text at https://github.com/0xGently/Malware-Dev-Analysis-Library/blob/main/Enumeration/EnumProcesses/EnumProcesses.c

  