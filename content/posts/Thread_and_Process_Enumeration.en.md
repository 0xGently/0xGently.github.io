---
tags:
  - enumeration
title: Thread_and_Process_Enumeration
date: 2026-10-17
draft:
author: 0xGently
---
In this article, I will explain how to gather information about processes or threads using the `CreateToolhelp32Snapshot` function.

  If we want to interact with a target process in the tools we develop or the malware we write, we first need to pinpoint exactly where that process resides in the system.
 
We will divide our operation into two main stages.
First, starting with plain text (such as a process name like `notepad.exe`), we will scan all the processes on the system and extract our target's unique identification number, namely its PID. In the second stage, using this PID we obtained, we will dive into the target process and capture a valid thread that we can manipulate or hijack.

In short, in this section, we will see practically through code how to enumerate processes and threads in the system using the most fundamental APIs, and how to obtain the necessary handles from the operating system while doing so.

**NOTE:** If you want to access all the functions mentioned in this topic, you can find them at https://github.com/0xGently/Malware-Dev-Analysis-Library/tree/main/Enumeration/CreateToolhelp32Snapshot.
### Step 1: Process Enumeration via function

First, we will look at how to get the PID and Handle of our target among the running processes in the system. Let's examine the code step by step and understand what goes on in the background.

Our first move is to obtain the current list of all processes in the system:

```c
HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
```

Here, we take a snapshot of the system using the `CreateToolhelp32Snapshot` API. If we cannot retrieve this list due to security or another reason, the function returns `FALSE` right from the start and aborts the operation.

Next, we set up the struct that will hold the data as we iterate through this list:

```c
PROCESSENTRY32W stEntry = { 0 };
stEntry.dwSize = sizeof(PROCESSENTRY32W);
```

Here, we created the `PROCESSENTRY32W` structure and initialized it to zero. The `dwSize` assignment on the next line is a critical detail. When working with Windows APIs, we need to notify the API of the relevant struct's size in memory; otherwise, the functions will usually throw an error.
Now it's time to enter the loop and compare the names in the list with our target:

```c
if (lstrcmpiW(stEntry.szExeFile, wszTargetName) == 0) {
    *pdwPid = stEntry.th32ProcessID;
```

In each iteration of the loop, we compare the current process's name (`szExeFile`) with the name we provided (`wszTargetName`). If we find a match, we write the target's ID (`th32ProcessID`) to the pointer to pass it back to where we called the function.

```c 
*phTarget = OpenProcess(PROCESS_ALL_ACCESS, FALSE, stEntry.th32ProcessID);
if (*phTarget == NULL) {
    break;
}
```

After finding the target, we request full access (`PROCESS_ALL_ACCESS`) over the process using the `OpenProcess` API. If the target process is opened successfully, we obtain the handle we need.

We have a critical check here: If the process cannot be opened (returns `NULL`) due to a lack of privileges or system protections, we terminate the loop with the `break` statement. Normally, a system might have multiple processes with the same name but different PIDs (like Chrome tabs). In advanced scenarios, if the first process fails, trying other processes with the same name using `continue` is a better approach. However, to simplify the topic and keep the flow straightforward in this educational article, we choose to stop the search (`break`) if we fail on the first matching process.

**Note:** In real-world scenarios, instead of requesting full access like `PROCESS_ALL_ACCESS`, requesting only the specific permissions for the operation you will perform (for example, only read/write permissions) is always a much better approach both to avoid getting caught by security mechanisms and for stealth.

Finally, we need to clean up the open resources when we are done:
```c
CloseHandle(hSnapshot);
```

To prevent a memory leak, we close the snapshot handle we obtained at the very beginning, returning the resource to the operating system and completing the operation.

### Step 2: Thread Enumeration via function

Now that we have successfully found the target process, it's time to capture a thread running inside that process.

First of all, we start with a small safety precaution:
```c
if (pdwTid) *pdwTid = 0;
if (phThread) *phThread = NULL;
```

We clear out the pointers that come to us as external parameters. If these variables contain residual garbage data from before, it is always a good practice to initialize them to zero right from the start so they don't cause headaches later.

Then, similar to what we did in the first function, we take a snapshot of the system:
```c
hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
stEntry.dwSize = sizeof(THREADENTRY32);
```

This time, we use the `TH32CS_SNAPTHREAD` flag instead of `TH32CS_SNAPPROCESS`. This is because our goal is not to list processes, but all the active threads in the system at that moment. We again don't forget to specify the `THREADENTRY32` struct size so that the API runs smoothly.

We now have all the threads in the system. Now we need to grab the one that belongs to our process:

```c
if (stEntry.th32OwnerProcessID == dwProcessId) {
    *pdwTid = stEntry.th32ThreadID;
```

The logic here is simple: We iterate through all the threads with a loop and ask, "Is the process ID that owns this thread (`th32OwnerProcessID`) the same as the `dwProcessId` we are looking for?" Once a match is found, we write the thread's own ID (`th32ThreadID`) to the pointer to export it.

Now it's time to open this thread and take control:
```c
*phThread = OpenThread( THREAD_ALL_ACCESS, FALSE, stEntry.th32ThreadID);
```

Here again, we are using almost the exact same function as above. Instead of asking for full access like `PROCESS_ALL_ACCESS`, requesting only the permissions specific to the operation you will perform is again much better. We are leaving it like this for now.

And finally, that critical error-checking point we resolved earlier:
```c
if (*phThread == NULL) {
    CloseHandle(hSnapshot);
    return FALSE;
}
```

If `OpenThread` fails (due to lack of privileges, etc.), we don't just quietly walk away. To avoid leaving a dangling handle in the system (which causes memory leaks), we cleanly shut down shop by calling `CloseHandle(hSnapshot)` and report our failure (`FALSE`). (Note that if we can't get permission on the first thread, we return `FALSE` immediately. If you want to try the other threads of the process, you can build a `continue` logic here instead of `return FALSE`, just like we mentioned in the previous function.)

To wrap up, we've examined step-by-step how to dive into the system's background and safely acquire target processes and threads using these two fundamental functions. When working at the operating system level, requesting only the permissions we need and cleaning up open handles when we are done are the core tenets of safe coding.
