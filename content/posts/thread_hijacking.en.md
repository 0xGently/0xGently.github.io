---
title: Thread Hijacking
tags:
  - Execution
date: 2026-10-09
draft:
author: 0xGently
---
## Remote_Thread_Creation

In this article, I will talk about a technique in which we suspend a legitimate process, inject shellcode into its memory region, and then manipulate the RIP/EIP registers of its existing thread.

In the cybersecurity world, APIs such as `CreateRemoteThread` are generally the preferred choice for executing code inside a target process. However, these functions are monitored very tightly by security mechanisms (AV/EDR) and blocked instantly. Thread Hijacking, on the other hand, instead of creating a brand-new and suspicious thread from scratch, aims to "steal" the route of an already existing legitimate thread.

In the scenario we are going to develop, we will first launch a victim Windows process (for example, a tool under System32) with the `CREATE_SUSPENDED` flag. Then, we will allocate a region in the target process's memory and inject our malicious shellcode into that region.

In the next stage, using the `GetThreadContext` and `SetThreadContext` APIs, we will take the address stored in the `RIP` or `EIP` register — the register that holds the address of the next instruction the processor will execute — and replace it with the address of the malicious code we have allocated and written in the target process.

Finally, when we wake the thread up with `ResumeThread`, the operating system will carry on executing our code without suspecting a thing. I will cover the topic in `part 1-2-3`. Rather than going through the entire code, I will explain the functions I used in parts `1-2-3` in the order of the chain.

### Part 1

In the first part of our code, we define the main function that will launch the target process in a suspended state:

```c
BOOL StartSuspendedProcess(const char* exeName,
                           DWORD* outPid,
                           HANDLE* outProcess,
                           HANDLE* outThread)
```

This function asks us for the name of the application we are targeting (`exeName`, for example "notepad.exe"). Once it completes its job successfully, it will hand the PID value, the process handle, and the main thread handle of the newly created process back to us through the pointers we pass in.

Now let's step inside the function and see what happens, step by step:

```c
    if (!GetSystemDirectoryA(path, MAX_PATH)) {
        printf("Oops! GetSystemDirectoryA failed. ^_^: %lu\n", GetLastError());
        return FALSE;
    }
```

The API we are using here is called `GetSystemDirectoryA`. Its purpose is to locate Windows' System32 directory (usually `C:\Windows\System32`) and write it into the `path` buffer. Using this API instead of hardcoding (manually writing) the path directly into the code is a much sounder approach, because Windows is not always installed on the C drive. If something goes wrong, we grab the error number Windows returned to us with `GetLastError()`, print it to the screen, and terminate the function.

```c
    // C:\Windows\System32\<exeName>
    if (!PathAppendA(path, exeName)) {
        printf("Oops! PathAppendA failed. ^_^:\n");
        return FALSE;
    }
```

Next up is the `PathAppendA` function. This function's job is quite simple: to safely combine the System32 directory we just obtained with the file name it receives as a parameter. Once the operation is done, we end up with a clean full path (for example, `C:\Windows\System32\notepad.exe`).


And this is the point where the process is actually launched:  
```c
    if (!CreateProcessA(NULL, path, NULL, NULL, FALSE,
                        CREATE_SUSPENDED,  
                        NULL, NULL, &si, &pi))
    {
        printf("Oops! CreateProcessA failed. ^_^: %lu\n", GetLastError());
        return FALSE;
    }
```

Here, we launch the target program using the `CreateProcessA` API. It takes a lot of parameters, but the most critical one for us is the `CREATE_SUSPENDED` flag.

Our reason for passing this parameter is as follows: The process is created and the necessary memory regions are allocated, but the main thread is suspended instantly, before it starts executing any code (before entering the entry point). This gives us a huge advantage; the process has come up in a perfectly legitimate way, but since it has not started running yet, we have a wide time window in which we can inject our own malicious code into it. When the function succeeds, the PID and handle information we need is written into the `pi` (PROCESS_INFORMATION) structure and becomes ready for use.

That wraps up the first stage of the technique. The chain was simple:
1. Gather the required information from the user
2. Find the actual path of the System32 directory on the system  
3. Combine it with the program name provided by the user
4. Finally, launch that program with the `CREATE_SUSPENDED` flag using the required information.

### Part 2
Now that we have successfully launched the target process in a suspended state, it is time to secretly write our own malicious code into this application's memory.

Let's take a look at the beginning of the custom function we wrote for this job:

```c
BOOL WriteCodeToRemoteProcess(HANDLE hTarget,
                              unsigned char* code,
                              size_t codeSize,
                              void** outRemoteAddr)
```

The name of the main function we will use in this step is `WriteCodeToRemoteProcess`. The function asks us for the handle of the target process (`hTarget`), the location in memory of the malicious code we are going to inject (`code`), and the size of that code (`codeSize`). When the job is done, it will give us back the exact address in the target process's memory where the code was written, through the `outRemoteAddr` pointer. Our goal is to place the code into the target memory smoothly and safely.

First, we allocate a region inside the target process.

```c
    remoteBase = VirtualAllocEx(hTarget, NULL, codeSize,
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_READWRITE);
```

The API we are using here is called `VirtualAllocEx`. Its job is to allocate a memory region of the size we request (`codeSize`) inside another process (`hTarget`).

We pass the second parameter as `NULL`, because we leave it up to the operating system itself to decide where in memory the region will be allocated. The `MEM_COMMIT | MEM_RESERVE` parameters indicate that we are both reserving that region in memory and physically committing it for use. `PAGE_READWRITE`, on the other hand, says that this region is only readable and writable. If you pay attention, we have not granted "execute" permission for now, because we have not written the code into memory yet. This is a good practice for avoiding the attention of EDRs.

We have allocated our region; now it is time to copy our code into that region:

```c
    if (!WriteProcessMemory(hTarget, remoteBase, code, codeSize,
                            &bytesWritten) || bytesWritten != codeSize) {
        printf("Oops! WriteProcessMemory failed. ^_^: %lu\n", GetLastError());
        return FALSE;
    }
```

The `WriteProcessMemory` API writes the code in our own memory (`code`) into that empty address we just allocated in the target process (`remoteBase`). If the function succeeds, it records how many bytes of data it wrote to the other side in the `bytesWritten` variable.

In this `if` block, we are not only checking whether the function returned an error; we are also checking whether the number of bytes written to the other side matches the original size of our code exactly (`bytesWritten != codeSize`). If fewer bytes were written, or if the function blows up, we print the error to the screen and abort the operation.

We have successfully written the code into the target process. We no longer need the code on our own side:

```c
    SecureZeroMemory(code, codeSize);
```

This one-line function is incredibly critical from an operational security (OPSEC) standpoint. After transferring the code to the target process, we destroy the original copy left in our own process's memory by filling it with zeros. That way, an antivirus or an analyst who scans our memory later on cannot find any trace of a suspicious payload on our side.

Now we are changing the permissions of the region we allocated inside the target process:

```c
    if (!VirtualProtectEx(hTarget, remoteBase, codeSize,
                          PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("Oops! VirtualProtectEx failed. ^_^: %lu\n", GetLastError());
        return FALSE;
    } 
```

If you recall, when we allocated the region in memory with `VirtualAllocEx`, we granted that region only read and write (`PAGE_READWRITE`) permission. Windows' security mechanism (DEP - Data Execution Prevention) prevents code sitting in memory regions that lack execute permission from being run.

That is why we tamper with the target process once again using the `VirtualProtectEx` API, updating the permissions of that memory region where we wrote our code to `PAGE_EXECUTE_READWRITE` (Read, Write, and Execute). If the permissions fail to change without a problem, we print an error and bail out. Once we get past this step as well, our code becomes fully ready to be executed inside the target process.

So here is what we have done up to this point:
1. Gather the required information from the user with our own main function.
2. Allocate a region inside the target process with `VirtualAllocEx`. 
3. Write the malicious code with `WriteProcessMemory`.
4. Wipe the malicious code we wrote earlier with `SecureZeroMemory`. 
5. Change the permissions of that region in the target process with `VirtualProtectEx`.

### Part 3
Now it is time to change the address shown in the RIP register of the existing thread in the target process to the memory address of our own malicious code. The `RedirectThreadExecution` function does exactly this job; in other words, it breaks the thread's current flow and tells it: "drop what you are doing, go run the code at the address I am pointing you to."

Let's step into the code:

```c
BOOL RedirectThreadExecution(HANDLE hTargetThread, void* remoteCodeAddr)
{
    CONTEXT ctx = { .ContextFlags = CONTEXT_CONTROL };
```

From the outside, we pass the target thread's handle (`hTargetThread`) and the memory address of the code we want it to execute (`remoteCodeAddr`) into the function.

Here, we first define a structure (struct) named `CONTEXT`. In Windows, when a thread is suspended, the state of its CPU registers at that moment is held in this structure. By writing `.ContextFlags = CONTEXT_CONTROL`, we tell the operating system: "I am not interested in all of this thread's registers; just give me the control registers (Instruction Pointer, etc.)." This both improves performance and saves us from dealing with unnecessary data.

```c
    if (!GetThreadContext(hTargetThread, &ctx)) {
        printf("Oops! GetThreadContext failed. ^_^: %lu\n", GetLastError());
        return FALSE;
    }
```

Our next API is `GetThreadContext`. This function takes the current state (the register values) of the suspended target thread and fills it into the empty `ctx` structure we created a moment ago. We could say that we are taking a snapshot of its current state before changing the thread's route. If this read operation fails, we print an error and exit.

And here is where the heart of the operation beats and where the real manipulation happens:

```c
#ifdef _WIN64
    ctx.Rip = (DWORD64)remoteCodeAddr;
#elif defined(_WIN32)
    ctx.Eip = (DWORD)(ULONG_PTR)remoteCodeAddr;
#else
#error "Unsupported architecture"
#endif
```

In a CPU, there is a very special register that holds the memory address of the next instruction to be executed. This register is called `RIP` (Instruction Pointer) on 64-bit systems and `EIP` on 32-bit systems.

Here, we completely overwrite the `Rip` or `Eip` value inside the `ctx` structure that we filled using `GetThreadContext`. In its place, we write the memory address where our own malicious code is located (`remoteCodeAddr`). The `#ifdef` blocks inside guarantee that the correct register gets selected depending on the architecture the code is compiled for (32-bit or 64-bit).

```c
    if (!SetThreadContext(hTargetThread, &ctx)) {
        printf("Oops! SetThreadContext failed. ^_^: %lu\n", GetLastError());
        return FALSE;
    }
}
```

The final blow: we read the state with `GetThreadContext`, and we swapped the target address with our own code via `ctx.Rip`. Now we need to load this manipulated, tampered-with structure back into the thread again. That is exactly what `SetThreadContext` does.

Once this API succeeds, the "next instruction to be executed" address in the thread's brain is now the address of our payload. All that is left for us to do is wake this suspended thread up (with `ResumeThread`). The second the thread wakes up, instead of going to the original program's entry point, it will start running directly from the address we pointed it to.

And so the final chain comes to an end like this:
1. Save the thread's current state with `GetThreadContext`.
2. Check whether it is 32-bit or 64-bit with the `#ifdef` blocks.
3. Load the modified thread back with `SetThreadContext`.

As you can see, this topic really offers us an extra method for the question "how can we execute our own shellcode/payload (whatever name you give it)?" .Instead of imagining this process solely in this way, it’s helpful to consider that we could take a different approach and run our own code in an entirely different manner. After all, throughout this text, we’ve seen not just one method, but what a piece of malware can actually do when it goes beyond its own boundaries.

**Note**: If you'd like the full code, you can find it at https://github.com/0xGently/Malware-Dev-Analysis-Library/tree/main/Injection/Thread%20Hijacking That's all for today—thank you for reading.

