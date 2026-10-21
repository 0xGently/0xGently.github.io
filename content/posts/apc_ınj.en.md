---
tags:
  - Execution
date: 2026-10-21
title: Local APC Injection
draft:
author: 0xGently
---

# Apc Injection

Today, there are many techniques we use to execute our payload when writing certain malware. In this post, we will focus on the APC Injection technique, which is one of the most fundamental and effective methods where we use the natural operation of the operating system to our advantage. Without wasting time on standard parts that are repeated in every injection, like memory allocation, we will focus directly on the technique.

## What is APC? (Asynchronous Procedure Call)

In its simplest form, an APC is a function queued to be executed asynchronously within the context of a specific thread. Every thread running in the Windows operating system has its own APC queue.

Technically, this situation is related to the structure of thread objects in the operating system kernel. Windows keeps each thread in memory as a struct named `_KTHREAD`. Within this struct, there is a hidden list pointer that indicates the tasks that the thread will process in order. So, APC is directly a part of the system mechanism managed by this structure.

We can think of this as the "to-do list" of that thread. Under normal circumstances, the system or other programs can externally add tasks to this list by telling the target thread, 'If you have some free time, take care of this function too.' Our goal, on the other hand, is to secretly add our malicious code to this list..

## What is a Queue?

The "to-do list" we mentioned above actually works entirely with the logic of a Queue, which is an algorithmic data structure. Queues, one of the most fundamental structures in computer science, operate according to the FIFO (First In, First Out) rule. Just like people waiting in a line at a bank or a bakery, the first task added to the thread's list is processed first by the thread. Thanks to this algorithmic structure, the operating system manages the order of tasks without ever mixing them up.

## What is an Alertable State?

We have a critical problem here: Adding a task to a thread's APC queue does not mean that task will be executed immediately. The thread will not drop its main job to look at the function you added.

For our malicious code to run, the thread we are targeting must enter a wait state called an "Alertable State". When the thread enters this state, it gives the following message to the operating system: "I am going into a wait state now. If there is a pending APC task in my queue, I can execute it." That is exactly the gap we are going to exploit.

## Local APC Injection

Our goals are quite clear when performing Local APC Injection. We are not trying to get into another process; we will use a thread within the process we created ourselves. Our flow basically proceeds as follows:

1. We create a thread within our own process.
        
2. We add the address of our malicious code to this thread's APC queue.
    
3. We deliberately put the thread into an "Alertable State".
    
4. The moment the thread goes into a wait state, it notices our task in the queue and executes our shellcode.
    
## QueueUserAPC Function

We use the `QueueUserAPC` function to add our malicious code to the thread's to-do list. The structure of this WinAPI is as follows:
```c
DWORD QueueUserAPC(
  [in] PAPCFUNC  pfnAPC,
  [in] HANDLE    hThread,
  [in] ULONG_PTR dwData
);
```

Let's briefly examine these three parameters:
- **pfnAPC:** This is the address of the function to be executed. Here, we will provide the address of our shellcode that we have set as executable in memory.
    
- **hThread:** This is the handle value of the thread we are targeting. From here, we specify to which thread's queue we will add and execute this task (payload).
    
- **dwData:** If our function needs an extra parameter, we send it from here. Since we are running shellcode in APC injection operations, we generally leave this value as NULL.
    
For instance, our example usage is as follows:
```c
// We are adding the malicious code address to the target thread's queue.
QueueUserAPC((PAPCFUNC)ShellcodeAddress, hThread, NULL);
```

We added our task to the queue, but how do we put the thread into an Alertable State? Windows offers various wait functions that we can use for this job. Their common feature is that they put the thread into an alertable state when the correct parameters are provided.

Most wait functions need an object handle to know what they are waiting for. In a real scenario, this object is triggered by another thread and the wait ends. However, since our only goal is to put the thread into an infinite wait and slip our APC in between, we create a "fake" event object that will never be triggered and make it wait on that.

We can create our fake object in a single line like this:
```c
HANDLE hDummyEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
```

Now let's examine how we use a few functions that put this thread into an Alertable State:

### SleepEx

`SleepEx` is a function that suspends a thread for a specified period of time. It does not require an extra object, which makes it the easiest to use. Its second parameter is `bAlertable`, and when set to `TRUE`, the thread enters an alertable state.
```c
// Puts the thread to sleep indefinitely and sets it to an Alertable state.
SleepEx(INFINITE, TRUE);
```

The thread falls into an infinite (`INFINITE`) sleep, but because it is Alertable, it immediately executes our code when our APC arrives.

### WaitForSingleObjectEx

This is a function that only waits for the state of a specific object (in our case, the fake event that will never be triggered). Its third parameter determines the Alertable state.
```c
// Wait indefinitely for the fake event object to be triggered in an alertable manner.
WaitForSingleObjectEx(hDummyEvent, INFINITE, TRUE);
```

Since the event will never receive a signal, the wait will never end through normal means, but our code will pop out when the APC queue comes into play.

### WaitForMultipleObjectsEx

This is the array version of the previous function. Instead of a single object, it is used to wait for multiple objects at the same time. We can exploit this function again by putting our own fake object into an array.
```c
// Wait for the object array, switch to Alertable mode with the last parameter being TRUE.
HANDLE eventArray[] = { hDummyEvent };
WaitForMultipleObjectsEx(1, eventArray, FALSE, INFINITE, TRUE);
```

### MsgWaitForMultipleObjectsEx

In addition to normal object waiting operations, this function can wait for input events in the thread's message queue. It is generally used in GUI threads, but we will use it again for our own manipulation. We use the `MWMO_ALERTABLE` flag to make it alertable.
```c
// Wait for the fake object and also switch to an alertable state.
MsgWaitForMultipleObjectsEx(1, &hDummyEvent, INFINITE, QS_ALLINPUT, MWMO_ALERTABLE);
```

### SignalObjectAndWait

This API first triggers an object, and immediately after, starts waiting for another object. At the end of its parameters, there is again the `bAlertable` flag. When using this, we can again point to the fake objects we created ourselves.
```c
// Signal the first event, wait for the second (fake) event in an alertable manner.
SignalObjectAndWait(hSignalEvent, hDummyEvent, INFINITE, TRUE);
```

That is all there is to it. In summary, first we slip our malicious code into the thread's pocket using `QueueUserAPC`, and then we force the thread to look at that code using one of the functions above. As you can see, Local APC Injection is actually an elegant technique that consists of using a thread's scheduling mechanisms to our advantage.

**NOTE:** If you want to access the entire PoC code for this technique, you can check out the [Malware-Dev-Analysis-Library](https://github.com/0xGently/Malware-Dev-Analysis-Library/tree/main/Injection/Apc-Injection) repository on my GitHub.
