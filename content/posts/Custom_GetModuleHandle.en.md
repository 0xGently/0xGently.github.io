---
tags:
  - obfuscation
title: Custom GetModuleHandle
date: 2026-10-25
draft:
author: 0xGently
---
## Introduction

Analyzing exactly how Windows APIs work under the hood gives us many new techniques and tactics when writing malware. In this post, we will explore how to implement one of the most frequently used APIs, `GetModuleHandle`, from scratch without calling a single Windows API. Of course, one of the main reasons for doing this is to hide this heavily used function from the IAT (Import Address Table).

As you know, `GetModuleHandle` returns the base memory address of a loaded module given its DLL name. What it actually does is quite straightforward: it scans a list of loaded modules maintained by the OS loader for each process. This list resides inside the Process Environment Block (PEB) structure. The focus of this post will be to show, step by step, how to manually access the PEB and parse this list.

However, before we start parsing the PEB, we need to understand the structure itself. The module data inside the PEB is essentially a linked list. Therefore, before diving into specific Windows structures, we will briefly discuss why the OS loader uses a linked list instead of a simple array for this task. Once you grasp this core concept, reading data from the PEB stops feeling like a complex operation and simply becomes traversing a standard linked list.

## Arrays and Linked Lists

When storing data in memory, arrays are contiguous memory blocks by design. As long as you know the element size, you can directly access any index by applying simple pointer arithmetic to the base address. This makes them extremely fast and cache-friendly. However, the biggest disadvantage of arrays is that expanding them dynamically is costly. When the allocated capacity is full and you want to add a new element, you have to allocate a new, larger space in memory and copy all the existing data over to this new area.

Throughout the lifecycle of a process, new DLLs can constantly be loaded or existing ones unloaded. Using an array for such a dynamic module list whose size constantly changes is highly inefficient because it would require constant memory copying operations.

Linked lists solve exactly this problem. Instead of a single, large contiguous memory block, an independent allocation is made for each element (node), and each element holds the memory address of the next (or previous) one via a pointer. When a new module is added to the list, there is no need to move the existing data; it is enough to just allocate a new space and update the pointer links in between.

The technical cost of this is losing the random access feature; you have to traverse the list from the beginning to reach a specific element. However, in the OS loader's module list scenario, there is no need to directly access a specific index anyway. The operation performed is simply traversing the list from start to finish until a match with the desired DLL name is found. Since index-based access is not needed and dynamic insertion/removal operations are frequent, Windows using a linked list instead of an array for this structure is the most logical engineering choice.

## Doubly Linked Lists

In singly linked lists, each node contains a single pointer that only points to the next one. If you are only going to move in one direction through the list, this structure is sufficient. However, it has a significant disadvantage: you cannot directly return to the previous node from your current node. When you need to go back, you have to return to the beginning of the list and traverse it all over again up to the relevant node.

The doubly linked list structure, on the other hand, completely eliminates this limitation by adding two pointers to each node. In the Windows architecture, this structure is called `LIST_ENTRY`. The pointers inside it are named `Flink` (Forward Link) for the forward connection and `Blink` (Backward Link) for the backward connection.

Let's look step by step at how Windows defines this structure in code. First comes the definition of the structure and the pointer indicating the next element:
```c
typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink; // Holds the memory address of the next node
```

Right after comes the backward-pointing pointer, completing the structure:
```c
    struct _LIST_ENTRY *Blink; // Holds the memory address of the previous node
} LIST_ENTRY, *PLIST_ENTRY;
```
The entire structure consists of just these two pointers. Thanks to this minimal design, you can traverse the list forward via `Flink` and backward via `Blink`. The biggest performance advantage it provides to the system is that you can delete a node with O(1) complexity (in constant time). Since the relevant node already knows the addresses of both its previous and next neighbors, it can be removed simply by updating the pointers without the need to traverse the list from the beginning.

The `LIST_ENTRY` struct is a fundamental building block used as a standard not only in the OS loader's module list, but in almost all Windows kernel and `ntdll` structures. Once you grasp the logic of this structure, you will have understood a large portion of the data structures within the inner workings of Windows.

## Circular Lists and List Head

When examining the `LIST_ENTRY` structure in the Windows architecture, the first technical question that usually comes to mind is how to determine the end of the list. In a standard linked list design, the iteration condition is simple: the forward-pointing pointer of the last node holds a `NULL` value, and the loop terminates when this `NULL` value is reached.

However, in its core structures, Windows uses a circular design instead of null-terminated lists. In this structure, the `Flink` pointer of the last node points back to the very beginning, rather than to `NULL`. Similarly, the `Blink` pointer of the first node is linked to the very end of the list. Thus, the structure becomes a continuous loop that closes in on itself—much like an Ouroboros, the snake eating its own tail.

![Logo](/assets/img/custom_getmodulehandle.png)

To prevent this circular structure from turning into an infinite loop, there needs to be a fixed starting point that can be used as a reference. In Windows terminology, this point is called the **List Head**. The list head is essentially a standard `LIST_ENTRY` variable, but with one fundamental difference: it does not represent actual data (such as a loaded module). It merely acts as a fixed reference point residing within a parent struct (in our scenario, the `PEB_LDR_DATA` structure, which we will cover shortly). Its `Flink` and `Blink` pointers point to the first and last "real" data nodes in the list.

Let's take a step-by-step look at how we set up the loop logic when we want to traverse a list on this architecture. First, we define our starting point, which is the first real element pointed to by the head:
```c
PLIST_ENTRY current = head->Flink;
```

Instead of looking for a `NULL` value as in standard lists, our loop checks whether the read address has returned to the initial fixed reference point (the head):
```c
while (current != head) {
    // Operations on the node are performed here...
```

After the operations in the loop body are finished, we advance to the next node using the `Flink` pointer again:
```c
    current = current->Flink;
}
```

The greatest engineering advantage of this design is that it eliminates the need for an extra `if (current == NULL)` check for empty lists. If the list is completely empty, the `head->Flink` pointer will point directly to the `head` itself, and since the `while` condition is not met from the start, the loop will never be entered.
## PEB_LDR_DATA

Now that we have established the logic of circular and doubly linked lists, we can move on to the actual structure Windows uses in the background to keep track of loaded modules: `PEB_LDR_DATA`.

At the beginning of the structure, basic size and status information are located:
```c
typedef struct _PEB_LDR_DATA {
    ULONG   Length;
    BOOLEAN Initialized;
    HANDLE  SsHandle;
```

Right after that come three `LIST_ENTRY` fields that hold the module lists:
```c
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    // ... (remaining fields)
} PEB_LDR_DATA, *PPEB_LDR_DATA;
```

Notice that the OS loader tracks modules using three different orders (load order, memory address order, and initialization order) instead of a single list. In reality, all three lists connect the exact same module records in memory; only the routes change via different `Flink`/`Blink` pairs inside each module. For our `GetModuleHandle` implementation, the field we will focus on is `InMemoryOrderModuleList`.

The list head (fixed reference point) concept we mentioned in the previous section is exactly this `InMemoryOrderModuleList`. It is not an actual module itself. Its `Flink` pointer points to the first loaded module, and its `Blink` pointer points to the last loaded module; by moving in the `Flink` direction from this fixed reference point, we can reach every DLL loaded into the process.

The actual data nodes in this list are a different struct called `LDR_DATA_TABLE_ENTRY`. This is the structure that actually holds the module's base address in memory and its name. However, a very critical technical detail comes into play here: the pointer we get via `Flink` while traversing the list does not point directly to the starting address of the `LDR_DATA_TABLE_ENTRY` structure. The address returned to us is the address of the `LIST_ENTRY` field embedded a bit deeper inside this struct.

To reach the actual module data (name, base address), we need to calculate the starting address of the struct based on this inner pointer. When we get to the coding phase, we will solve this memory arithmetic using the `CONTAINING_RECORD` macro in C.

## Reading the PEB via the TEB

We have examined how to traverse the module lists inside the PEB structure, but we haven't answered the most fundamental question yet: how do we get the memory address (pointer) of the PEB in the first place? Due to our rule of not using any Windows APIs, we cannot resort to system calls like `GetModuleHandle` or similar ones. Therefore, we need to go directly to the hardware-level registers.

Every thread running on Windows has its own Thread Environment Block (TEB) structure. This TEB contains a pointer that points to the overall PEB of the process it belongs to. In Windows systems on the x64 architecture, the operating system holds the TEB address of the currently running thread via the `GS` segment register. You do not need to ask the operating system for any address; as long as the thread is running, the TEB's address is always located at a fixed offset of `GS:[0x30]`. The offset needed to go from the TEB to the PEB pointer is `0x60`. In short, reading the `GS:[0x60]` address gives us a `PEB*` directly, without any API calls.

However, standard C syntax cannot express segment-based memory reads on its own. For this, we need to tell the hardware directly using inline assembly suitable for GCC/Clang compilers.

First, we ensure that we are strictly on the x64 architecture and define our return variable:
```c
static PPEB GetPebManually(void)
{
#if defined(__x86_64__)
    PPEB peb;
```

Next, we start our inline assembly block. The `__volatile__` keyword used here is critical; it tells the compiler not to skip this code during optimization, not to change its execution order, and to definitely execute it:
```c
    __asm__ __volatile__(
```

The CPU instruction, which is the heart of the matter, is exactly here. We are reading 64-bit data with `movq` (move quadword). The `%%gs:0x60` expression takes the data from the address at the `0x60` offset relative to the `GS` segment register and writes it to the first output target denoted by `%0`. (Since registers are indicated with `%` in GCC assembly syntax, we need to use a double `%` as an escape character when writing `gs` inside inline assembly):
```c
        "movq %%gs:0x60, %0"
```

Now we need to explain to the compiler which variable in the C world this `%0` target from the assembly world corresponds to. The `=` in the `"=r"` expression indicates that this is a write-only output. The `r` gives the compiler the freedom to choose any general-purpose register it deems suitable for this copying operation. Consequently, the read value is transferred to the `peb` variable on the C side:
```c
        : "=r" (peb)
    );
    return peb;
```

If the code is not being compiled on the x64 architecture, we throw an error and close the block:
```go
#else
    #error "x64 only (GS:[0x60])"
#endif
}
```
That is it. By writing a single CPU instruction, we fetched the PEB pointer directly without touching any Windows API. Now, we can move on to the main function where we will parse the module lists using this pointer we just obtained.

## FindModuleBaseManually Function

In the first step, we define our function and retrieve the base address of the PEB by calling the inline assembly function we wrote in the previous section:
```c
PVOID FindModuleBaseManually(const wchar_t* targetModuleName)
{
    PPEB peb = GetPebManually();
```

Immediately after, we perform a standard safety check. If the PEB itself or the `LDR_DATA` structure inside it (the area holding the module lists) is uninitialized for any reason, we abort the operation and return `NULL` to prevent the program from crashing:
```c
    if (!peb || !peb->Ldr) {
        return NULL;
    }
```

Now we can access the module list itself. To traverse the circular list, we define our fixed reference point (`head`) and select the first "real" element where we will start the loop via `Flink`:
```c
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY current = head->Flink;
```

After defining the variable where we will store the found base address, we start our circular list loop. As we discussed earlier, our stopping condition is not `NULL`, but rather the read address being equal to the initial fixed reference point (`head`) again:
```c
    PVOID foundBase = NULL;

    while (current != head)
    {
```

Here we arrive at the most critical mathematical operation of the entire process. Our `current` pointer points not to the very beginning of the module structure, but to the `LIST_ENTRY` field embedded within it. Using the `CONTAINING_RECORD` macro, we go backwards from this inner offset and calculate the starting address of our actual data structure, `LDR_DATA_TABLE_ENTRY_COMPLETE`:
```c
        PLDR_DATA_TABLE_ENTRY_COMPLETE entry = CONTAINING_RECORD(
            current,
            LDR_DATA_TABLE_ENTRY_COMPLETE,
            InMemoryOrderLinks
        );
```

Now that we have reached the actual structure, we can start reading the module's name. The `BaseDllName` field is typically a `UNICODE_STRING` structure. First, we check whether the buffer is valid, and then we calculate the character count (because the `Length` field gives the size in bytes, not the number of characters):
```c
        if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0)
        {
            int charCount = entry->BaseDllName.Length / sizeof(WCHAR);
```

To see what is happening under the hood, we print out each DLL we find and its base address to the screen while traversing the list:
```c
            wprintf(L"[Loaded Module] %-20.*s  (Base: 0x%p)\n",
                    charCount,
                    entry->BaseDllName.Buffer,
                    entry->DllBase);
```

And the match check: Does the name of the module we read match the name of the module we are looking for (e.g., "kernel32.dll")? We perform a case-insensitive comparison (`_wcsnicmp`). If it matches, we save the module's base address (`DllBase`) and break out of the loop:
```c
            if (targetModuleName &&
                _wcsnicmp(entry->BaseDllName.Buffer, targetModuleName, charCount) == 0)
            {
                foundBase = entry->DllBase;
                break; 
            }
        }
```
If this is not the module we are looking for, we move on to the next element via `Flink` to continue traversing the list:
```c
        current = current->Flink;
    }
```

Finally, if the loop was broken, we return the base address we found; if the list has ended and no match was found, we return the initial `NULL` value and terminate the function:
```c
    return foundBase;
}
```

Thus, without touching the `GetModuleHandle` API at all, we have obtained the memory address of a DLL entirely through our own methods by manually parsing the operating system's internal data structures.

That wraps up our topic. It might have taken a bit long, but this was the most concise and clear way I could explain the fundamental concepts and structs. If you want to access the complete code discussed in this post, you can find it at [malware-development-library](https://github.com/0xGently/malware-development-library/tree/main/IAT-Hiding/GetModuleHandle)
