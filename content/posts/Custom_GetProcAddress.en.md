---
tags:
  - obfuscation
title: Custom GetProcAddress
date: 2026-10-27
draft:
author: 0xGently
---
## Introduction

When developing with C or C++ on Windows systems, we generally use `GetProcAddress` to call a function inside a DLL. The process is fundamentally simple: the DLL is loaded into memory with `LoadLibrary`, and then the DLL's handle value and the name of the searched function are passed to `GetProcAddress`. But how exactly does this process work in the background? How does the operating system find the string value we provided inside a massive memory block and return its address to us? In this post, instead of using standard Windows APIs, we are writing our own `GetProcAddress` function by parsing the memory structure of a PE file.

When a DLL is loaded into memory, it is not placed randomly; it is structured according to the rules of the PE format. The operating system relies on these PE Header structures when writing the file to disk and loading it into memory. DLLs keep the list of functions they export in a table called the "Export Directory". The original `GetProcAddress` starts from the Base Address of the given module in memory. First, it reads the DOS Header, moves from there to the NT Header, and reaches the Export Directory. It compares the names in this directory one by one with the string it received. When a match is found, it retrieves the "Ordinal" value of that name. Using this value, it extracts the real memory address of the function from the array where the actual addresses are located and returns it as a pointer. The function we are going to write will follow this exact route.

Before moving on to the Custom Function itself, we need to examine the `IMAGE_EXPORT_DIRECTORY` struct.
```c
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;
    DWORD   AddressOfNames;
    DWORD   AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```
The critical elements in this structure are:

- **NumberOfNames**: The total number of functions the DLL exports by name. This value will determine the limit of our loop.
    
- **AddressOfNames**: The array that holds the memory addresses of the function names.
    
- **AddressOfFunctions**: The array that holds the memory addresses where the actual executable codes of the functions are located.
    
- **AddressOfNameOrdinals**: Holds the Ordinal values that establish the connection between the `AddressOfNames` array and the `AddressOfFunctions` array.
    
The values starting with "AddressOf" here are not direct absolute memory addresses, but RVA (Relative Virtual Address) values. RVA represents the distance (offset) of a piece of data from the Base Address where the DLL is loaded. To find the correct address, we will constantly perform the `Base Address + RVA` operation.

Now let's look at the code step by step. Our first principle is not to depend on any external API. Instead of using `strcmp` or `lstrcmpA`, we are writing our own custom string comparison function.
```c
BOOL CustomStringCompare(const char* str1, const char* str2) 
{
    if (!str1 || !str2) return FALSE;
    while (*str1 && (*str1 == *str2)) {
        str1++;
        str2++;
    }
    return (*str1 == *str2);
}
```
We move forward on two string pointers and compare the characters. The loop continues until there is a difference or the string ends, and finally, we return the equality status.

We define our main function and make the basic pointer assignment:
```c
FARPROC CustomGetProcAddress(HMODULE moduleBase, const char* apiName) 
{
    if (!moduleBase || !apiName) return NULL;
    uint8_t* baseAddr = (uint8_t*)moduleBase;
```

The `moduleBase` parameter is the starting address where the DLL is loaded into memory. We cast this to the `uint8_t*` type. Our goal is to ensure that C language pointer arithmetic works correctly on a byte basis (advancing 1 byte) when adding RVA values.

We check the DOS Header, which is the first structure of the PE file.
```c
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddr;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL; 
```

We cast the base address to the `IMAGE_DOS_HEADER` struct. The `e_magic` value of the DOS Header must be "MZ" in a valid Windows executable file. We perform this verification with `IMAGE_DOS_SIGNATURE`.

Then, we transition to the NT Header.
```c
    PIMAGE_NT_HEADERS ntHeaders =
     (PIMAGE_NT_HEADERS)(baseAddr + dosHeader->e_lfanew);
    
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;
```

The `e_lfanew` value inside the DOS Header indicates where the NT Header begins. By adding this value to the base address, we reach the NT Header and verify its validity with the `IMAGE_NT_SIGNATURE` check.

To find the location of the Export Directory, we access the Data Directory:
```c
IMAGE_DATA_DIRECTORY exportDataDir = 
ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

if (exportDataDir.Size == 0 || exportDataDir.VirtualAddress == 0) return NULL;
```

We take the `IMAGE_DIRECTORY_ENTRY_EXPORT` index, which represents the Export table, from the `OptionalHeader` inside the NT Headers. If the size or address is zero, it means the module does not export any functions.

We locate the Export Directory structure in memory:
```c
PIMAGE_EXPORT_DIRECTORY exportDirectory = 
(PIMAGE_EXPORT_DIRECTORY)(baseAddr + exportDataDir.VirtualAddress);
```

By adding the RVA we got from the Data Directory to the base address, we directly reach the `IMAGE_EXPORT_DIRECTORY` struct.

Now we define the necessary arrays inside this struct:
```c
DWORD* nameArray = (DWORD*)(baseAddr + exportDirectory->AddressOfNames);
DWORD* functionArray = (DWORD*)(baseAddr + exportDirectory->AddressOfFunctions);
WORD* ordinalArray = (WORD*)(baseAddr + exportDirectory->AddressOfNameOrdinals);
```

By adding the base address onto the respective array addresses (RVAs), we determine the actual locations of the arrays in memory. Let's note that `ordinalArray` is of `WORD` (2 bytes) type, not `DWORD`.

So what exactly is this "Ordinal", and why do we need such a bridge? The logic of the system works like this: the array named `nameArray` is sorted alphabetically so that the operating system can gain speed when searching (to be able to use algorithms like binary search). However, when names are arranged alphabetically, the order of a name in this array and its order in `functionArray`, where the actual memory address of that function is located, naturally do not match. This is exactly where `ordinalArray` comes into play. This array works completely in parallel with `nameArray`. When we find the function name we are looking for in `nameArray`, for example, in the 5th position (`i = 5`), the actual address of that function is not in the 5th position in `functionArray`. To find out the real index, we look at the `ordinalArray[5]` value, which acts as a bridge. The value that comes out of there (the ordinal) shows the actual location of the function in the address array. In summary, the ordinal is an index map that provides alignment between the alphabetical name list and the memory address list.

After understanding this logic, we set up the loop where we will search among the function names:
```c 
    DWORD totalNames = exportDirectory->NumberOfNames;
    for (DWORD i = 0; i < totalNames; i++) 
    {
        char* currentFuncName = (char*)(baseAddr + nameArray[i]);
```

We start a loop that iterates for the value of `NumberOfNames`. In each step, we add the RVA value in `nameArray` to the base address to obtain the memory address of the current function name.

We perform the comparison operation with the target API name and the use of the ordinal:
```c
        if (CustomStringCompare(apiName, currentFuncName)) 
        {
            WORD ordinalIndex = ordinalArray[i];
            
            FARPROC targetFunction =
             (FARPROC)(baseAddr + functionArray[ordinalIndex]);
            
            return targetFunction;
        }
    }
    return NULL;
}
```
We check the match status with our own string function. When a match is found, we operate the bridge logic we just mentioned: Using the index `i` in the loop, we get the real sequence number (`ordinalIndex`) of the function via `ordinalArray`. We use this sequence number as an index on `functionArray` and extract the RVA value of the actual function. Finally, by adding this RVA to the base address, we reach the executable memory address of the target function (FARPROC) and return it. If no match is found when the loop ends, we return `NULL`.

As a result of these operations, we have implemented the background PE Header parsing operations of `GetProcAddress`, a standard Windows API, with our own code. The original `GetProcAddress` function, in addition to this basic structure, also manages exceptional situations like "Forwarded Exports" (where a function inside one DLL is redirected to a different DLL). However, writing this basic implementation step by step is highly productive for understanding the architecture in order to grasp RVA calculations on memory, the Ordinal bridge, and the PE file structure. We have completed the operation without external dependencies, directly over memory addresses.

If you want to access the entire code explained in the topic, you can find it at [malware-development-library](https://github.com/0xGently/malware-development-library/tree/main/IAT-Hiding/GetProcAddress)