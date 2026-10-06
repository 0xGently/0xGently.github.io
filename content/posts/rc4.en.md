---
title: RC4 Encryption
date: 2026-04-20
draft: false
author: 0xGently
tags:
  - encryption
---
# RC4 Encryption

RC4 is a symmetric stream cipher that encrypts data byte by byte rather than in blocks. Under the hood, it consists of two primary phases: the Key-Scheduling Algorithm (KSA), where the key is initialized and permuted in memory, and the Pseudo-Random Generation Algorithm (PRGA), which generates keystream bytes to be XORed with the data. Thanks to its symmetric architecture, the exact same routine is utilized for both encryption and decryption.

In malware development, three primary approaches are typically used to integrate RC4:

1. **SystemFunction032:** An undocumented RC4 API hosted inside `Advapi32.dll`.
2. **SystemFunction033:** An alternative undocumented API that takes identical parameters and performs the exact same operation as `SystemFunction032`. In practice, there is no functional difference between the two.
3. **Custom RC4:** Implementing the algorithm from scratch without relying on any native Windows APIs.

The following structure illustrates how to perform this operation using Windows' built-in `SystemFunction032` (or `033`).

---

## 1. Required Structures

Because `SystemFunction032` is an undocumented API, it does not directly take a raw byte pointer (`PBYTE`). Instead, it expects a specific internal buffer descriptor structure similar to `USTRING` (or `UNICODE_STRING` / `ANSI_STRING`).

```c
typedef struct _RC4_CTX {
    DWORD BufferSize;
    DWORD MaxBufferSize;
    PVOID pBufferData;
} RC4_CTX, *PRC4_CTX;

```

This struct, defined here as `_RC4_CTX`, provides the memory layout expected by the API. Both the encryption key and the target payload must be wrapped into this structure before processing.

---

## 2. Execution Flow

In this approach, the API is not statically imported (to prevent it from appearing in the Import Address Table / IAT). Instead, its address is resolved dynamically at runtime:

```c
typedef NTSTATUS(WINAPI* PFN_SYS_FUNC_032)(PRC4_CTX pData, PRC4_CTX pKey);

```

A suitable function pointer (`PFN_SYS_FUNC_032`) is defined to invoke the API once its memory address is resolved.

### Execution Chain:

1. **Struct Initialization:** The `rc4Key` and `rc4Data` variables are defined, wrapping the raw memory addresses and lengths into the structure declared above:
```c
RC4_CTX rc4Key = { keySize, keySize, keyBuffer }; 
RC4_CTX rc4Data = { payloadSize, payloadSize, payloadBuffer };    

```


2. **Loading the Library:** The module hosting the function is loaded into the process address space using `LoadLibraryA`:
```c
HMODULE hLib = LoadLibraryA("Advapi32.dll");

```


3. **Resolving the Address:** The exact address of `SystemFunction032` is located via `GetProcAddress`:
```c
PFN_SYS_FUNC_032 SysFunc032 = (PFN_SYS_FUNC_032)GetProcAddress(hLib, "SystemFunction032");

```


4. **Execution:** The resolved address is cast to the function pointer type and executed:
```c
SysFunc032(&rc4Data, &rc4Key);

```



Upon completion, the contents of `payloadBuffer` are encrypted (or decrypted, if already encrypted) directly in-place in memory.

Now, let's examine how to implement RC4 with a custom routine.

# Custom RC4

To avoid Blue Team detection mechanisms such as API hooking, the most reliable method is to implement the RC4 algorithm directly from scratch within the code, without relying on any external DLLs or Windows APIs.

> Note: The core C implementation of the RC4 algorithm examined below is adapted from the open-source CycloneCRYPTO library developed by Oryx Embedded:
> `[https://www.oryx-embedded.com/doc/rc4_8c_source.html](https://www.oryx-embedded.com/doc/rc4_8c_source.html)`

Mathematically, the RC4 algorithm consists of two primary routines. The entire operation is carried out on a 256-byte state array known as the S-box.

First, we define a structure (`struct`) to hold the state values in memory during the encryption process:

```c
typedef struct _RC4_STATE {
    unsigned char stateArray[256];
    int iter1;
    int iter2;
} RC4_STATE;

```

* `stateArray[256]`: The core 256-byte lookup table (S-box) upon which all encryption and decryption operations take place.
* `iter1` and `iter2`: Simple counters used in the subsequent loops to track state progression.

---

## State Initialization and Permutation (KSA)

Once the struct is defined, we proceed to initialization via the `PrepareRc4` function. This function requires three fundamental parameters: our empty state object to be populated (`rc4Obj`), the encryption key (`secretKey`), and the key length (`keySize`).

```c
void PrepareRc4(RC4_STATE* rc4Obj, const unsigned char* secretKey, size_t keySize) 
{
    int i, j = 0;
    unsigned char temp;

    // Step 1: Initialize the table sequentially
    for (i = 0; i < 256; i++) {
        rc4Obj->stateArray[i] = i;
    }

    // Step 2: Permute the table using the key
    for (i = 0; i < 256; i++) {
        // Mathematical permutation formula
        j = (j + rc4Obj->stateArray[i] + secretKey[i % keySize]) % 256;

        // Swap operation
        temp = rc4Obj->stateArray[i];
        rc4Obj->stateArray[i] = rc4Obj->stateArray[j];
        rc4Obj->stateArray[j] = temp;
    }
}

```

Here is a breakdown of what these code blocks accomplish step by step:

1. **Step 1 (Arranging the Deck):** We initialize the 256-byte `stateArray` sequentially with values from 0 to 255. You can think of this as an ordered, freshly opened deck of cards.
2. **Step 2 (Shuffling the Deck):** This is the core permutation stage. The routine takes the sequentially ordered array and shuffles it pseudo-randomly using the provided `secretKey`.
* The formula (`j = ...`) generates a pseudo-random index based on the key bytes. The `% 256` operation ensures the index wraps within the array bounds.
* The `temp` variable immediately below executes a standard swap operation, exchanging the positions of the two selected values within the array.



Once `PrepareRc4` finishes, we obtain a fully permuted, high-entropy 256-byte `stateArray` uniquely determined by the `secretKey`.

---

## The Encryption Function (PRGA)

Having prepared and permuted the state table, we move to the data encryption phase using the `Rc4Cipher` function.

### Step 1: Context Restoration

```c
void Rc4Cipher(RC4_STATE* rc4Obj, const unsigned char* input, unsigned char* output, size_t length) 
{
    unsigned char temp;

    unsigned int i = rc4Obj->iter1;
    unsigned int j = rc4Obj->iter2;
    unsigned char* s = rc4Obj->stateArray;

```

Here, we retrieve the initialized table (`s`) and the loop counters (`i` and `j`) from the `RC4_STATE` struct.

### Step 2: Encryption Loop

Now we proceed to the main loop that performs the actual payload transformation:

```c
    // Core Encryption/Decryption Loop
    while (length > 0) 
    {
        // Step 1: Increment indices
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;

        // Step 2: Swap (continue shuffling the state)
        temp = s[i];
        s[i] = s[j];
        s[j] = temp;

        // Step 3: Keystream generation and XOR operation
        *output = *input ^ s[(s[i] + s[j]) % 256];

        // Step 4: Advance to the next byte
        input++;
        output++;
        length--;
    }

    // Save the final state back into the struct upon completion
    rc4Obj->iter1 = i;
    rc4Obj->iter2 = j;
}

```

The loop operates as follows:

* **Index Shift and Swap:** On each iteration, the state table does not remain static. The `i` and `j` indices advance, and the corresponding elements in the table are continuously swapped. The state continues to evolve throughout the entire encryption process.
* **XOR Transformation:** The core operation is `*output = *input ^ s[(s[i] + s[j]) % 256];`. A pseudo-random keystream byte is derived from the state table and XORed with the current byte (`*input`). The resulting byte is written directly to `output`.
* **State Preservation:** Once the entire buffer is processed, the updated index counters (`i` and `j`) are saved back to the struct so that subsequent operations can resume seamlessly from the same state offset.

This establishes the baseline implementation of a custom RC4 routine. For further modifications or to inspect the complete source, refer to the CycloneCRYPTO repository linked above.

**NOTE**: To hinder signature detection of standard RC4 loop constructs, minor variations can be introduced. For example, expanding the state table size or combining the keystream output with additional transformations (such as bitwise rotations or arithmetic offsets) alters the generated bytecode and disrupts static pattern matching.
