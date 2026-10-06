---
title: IPv4/IPv6 DeObfuscation
date: 2026-04-10
draft: false
author: 0xGently
tags:
  - obfuscation
---
## IPv4/v6 DeObfuscation

In this post, we will examine how a network configuration function, which looks completely ordinary from the outside, is transformed into a shellcode decoder. Our goal is to understand the attacker's mindset and design our defensive systems to catch these types of "normal-looking anomalies."

**Note**: You can find the entirety of the code explained in this text at https://github.com/0xGently/Malware-Dev-Analysis-Library/blob/main/Payload-Encryption-and-Obfuscation/06-IPv4_IPv6_DeObf/Deobfuscat%C4%B1on.c. Furthermore, once you establish the logic of this topic and examine the full version of the code, you can also construct DeObfuscation processes applied to other techniques. They are pretty much the same anyway; you only need to make a few modifications, that is all.

At the center of this technique lies the `RtlIpv4StringToAddressA` function located within `ntdll.dll`. When you look at Microsoft's official documentation, you will see that this function is quite simple and has a single purpose: to take a text-based (string) IPv4 address like `"192.168.1.1"` and convert it into a 4-byte binary `struct in_addr` structure so that it can be used in network sockets.

We, however, will view this function not as a network configuration tool, but as a built-in "decoder" function embedded into the heart of the system that accepts plain text as a parameter and produces 4-byte pure machine code (hex) in return.

```c
// Call our resolved IPv4 to address function to decode the current IP string into binary bytes
NTSTATUS status = pRtlIpv4ToAddr(ObfuscatedIpv4Array[i], FALSE, &pszTerminator, pCurrentWritePos);
```
The most critical point here is the 4th parameter, the `pCurrentWritePos` variable. Under normal circumstances, the API expects a `struct in_addr*` pointer to write the converted data. However, we are passing a `PBYTE` (byte array pointer) that we allocated ourselves.

In the software world, this concept is called **Type-Punning**. In C and C++ languages, the operating system does not care much about the "type" of the pointer you provide at runtime; it only focuses on the memory address that the pointer points to. While the API thinks it is writing an innocent network configuration to that address, we are actually forcing it to write our 4-byte shellcode piece, disguised as an IP address, directly into our own buffer.
```c
// Check if the API function failed to execute correctly
if (status != 0x00000000) 
{ 
    // Free the allocated memory buffer before returning to prevent memory leaks
    HeapFree(GetProcessHeap(), 0, pDecodedBuffer);
    return NULL;
}
```
If the API fails for any reason (for example, if the IP string in the array is in an incorrect format), the code does not panic and exit blindly. First, it returns the memory it allocated back to the system using `HeapFree`. Remember; memory leaks cause processes to run unstably, and the behavioral analysis radars of modern EDRs are highly sensitive to such instabilities.
```c
// Move the current writing pointer 4 bytes forward to prepare for the next chunk
pCurrentWritePos += 4;
```

In each iteration of the loop, the target pointer is shifted forward by exactly 4 bytes. This is because each IPv4 address is mathematically a 32-bit (4-byte) data block. Thanks to this simple pointer arithmetic applied, dozens of IP addresses, which stand like independent texts within the code, turn into a contiguous and holistic shellcode in memory.

After the shellcode is successfully written to memory, an alignment problem comes into play here.

Your actual payload — for example, a Cobalt Strike beacon, a reverse shell, or a custom implant — will not always be an exact multiple of 4 in length. Let's say you have a 201-byte payload. If you want to divide this into 4-byte IP blocks, a 3-byte padding must be appended to the end so that the final block is not left incomplete. Tools that prepare payloads usually do this according to the **PKCS#7** standard, which we see very frequently in cryptography.

If your loader code attempts to execute the payload without clearing these redundant padding bytes in memory, the processor will try to read these padding bytes as Assembly instructions. And because of this, the process immediately crashes, throwing an "Access Violation" or "Illegal Instruction" error.

To prevent this, it is mandatory for us to go to the end of the payload and clear that padding part:
```c
// Read the very last byte of the decoded buffer to determine the padding value
BYTE padValue = pDecodedBuffer[totalBufferSize - 1];
```

In the first step, we read the very last byte of the decoded memory area. The PKCS#7 standard relies on a very simple logic: the appended **padding** value is equal to the number of bytes added to ensure alignment. In other words, if a 3-byte **padding** was added to complete the payload to multiples of 4 bytes, the last 3 bytes will be `0x03, 0x03, 0x03`. By reading only the last byte, we learn what this **padding amount** is (3 in our example).

```c
// Validate that the padding value is within the mathematically possible range
if (padValue == 0 || padValue > 4 || padValue > totalBufferSize) 
{
    // Free the heap memory if the padding value is corrupted or invalid
    HeapFree(GetProcessHeap(), 0, pDecodedBuffer);
    return NULL;
}
```

This control line is one of the main elements that ensures the safety and stability of the code. Since an IPv4 address can be at most 4 bytes, the applied **padding value** can mathematically only be 1, 2, 3, or 4. If the `padValue` we read is 0 or greater than 4, it means the structure of the data is corrupted somehow. In this case, the code refuses to proceed blindly, aborts the operation, and cleans up the memory.

```c
// Loop backwards through the padding region to verify all padding bytes match
for (BYTE i = 1; i <= padValue; i++) 
{
    // Check if the current trailing byte matches the expected padding value
    if (pDecodedBuffer[totalBufferSize - i] != padValue) 
    {
        // Free the allocated memory if a corrupted byte sequence is detected
        HeapFree(GetProcessHeap(), 0, pDecodedBuffer);
        return NULL;
    }
}
```

We must verify whether this data is truly a valid **padding sequence**. The loop above reads backward from the end as much as the detected **padding size**. If the `padValue` is 3, it confirms that all 3 bytes it reads retrospectively are indeed `0x03`. If even one of them is different, there is **corrupted** data involved, and the operation is canceled.

```c
// Subtract the verified padding amount from the total buffer size to get the actual payload size
*DecodedSize = totalBufferSize - padValue;
```

In the final step, we subtract the **padding amount** from the total **buffer size** we allocated at the beginning. Now we have a smooth and pure payload of `*DecodedSize` in size, completely ready to be executed, and **stripped of padding bytes**.

In offensive security research, the core of the work stems from knowing how the operating system manages memory, grasping the hardware counterparts of pointers within the C language, and understanding how you can stretch the type-checking of APIs in your own favor.

We saw how an ordinary string conversion function written for network administrators from the outside turns into a flawless shellcode decoder with a bit of pointer arithmetic and a correct **Type-Punning** approach. The things that complicate defense architectures and malware analysis are not just complex encryption algorithms, but these elegant engineering approaches that use the system's own regular operation against the system itself.
