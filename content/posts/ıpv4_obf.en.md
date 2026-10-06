---
title: IPv4/IPv6 Obfuscation
date: 2026-02-05
draft: false
author: 0xGently
tags:
  - obfuscation
---
## IPv4/IPv6 Obfuscation

In the world of cybersecurity, when we want to hide data, we generally have two fundamental paths ahead of us: we either encrypt the data directly (such as AES, RC4, or XOR) or we obfuscate it.

When developing software, obfuscating the code sometimes plays a critical role not only in protecting intellectual property but also in bypassing security mechanisms. For example, suppose we have a shellcode and we want to hide it. Although encryption is the first solution that comes to mind, it might not always be the smartest route. This is because encrypted data causes the **entropy (randomness rate)** in that specific section of the file to skyrocket, and this situation immediately catches the radar of security analysts or AV/EDR solutions. At this point, obfuscating without drawing attention transforms into a much more logical alternative.

But what if we could take this shellcode and make it look like a perfectly innocent network configuration file? In this post, that is exactly what we are going to do. We will split our shellcode into pieces and convert each piece into a standard **IPv4 address** string (such as `192.168.1.1`). This way, instead of suspicious hex values inside our file, hundreds of innocent-looking IP addresses will appear.

**Note**: You can find the entirety of the code explained in this text at https://github.com/0xGently/Malware-Dev-Analysis-Library/tree/main/Payload-Encryption-and-Obfuscation/05-IPv4_IPv6_Obf. Furthermore, once you grasp the logic of this topic, the workflow of other techniques (such as MAC and UUID obfuscation) is exactly identical.

### 1. The GeneratePkcs7Padding Function

An IPv4 address consists of exactly 4 bytes (e.g., `192.168.1.1` -> `C0 A8 01 01`). However, a shellcode generated from tools like msfvenom or Cobalt Strike is not guaranteed to have a size that is an exact multiple of 4. For example, if you have a 275-byte shellcode and you divide it into groups of 4, you will be left with 3 bytes at the very end. When the program attempts to generate that final IP address, it will crash and throw a memory error because it cannot find the 4th byte.

To prevent this, we need to fill the end of our shellcode with safe bytes (padding) and align the total size to an exact multiple of 4. We will have a function dedicated solely to this operation, and this function will make the byte count of the shellcode perfectly divisible by 4. Let's name the function that will perform this operation `GeneratePkcs7Padding`. This function will take **the address of the raw shellcode** and **its size** from us.

Before moving on to the code, let's define our constants (macros) that will ease our workload and increase code readability:

```go
#define IPV4_ALIGNMENT 4    // To create an IPv4 address, we must take 4 bytes from the shellcode
```
Now, let's take a look at a portion of the function we named `GeneratePkcs7Padding`:
```c
uint8_t padValue = (uint8_t)(IPV4_ALIGNMENT - (originalSize % IPV4_ALIGNMENT));
```
Let's assume the size of our shellcode (`originalSize`) is 275 bytes. The operation `275 % 4` yields a remainder of `3`. When we subsequently perform the operation `4 - 3 = 1`, we understand that the amount of padding we need to add is 1 byte, and we assign this value to our variable named `padValue`.
```c
size_t newBufferSize = originalSize + padValue; // Allocating memory equal to newBufferSize
uint8_t* paddedBuffer = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, newBufferSize); 
if (!paddedBuffer) return NULL;
```
Right after, we add this 1 byte to the original size (`newBufferSize = 276`) and allocate our space in memory. Here, a tiny detail saves the day: since we call the `HeapAlloc` function with the **`HEAP_ZERO_MEMORY`** flag, Windows does not just allocate space for us, it automatically zeroes out (`0x00`) all the bytes within that region.

When we copy our original shellcode here, it will become 276 bytes with the added padding. Our payload is now ready and perfectly divisible by 4!

### 2. The ConvertBytesToIP Function

Now, it is time for our `ConvertBytesToIP` function, which will take these 4-byte segments and produce strings from them in the format of `255.255.255.255`.

Many poorly written codes beg the operating system for new memory every single time. To avoid losing performance, we will move the memory allocation task outside of this function. This function will only perform translation into an "externally provided text box (buffer)."

To convert the hex values we have into decimal numbers separated by dots, we utilize `snprintf` or `sprintf_s`, which are secure functions of the standard C library:
```c
sprintf_s(outIpString, bufferSize, "%d.%d.%d.%d", pBytes[0], pBytes[1], pBytes[2], pBytes[3]);
```
Let's say the next 4 bytes in line from our shellcode are `0xFC, 0x48, 0x83, 0xE4`. The `sprintf_s` function converts these hex values into the decimal base in order, inserts dots between them, and writes them into `outIpString`. Consequently, those 4 bytes inside our shellcode turn into the IP address `252.72.131.228`!

### 3. The PayloadIPv4Array Function

We have completed the preparation phases; we have data that is perfectly divisible into multiples of 4 and a function that converts this data into an IP address. Now, the only thing left is to write the main control mechanism that will manage this process from start to finish, reading the data in blocks and printing it to the screen.

```c
// 1. We call our padding function and retrieve our aligned data
uint8_t* paddedData = GeneratePkcs7Padding(rawData, rawSize, &paddedSize);

// 2. We calculate how many 4-byte pieces (chunks) we will obtain
size_t chunkCount = paddedSize / 4;
```

In the first step, we call our `GeneratePkcs7Padding` function and receive the aligned data directly into our pointer named `paddedData`.  
In the line immediately below, simple math takes place: if an aligned data of 276 bytes is formed as a result of the padding process, thanks to the operation `276 / 4 = 69`, we calculate that we will obtain a total of exactly 69 IPv4 addresses (`chunkCount`).
```c
// We open a fixed space on the Stack to avoid allocating memory continuously inside the loop
char ipStackBuffer[16]; 

// Our loop that converts each 4-byte piece into the IP format
for (size_t i = 0; i < chunkCount; i++)
{
    ConvertBytesToIP(&paddedData[i * 4], ipStackBuffer, sizeof(ipStackBuffer));
    
    // ... (Operations to print the obtained string to the screen)
}
```
The for loop we opened will run as many times as the total amount we obtained, and it will process the data step by step in each iteration. The most important detail here is the line `char ipStackBuffer[16]`. Instead of slowing down the program by continuously requesting memory from the operating system inside the loop, we allocate a fixed space of 16 characters on the stack of the processor, and we change the text inside it in every iteration. This is a massive step for performance and cleanliness.

The operation of traversing over the actual data lies within the logic of `&paddedData[i * 4]`. Inside that raw data stack in memory, the following actions take place step by step:

- **In the first step (i = 0):** The calculation `0 * 4 = 0` is made, and the address of the 0th byte in memory is sent to the function.
- **In the second step (i = 1):** It becomes `1 * 4 = 4`, and the function jumps directly to the 4th byte in memory.
- **In the third step (i = 2):** The address of the 8th byte is read directly.

In this manner, without sacrificing a single shred of performance, we scan our entire shellcode by jumping precisely in 4-byte increments in memory.

### IPv6

If we want to perform obfuscation in IPv6 as well, we need to use the exact same logic that we applied for IPv4 above; almost nothing changes. The logic of the code or the functions used are completely identical. The only difference is that you must remember that it needs to be a multiple of 16 this time, and you must adapt it to `2001:0db8:85a3:0000:0000:8a2e:0370:7334` while merging.

I will explain the Deobfuscation part of the matter in another post.
