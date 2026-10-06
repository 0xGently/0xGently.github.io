---
title: XOR Encryption
date: 2026-04-15
draft: false
author: 0xGently
tags:
  - encryption
---

## XOR Encryption

In the world of malware development, one of the most critical factors determining the lifespan of your payload is how effectively you can conceal it. If you embed shellcode or a PE file into memory in plain text, static analysis tools and antivirus (AV) signatures will flag it within seconds.

This is precisely where payload encryption comes into play. In this post, we will examine the XOR algorithm—one of the most fundamental yet heavily modified encryption techniques in the malware domain. We will start from the basics and progress toward complex, position-dependent rolling structures.


**Note**: You can find the complete code discussed in this post at:
https://github.com/0xGently/Malware-Dev-Analysis-Library/blob/main/Payload-Encryption-and-Obfuscation/01-XOR/xor.c

### XOR (Exclusive OR)

The XOR operator (`^`) is indispensable in cryptography and malware development because it is symmetric. In other words, you use the exact same operation to both encrypt and decrypt data:

* `Data ^ Key = Encrypted Data`
* `Encrypted Data ^ Key = Data`

This characteristic provides substantial flexibility and code economy; there is no need to write a separate decryption routine. Let's see how this logic translates into code.

### Single-Byte Key XOR

Let's begin with the simplest form: a function that encrypts the entire payload using a single byte key.

```c
static VOID SingleKeyXor(IN PBYTE pPayload, IN SIZE_T sPayloadSize, IN const BYTE bXorKey)
{
    for (size_t x = 0; x < sPayloadSize; x++)
    {
        pPayload[x] = pPayload[x] ^ bXorKey;
    }
}

```

This function accepts three parameters:

* `pPayload`: Memory address of the data to be encrypted (or decrypted).
* `sPayloadSize`: Total size of the data buffer.
* `bXorKey`: The single-byte key used for the operation (e.g., `0xAA`).

The logic is straightforward: a `for` loop iterates sequentially through the payload from start to finish. Each byte is XORed with the specified `bXorKey` and written back in place.

While this approach might initially bypass basic signature-based static scans, it is largely insufficient today. Because a single-byte key is used, repeating byte sequences in the payload (such as consecutive `0x00` null bytes) will consistently produce the same encrypted byte value throughout the output.

### Advanced Rolling XOR

Having seen the limitations of a single-byte key, bypassing modern security controls requires a mechanism where identical input bytes yield distinct outputs across different offsets.

To achieve this, rather than relying on a static value, we implement a custom rolling XOR algorithm that leverages a multi-byte key array and introduces position-dependent mutation.

```c
static VOID CustomRollingXor(IN PBYTE dataBuffer, IN SIZE_T dataLen, IN PBYTE keyBuffer, IN SIZE_T keyLen)
{
    SIZE_T keyIndex = 0;

    for (SIZE_T i = 0; i < dataLen; i++)
    {
        // Step 1: Calculate a dynamic mask (salt) unique to the current offset (i)
        BYTE positionSalt = (BYTE)(i * 0x9B) ^ (BYTE)(i >> 3);

        // Step 2: XOR the data byte with both the key byte and the position salt
        dataBuffer[i] = dataBuffer[i] ^ keyBuffer[keyIndex] ^ positionSalt;

        // Step 3: Advance the key index; wrap around to the beginning if the end is reached
        keyIndex++;
        if (keyIndex == keyLen) 
        {
            keyIndex = 0;
        }
    }
}

```

This function extends basic XOR into a significantly more resilient routine. Here is how it functions step-by-step:

#### 1. Multi-Byte Rolling Key Structure (`keyIndex`)

Instead of a single byte, encryption relies on an array of bytes (e.g., `0xDE`, `0xAD`, `0xBE`, `0xEF`). The `keyIndex` counter steps through this array sequentially. When the end of the key buffer is reached, the condition `if (keyIndex == keyLen)` resets the index to zero. This cyclic reuse ("rolling") allows continuous encryption regardless of the payload's length.

#### 2. Position-Dependent Mutation (`positionSalt`)

This step disrupts repetitive byte patterns and defeats simple frequency analysis. In addition to the key byte, the current buffer index (`i`) is incorporated into the operation via the `positionSalt` variable:

* `i * 0x9B`: The current index is multiplied by a constant multiplier (`0x9B`).
* `i >> 3`: The index is bitwise right-shifted by 3 bits and XORed with the multiplied value.

The resulting dynamic salt is combined with the key byte to transform the data byte. The primary benefit: even if the input contains dozens of identical consecutive characters (such as repeated `0x41` / `'A'` bytes), each encrypted output byte will differ because the index `i` is unique for every position.

Predicting or reversing this position-mutated sequence via static frequency analysis is substantially more difficult than breaking standard single-byte XOR schemes.

## How is This Technique Detected?
### Static Analysis
The clues we can identify during static analysis include:

Suspicious Mathematical Signatures: XOR operations are frequently used in legitimate software. However, if consecutive instructions such as XOR, MUL (multiplication), and SHR (right shift) are contained within a loop structure (CMP and JMP blocks) inside a single code block, this is highly likely to be flagged as a "Decryption Stub."

High Entropy: If sections like .data or .rsrc contain large chunks of meaningless, completely random data (high entropy), this raises strong suspicion that the section contains encrypted data or code.

### Dynamic Analysis
During dynamic analysis, analysts typically look at the following workflow:

Hardware Breakpoint: A hardware breakpoint is placed directly on the memory address of the high-entropy encrypted data identified during static analysis.

Skipping the Loop: When execution begins and that memory region is accessed, the debugger triggers and pauses execution. Instead of stepping into the complex loop line-by-line (Step Into), the analyst places an execution breakpoint on the instruction immediately following the end of the loop and resumes execution (Run).

Memory Dump: As soon as the loop finishes, the program hits the breakpoint and pauses again. At this point, the elaborate Rolling XOR routine has completed its job. Inspecting the memory window reveals the fully decrypted, plain-text original payload in place of the encrypted bytes. Right-clicking and selecting "Dump to File" allows the original payload to be extracted in seconds.