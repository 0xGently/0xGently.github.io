---
title: Chacha20 Encryption
date: 2026-04-01
draft: false
author: 0xGently
tags:
  - encryption
---
# ChaCha20 Encryption

In this post, I will talk about ChaCha20. Frankly, I thought about how to introduce the topic, but I couldn't come up with a sensible introductory sentence. Therefore, I prefer to dive straight into the subject.

File size and simplicity are everything. There is only one reason we prefer ChaCha20: it is compact, fast, and eliminates the need to write an extra decryption routine.

So why do we choose ChaCha20? Because it is exceptionally fast, does not rely on dedicated CPU cryptographic hardware extensions (such as AES-NI), and is far less cumbersome to implement from scratch in C/C++. Furthermore, we use the exact same code for both encryption and decryption, which minimizes the overall stub size of the software.

Today, we will examine how this mechanism works through standard ChaCha20 C code. Without getting bogged down in hundreds of lines of memory management or error handling, we focus strictly on the 3 most crucial aspects of the algorithm.

> Note: If you would like to inspect the remainder of the code, you can find it via the following link:
> https://www.oryx-embedded.com/doc/chacha_8c_source.html

---

## 1. Initializing the State Matrix

ChaCha20 is a stream cipher. Its objective is to use the provided key to generate a very long, pseudo-random keystream. Everything begins with constructing a 4x4 table (a state matrix of 16 32-bit words / 64 bytes) in memory.

Looking at the `chachaInit` function in the code, we observe that the first row of this matrix is populated with specific constants:

```c
// First 4 words of the state matrix for a 32-byte (256-bit) key
w[0] = 0x61707865;
w[1] = 0x3320646E;
w[2] = 0x79622D32;
w[3] = 0x6B206574;

```

When you place these hex values in little-endian order and convert them to ASCII, the phrase `"expand 32-byte k"` emerges. The remainder of the matrix is populated by the user-defined 32-byte key, block counter, and nonce values.

> NOTE: If you ever employ a cryptographic routine other than ChaCha20 and insert this constant segment somewhere in your binary, you can confuse and mislead analysts reverse engineering your code. At least, while not guaranteed to fool seasoned analysts, it represents an interesting anti-analysis concept.

---

## 2. ARX and Permutation (Mixing)

The security of the algorithm stems from mixing the values within that state matrix using an intricate mathematical routine prior to keystream generation. Let us take a close look at the core engine of the implementation, the `QUARTER_ROUND` macro:

```c
#define QUARTER_ROUND(a, b, c, d) \
{ \
   a += b; \
   d ^= a; \
   d = ROL32(d, 16); \
   c += d; \
   b ^= c; \
   b = ROL32(b, 12); \
   a += b; \
   d ^= a; \
   d = ROL32(d, 8); \
   c += d; \
   b ^= c; \
   b = ROL32(b, 7); \
}

```

Notice that there are only three elementary operations here: Addition (`+=`), XOR (`^=`), and Bitwise Left Rotation (`ROL32`). In cryptography, this design is known as an ARX (Add-Rotate-Xor) architecture. It puts minimal strain on the CPU while providing high diffusion and non-linearity.

How is this macro applied to the state table? In the `chachaProcessBlock` function, we observe the following sequence:

```c
// First, mix the columns...
QUARTER_ROUND(w[0], w[4], w[8],  w[12]);
QUARTER_ROUND(w[1], w[5], w[9],  w[13]);
QUARTER_ROUND(w[2], w[6], w[10], w[14]);
QUARTER_ROUND(w[3], w[7], w[11], w[15]);

// ...then mix the diagonals.
QUARTER_ROUND(w[0], w[5], w[10], w[15]);
QUARTER_ROUND(w[1], w[6], w[11], w[12]);
QUARTER_ROUND(w[2], w[7], w[8],  w[13]);
QUARTER_ROUND(w[3], w[4], w[9],  w[14]);

```

This sequence iterates over the table across 20 rounds (hence the name ChaCha20). The algorithm alternates 10 column rounds and 10 diagonal rounds. You can think of this like scrambling a Rubik's cube 20 times consecutively. The resulting keystream is so thoroughly diffused that recovering the original plaintext without the key is mathematically intractable.

---

## 3. Encrypting the Payload

We constructed the matrix, executed the permutation rounds, and derived the keystream (`k`). Now we arrive at the core task: encrypting the target payload.

The transformation occurs within this concise `for` loop (located inside the `chachaCipher` function):

```c
// XOR the payload (input) with the keystream (k)
for(i = 0; i < n; i++)
{
   output[i] = input[i] ^ k[i];
}

```

The resulting keystream (`k`) is XORed byte by byte with our original payload buffer (`input`). The result is a fully transformed, high-entropy output buffer (`output`).

As stated earlier, XOR is an involutory operation. When executing or processing this payload on the target system, initializing the cipher with the same key and nonce generates the exact same keystream, allowing the encrypted data to be decrypted using the identical routine without writing a separate decryptor function.

---

### Auxiliary Operations

If you review the linked source code, you will find additional logic beyond the sections highlighted above. To focus on the cryptographic architecture rather than boilerplate, those segments were omitted. A brief summary of those supporting components:

#### Matrix Population

```c
w[4] = LOAD32LE(key);
w[5] = LOAD32LE(key + 4);
w[6] = LOAD32LE(key + 8);
w[7] = LOAD32LE(key + 12);
// ...

```

This is a data parsing/packing routine. The key and nonce buffers are passed in as flat byte arrays. Because the internal state of ChaCha20 consists of 32-bit registers, conditional branches verify whether the key is 128-bit (16 bytes) or 256-bit (32 bytes), followed by inspecting nonce sizing (64-bit, 96-bit, or 128-bit). Once verified, the `LOAD32LE` (Load 32-bit Little Endian) helper parses the stream into 4-byte chunks and loads them into their corresponding matrix slots (`w`).

#### The `chachaDeinit` Function

```c
void chachaDeinit(ChachaContext *context)
{
   // Clear ChaCha context
   osMemset(context, 0, sizeof(ChachaContext));
}

```

This function serves a single purpose: scrubbing RAM once operations are complete. In cryptographic implementations, leaving keys or internal state tables lingering in volatile memory introduces security risks. `osMemset` overwrites the context struct with zeros to ensure secure cleanup.


### In Summary

The operational philosophy of ChaCha20 remains straightforward: construct the state matrix, diffuse the data using ARX rounds, and XOR the output with the payload buffer.
