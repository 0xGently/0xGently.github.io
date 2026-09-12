---
title: "What are Prologue and Epilogue in Assembly?"
date: 2026-05-21
draft: false
author: "0xGently"
---

When writing programs in high-level languages, there are many operations handled automatically in the background that we must manage manually in low-level languages (especially Assembly). Among the most critical of these are the **prologue** and **epilogue** sequences.

![Diagram of Prologue Operation on the Stack](/assets/img/assembly-image.webp)

Before diving into this topic, let's touch upon a few fundamental concepts:

- **Register:** The fastest data storage area within the CPU; data to be processed is held here.
- **Stack:** A memory area operating on a LIFO (Last In, First Out) basis, holding temporary data during function calls.
- **Stack Frame:** A block of memory allocated on the stack each time a function is called, containing arguments and local variables.
- **ESP/RSP:** The stack pointer; it points to the top of the stack. It is called ESP in x86 and RSP in x64 architecture.
- **EBP/RBP:** The base pointer; it holds the base address of the stack frame and serves as a reference point for accessing variables.
- **Calling Convention:** A set of rules determining how arguments are passed to functions and how return values are retrieved.
- **Push:** Pushes a value onto the stack, moving the stack pointer down.
- **Pop:** Pops the value from the top of the stack, moving the stack pointer up.

All these concepts form the foundation for understanding prologue and epilogue operations. Essentially, these two sequences consist entirely of setting up and tearing down the stack frame.

## What is a Prologue?

The prologue runs at the beginning of a function and sets up a "frame" on the stack. This frame is used to store the function's local variables and any registers that need to be preserved. This operation consists of 3 stages, as illustrated in the image below.

![Epilogue Steps and EBP Register State](/assets/img/assembly-image-2.webp)

Now let's examine these 3 steps one by one.

### 1. `push ebp`

First, we save our old reference point. When the current function finishes, the values we used inside the function will no longer need to remain on the stack. Therefore, before the frame is even opened, we record the point to which we must return at the end of the function.

### 2. `mov ebp, esp`

Here, we are actually preparing the upper boundary of the frame we are about to build. We move EBP to where ESP is. In other words, we are saying; 'from here on out, this function's territory begins.' Thus, the function's own workspace within the stack is clearly defined.

### 3. `sub esp, 0x10`

Finally, we allocate as much space as this function needs to use for storage on the stack, and in this way, the rest of the frame area is completed. We move ESP down a bit; that is, we make some room on the stack. This space becomes the dedicated area reserved for the function's local variables.

## In Summary

These three steps are essentially the process of creating a stack frame. The first command secures the return path by saving the old EBP value. The second command establishes the base of the new stack frame, facilitating access. The final step allocates enough space to store local variables. Consequently, the function obtains its own isolated working environment without corrupting the data of other functions.

## What is an Epilogue?

The epilogue is the code that runs at the end of a function and reverses the actions of the prologue. Its main purpose is to clean up the space the function allocated on the stack, restore the old layout, and safely return to the calling code. While the prologue sets up the stack frame, the epilogue tears it down. Together, they ensure that functions execute safely and systematically.

The epilogue generally occurs in three basic steps:

![Epilogue Steps and EBP Register State](/assets/img/assembly-image-3.webp)

### 1. `mov esp, ebp`

This step frees the stack space used by the function. The stack pointer (ESP) is brought back to the base pointer (EBP) it marked at the beginning of the function. As a result, the area temporarily used by the function is reclaimed by the stack.

### 2. `pop ebp`

The old base pointer (EBP), which was pushed to the top of the stack during the prologue, is now restored. The environment prior to the function—the stack and the base pointer—reverts exactly to its former state. This gives the impression that the function was never called.

### 3. `ret`

In the final step, the CPU pops the instruction pointer (EIP) from the stack and returns to the calling code. The function's job is now completely finished, and program execution continues from where it left off.

Without the epilogue, the stack becomes corrupted and program flow is disrupted. If the stack frame is not removed, ESP remains in the wrong place, and functions cannot return correctly.

Functions are the fundamental building blocks of programs, and they require both **prologue** and **epilogue** sequences for correct operation. The prologue prepares the environment the function needs, while the epilogue finishes the job, cleans up the environment, and returns to the old layout.

Understanding the epilogue is crucial, especially when working with low-level programming and Assembly. Proper management of the stack is essential for the stability and security of the program. Therefore, seeing how a function starts and ends is a major step toward understanding the inner workings of the code.

In this text, we discussed two fundamental operations that people will frequently encounter in Reverse Engineering or when reading Assembly. That's all for our topic. See you in the next text.
