---
layout: post
title: "Live kernel introspection on iOS"
author: Brandon Azad
date: 2017-09-15 16:00:00 -0700
category: security
tags: [memctl, iOS, macOS]
description: >
  A live kernel memory inspection tool to aid in analyzing vulnerabilities and
  modifying the kernel.
---

Part of effective security research is having the right tools to analyze vulnerabilities. Apple
allows users to develop kernel extensions and debug the kernel on macOS, but neither is supported
on iOS. This post explains how I developed [memctl], a kernel introspection tool for macOS and iOS
that I've been using for the past year to analyze the kernel.

[memctl]: https://github.com/bazad/memctl

Memctl uses the kernel task port to reliably read and write kernel memory and to reliably call
arbitrary kernel functions with arbitrary arguments on both macOS and iOS. Other useful features
are implemented on top of this basic functionality, mostly convenience routines to call kernel
functions that would otherwise be difficult to find or call. Memctl's functionality is provided
both as a library (called libmemctl) and as a command-line tool.

Coincidentally, Ian Beer described how he developed his own kernel memory debugger in
[Exception-oriented exploitation on iOS], which was published late into my work on memctl. To me
this shows how useful such a tool could be. While I developed memctl primarily for my own use, I am
open-sourcing it in case someone else finds my work useful.

[Exception-oriented exploitation on iOS]: https://googleprojectzero.blogspot.com/2017/04/exception-oriented-exploitation-on-ios.html

<!--more-->

## Table of Contents
{:.no_toc}

* TOC
{:toc}

## Kernel debugging on iOS

Debuggers make analyzing security vulnerabilities much easier. Unfortunately, outside of Apple,
there is no straightforward way to support true kernel debugging on iOS. Memctl is my attempt at
the next best thing: creating a framework to provide some of the functionality of a kernel
debugger.

Unfortunately, memctl does not support breakpoints, which is why I call it a kernel introspection
tool rather than a debugger. It might be possible to implement live kernel breakpoints (where the
debugger is running on the kernel being debugged), but this seems difficult and error-prone at
best, and would certainly need a [Kernel Patch Protection] bypass.

[Kernel Patch Protection]: http://technologeeks.com/files/TZ.pdf

What memctl does support is the memory access part of a debugger.[^1] Specifically, libmemctl
includes functions to safely (or, as safely as possible) read and write kernel memory. All other
features, including the ability to call kernel functions, are built on top of this capability.

Of course, Apple does not provide a way for user-space programs to directly access kernel memory;
we'll need a way around these restrictions. One way is to use a kernel vulnerability directly.
Another way, more common on jailbroken devices, is to access the kernel task through a Mach port.
The advantage of using the kernel task port is that the API is consistent: you don't need to
rewrite your memory access functions if you switch to a different vulnerability. Libmemctl uses the
kernel task approach. However, this means that in order to get memctl running on a platform, we
need an exploit that obtains the kernel task port.

Fortunately, many iOS jailbreaks, including [mach_portal] and [yalu102], provide a way for programs
to access the kernel task port, meaning memctl can run on top of these jailbreaks. I've only tested
memctl on those two, but theoretically it should work fine on other jailbreaks as well.

[mach_portal]: https://bugs.chromium.org/p/project-zero/issues/detail?id=965
[yalu102]: https://github.com/kpwn/yalu102

## An overview of memctl

Memctl is divided into two parts: a library called libmemctl that implements kernel introspection,
modification, and function calling, and a command-line tool called memctl that allows users to
access much of this functionality from the terminal. However, you also need a third part that is
separate from memctl: a library called a "core" to get the kernel task port.

The purpose of the core is simply to give memctl a consistent API through which it can obtain the
kernel task port. On jailbroken devices, the core could be as simple as a call to `task_for_pid(0)`
or `host_get_special_port(4)`.[^2] However, non-jailbroken devices will need a core that actually
exploits a vulnerability to install a send right to the kernel task into the current task. The
[memctl-physmem-core] repository shows how to do this for the physmem vulnerability, although
physmem is likely easier to exploit than most modern vulnerabilities.

[memctl-physmem-core]: https://github.com/bazad/memctl-physmem-core

The primary purpose of libmemctl is to provide a safe API to access kernel memory and call kernel
functions. In order to do so, libmemctl offers many features:

* A partial AArch64 disassembler and simulator
* On-device kernelcache decompression
* Symbol resolution for exported symbols
* Special symbol resolution to find certain unexported symbols on AArch64, including vtables
* Discovery of the kASLR slide
* Kernel virtual and physical memory read and write, including safe memory scanning
* Virtual-to-physical address translation
* Kernel memory allocation
* Kernel function calling (with up to 8 arguments on AArch64)
* Process and task modification
* Privilege escalation

The memctl command-line utility packages libmemctl so that it can be used to debug the device on
which it is running. Its CLI takes inspiration from [radare2]. Some of the most useful memctl
commands are:

* `r`: Read kernel virtual or physical memory
* `w`: Write kernel virtual or physical memory
* `f`: Find a value in memory (all memory locations containing the given value are printed)
* `fc`: Find instances of a C++ class
* `lc`: Determine the C++ class from an object pointer
* `kp`: Translate a kernel virtual address to a physical address
* `zs`: Print the size of a block of memory allocated with zalloc
* `vmm`: Show the kernel virtual memory map (like vmmap)
* `a`: Print the address of a kernel symbol
* `s`: Look up the symbol containing the given kernel virtual address

[radare2]: https://rada.re/r/

It's also important to understand what memctl is not. Memctl is not an exploit and it leverages no
vulnerabilities, zero-day or otherwise. Such vulnerabilities could be used in a core to allow
memctl to run on a certain platform, but memctl itself does not exploit any vulnerabilities.

Memctl is also not designed to be a replacement for other reversing tools such as IDA and radare.
Memctl is useful for inspecting the kernel as it is running and for facilitating iOS research. Some
limited static analysis is performed on-device in order to find kernel symbols, but this analysis
is not nearly as sophisticated as that performed by dedicated reversing frameworks.

Finally, memctl is not designed to work on all OS versions and platforms. Libmemctl relies on the
ability to locate certain kernel symbols, which is not possible on the encrypted kernelcaches prior
to iOS 10.[^3] Additionally, libmemctl currently offers no support for 32-bit versions of macOS and
iOS, and no such support is planned. This makes memctl unsuitable for analyzing 32-bit devices like
the iPhone 5 or the Apple Watch.

I have tested memctl on macOS 10.12.1, macOS 10.12.6, iOS 10.1.1, and iOS 10.2. Because libmemctl
relies on many XNU internals, it likely needs significant tweaking to work on other versions and
platforms. Moreover, since memctl is primarily a tool for my own research, it is geared for my own
use cases and may not be stable.

The rest of this post talks about the implementation details of libmemctl and concludes with some
examples showing how to use memctl.

## Basic kernel memory access

The most primitive operations supported by libmemctl are unsafe kernel memory reads and writes,
provided by the functions `kernel_read_unsafe` and `kernel_write_unsafe`, respectively. These
functions use the `mach_vm_read_overwrite` and `mach_vm_write` Mach traps to read and write memory
in the kernel task.

Two other useful functions are `kernel_read_heap` and `kernel_write_heap`, which are analogous
functions that attempt to access kernel memory but fail safely if it is possible that the accessed
memory address does not refer to the kernel heap. Unlike the unsafe functions, these functions are
(or should be) safe: trying to read a nonexistent kernel address will simply return an error rather
than crashing the kernel. The kernel heap can be identified using the `mach_vm_region_recurse` Mach
trap to get the region's `user_tag` attribute. Memory addresses allocated with `zalloc` (used by
`kalloc` for small allocations) will have the `user_tag` set to `VM_KERN_MEMORY_ZONE` (12).[^4]

While it might not seem like much, the ability to read kernel memory safely is crucial for
implementing the rest of the functionality, because it allows us to scan memory without risk of
crashing the system.

## Finding the kernel slide

Using the kernel task and the basic memory read functions, we can find the kASLR slide in a number
of different ways, depending on the platform.

On macOS, the most straightforward way is to use the symbol `_last_kernel_symbol`. The macOS kernel
is shipped unstripped, meaning we can get the static addresses of all sorts of useful symbols just
by parsing the symbol table. In this case, `_last_kernel_symbol` designates the very last page in
the kernel image.

For example, on macOS 10.12.4, the kernel might lie somewhere in the following memory region:[^5]

```
          START - END             [ VSIZE ] PRT/MAX SHRMOD DEPTH RESIDENT REFCNT TAG
ffffff8000000000-ffffff8030152000 [  769M ] ---/---    NUL     0        0      0   0
```

By parsing the kernel it is possible to determine that `_last_kernel_symbol` lives at static
(unslid) address `0xffffff8000b51008`, which means that the first page after the kernel is
`0xffffff8000b52000` (the page size on this platform is 4K). Subtracting this static address from
the runtime address `0xffffff8030152000` gives the kernel slide of `0x000000002f600000`.

This trick does not work on iOS because on iOS the kernel lives at an unknown location (read: not
at the end) in a much larger memory region. The simplest approach is to scan every page in the
region until we find the one containing the kernel's Mach-O header. Unfortunately, this does not
work in practice because not all pages in this region are mapped, meaning the scan will trigger a
panic if it accesses an unmapped page.

A safer approach relies on a few implementation details in XNU. There's at least one memory region
in the kernel memory map with depth 0 and `user_tag` `VM_KERN_MEMORY_ZONE`. The first word of this
region is a pointer to somewhere in the middle of the kernel's `_zone_array` symbol. Thus, a
pointer into the kernel can be found by locating a memory region with depth 0 and `user_tag`
`VM_KERN_MEMORY_ZONE` and dereferencing the first pointer in that region. From there, finding the
start of the kernel is as simple as scanning memory backwards, since all addresses between the
`_zone_array` symbol and the start of the kernel's Mach-O header will be mapped.

For example, on an iPhone 5s running iOS 10.2, the kernel memory map includes the following
regions:

```
          START - END             [ VSIZE ] PRT/MAX SHRMOD DEPTH RESIDENT REFCNT TAG
ffffffe000000000-fffffff000000000 [   64G ] ---/---    NUL     0        0      0   0
...
fffffff01a825000-fffffff01a827000 [    8K ] rw-/rwx    S/A     0        2    829  12
...
fffffff01b1e2000-fffffff01b1f6000 [   80K ] rw-/rwx    S/A     0       20    829  12
...
fffffff01c800000-fffffff11e000000 [  4.0G ] ---/---    NUL     0        0      0   0
...
fffffff27fef8000-fffffff27ffff000 [  1.0M ] ---/---    NUL     0        0      0   0
```

Reading 8 bytes at `0xfffffff01a825000` yields the pointer `0xfffffff01dd6a720`. Checking the
memory map confirms that this address lies within a large, 4GB carve-out of virtual memory with no
access permissions, a strong indication that the address actually does point to the kernel.[^6]
Scanning backwards from that address, we eventually encounter the value `0x0100000cfeedfacf` at
address `0xfffffff01d804000`, which looks like the start of a 64-bit Mach-O file. Reading the rest
of the Mach-O header quickly confirms that this is the start of the kernel's `__TEXT` segment. The
kernel slide is then computed as `0xfffffff01d804000 - 0xfffffff007004000 = 0x0000000016800000`,
where `0xfffffff007004000` is the static address of the kernel's `__TEXT` segment in the Mach-O
file.

## Generic kernel function calls on iOS and macOS

Once we have the basic kernel memory functions and the kernel slide, we can patch parts of the
kernel heap in order to create a limited kernel function call capability, which libmemctl provides
as the function `kernel_call_7`. Stefan Esser describes this technique in [Tales from iOS 6
Exploitation and iOS 7 Security Changes]. The idea is to patch the vtable of an `IOUserClient`
instance in the kernel so that invoking the `iokit_user_client_trap` Mach trap on the user client
causes a controlled function pointer to be called.

[Tales from iOS 6 Exploitation and iOS 7 Security Changes]: https://conference.hitb.org/hitbsecconf2013kul/materials/D2T2%20-%20Stefan%20Esser%20-%20Tales%20from%20iOS%206%20Exploitation%20and%20iOS%207%20Security%20Changes.pdf

The `iokit_user_client_trap` Mach trap is used to invoke external traps, described by the
`IOExternalTrap` struct, on an `IOUserClient` instance. We can invoke this trap from user space
using the `IOConnectTrap6` function. The kernel implementation calls the user client's
`getTargetAndTrapForIndex` method to obtain an `IOExternalTrap` object and then calls the trap
function with the user-supplied arguments. Here's the code, from [IOUserClient.cpp]:

[IOUserClient.cpp]: https://opensource.apple.com/source/xnu/xnu-3789.51.2/iokit/Kernel/IOUserClient.cpp.auto.html

{% highlight C %}
kern_return_t iokit_user_client_trap(struct iokit_user_client_trap_args *args)
{
    kern_return_t result = kIOReturnBadArgument;
    IOUserClient *userClient;

    if ((userClient = OSDynamicCast(IOUserClient,
            iokit_lookup_connect_ref_current_task((OSObject *)(args->userClientRef))))) {
        IOExternalTrap *trap;
        IOService *target = NULL;

        trap = userClient->getTargetAndTrapForIndex(&target, args->index);

        if (trap && target) {
            IOTrap func;

            func = trap->func;

            if (func) {
                result = (target->*func)(args->p1, args->p2, args->p3, args->p4, args->p5, args->p6);
            }
        }

	iokit_remove_connect_reference(userClient);
    }

    return result;
}
{% endhighlight %}

If we can control the `target` and `trap` returned by `getTargetAndTrapForIndex`, then we can call
any function in the kernel with up to 7 arguments.[^7]

First we need to create an `IOUserClient` instance at a known address in the kernel so that we can
manipulate it. I chose `AppleKeyStoreUserClient` as the user client class because most applications
can access it on both macOS and iOS, reducing the implementation overhead. At this point, our only
useful primitive is a kernel heap memory scan, so we will create the user client and then try to
find it in memory by inspecting the heap.

We'll need two pieces of information to fully identify the user client: the address of the
`AppleKeyStoreUserClient` vtable and the user client's registry entry ID. The former we can compute
since we already know the kernel slide. We can find the user client's registry entry ID by
recording the IDs of all children of the `AppleKeyStore` service before and after creating the user
client, and then looking for a new child entry.[^8] We then scan the kernel heap looking for
pointers to the `AppleKeyStoreUserClient` vtable. Each of these locations could be the start of an
`AppleKeyStoreUserClient` instance, but some of these addresses may point to freed objects or
random heap garbage. However, we do know that our user client must be in this list.

We can figure out which address corresponds to our user client by reading the registry entry ID
field of each possible instance using our kernel memory functions: if any potential user client
instance has the wrong registry entry ID, we can eliminate it. As long as there is exactly one
match (which happens the overwhelming majority of the time), we can be sure that we've found the
address of the user client to which we have a connection.

The next step is to create a fake vtable that will allow us to control the `target` and `trap`
returned by `getTargetAndTrapForIndex`. The default implementation of this method calls
`getExternalTrapForIndex` to get the `IOExternalTrap`, then extracts the target service from the
returned object:

{% highlight C++ %}
IOExternalTrap * IOUserClient::
getTargetAndTrapForIndex(IOService ** targetP, UInt32 index)
{
      IOExternalTrap *trap = getExternalTrapForIndex(index);

      if (trap) {
              *targetP = trap->object;
      }

      return trap;
}
{% endhighlight %}

Thus, in order to control both parameters, the only thing we need to do is override
`getExternalTrapForIndex` with a function that will return a pointer to controlled data. There are
many possible candidates, but since we already know the address of the user client's registry entry
ID field, I chose to replace `getExternalTrapForIndex` with `getRegistryEntryID`. That way, when
`getExternalTrapForIndex` is called, the user client's registry entry ID will be returned instead.
Of course, the user client's registry entry ID is not going to be a valid kernel pointer. However,
we know the address of our user client's registry entry ID field, so we can overwrite it with a
pointer to a controlled `IOExternalTrap` object.

To create the fake vtable, we simply read the real `AppleKeyStoreUserClient` vtable from kernel
memory and replace the `IOUserClient::getExternalTrapForIndex` method with
`IORegistryEntry::getRegistryEntryID`. We can then allocate kernel memory with `mach_vm_allocate`
and write the modified vtable into it.

Finally, we need to patch the user client so that invoking `iokit_user_client_trap` will call the
function we want. We allocate more kernel memory to store the fake `IOExternalTrap` object and
overwrite the user client's registry entry ID field with this address. Last of all, we overwrite
the user client's vtable pointer with the address of the fake vtable we copied into the kernel
earlier.

At this point, when `iokit_user_client_trap` calls `getTargetAndTrapForIndex`, the trap that is
returned will be the address of our fake `IOExternalTrap` object. However, the fields of this
object need to be initialized for each function call.

In order to actually call a kernel function, we must overwrite the `IOExternalTrap` object so that
the `func` field points to the function we want to call and the `object` field is the first
argument to that function. Then, we can invoke `IOConnectTrap6` with the remaining arguments to
perform the actual function call.

Unfortunately, using `iokit_user_client_trap` places some restrictions on the arguments and return
value of the kernel function call. Because the `trap->object` pointer is verified as non-NULL
before the trap is invoked, the first argument to the called function cannot be 0. Additionally,
the return value of `iokit_user_client_trap` is a `kern_return_t`, which on 64-bit platforms is a
32-bit integer. Getting around these restrictions is the subject of the next two sections.

## Arbitrary kernel function calls on AArch64

It's possible to construct a less restricted kernel function call capability on top of the generic
mechanism just described. Libmemctl implements several [jump-oriented programs][jump-oriented
programming] to call arbitrary kernel functions with up to 8 arguments and retrieve the 64-bit
return value in user space.[^9] The specific implementation is chosen based on the gadgets
available in the running kernel. Here I'll briefly describe one such program, which can be used
when running iOS 10.1.1 on the iPhone 6s and iPhone 7. A complete listing of the gadgets executed
in this payload, including the intermediate register values, is available in the [source
code][kernel_call_aarch64.c].

[jump-oriented programming]: https://www.comp.nus.edu.sg/~liangzk/papers/asiaccs11.pdf
[kernel_call_aarch64.c]: https://github.com/bazad/memctl/blob/master/src/libmemctl/aarch64/kernel_call_aarch64.c

At a high level, we will construct a JOP payload in kernel memory and then use the generic kernel
function call method we just established to start executing that payload. The generic function call
mechanism supports up to 7 arguments: not enough for all 8 arguments to the target function, but
plenty to initialize registers for a JOP payload. The payload will set up the function arguments in
registers `x0` through `x7`, jump to the target function, write the return value (stored in `x0`)
into memory, and then return to the caller.

The JOP payload has three parts: the JOP stack (called JOP_STACK), the value stack (called
VALUE_STACK), and a block of memory to resume JOP execution after running the store gadget (called
STORE_RESUME). The JOP_STACK stores the sequence of gadgets to execute, while the VALUE_STACK
stores the values that will get loaded into registers.

The most important JOP gadget is the dispatcher, called JOP_DISPATCH. For this payload, I am using
this wonderful gadget from the com.apple.filesystems.apfs kext:

	ldp     x2, x1, [x1]
	br      x2

This gadget loads the `x2` and `x1` registers with the two 64-bit words at the address in `x1` and
then jumps to the address in `x2`. Because the load overwrites the dereferenced register `x1`,
calling this gadget a second time will perform a different load and jump than before, which makes
this gadget suitable as a JOP dispatcher. In fact, if you imagine this gadget being run repeatedly
in a loop, you can see that it behaves kind of like a linked-list traversal. Thus, we can implement
the JOP_STACK as a linked list, where the first pointer in each node is the gadget to execute and
the second pointer is the address of the next node. We can chain the execution of these gadgets as
long as each gadget jumps back to JOP_DISPATCH.

This is what the JOP_STACK looks like in memory if we place all the nodes sequentially:

	JOP_STACK  8          10         18         20         28         30         38
	+----------+----------+----------+----------+----------+----------+----------+-
	| gadget 0 |  +0x10   | gadget 1 |  +0x20   | gadget 2 |  +0x30   | gadget 3 |  ...
	+----------+----------+----------+----------+----------+----------+----------+-

Once the JOP_STACK is running, we can load values from the VALUE_STACK into registers using the
load gadget. The load gadget populates `x3` through `x6` from `x20`, which is the register used to
store the address of the VALUE_STACK:

	ldp     x3, x4, [x20, #0x20]
	ldp     x5, x6, [x20, #0x30]
	blr     x8

In order to keep running from the JOP_STACK after this gadget, we must set `x8` equal to the
address of JOP_DISPATCH.

However, after the load gadget is run, we won't be able to load new values until the VALUE_STACK is
advanced past the values we just loaded. We can use the following gadget to advance the
VALUE_STACK in preparation for another load:

	add     x20, x20, #0x34
	br      x8

With the right collection of gadgets to shuffle values around the registers, we can perform a
sequence of loads and moves to populate all the registers we need for the function call. I ended up
using 4 loads with 3 intervening advances in order to populate registers with all the values I
needed.

Here is the layout of the VALUE_STACK in memory. Each chunk represents a single load, but because
the advance gadget only moves the value stack forward by `0x34` bytes each time, the end of each
chunk in the diagram overlaps with the beginning of the next one. The load gadget populates `x3`,
`x4`, `x5`, and `x6` with the contents of each chunk at offset `0x20`, `0x28`, `0x30`, and `0x38`,
respectively. The result of the function call eventually gets written back to the VALUE_STACK at
offset `0x9c`.

	VALUE_STACK         10                  20                  30   34             40
	+---------+---------+---------+---------+---------+---------+----+----+---------+
	| ~ STORE_RESUME ~~ |         |         | gadget  | gadget  | _______ | STORE_R |  >---+
	+---------+---------+---------+---------+---------+---------+----+----+---------+      |
	                                                                                       |
	   +-----------------------------------------------------------------------------------+
	   |
	   V
	34             40   44                  54                  64   68             74
	+----+---------+----+---------+---------+---------+---------+----+----+---------+
	____ | STORE_R |    :         :         : <func>  : _______ : <arg7>  : _______ :  >---+
	+----+---------+----+---------+---------+---------+---------+----+----+---------+      |
	                                                                                       |
	   +-----------------------------------------------------------------------------------+
	   |
	   V
	68             74   78                  88                  98   9c             a8
	+----+---------+----+---------+---------+---------+---------+----+----+---------+
	g7>  : _______ :    |         |         | <arg1>  | <arg2>  | <arg0>  | _______ |  >---+
	+----+---------+----+---------+---------+---------+---------+----+----+---------+      |
	                                                                                       |
	   +-----------------------------------------------------------------------------------+
	   |
	   V
	9c             a8   ac                  bc                  cc   d0             dc
	+----+---------+----+---------+---------+---------+---------+----+----+---------+
	g0>  | _______ |    : JOP_DIS : JOP_STA : <arg3>  : <arg4>  : <arg5>  : <arg6>  :
	+----+---------+----+---------+---------+---------+---------+----+----+---------+
	^^^^^^^^^^^
	| result  |
	+---------+

Once all the registers have been populated from the VALUE_STACK, we can perform the function call.
The last registers we overwrite will be `x1` and `x2`, since those are used by the JOP_DISPATCH
gadget; once they are overwritten we can no longer use the dispatcher. However, this presents a
challenge: How do we start executing the JOP payload again after the function call? Fortunately,
AArch64 provides a native way to control what code to run after a function call: the return
address, stored in register `x30`. Thus, we need to fill `x30` with the address of a gadget that
will resume execution from the JOP stack.

A quick scan of the available gadgets reveals this candidate:

	ldp     x8, x1, [x20, #0x10]
	blr     x8

We can use this gadget to resume execution by storing the JOP_DISPATCH and JOP_STACK in the
VALUE_STACK, at offsets `0x10` and `0x18` of chunk 4. That way, the load will put JOP_DISPATCH in
`x8`, the rest of the JOP_STACK in `x1`, and jump to JOP_DISPATCH, exactly as we needed. This
gadget is also a good choice because it does not clobber `x0`, the register that contains the
return value from the function call.

Once we are running code from the JOP_STACK, the next step is to store the return value back into
the VALUE_STACK so that we can read it from user space later. In order to store the return value,
we need a store gadget. Unfortunately, none of the usable store gadgets I found in the iOS 10.1.1
and 10.2 kernelcaches could be executed directly: they were all stores followed by a C++ virtual
method call, and hence needed a fake vtable in order to resume executing from the JOP_STACK. This
is where STORE_RESUME comes in.

Here's the gadget I ended up using to store `x0` into the VALUE_STACK:

	str     x0, [x20]
	ldr     x8, [x22]
	ldr     x8, [x8, #0x28]
	mov     x0, x22
	blr     x8

The gadget assumes that `x22` is a pointer to some C++ object and performs a virtual method call
(index 5) on that object. STORE_RESUME is a fake C++ object, a pointer to which we will store in
`x22`, such that the virtual method call in this gadget will actually end up jumping back to the
JOP_DISPATCH gadget and running the rest of the JOP_STACK.

In order to continue executing the JOP_STACK, `x8` must be JOP_DISPATCH at the final branch. We can
use the following layout for STORE_RESUME:

	STORE_RESUME            8                       10
	+-----------------------+-----------------------+
	| STORE_RESUME+0x8-0x28 |     JOP_DISPATCH      |
	+-----------------------+-----------------------+

Finally, after the store gadget writes the target function's return value into the VALUE_STACK, we
can have the JOP program return back to the caller. The caller will eventually return to user
space, and from there we can read back the return value from kernel memory.

While this strategy works very well on the systems I have tested, a significant limitation is
that it may not work on other platforms and builds until an appropriate JOP program has been
constructed using the available gadgets. These JOP programs are hard-coded: libmemctl does not have
the power to dynamically create JOP payloads from unknown sets of gadgets. I originally tried
implementing a limited dynamic payload generator, but it was complicated enough that I didn't end
up completing it.

## Arbitrary kernel function calls on x86_64

Calling arbitrary kernel functions on x86_64 platforms is a bit simpler than on AArch64. I use the
same technique in libmemctl as I used in [physmem][physmem syscall hook]: add a new system call by
overwriting an entry in the system call table. We can overwrite read-only kernel memory by calling
a kernel function to write to physical, rather than virtual, memory. Since the technique is
described in detail in that post, I refer the interested reader there.

[physmem syscall hook]: /2017/01/physmem-accessing-physical-memory-os-x/#reliable-kernel-code-execution

## Safe kernel memory access

Once we can call arbitrary kernel functions, we can build safe mechanisms to read and write kernel
memory outside the heap. This is because we can call kernel functions like `pmap_find_phys` and
`pmap_cache_attributes` to translate a virtual address into a physical address and to determine
physical cache attributes associated with an address.

The safest access mechanism is `kernel_read_safe`, which ensures that an address is mapped and not
a special I/O region before accessing it. We can check if the virtual address is mapped with
`pmap_find_phys`, since this function will return 0 if a virtual address has no backing page.
Determining whether or not an address is a special I/O region is trickier. One way is to check the
region's share mode: in my testing, all special physical memory regions have the share mode of the
corresponding virtual region set to `SM_EMPTY`. Thus, as long as the share mode is not `SM_EMPTY`,
the region is safe to access.

However, there's a big downside to `kernel_read_safe`: Many interesting and safe-to-access memory
regions also have their share mode set to `SM_EMPTY`, including the kernel carveout (the large
virtual memory region containing the kernel image). This means that `kernel_read_safe` and
`kernel_write_safe` will fail to read or write to the kernel image.

Libmemctl offers a way around this restriction with the `kernel_read_all` access mechanism. The
idea is that most special I/O regions (for example, memory-mapped device registers) are located at
predictable physical addresses; if we are careful not to access those addresses, we can avoid
triggering a panic. Thus, `kernel_read_all` only forbids access to unmapped pages and static memory
regions that are known to be inaccessible. The advantage is that a much larger portion of kernel
memory can be accessed. However, because the blacklist of bad regions is static and hardcoded, it's
possible that `kernel_read_all` will trigger a panic on an untested platform.

On some platforms, it's also possible to safely read physical memory without first knowing the
virtual address. The kernel function `pmap_cache_attributes` returns the physical cache attributes
associated with an address. On iOS, all unsafe physical addresses have the `VM_MEM_GUARDED` bit set
in these attributes (although some safe addresses also have that flag set). Libmemctl provides the
function `physical_read_safe` which will only try to read physical addresses for which the
`VM_MEM_GUARDED` bit is cleared. This is useful because it allows us to perform physical memory
scans.

Unfortunately, I have yet to smooth out a few issues with `physical_read_safe`: on some platforms
(my Macbook Pro), there are unsafe physical addresses with the `VM_MEM_GUARDED` bit clear, meaning
`physical_read_safe` is not actually safe. Thus, if you want to avoid a panic, don't use
`physical_read_safe` to scan memory.

## Implementing mach_portal with libmemctl

In order to check libmemctl's functionality, I reimplemented parts of Ian Beer's [mach_portal]
exploit using libmemctl APIs. The goal was to replace most of the kernel manipulations after
acquiring the kernel task port. The repository is available at [mach_portal_memctl].

[mach_portal_memctl]: https://github.com/bazad/mach_portal_memctl

## Examples of using memctl

Finally, I'll give a brief overview of how to use memctl.

When you run memctl without arguments, it drops into a REPL. You can type commands which memctl
will run. These commands are self-documented. To see a list, type `?` at the prompt:

	memctl> ?
	i                                    Print system information
	r <address> [length]                 Read and print formatted memory
	rb <address> <length>                Print raw binary data from memory
	rs <address> [length]                Read a string from memory
	w <address> <value>                  Write an integer to memory
	wd <address> <data>                  Write arbitrary data to memory
	ws <address> <string>                Write a string to memory
	f <value> [range]                    Find an integer in memory
	fpr <pid>                            Find the proc struct for a process
	fc <class> [range]                   Find instances of a C++ class
	lc <address>                         Look up the class of a C++ object
	kp <address>                         Translate virtual to physical address
	kpm <range>                          Print virtual to physical address map
	zs <address>                         Get zalloc memory size
	pca <address>                        Show physical cache attributes
	vt <class>                           Find the vtable of a C++ class
	vtl <address>                        Look up the class name for a vtable
	vm <address>                         Show virtual memory information
	vmm [range]                          Show virtual memory information for range
	vma <size>                           Allocate virtual memory
	vmd <address> [size]                 Deallocate virtual memory
	vmp <protection> <address> [length]  Set virtual memory protection
	ks [address]                         Kernel slide
	a <symbol>                           Find the address of a symbol
	ap [address]                         Address permutation
	s <address>                          Find the symbol for an address
	kcd <file>                           Decompress a kernelcache
	root                                 Exec a root shell
	quit                                 Exit the REPL

Here, you can see a brief overview of every command supported by memctl. To get additional
information about a specific command, type the name of the command (the part before the first
space) followed by `?`. For example, one of the most commonly used commands is `r`, which reads
kernel memory:

	memctl> r?
	
	r[width] [-d] [-f] [-p] [-x access] <address> [length]
	
	    Read data from kernel virtual or physical memory and print it with the
	    specified formatting.
	
	Options:
	    [width]      The width to display each value
	    [-d]         Use dump format with ASCII
	    [-f]         Force read (unsafe)
	    [-p]         Read physical memory
	    [-x access]  The memory access width
	
	Arguments:
	    <address>    The address to read
	    [length]     The number of bytes to read

Each command consists of a command name, followed by options, followed by arguments. Options are
designated in square brackets and start with a dash. Options may take a single argument, such as
the `-x` option above. Arguments to the command are designated in angle brackets. The last few
arguments to a command may be optional, in which case they are surrounded by square brackets
instead. If an optional argument is not supplied a suitable default value will be used. A command
may also have an unnamed option, which is designated by placing it in square brackets directly
following the command name. Unnamed options are provided when a particular option is used
frequently enough that specifying the option name each time would be a nuisance. In the case of the
`r` command, the unnamed `width` option indicates the integer width of the value or values to read.

Memctl accepts two ways of specifying options to a command: verbose and compact. In the verbose
form, each option is written out individually. For example, the following command reads 64 bytes
from physical address `0x100`, skipping safety checks, with an access width of 4 (that is, the read
is performed 4 bytes at a time), and displays the result in dump format with a column width of 2:

	memctl> r2 -p -f -x 4 -d 100 64
	0000000000000100:  0001 0203 0405 0607 0809 0a0b 0c0d 0e0f  |................|
	0000000000000110:  1011 1213 1415 1617 1819 1a1b 1c1d 1e1f  |................|
	0000000000000120:  2021 2223 2425 2627 2829 2a2b 2c2d 2e2f  | !"#$%&'()*+,-./|
	0000000000000130:  3031 3233 3435 3637 3839 3a3b 3c3d 3e3f  |0123456789:;<=>?|

However, since this command is so long to type, memctl also supports a compact format: any options
that take no arguments or simple numeric arguments may be condensed and placed at the end of the
command name. The following command is equivalent to the longer form above:

	memctl> r2pfx4d 100 64

Another useful command is the `a` (address) command, which takes a (mangled) symbol name and prints
the runtime address of the symbol and a guess of the symbol's size. By default, symbols are assumed
to be in the kernel. If the symbol is in a kernel extension, you can place the bundle ID and a
colon before the symbol name. To search the kernel and all kernel extensions for the symbol, put a
colon before the symbol name but omit the bundle ID.

	memctl> a _copyout
	0xffffff8015dfd700  (48)
	memctl> a com.apple.driver.AppleMobileFileIntegrity:_csEnforcementDisable
	0xffffff7f9692396a  (1)
	memctl> a :_csEnforcementDisable
	0xffffff7f9692396a  (1)

The `s` command is the inverse of the `a` command: given an address, it prints information about
the symbol corresponding to that address.

	memctl> s 0xffffff7f9692396b
	com.apple.driver.AppleMobileFileIntegrity __DATA: _lvEnforceThirdParty  (1)

Any time a command takes an address, you can also specify a symbol; the symbol will automatically
be converted to its virtual address.

	memctl> vm :_csEnforcementDisable
	          START - END             [ VSIZE ] PRT/MAX SHRMOD DEPTH RESIDENT REFCNT TAG
	ffffff7f96922000-ffffff7f96925000 [   12K ] rw-/rw-    P/A     1        3      3   6
	memctl> r1 :_csEnforcementDisable
	setting up kernel function call...
	ffffff7f9692396a:  00
	memctl> w1 :_csEnforcementDisable 1
	memctl> r1 :_csEnforcementDisable
	ffffff7f9692396a:  01

Other useful commands for inspecting IOKit objects are `fc` and `lc`, which find instances of a
class and determine the class type of an object:

	memctl> fc AppleMobileFileIntegrity
	0xffffff8035bf9000
	memctl> vm 0xffffff8035bf9000
	          START - END             [ VSIZE ] PRT/MAX SHRMOD DEPTH RESIDENT REFCNT TAG
	ffffff8034c86000-ffffff804538c000 [  263M ] rw-/rwx    S/A     1    67334    214  12
	memctl> zs 0xffffff8035bf9000
	160
	memctl> r 0xffffff8035bf9000 160
	ffffff8035bf9000:  ffffff7f96922d70 0000000000020003
	ffffff8035bf9010:  ffffff803547cb00 ffffff8035bf6d00
	ffffff8035bf9020:  ffffff8035bf6a00 ffffff803547c320
	ffffff8035bf9030:  ffffff80352b00e0 0000000000000003
	ffffff8035bf9040:  0000000000000000 000000000000001e
	ffffff8035bf9050:  0000000000000000 0000000000006cc7
	ffffff8035bf9060:  0000000000000000 0000000000000000
	ffffff8035bf9070:  0000000000000000 0000000000000000
	ffffff8035bf9080:  0000000000000000 ffff4c85c7ffffff
	ffffff8035bf9090:  bd394c00000000ff deadbeefdeadbeef
	memctl> lc ffffff803547cb00
	error: address 0xffffff8035bf7e40 is not a vtable
	memctl> lc ffffff8035bf6d00
	OSDictionary
	memctl> lc ffffff8035bf6a00
	OSDictionary
	memctl> lc ffffff803547c320
	error: address 0x0000000000000000 is not a vtable
	memctl> lc ffffff80352b00e0
	IOResources

Overall, I find memctl a useful aid to understand what's happening in kernel memory.

## Conclusion

In this post I have introduced memctl, a library and tool to safely access kernel memory and call
kernel functions. Memctl is primarily a research tool to aid me in analyzing the macOS/iOS kernel.
However, I have open sourced it in the hope that someone else finds either the tool or the
techniques useful.

## Credits
{:.no_toc}

Many thanks to Ian Beer, Luca Todesco, Stefan Esser, and Jonathan Levin for their invaluable iOS
security and internals research.

## Footnotes
{:.no_toc}

[^1]: Memctl is facetiously named after sysctl, the system control utility; it is called "memctl"
    because it controls memory, not the system.

[^2]: Yalu102 patches the `task_for_pid` system call to enable it to return the task port for the
    kernel task. mach_portal stashes the kernel task port in host special port 4. The
    [memctl-tfp0-core] core checks for both patches, and is the recommended core for jailbroken iOS
    devices.

[memctl-tfp0-core]: https://github.com/bazad/memctl-tfp0-core

[^3]: Of course, it is possible to hardcode the addresses of these kernel symbols, but libmemctl
    tries to avoid hardcoding offsets as much as possible, and always avoids hardcoding addresses.
    Kernel dumps could also be used on earlier platforms, but these tend to be missing symbol and
    prelink information as well. Instead, libmemctl tries to rely on the kernel itself (as found on
    the filesystem) to discover offsets and addresses, making transitions between new OS versions
    easier.

[^4]: The `user_tag` attribute is only useful starting with OS X 10.11 El Capitan.

[^5]: Even though the memory region containing the kernel is marked as non-readable non-writable in
    the virtual memory map, the actual page-table permissions clearly allow reading and sometimes
    writing these pages. I am not sure why the memory region containing the kernel image has these
    strange permissions.

[^6]: On the iPhone 7, the virtual memory carveout that contains the kernel looks different:
    ```
              START - END             [ VSIZE ] PRT/MAX SHRMOD DEPTH RESIDENT REFCNT TAG
    ffffffe000000000-ffffffe0000e0000 [  896K ] rw-/rwx    PRV     0       56      1  79
    ...
    ffffffe02a2d0000-ffffffe02a2e8000 [   96K ] rw-/rwx    S/A     0        6    180  12
    ...
    fffffff000000000-fffffff27fffc000 [   10G ] ---/---    NUL     0        0      0   0
    ```
    The kernel lies somewhere in the very last region, which starts at address
    `0xfffffff000000000`.

[^7]: The reason why we control 7 arguments and not 6 is that `func` is treated as a C++ method
    being invoked on the `target` object, which means `target` will be passed as the implicit first
    parameter to `func`.

[^8]: Despite searching far and wide, I could not find an official API to retrieve the registry
    entry ID associated with an `io_connect_t` object returned by `IOServiceOpen`. This was the
    simplest and most flexible workaround I could find.

[^9]: It would have been possible to do the same using a return-oriented program instead, but JOP
    has the advantage of preserving the kernel stack, making clean-up easier.
