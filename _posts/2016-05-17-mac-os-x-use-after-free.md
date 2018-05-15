---
layout: post
title: "Mac OS X Privilege Escalation via Use-After-Free: CVE-2016-1828"
author: Brandon Azad
date: 2016-05-17 15:00:00 -0700
category: security
description: >
  Exploiting a use-after-free vulnerability in the OS X kernel to elevate
  privileges on Yosemite.
---

Among the bugs that Apple [patched][10.11.5] in OS X 10.11.5 is CVE-2016-1828,
a use-after-free I discovered late last year while looking through the kernel
source. Combined with CVE-2016-1758, an information leak [patched][10.11.4] in
10.11.4, this vulnerability can be used to execute arbitrary code in the
kernel. In this post I'll document how I created [rootsh], a local privilege
escalation for OS X 10.10.5 (14F27).

[10.11.5]: https://support.apple.com/en-us/HT206567
[10.11.4]: https://support.apple.com/en-us/HT206167
[rootsh]: https://github.com/bazad/rootsh

[CVE-2016-1828] is a use-after-free in the function `OSUnserializeBinary`. By
passing a crafted binary blob to this function, it is possible to invoke a
virtual method on an object with a controlled vtable pointer. I leveraged the
use-after-free to create a NULL pointer dereference, allowing the vtable and
the ROP stack to live in user space.

[CVE-2016-1828]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1828

[CVE-2016-1758] is a kernel stack disclosure in the function `if_clone_list`. 8
bytes of uninitialized kernel stack are copied to user space. Those bytes can
be initialized to a known location within the kernel text segment by invoking a
system call prior to triggering the disclosure. After leaking the text segment
pointer, the kernel slide can be computed by subtracting the base address of
that particular text segment location from the leaked address.

[CVE-2016-1758]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1758

<!--more-->

I made several simplifying assumptions while developing rootsh. First, rootsh
relies on SMAP being disabled, which means the exploit would have to be
redesigned to work on newer (Broadwell and later) Macs. Second, I targeted the
ROP gadgets at 10.10.5, since this was my initial development platform. Between
10.10.5 and 10.11 these ROP gadgets disappeared, so as written rootsh will fail
on all versions of El Capitan. The exploit could be rewritten to work on El
Capitan up through 10.11.3, but I chose not to. If you want to try rootsh on
your own, you can set up a [virtual machine running 10.10.5][Yosemite VM].[^1]

[Yosemite VM]: http://sqar.blogspot.de/2014/10/installing-yosemite-in-virtualbox.html

## Table of Contents
{:.no_toc}

* TOC
{:toc}

## Overview of the OS X Kernel

Before describing the exploit process, we'll briefly look at the various pieces
of the OS X  kernel. The kernel, known as [XNU][XNU source], is composed of
three major subsystems:

[XNU source]: http://opensource.apple.com/source/xnu/xnu-2782.40.9/

* **BSD**: The BSD portion of the kernel implements most of the system calls,
  networking, and filesystem functionality. Much of this code is taken directly
  from FreeBSD 5.

* **Mach**: The Mach part of the kernel is derived from the Mach 3.0
  microkernel developed at Carnegie Mellon University. It implements
  fundamental services like memory maps and IPC primitives. User space programs
  access Mach services via Mach traps.

* **IOKit**: IOKit is Apple's [framework][IOKit] for writing drivers for XNU.
  It is written in C++. Many C++ features (notably exceptions, multiple
  inheritance, and RTTI) are too complicated or inefficient to include in the
  kernel, so Apple provides its own runtime system called [libkern].

[IOKit]: https://developer.apple.com/library/mac/documentation/DeviceDrivers/Conceptual/IOKitFundamentals/Introduction/Introduction.html
[libkern]: https://developer.apple.com/library/mac/documentation/DeviceDrivers/Conceptual/WritingDeviceDriver/CPluPlusRuntime/CPlusPlusRuntime.html

## `OSUnserializeBinary`

When a user application communicates with a kernel driver, it often wants to
pass structured data objects like strings, arrays, and dictionaries. Libkern
makes this easy by defining [container and collection classes][libkern classes]
that correspond to the CoreFoundation objects users pass to the user space
APIs. These classes, which all inherit from `OSObject`, are outlined in the
table below.

[libkern classes]: https://developer.apple.com/library/mac/documentation/DeviceDrivers/Conceptual/WritingDeviceDriver/ContainerClasses/Libkern_Classes.html

| XML tag           | CoreFoundation class | Libkern class  | Contents                   |
| ----------------- | -------------------- | -------------- | -------------------------- |
| `true` or `false` | `CFBoolean`          | `OSBoolean`    | Boolean `true` or `false`  |
| `data`            | `CFData`             | `OSData`       | Array of bytes             |
| `integer`         | `CFNumber`           | `OSNumber`     | Integer value              |
| `string`          | `CFString`           | `OSString`     | Array of characters        |
|                   |                      | `OSSymbol`     | Reference to unique string |
| `array`           | `CFArray`            | `OSArray`      | Array of objects           |
| `dict`            | `CFDictionary`       | `OSDictionary` | Map of strings to objects  |
| `set`             | `CFSet`              | `OSSet`        | Set of unique objects      |

When a CoreFoundation object is to be sent to the kernel, it is first converted
into a binary or XML representation by `IOCFSerialize`. The serialized data is
then copied into the kernel and deserialized using `OSUnserializeXML`.
`OSUnserializeXML` will call `OSUnserializeBinary` if the supplied data is
actually a binary encoding.

The [`OSUnserializeBinary`][OSUnserializeBinary] function attempts to decode
the supplied data and reconstruct the original object. Often the deserialized
object is a container such as `OSDictionary` containing several entries. In
order to minimize the size of the encoding when the same object is included in
a collection several times, the binary encoding format supports referencing
previously serialized objects by index. Thus, the decoding logic stores each
reconstructed object in an array so that it may be referenced by index later.

[OSUnserializeBinary]: http://opensource.apple.com/source/xnu/xnu-3248.20.55/libkern/c++/OSSerializeBinary.cpp

Presumably for efficiency reasons, this array is not an automatically managed
collection like `OSArray`. Instead, `OSUnserializeBinary` manually manages a
dynamically allocated array of `OSObject` pointers. After each new object is
deserialized, it is appended to the end of the `objsArray` array without
incrementing its reference count. This should be safe since each generated
object is stored in its parent: the parent increments the entry's reference
count to keep it alive.

When an entry is referenced by index during deserialization, the object pointer
is looked up in `objsArray`, stored in the local variable `o`, and retained:

{% highlight C %}
case kOSSerializeObject:
    if (len >= objsIdx) break;
    o = objsArray[len];
    o->retain();
    isRef = true;
    break;
{% endhighlight %}

The entry `o` is then released once it has been inserted into the parent
collection:

{% highlight C %}
if (o != dict) ok = dict->setObject(sym, o);
o->release();
sym->release();
sym = 0;
{% endhighlight %}

## Use After Free

Unfortunately, this strategy does not ensure safety, since it is possible for
an object in `objsArray` to be freed during deserialization, leaving a dangling
pointer.

In a serialized dictionary, it is possible for the same key to be assigned a
value multiple times. Consider passing the following dictionary to
`OSUnserializeBinary`, presented in XML for readability:

{% highlight XML %}
<dict>                          <!--  object 0  -->
    <key>a</key>                <!--  object 1  -->
    <string>foo</string>        <!--  object 2  -->
    <key>a</key>                <!--  object 3  -->
    <string>bar</string>        <!--  object 4  -->
    <key>b</key>                <!--  object 5  -->
    <object>2</object>          <!--  object 6  -->
</dict>
{% endhighlight %}

When the second assignment to `a` is deserialized, the string `bar` will be
inserted into the dictionary via `setObject`. Since the old `foo` string
associated with `a` is being replaced by `bar`, the dictionary will release a
reference on it. `foo` wasn't retained when inserted into `objsArray`, so the
only reference on `foo` is from the dictionary itself; since no one else has a
retain on `foo`, it is freed. This leaves a dangling pointer to `foo` in
`objsArray[2]`. When the object at index 2 is later referenced, `retain` will
be called on the freed `foo` object.

In order to exploit this bug we need to control the contents of the freed
memory, causing the call to `retain` to use a [vtable] pointer we control.
Fortunately, we can easily control the allocation and freeing of objects by
specifying elements in the dictionary being deserialized. We can also cause a
block of memory to be allocated and filled with data we control by including
`OSData` objects in the dictionary.

[vtable]: https://en.wikipedia.org/wiki/Virtual_method_table

If we are going to control the vtable pointer of an object, we need to ensure
that the freed object's memory is used to allocate the `OSData` object's data
buffer, and not the `OSData` object itself. However, the `OSData` object is
allocated before its data buffer, so we will create two freed objects: the
first will be reallocated for the `OSData` container and the second will
contain our fake vtable pointer.

{% highlight XML %}
<dict>                              <!--   0: dict                                    -->
    <key>a</key>                    <!--   1: key "a"                                 -->
    <integer>10</integer>           <!--   2: allocate block1                         -->
    <key>b</key>                    <!--   3: key "b"                                 -->
    <integer>20</integer>           <!--   4: allocate block2                         -->
    <key>a</key>                    <!--   5: key "a"                                 -->
    <true/>                         <!--   6: free block1; free list: block1          -->
    <key>b</key>                    <!--   7: key "b"                                 -->
    <true/>                         <!--   8: free block2; free list: block2, block1  -->
    <key>a</key>                    <!--   9: key "a"                                 -->
    <data> vtable pointer </data>   <!--  10: OSData gets block2, data gets block1    -->
    <key>b</key>                    <!--  11: key "b"                                 -->
    <object>2</object>              <!--  12: block1->retain()                        -->
</dict>
{% endhighlight %}

More specifically, we will use a dictionary with two keys, `a` and `b`, that we
shall repeatedly assign. First we will associate `a` and `b` with `OSNumber`s,
since on 64-bit OS X they are close enough in size to `OSData` to share a free
list. We then assign `a` and `b` to `true`, which causes the dictionary to
`release` the `OSNumber`s, freeing them.[^2]  At this point the heap free list
contains `b`'s `OSNumber` at the head and `a`'s `OSNumber` right behind it. By
inserting an `OSData` object in the dictionary we can cause the `OSData`
container to use `b`'s `OSNumber` and the `OSData`'s data buffer to use `a`'s
`OSNumber`. Referencing `a`'s original `OSNumber` by index will cause `retain`
to be called on the dead `OSNumber` object whose vtable we overwrote, giving us
code execution.

<figure class="center">
  <object data="/img/2016/use-after-free.svg" type="image/svg+xml">
    <div>
      Error: Failed to load SVG
    </div>
  </object>
  <figcaption>
    What happens in memory while parsing the malicious dictionary. Click to start the animation.
  </figcaption>
</figure>

We can disassemble the area around the exploitable call to `retain` using lldb
to find the layout of the vtable:

{% highlight Assembly %}
ffffff800088016a        cmp    eax, 0xc000000                   ;; case kOSSerializeObject
ffffff800088016f        jne    0xffffff8000880819
ffffff8000880175        mov    qword ptr [rbp - 0x40], rdi
ffffff8000880179        mov    rax, qword ptr [rbp - 0x58]
ffffff800088017d        cmp    r12d, eax                        ;;   if (len >= objsIdx) break;
ffffff8000880180        jae    0xffffff8000880819
ffffff8000880186        mov    dword ptr [rbp - 0x4c], edx
ffffff8000880189        mov    eax, r12d
ffffff800088018c        mov    rcx, qword ptr [rbp - 0x60]
ffffff8000880190        mov    r14, qword ptr [rcx + 8*rax]     ;;   o = objsArray[len]
ffffff8000880194        mov    rax, qword ptr [r14]
ffffff8000880197        mov    rdi, r14
ffffff800088019a        call   qword ptr [rax + 0x20]           ;;   o->retain()
{% endhighlight %}

At address `194` the first 8 bytes of `o` (pointed to by `r14`) are read into
the `rax` register. This is the vtable pointer, which we control because we
overwrote the old `OSNumber` object with the contents of the data buffer. Later
at `19a` the function pointer at address `rax + 0x20` is called. This means
`rip` will be set to the vtable entry at index 4 while `rax` points to the
start of the vtable.

Before we move on, it's important to realize that this exploit will never be
fully reliable. Due to the nature of use-after-free errors, there's a window
between when the memory is freed and when it is reallocated and filled with the
fake vtable pointer during which another kernel thread could allocate or free
memory. Losing the race means calling `retain` on a random vtable, which will
probably panic the kernel. The best we can do is develop the exploit and hope
that reliability is not too bad.

## SMEP and SMAP

In order to make exploiting this type of bug more difficult, recent versions of
OS X ship with two protection mechanisms, known as Supervisor Mode Execution
Prevention ([SMEP]) and Supervisor Mode Access Prevention ([SMAP]).

[SMEP]: http://vulnfactory.org/blog/2011/06/05/smep-what-is-it-and-how-to-beat-it-on-linux/
[SMAP]: https://lwn.net/Articles/517475/

SMEP causes the CPU to generate a page fault whenever the kernel tries to
execute code in user space memory. A SMEP fault will trigger a kernel panic,
bringing down the system. To avoid this, the exploit code cannot reside in user
space; once we control the kernel instruction pointer, it must point to valid
kernel memory.

We can get around this restriction by executing a [ROP] payload rather than
shellcode. ROP, which stands for return-oriented programming, is a technique
for chaining together segments of code that already exist in the target program
to construct an exploit payload. Since `rip` will only ever point into the
kernel, no SMEP fault will be generated. We will return to ROP later.

[ROP]: https://cseweb.ucsd.edu/~hovav/dist/rop.pdf

The other mechanism, SMAP, extends the protection offered by SMEP beyond just
execution. When SMAP is enabled, _any_ attempt by the kernel to access user
space memory will trigger a page fault. (There are legitimate cases where the
kernel needs to read user space memory, for example during system calls. Thus
there are ways for the kernel to temporarily disable SMAP. However, we would
already need to be executing arbitrary kernel code in order to do so, which
makes this strategy useless for us.)

Bypassing SMAP is more difficult, since we would need to put both our fake
vtable and our ROP stack at a known location in kernel memory. However, SMAP
support was only added to Intel processors in Broadwell. In order to simplify
the exploit, we will assume that the target is an older Mac without SMAP
support. This allows us to place the fake vtable and ROP stack in user space.
While the exploit could be made to work on SMAP-enabled CPUs, I didn't have the
patience while developing rootsh to do so.

In my testing, rootsh works on Broadwell processors when running under
VirtualBox. Thus, even on newer systems with SMAP support, it should still be
possible to run the exploit in a virtual machine.

## Kernel ASLR

At this point we know how to control the kernel instruction pointer and we have
a strategy for bypassing SMEP. However, we still need to find the locations of
kernel functions we can use to elevate privileges. The OS X kernel binary lives
at `/System/Library/Kernels/kernel` on the filesystem. Fortunately this is an
unstripped [Mach-O file][Mach-O], which means we can parse the symbol
information embedded in the kernel image to find the base address of any kernel
function by name.

[Mach-O]: https://developer.apple.com/library/mac/documentation/DeveloperTools/Conceptual/MachORuntime/index.html

However, the functions don't actually reside at those addresses in the running
kernel. For instance, the `current_proc` function, which returns the `proc`
structure of the currently running process, is at address `0xffffff8000857180`
in the kernel image, but on a live system it might actually be at address
`0xffffff8018c57180`. The difference of `0x0000000018400000` between these
addresses is the kernel slide.

OS X uses kernel [address space layout randomization][ASLR] (kASLR) to hide the
exact location of the kernel at runtime. During boot, the kernel is loaded at
one of 384 possible locations[^3] that are 2MB
apart. To figure out where the kernel is we need an information leak.

[ASLR]: https://en.wikipedia.org/wiki/Address_space_layout_randomization

Our goal is to find a way to sneak a pointer to some kernel memory location out
to user space. If we can get a pointer to a known piece of kernel code, we can
subtract its static address from its runtime address to recover the kernel
slide.

One promising way to look for information leaks is to search the XNU source for
calls to `copyout`. [`copyout`][copyout] is a kernel function that copies bytes
from kernel space to user space. Often the data is copied out from the kernel
stack, which presents an opportunity for an information leak if not all of the
copied bytes have been initialized.

[copyout]: https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man9/copyout.9.html

## `if_clone_list`

The code of the [`if_clone_list`][if_clone_list] function is shown below:

[if_clone_list]: http://opensource.apple.com/source/xnu/xnu-3248.20.55/bsd/net/if.c

{% highlight C %}
static int
if_clone_list(int count, int *ret_total, user_addr_t dst)
{
    char outbuf[IFNAMSIZ];
    struct if_clone *ifc;
    int error = 0;

    *ret_total = if_cloners_count;
    if (dst == USER_ADDR_NULL) {
        /* Just asking how many there are. */
        return (0);
    }

    if (count < 0)
        return (EINVAL);

    count = (if_cloners_count < count) ? if_cloners_count : count;

    for (ifc = LIST_FIRST(&if_cloners); ifc != NULL && count != 0;
         ifc = LIST_NEXT(ifc, ifc_list), count--, dst += IFNAMSIZ) {
        strlcpy(outbuf, ifc->ifc_name, IFNAMSIZ);
        error = copyout(outbuf, dst, IFNAMSIZ);
        if (error)
            break;
    }

    return (error);
}
{% endhighlight %}

This function attempts to copy the names of network interface cloners to user
space. For each interface, the `outbuf` buffer is filled with the interface
name and then copied out to user space. When `ifc_name` is smaller than
`outbuf`, `strlcpy` leaves the last few bytes of `outbuf` uninitialized.
However, passing `IFNAMSIZ` to `copyout` makes it copy the full `outbuf` to
user space, including the uninitialized bytes at the end.

`IFNAMSIZ` is `#define`&#8217;d to 16, which doesn't leave much room for an
8-byte kernel pointer if the interface name is long. Fortunately, the first
interface cloner is called "bridge", leaving 9 uninitialized bytes in `outbuf`.
Since this function can leak a full kernel pointer, we can probably recover the
kernel slide.

By inspecting the code, we discover the following call graph for
`if_clone_list`:

```
soo_ioctl
  soioctl
    ifioctllocked
      ifioctl
        ifioctl_ifclone
          if_clone_list
```

`soo_ioctl` itself is used in the declaration of the [`socketops`][socketops]
structure:

{% highlight C %}
const struct fileops socketops = {
    DTYPE_SOCKET,
    soo_read,
    soo_write,
    soo_ioctl,
    soo_select,
    soo_close,
    soo_kqfilter,
    soo_drain
};
{% endhighlight %}

This structure associates socket objects in the kernel with the implementations
of common file operations like `read`, `write`, and `ioctl`. The call graph
suggests it should be possible to reach `if_clone_list` by calling the
[`ioctl`][ioctl] system call on a socket. To determine which ioctl command to
pass, we can look at the source of `ifioctl`:

{% highlight C %}
int
ifioctl(struct socket *so, u_long cmd, caddr_t data, struct proc *p)
{
...
    switch (cmd) {
    case OSIOCGIFCONF32:            /* struct ifconf32 */
    case SIOCGIFCONF32:             /* struct ifconf32 */
    case SIOCGIFCONF64:             /* struct ifconf64 */
    case OSIOCGIFCONF64:            /* struct ifconf64 */
        error = ifioctl_ifconf(cmd, data);
        goto done;

    case SIOCIFGCLONERS32:          /* struct if_clonereq32 */
    case SIOCIFGCLONERS64:          /* struct if_clonereq64 */
        error = ifioctl_ifclone(cmd, data);
        goto done;
...
    }
...
}
{% endhighlight %}

Here we see that the `SIOCIFGCLONERS` command should be used with an
`if_clonereq` structure.

[socketops]: http://www.opensource.apple.com/source/xnu/xnu-3248.20.55/bsd/kern/sys_socket.c
[ioctl]: https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man2/ioctl.2.html

Given the above, it should be possible to leak parts of the kernel stack into
user space with the following sequence of system calls:

{% highlight C %}
int sockfd = socket(AF_INET, SOCK_STREAM, 0);
char buffer[IFNAMSIZ];
struct if_clonereq ifcr = {
    .ifcr_count  = 1,
    .ifcr_buffer = buffer,
};
int err = ioctl(sockfd, SIOCIFGCLONERS, &ifcr);
printf("0x%016llx\n", *(uint64_t *)(buffer + 8));
{% endhighlight %}

If you're lucky, running the above code prints a pointer value like
`0xffffff801873487f`. The kernel slide is a multiple of 2 megabytes, so we know
that the lower 21 bits of the pointer are correct. Examining the OS X 10.10.5
kernel with otool, we find that there is only one instruction in the entire
kernel with a matching base address:

{% highlight Assembly %}
_ledger_credit+95:
ffffff800033487f        mov    eax, r14d
{% endhighlight %}

Thus, we can subtract the reference address `0xffffff800033487f` from the
leaked pointer to recover the kernel slide.[^4]

Just like with the use-after-free, this information leak is not fully reliable:
we're counting on a pointer written to the stack during a previous system call
to still be there when we call `ioctl`. At any point in between, any kernel
code that executes in the current process's context could overwrite that
pointer. In practice this information leak is reliable enough, and it can be
improved by repeatedly leaking pointers and taking the majority value.

## Elevating Privileges

Now that we have the kernel slide, we can calculate the address of any function
in the kernel by adding the kernel slide to the base address of the function,
which we can find in the kernel image. The next step is determining how to
elevate privileges. To do this, we first look at how a process's privilege
information is stored in the kernel.

Each process on OS X has a corresponding [`proc`][proc] structure, which stores
the information the kernel needs to manage the process. A kernel thread can get
a pointer to its `proc` struct by calling `current_proc`. The `proc` structure
contains a number of pointers to substructures describing various attributes of
the process. One such substructure is the [`ucred`][ucred] structure:

{% highlight C %}
/*
 * In-kernel credential structure.
 *
 * Note that this structure should not be used outside the kernel, nor should
 * it or copies of it be exported outside.
 */
struct ucred {
    TAILQ_ENTRY(ucred)    cr_link;  /* never modify this without KAUTH_CRED_HASH_LOCK */
    u_long    cr_ref;               /* reference count */

struct posix_cred {
    /*
     * The credential hash depends on everything from this point on
     * (see kauth_cred_get_hashkey)
     */
    uid_t    cr_uid;                /* effective user id */
    uid_t    cr_ruid;               /* real user id */
    uid_t    cr_svuid;              /* saved user id */
    short    cr_ngroups;            /* number of groups in advisory list */
    gid_t    cr_groups[NGROUPS];    /* advisory group list */
    gid_t    cr_rgid;               /* real group id */
    gid_t    cr_svgid;              /* saved group id */
    uid_t    cr_gmuid;              /* UID for group membership purposes */
    int      cr_flags;              /* flags on credential */
} cr_posix;
    struct label    *cr_label;      /* MAC label */
    /*
     * NOTE: If anything else (besides the flags)
     * added after the label, you must change
     * kauth_cred_find().
     */
    struct au_session cr_audit;     /* user auditing data */
};
{% endhighlight %}

The relevant fields are `cr_uid`, `cr_ruid`, and `cr_svuid` of the contained
`posix_cred` struct. These values control the user ID, real user ID, and saved
user ID of the process.

[proc]: http://opensource.apple.com/source/xnu/xnu-3248.20.55/bsd/sys/proc_internal.h
[ucred]: http://opensource.apple.com/source/xnu/xnu-3248.20.55/bsd/sys/ucred.h

Although it's tempting to directly set `cr_uid` and `cr_ruid` to 0 to become
root, the `ucred` structure might be shared between multiple processes. If the
`ucred` of the attacking process is shared, setting `cr_uid` and `cr_ruid` to 0
will magically elevate a whole bunch of processes to root, which can have
unintended consequences. (I discovered this fact while running the exploit
under tmux; the exploit succeeded but each new tmux window I opened would
present a root shell. Less than ideal.)

The proper solution is to create a new `ucred` structure with elevated
privileges for the current process. However, I just set `cr_svuid` to 0
instead. This sets the saved UID of the current process and any processes
sharing its `ucred` to root. From user space, our process could then elevate
privileges by calling `seteuid(0)` to set the effective UID to root as well. We
haven't eliminated the problem since any other process sharing the `ucred`
could also `seteuid` to root. Nonetheless, this is much better than before:
other processes aren't automatically granted root powers, and it's unlikely in
practice that a normal process will suddenly try to `seteuid` to root.

Thus, once we control `rip`, we will get our `proc` struct by calling
`current_proc`. We can then get a pointer to the `ucred` struct by calling
`proc_ucred` and a pointer to the inner `posix_cred` struct by calling
`posix_cred_get` on the `ucred`. Once we have a pointer to the `posix_cred`
struct, we will need an instruction sequence to set `cr_svuid` to 0. Finally,
we will need a way to gracefully return from kernel space.

## Building the ROP Stack

At this point we'll examine how to leverage control of `rip` to execute our
payload. When we get control of `rip` we know that `rax` points to the start of
the fake vtable. There is no single point in the kernel to which we can jump to
execute the desired attack, so we will need to use our control of `rax` to
guide control flow across multiple jumps.

A good general strategy at this point is to try to pivot the stack pointer so
that it points to a fake stack that we control. If we jump to a short
instruction sequence in the kernel that makes `rsp` point to our fake stack and
then executes a `ret` instruction, `rip` will be set to the address at the top
of our fake stack and the stack will be popped. If the new `rip` points to
another short sequence of instructions followed by `ret`, then we can execute a
few useful instructions and then jump to the new address at the top of the
stack. Continuing in this way, we can chain a series of short instruction
sequences together to build a full exploit. This technique is called
return-oriented programming (ROP).

The first order of business in building a ROP payload is to find a useful stack
pivot. There are several tools capable of finding ROP gadgets or even
automatically building ROP payloads. I prefer building ROP payloads myself, so
I used [ROPgadget] to find useful gadgets in the kernel.

[ROPgadget]: https://github.com/JonathanSalwan/ROPgadget

Running ROPgadget on the 10.10.5 kernel image produces over 45,000 gadgets.
There's a very interesting gadget at address `0xffffff80007d5158`:

{% highlight Assembly %}
ffffff80007d5158        xchg   eax, esp
ffffff80007d5159        pop    rsp
ffffff80007d515a        ret
{% endhighlight %}

This instruction sequence swaps the `esp` and `eax` registers, pops the top
element of the new stack into `rsp`, and then jumps execution to the address at
the top of the _new_ new stack. `rax` points to the fake vtable, so the `xchg`
instruction will set the low bits of `rsp` to the low bits of the address of
the vtable. One nuance of the x86-64 instruction set is that the high bits of
`rsp` will be cleared by the `xchg` because it's operating on the 32-bit
sub-registers. If the vtable resides below address `0x100000000`, this `xchg`
will set `rsp` to the vtable.

The subsequent `pop rsp` will move the very first element in our vtable into
`rsp`. We can use this to make `rsp` point to the true ROP stack. The final
`ret` will start executing the ROP payload.

The first element of the ROP stack can be the address of `current_proc`, which
will set `rax` to the address of this process's `proc` struct. In order to feed
this result into `proc_ucred` we need the next gadget to move `rax` into `rdi`,
as `rdi` is used to store the first argument of a function call. Looking
through the list of ROP gadgets we find the following instruction sequence:

{% highlight Assembly %}
ffffff80004d49c4        xchg   rax, rdi
ffffff80004d49c6        ret
{% endhighlight %}

This gadget exchanges the contents of `rax` and `rdi`, effectively moving the
returned value into `rdi`. We can then use the same approach to call
`proc_ucred` and move its return value into `rdi`, and once again to call
`posix_cred_get`, leaving the `posix_cred` struct in `rdi`.

Now we need to set the `cr_svuid` field in the `posix_cred` struct to 0.
Conveniently, at address `0xffffff800041ab81` we find the sequence:

{% highlight Assembly %}
ffffff800041ab81        mov    dword ptr [rdi + 0x8], 0x0
ffffff800041ab88        ret
{% endhighlight %}

Jumping to this gadget will zero out the third 32-bit integer in the
`posix_cred` struct, setting our saved UID to root.

Finally, we must safely stop executing the ROP payload. The simplest way to do
this is to call `thread_exception_return`, which will immediately return
execution to user space.

This leaves us with a vtable with slots 0 and 4 filled and an 8 element ROP
stack.

## Running the Payload

The last piece of the puzzle is figuring out how to trigger the use-after-free
and get our payload to run. In fact it's quite easy to call
`OSUnserializeBinary` from user space: any function that passes a
CoreFoundation object into the kernel must serialize and subsequently
deserialize the object. We'll use the
[`IOServiceGetMatchingServices`][IOServiceGetMatchingServices] function from
IOKit.

[IOServiceGetMatchingServices]: https://developer.apple.com/library/mac/documentation/IOKit/Reference/IOKitLib_header_reference/index.html#//apple_ref/c/func/IOServiceGetMatchingServices

However, we can't just give the attack dictionary to
`IOServiceGetMatchingServices` because the matching dictionary is passed as a
`CFDictionary`. No valid `CFDictionary` will ever serialize to our attack
dictionary, so we need to call a lower-level function.

Looking at the [source][IOServiceGetMatchingServices source], we can see that
`IOServiceGetMatchingServices` internally calls the
`io_service_get_matching_services_bin` Mach trap to pass a binary-serialized
dictionary to the kernel:

{% highlight C %}
kern_return_t
IOServiceGetMatchingServices(
        mach_port_t     _masterPort,
        CFDictionaryRef matching,
        io_iterator_t * existing )
{
    kern_return_t       kr;
    CFDataRef           data;
    CFIndex             dataLen;
    mach_port_t         masterPort;
...
    data = IOCFSerialize(matching, gIOKitLibSerializeOptions);
...
    dataLen = CFDataGetLength(data);
...
    if (kIOCFSerializeToBinary & gIOKitLibSerializeOptions)
    {
        if ((size_t) dataLen < sizeof(io_struct_inband_t))
        {
            kr = io_service_get_matching_services_bin(masterPort,
                        (char *) CFDataGetBytePtr(data), dataLen, existing);
            ool = false;
        }
    }
...
}
{% endhighlight %}

The kernel entrypoint is the function
[`is_io_service_get_matching_services_bin`][is_io_service_get_matching_services_bin source],
which eventually calls `OSUnserializeXML` to deserialize the dictionary.

[IOServiceGetMatchingServices source]: http://opensource.apple.com/source/IOKitUser/IOKitUser-1179.20.6/IOKitLib.c
[is_io_service_get_matching_services_bin source]: http://opensource.apple.com/source/xnu/xnu-3248.20.55/iokit/Kernel/IOUserClient.cpp

Thus, we can exploit the vulnerability from user space by allocating a page
below `0x100000000` to store the fake vtable and ROP stack and then calling
`io_service_get_matching_services_bin` with the malicious dictionary.

When I tested the exploit with this setup, I found that the system would
occasionally panic trying to dereference a NULL pointer:

```
*** Panic Report ***
panic(cpu 0 caller 0xffffff8018816df2): Kernel trap at 0xffffff8018c8019a, type 14=page fault, registers:
CR0: 0x00000000c0010033, CR2: 0x0000000000000020, CR3: 0x0000000093386000, CR4: 0x0000000000040660
RAX: 0x0000000000000000, RBX: 0xffffff802042f8c0, RCX: 0xffffff80209c7200, RDX: 0x000000008c000002
RSP: 0xffffff8094723cd0, RBP: 0xffffff8094723db0, RSI: 0x0000000000000078, RDI: 0xffffff802042f7c0
R8:  0x0000000000000001, R9:  0xffffff802042fac0, R10: 0x0000000000000000, R11: 0x0000000000000040
R12: 0x0000000000000002, R13: 0xffffff802042fac0, R14: 0xffffff802042f7c0, R15: 0x0000000000000078
RFL: 0x0000000000010297, RIP: 0xffffff8018c8019a, CS:  0x0000000000000008, SS:  0x0000000000000010
Fault CR2: 0x0000000000000020, Error code: 0x0000000000000000, Fault CPU: 0x0 VMM

Backtrace (CPU 0), Frame : Return Address
0xffffff8094723980 : 0xffffff801872ad21 mach_kernel : _panic + 0xd1
0xffffff8094723a00 : 0xffffff8018816df2 mach_kernel : _kernel_trap + 0x8d2
0xffffff8094723bc0 : 0xffffff8018833ca3 mach_kernel : _return_from_trap + 0xe3
0xffffff8094723be0 : 0xffffff8018c8019a mach_kernel : __Z19OSUnserializeBinaryPKcmPP8OSString + 0x2ca
0xffffff8094723db0 : 0xffffff8018cfbd3e mach_kernel : _is_io_service_get_matching_services_bin + 0x2e
0xffffff8094723de0 : 0xffffff80187df5c8 mach_kernel : _iokit_server + 0x738
0xffffff8094723e10 : 0xffffff801872ef8c mach_kernel : _ipc_kobject_server + 0xfc
0xffffff8094723e40 : 0xffffff80187139f3 mach_kernel : _ipc_kmsg_send + 0x123
0xffffff8094723e90 : 0xffffff801872429d mach_kernel : _mach_msg_overwrite_trap + 0xcd
0xffffff8094723f10 : 0xffffff8018802115 mach_kernel : _mach_call_munger + 0x175
0xffffff8094723fb0 : 0xffffff8018834278 mach_kernel : _hndl_mach_scall + 0xd8

BSD process name corresponding to current thread: rootsh
Boot args: usb=0x800 keepsyms=1 -v -serial=0x1

Mac OS version:
14F27

Kernel version:
Darwin Kernel Version 14.5.0: Wed Jul 29 02:26:53 PDT 2015; root:xnu-2782.40.9~1/RELEASE_X86_64
Kernel UUID: 58F06365-45C7-3CA7-B80D-173AFD1A03C4
Kernel slide:     0x0000000018400000
Kernel text base: 0xffffff8018600000
```

The page fault occurred on (unslid) address `0xffffff800088019a`, which is the
instruction that invokes `retain` on the freed object. The vtable pointer is
stored in `rax` just before this instruction. Looking at the panic log, it's
clear that the `rax` register somehow got set to 0 rather than the address of
the vtable.

What's likely going on is we're occasionally losing the race to reallocate the
freed memory. In between when we free the two `OSNumber`s and when we allocate
the `OSData` object, there's a window in which another kernel thread can either
allocate or free memory and mess everything up. In practice it seems that the
most common value of `rax` when we lose the race is 0. This indicates that a
simple way to make the exploit more reliable is to allocate our fake vtable at
address `0`. To implement this hack we need to compile the exploit as 32-bit to
enable legacy support for mapping the NULL page and we need to pass special
linker flags so that the final Mach-O doesn't have a `__PAGEZERO` segment.
However, placing the payload on the NULL page gives the exploit a chance to
succeed even when we lose the race.

The final exploit is reasonably reliable, triggering a panic twice in 3000
executions on an idle machine. Panics are significantly more likely when the
system is under even slight load because the frequent allocations and frees are
more likely to beat us in the race to reallocate the freed memory.

## Conclusion

This wraps up our discussion. We've walked through the process of developing a
full local privilege escalation exploit from two vulnerabilities, CVE-2016-1828
and CVE-2016-1758. The complete exploit code is available in my [rootsh]
repository on GitHub.

I chose to target OS X 10.10.5 rather than 10.11.3 (the last release with both
vulnerabilities) for a few reasons. First and foremost is that I was running
10.10.5 while I developed rootsh. However, even after updating I decided not to
rewrite the exploit so that you can test it in a virtual machine. The App Store
doesn't keep the installers for old point releases: once 10.11.4 comes out, the
10.11.3 installer goes away, making it much more difficult to create a 10.11.3
virtual machine. By contrast, the Yosemite installer in the App Store shall
forever remain at version 10.10.5, meaning anyone can come along at a later
time and create a virtual installation. That being said, it shouldn't be too
difficult to rework this exploit for 10.11.3.

The actual path I took in developing this exploit wasn't nearly as clean or
guided as it's presented here. There was a lot of trial and error and many,
many hours debugging random kernel panics.

## Licensing
{:.no_toc}

The `rootsh` code is released into the public domain. As a courtesy I ask that
if you use any of my code in another project you attribute it to me.

## Footnotes
{:.no_toc}

[^1]: Apple has since released Security Update 2016-002 for Yosemite, which bumped the build number up to 14F1713. Just like El Capitan, this new build is missing the ROP gadgets used by rootsh. At the time of this writing, however, the App Store is still distributing version 14F27, which is vulnerable to rootsh without modification.

[^2]: The freed `OSNumber` associated with `a` is not used to fulfill the allocation of `b`'s `OSBoolean` because `OSBoolean`s are never allocated: there are only two distinct values, and all references to them are shared.

[^3]: Numerous sources online suggest that the kernel is loaded into one of 256 possible locations. However, empirical testing on a 2011 Macbook Pro running OS X Yosemite 10.10.5 suggests that, at least on some systems and in some configurations, there may be closer to 384 possible locations.

[^4]: This hardcoded reference address only works on 10.10.5 build 14F27; in order to find the kernel slide on another version of OS X we would need a new reference pointer, which might not even be in the same function.
