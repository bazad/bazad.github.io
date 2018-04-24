---
layout: post
title: "Who put that kernel pointer in my crash log?"
author: Brandon Azad
date: 2018-04-06 10:15:00 -0700
modified: 2018-04-06 11:30:00 -0700
category: security
tags: [iOS]
description: >
  In February 2018 I noticed that kernel pointers were showing up in register x18 of iOS crash
  logs. Figuring out why took me all the way back to the Meltdown vulnerability and the buggy fix
  that made it trivial to bypass Apple's kernel ASLR defense.
---

On February 26th, while looking at an iOS application crash log, I noticed a distinctive value in
register `x18`:

{% include image.html
           image = "/img/2018/x18-infoleak-nytimes-crash.png"
           max-height = "500px"
           title =
"Register x18 contains a kernel pointer."
           description =
"Register x18 in this NYTimes app crash log contains a kernel pointer."
           caption =
"This crash log from the New York Times app contains a kernel pointer in register `x18`." %}

Register `x18` contained a value prefixed by `0xfffffff0` (7 `f`s and a `0`), which is the telltale
signature of a kernel pointer. I almost dismissed this as a coincidence, but decided to check some
other crash logs as well. To my surprise, all of them contained the same value in register `x18`,
even across different apps. This suggested a true kernel information leak, and a serious one. What
was going on? The answer would lead back, of all places, to the Meltdown vulnerability.

<!--more-->


## The shape of a pointer

Kernel pointers are distinctive because they have low entropy (the kernel doesn't take up that much
memory). For example, on macOS, pointers to the kernel image typically begin with `0xffffff80[0-2]`,
pointers to the kernel heap begin with `0xffffff80[1-2]` or `0xffffff9[0-2]`, and pointers to
kernel driver images begin with `0xffffff7f[8-9]`.

On iOS, the layout of the kernel address space is different and varies by device. On the iPhone 7
and later, kernel heap addresses begin with `0xffffffe0` and kernel image addresses begin with
`0xfffffff0[0-2]`. On the iPhone 5s through iPhone 6s, kernel image and kernel heap addresses both
begin with `0xfffffff0`.

These ranges may be large, but they are actually quite small when compared to the full space of
64-bit integers. Thus, when I saw that register `x18` began with `0xfffffff0`, I knew there was a
good chance it actually came from the kernel and wasn't just a big negative number.


## Identifying the source of the leak

The first step was to figure out how kernel pointers were getting into register `x18`. For example,
the leak might only be triggered while a process is crashing, or even worse, it might be a strange
artifact of the crash reporting machinery itself. Such an information leak would still be
interesting, but of limited value. Thus, the very first thing I tried was to create an empty iOS
app, set a breakpoint, and read the value in register `x18`:

{% include image.html
           image = "/img/2018/x18-infoleak-debug-1.png"
           title =
"Demonstrating the infoleak with lldb."
           caption =
"The infoleak can be triggered by simply reading the value of register `x18` using lldb." %}

And just like that, without writing any code at all, I had a working proof of concept! The fact
that the leaked kernel pointer could be retrieved by a debugger on a still-running app strongly
suggested that it would be possible to write a standalone exploit.

It looked to me like the `x18` register was somehow not being cleared on return from the kernel.
The AArch64 ABI specifies that register `x18` is reserved for use by the platform, so it's
plausible that no userspace code had modified `x18` since the last syscall return.

The next question was whether the kernel pointer could be retrieved directly by the running app.
A straightforward way to read the value in a particular register is using inline assembly.[^1]
Thus, I added inline assembly to read `x18` into a variable and printed the result.

{% include image.html
           image ="/img/2018/x18-infoleak-debug-2.png"
           title =
"Register x18 does not contain the kernel pointer when read using inline assembly."
           caption =
"The kernel pointer does not appear when reading the value of register `x18` using inline
assembly." %}

Interestingly, even though the debugger claimed that `x18` contained the kernel pointer, the inline
assembly read the value `0`. This meant one of two things: either there was some sort of
architectural magic going on, or the debugger was somehow not getting the true register values.

As it happens, the way a debugger reads registers from the thread being debugged is using the
function `thread_get_state`. This function retrieves the state of a thread's registers as they are
saved when that thread enters the kernel. Thus, the leaked kernel pointer could be reaching
userspace through that function, in which case register `x18` might never actually contain a kernel
pointer while in userspace.

To test this, I simply called `thread_get_state` on the current thread and printed the value that
the kernel claimed was in register `x18`:

{% include image.html
           image = "/img/2018/x18-infoleak-debug-3.png"
           title =
"Register x18 does contain the kernel pointer when read using thread_get_state."
           caption =
"The function `thread_get_state`, which is called by debuggers to get a thread's registers, proves
to be the source of the kernel pointer leak." %}

And voilà! We have found the source of the leak.

While the exploit in this case is completely trivial, you can find a POC on my [GitHub][x18-leak].

[x18-leak]: https://github.com/bazad/x18-leak


## Is it useful?

The next thing I wanted to know was what type of leak this was. The most interesting kernel pointer
disclosures are those that can be used to defeat the kernel's address space layout randomization
(kASLR), which hides where the kernel resides in memory. Because kASLR simply slides the entire
kernel image in memory to a new base address, revealing a single known pointer into the kernel
image breaks the whole defense by allowing you to compute the kASLR slide directly.

The simplest way to check whether a kernel infoleak is disclosing a kernel image pointer or
something else is to get the leaked value, subtract the kASLR slide, and see if the difference is
consistent across reboots. If it is, then the infoleak is disclosing a kernel image pointer and
the difference is the static address of the leaked pointer in the kernelcache binary.

So, I disclosed the kernel pointer, panicked the phone, and subtracted the kernel slide recorded in
the panic log. Repeating this experiment several times always yielded the same value. Thus, I had
found a kernel image pointer leak capable of revealing the kernel slide.


## Analyzing the cause of the leak

Once I'd demonstrated that this infoleak could be used to recover the kASLR slide, I reported it to
Apple. A few days later, I had some time to try and figure out what was causing the leak.

Since the leak only manifested in register `x18`, the natural place to begin was scanning XNU
source code diffs for occurrences of `x18`. It quickly became apparent that a large number of
changes involving register `x18` took place in the file [`osfmk/arm64/locore.s`][XNU 4570.31.3
locore.s] between XNU versions [4570.20.62][XNU 4570.20.62] (iOS 11.1) and [4570.31.3][XNU
4570.31.3] (iOS 11.2). These changes seemed to be related to a feature called
`__ARM_KERNEL_PROTECT__`. Grepping through the source code for references to that string eventually
revealed the following comment in the file [`osfmk/arm64/proc_reg.h`][XNU 4570.31.3 proc_reg.h]:

[XNU 4570.31.3 locore.s]: https://opensource.apple.com/source/xnu/xnu-4570.31.3/osfmk/arm64/locore.s.auto.html
[XNU 4570.20.62]: https://opensource.apple.com/source/xnu/xnu-4570.20.62/
[XNU 4570.31.3]: https://opensource.apple.com/source/xnu/xnu-4570.31.3/
[XNU 4570.31.3 proc_reg.h]: https://opensource.apple.com/source/xnu/xnu-4570.31.3/osfmk/arm64/proc_reg.h.auto.html

	__ARM_KERNEL_PROTECT__ is a feature intended to guard against potential
	architectural or microarchitectural vulnerabilities that could allow cores to
	read/access EL1-only mappings while in EL0 mode.  This is achieved by
	removing as many mappings as possible when the core transitions to EL0 mode
	from EL1 mode, and restoring those mappings when the core transitions to EL1
	mode from EL0 mode.

That is, when `__ARM_KERNEL_PROTECT__` is enabled, transitioning from EL1 (kernel mode) to EL0
(user mode) will remove as many kernel memory mappings as possible. The purpose of this feature is
to limit the possible attack surface against kernel memory mappings when exploiting
microarchitectural vulnerabilities like [Spectre or Meltdown][Spectre and Meltdown]. In fact, a
[knowledge base article][Spectre and Meltdown mitigations] suggests that these changes in iOS 11.2
were specifically designed to protect against Meltdown.

[Spectre and Meltdown]: https://meltdownattack.com
[Spectre and Meltdown mitigations]: https://support.apple.com/en-us/HT208394

The file `osfmk/arm64/locore.s` is responsible for, among other things, implementing the ARM
exception vectors. `Lel0_synchronous_vector_64`, the exception vector invoked on a system call
(instruction `svc #0`), was significantly changed while adding support for
`__ARM_KERNEL_PROTECT__`. In iOS 11.2, the implementation looks like this:

{% highlight assembly %}
	.text
	.align 7
Lel0_synchronous_vector_64:
	MAP_KERNEL
	BRANCH_TO_KVA_VECTOR Lel0_synchronous_vector_64_long, 8
{% endhighlight %}

The macro `MAP_KERNEL` is responsible for setting up the EL1 memory mappings for the kernel. It is
defined as:

{% highlight assembly %}
/*
 * MAP_KERNEL
 *
 * Restores the kernel EL1 mappings, if necessary.
 *
 * This may mutate x18.
 */
.macro MAP_KERNEL
#if __ARM_KERNEL_PROTECT__
	/* Switch to the kernel ASID (low bit set) for the task. */
	mrs	x18, TTBR0_EL1
	orr	x18, x18, #(1 << TTBR_ASID_SHIFT)
	msr	TTBR0_EL1, x18

	/*
	 * We eschew some barriers on Apple CPUs, as relative ordering of writes
	 * to the TTBRs and writes to the TCR should be ensured by the
	 * microarchitecture.
	 */
#if !defined(APPLE_ARM64_ARCH_FAMILY)
	isb	sy
#endif

	/*
	 * Update the TCR to map the kernel now that we are using the kernel
	 * ASID.
	 */
	MOV64	x18, TCR_EL1_BOOT
	msr	TCR_EL1, x18
	isb	sy
#endif /* __ARM_KERNEL_PROTECT__ */
.endmacro
{% endhighlight %}

Meanwhile, the macro `BRANCH_TO_KVA_VECTOR` is responsible for branching to the real implementation
of the exception vector, which in this case is `Lel0_synchronous_vector_64_long`. It is defined as:

{% highlight assembly %}
/*
 * BRANCH_TO_KVA_VECTOR
 *
 * Branches to the requested long exception vector in the kernelcache.
 *   arg0 - The label to branch to
 *   arg1 - The index of the label in exc_vectors_tables
 *
 * This may mutate x18.
 */
.macro BRANCH_TO_KVA_VECTOR
#if __ARM_KERNEL_PROTECT__
	/*
	 * Find the kernelcache table for the exception vectors by accessing
	 * the per-CPU data.
	 */
	mrs	x18, TPIDR_EL1
	ldr	x18, [x18, ACT_CPUDATAP]
	ldr	x18, [x18, CPU_EXC_VECTORS]

	/*
	 * Get the handler for this exception and jump to it.
	 */
	ldr	x18, [x18, #($1 << 3)]
	br	x18
#else
	b	$0
#endif /* __ARM_KERNEL_PROTECT__ */
.endmacro
{% endhighlight %}

Finally, `Lel0_synchronous_vector_64_long` contains the original definition of the exception vector
`Lel0_synchronous_vector_64` from iOS 11.1:

{% highlight assembly %}
Lel0_synchronous_vector_64_long:
	EL0_64_VECTOR
	mrs	x1, TPIDR_EL1				// Load the thread register
	ldr	x1, [x1, TH_KSTACKPTR]			// Load the top of the kernel stack to x1
	mov	sp, x1					// Set the stack pointer to the kernel stack
	adrp	x1, fleh_synchronous@page		// Load address for fleh
	add	x1, x1, fleh_synchronous@pageoff
	b	fleh_dispatch64
{% endhighlight %}

Thus, Apple has effectively prefixed the original exception vector with some code to restore the
kernel mappings and perform an indirect jump (via `x18`) to the original implementation.

The problem is that this prefix code clobbers the value of `x18` from userspace before the
userspace registers are saved. While both macros clobber `x18`, the information leak that we
observe is due to `BRANCH_TO_KVA_VECTOR`. This macro performs an indirect branch to
`Lel0_synchronous_vector_64_long` through register `x18`. However, this means `x18` is set to
`Lel0_synchronous_vector_64_long` before `Lel0_synchronous_vector_64_long` has a chance to save the
userspace registers. And since the original exception vector implementation does not clear `x18`
before saving the userspace registers, this makes the clobbered value of `x18` available to clients
of `thread_get_state`. The result is that when we call `thread_get_state`, we end up with a pointer
to `Lel0_synchronous_vector_64_long` in `x18`.


## Timeline

After I discovered and reported the bug on February 26 and provided a more complete analysis on
March 2, Apple managed to have the hole fixed in time for their iOS 11.3 release on March 29. The
speed at which this bug was fixed was quite a pleasant surprise, especially given that I initially
found the bug on a beta release of iOS 11.3.

However, Apple's initial security announcement for iOS 11.3 did not mention this bug at all. This
was a disappointment, but I contacted Apple and they promptly recognized the issue and agreed to
assign a CVE and update the advisory.

While waiting for the updated advisory, a friend sent me a link to the following tweet:

<center> <blockquote class="twitter-tweet" data-lang="en"><p lang="en" dir="ltr">How to defeat KASLR on
11.2.6: 1. Create a new xcode project 2. Close it and delete it, choose &#39;Delete
Immediately&#39; from trash 3. Open extra_recipe instead 4. Add a 2 on line 547 so that &quot;i
&lt; 28&quot;. 5. Remove line 527 6. Who would win, an American multi billion company or one
2boi</p>&mdash; John Åkerblom (@jaakerblom) <a
href="https://twitter.com/jaakerblom/status/981894636141727745?ref_src=twsrc%5Etfw">April 5,
2018</a></blockquote> <script async src="https://platform.twitter.com/widgets.js"
charset="utf-8"></script> </center>

Intrigued, I looked at the GitHub project by John Åkerblom ([@jaakerblom] and [@potmdehex]),
[extra_recipe_extra_bug], that the author mentioned in a reply to the original tweet. It quickly
became clear from looking at the [source][jailbreak.c:403] that the leak was coming from Mach
exception messages containing register state for a thread. As it turns out, Mach exception messages
use the same state that is returned by `thread_get_state`, which means this is another way of
triggering the same bug.

[@jaakerblom]: https://twitter.com/jaakerblom
[@potmdehex]: https://twitter.com/potmdehex
[extra_recipe_extra_bug]: https://github.com/potmdehex/extra_recipe_extra_bug
[jailbreak.c:403]: https://github.com/potmdehex/extra_recipe_extra_bug/blob/cf884b25e03c56a757587b5957d8b74c1b288ee7/extra_recipe/jailbreak.c#L403

Shortly after that, Viktor Oreshkin ([@stek29]) published a brief analysis:

[@stek29]: https://twitter.com/stek29

<center> <blockquote class="twitter-tweet" data-lang="en"><p lang="en" dir="ltr">So, speaking of
info leak (found by <a href="https://twitter.com/potmdehex?ref_src=twsrc%5Etfw">@potmdehex</a> I
guess): It leaks kernel address of Lel0_synchronous_vector_64_long exception
handler.<br><br>Here&#39;s how you find unslid address (in kernel cache for example): <a
href="https://t.co/egJA3FI4As">https://t.co/egJA3FI4As</a></p>&mdash; Viktor Oreshkin (@stek29) <a
href="https://twitter.com/stek29/status/982285394447405056?ref_src=twsrc%5Etfw">April 6,
2018</a></blockquote> <script async src="https://platform.twitter.com/widgets.js"
charset="utf-8"></script> </center>

At that point, I decided to publish my work, even though Apple hadn't updated the advisory yet.


## Conclusion

Given how easy it was to detect, I'm quite surprised that this information leak lasted for nearly 3
months before it was discovered. I wouldn't be surprised to learn that other parties had found the
leak earlier than me but didn't disclose it.

This bug was an all-around pleasure to find, exploit, and analyze. Stumbling onto a security issue
by accident is by far my favorite way to find a bug. Not only that, I quite enjoyed the experience
of developing a complete proof-of-concept exploit for a serious security vulnerability without
writing a single line of code. And to top it all off, I learned that the bug was actually
introduced by the mitigation against Meltdown! (Who'd have thought that the fix for a really big
information leak would introduce a small information leak?) Quite good fun, and I hope we never see
its like again.


## Footnotes

[^1]: An even easier way is to mark a local variable as occupying a particular register using an
      `asm` annotation. However, I wanted to explicitly step through what happened when `x18` was
      read into another register.

