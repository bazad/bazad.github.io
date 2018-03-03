---
layout: post
title: "CVE-2017-13868: A fun XNU infoleak"
author: Brandon Azad
date: 2018-03-02 18:00:00 -0800
category: security
tags: [iOS, macOS]
description: >
  The discovery and exploitation of CVE-2017-13868, a race condition in XNU leading to the
  disclosure of uninitialized kernel heap data.
---

Way back in October of 2017, I discovered CVE-2017-13868, a kernel information leak in XNU that was
quite fun to analyze and exploit. While browsing the XNU source code, I noticed that the function
`ctl_ctloutput` didn't check the return value of a call to `sooptcopyin`. This immediately caught
my attention because error checking in the kernel is very important: poor error checking is a
frequent source of security bugs. In this case, failing to check the return value opened a race
window that could allow a privileged process to read an arbitrary amount of uninitialized kernel
heap data.

<!--more-->

## Finding the vulnerability

One of the most effective ways I have for finding vulnerabilities is simply reading through the
source code of areas of the kernel that seem relevant to security. I've found more bugs by source
code auditing and reverse engineering than by any other technique, including fuzzing and, my
favorite, stumbling onto a security flaw by accident (it happens surprisingly often).

I started looking for iOS bugs again around mid September of last year. Around that time I noticed
that there seemed to be an uptick in the number of race conditions reported in Apple's security
notes for macOS and iOS. Because of that, I figured it would be good to keep parallelism in mind
while auditing.

I had decided to look at indirect calls to `copyout` to see if I could discover any obvious
information leaks. Information leaks are a category of vulnerability where the kernel discloses
information that it shouldn't. For example, disclosing kernel pointers to userspace may allow a
local attacker to defeat the kernel's address space randomization (kASLR) exploit mitigation.
Exploit techniques like ROP depend on knowing the location of the kernel's executable code in
memory, which means kernel pointer disclosures have become a key component of modern macOS and iOS
kernel exploitation.

The `copyout` function is responsible for copying data from the kernel's address space into the
address space of usermode processes. Most kernel infoleaks will pass the leaked data through
`copyout`, which makes call sites to this function promising areas to look for bugs. However, it's
not just this one function: there are many wrappers around `copyout` that are also worth
investigating. For example, one such wrapper is `sooptcopyout`, which is used to copy out socket
options data for the `getsockopt` system call.

It was while looking through calls to this function that the following code, from the
`ctl_ctloutput` function in the file [`bsd/kern/kern_control.c`][kern_control.c], caught my eye:

[kern_control.c]: https://opensource.apple.com/source/xnu/xnu-4570.1.46/bsd/kern/kern_control.c.auto.html

{% highlight C %}
if (sopt->sopt_valsize && sopt->sopt_val) {
	MALLOC(data, void *, sopt->sopt_valsize, M_TEMP,	// (a) data is allocated
		M_WAITOK);					//     without M_ZERO.
	if (data == NULL)
		return (ENOMEM);
	/*
	 * 4108337 - copy user data in case the
	 * kernel control needs it
	 */
	error = sooptcopyin(sopt, data,				// (b) sooptcopyin() is
		sopt->sopt_valsize, sopt->sopt_valsize);	//     called to fill the
}								//     buffer; the return
len = sopt->sopt_valsize;					//     value is ignored.
socket_unlock(so, 0);
error = (*kctl->getopt)(kctl->kctlref, kcb->unit,		// (c) The getsockopt()
		kcb->userdata, sopt->sopt_name,			//     implementation is
			data, &len);				//     called to process
if (data != NULL && len > sopt->sopt_valsize)			//     the buffer.
	panic_plain("ctl_ctloutput: ctl %s returned "
		"len (%lu) > sopt_valsize (%lu)\n",
			kcb->kctl->name, len,
			sopt->sopt_valsize);
socket_lock(so, 0);
if (error == 0) {
	if (data != NULL)
		error = sooptcopyout(sopt, data, len);		// (d) If (c) succeeded,
	else							//     then the data buffer
		sopt->sopt_valsize = len;			//     is copied out to
}								//     userspace.
{% endhighlight %}

The `ctl_ctloutput` function is responsible for handling the `getsockopt` system call on kernel
control sockets (that is, sockets created with domain `PF_SYSTEM` and protocol `SYSPROTO_CONTROL`).
The code does the following:

1. It allocates a kernel heap buffer for the data parameter to `getsockopt`. Because the `M_ZERO`
   flag is not specified, the allocation is not zeroed out.
2. It copies in the `getsockopt` data from userspace using `sooptcopyin`, filling the data buffer
   just allocated. This copyin should completely overwrite the allocated data, which is why the
   `M_ZERO` flag was not needed. The return value is not checked.
3. It then calls `kctl->getopt`, the real `getsockopt` implementation for this kernel control
   socket. This implementation will process the input buffer, possibly modifying it and shortening
   it, and return a result code.
4. Finally, if the real `getsockopt` implementation doesn't return an error, `ctl_ctloutput` calls
   `sooptcopyout` to copy the data buffer back to user space.

The issue is that the return value from `sooptcopyin` is not checked. This begs the question:
what could happen if `sooptcopyin` fails that wouldn't be possible if the return value were
checked?

## Analyzing exploitability

The function `sooptcopyin` is responsible for copying in the `getsockopt` options data from
userspace into the allocated buffer. If `sooptcopyin` fails, perhaps because the socket options
data address is invalid, then the kernel data buffer which should have contained the options data
will be uninitialized. And because the data buffer was allocated without the `M_ZERO` flag, that
means that it will contain uninitialized kernel heap data, possibly rife with useful kernel
pointers.

So, the lack of error checking means that the data buffer passed to `kctl->getopt` could actually
contain uninitialized kernel heap data, even though the code as written seems to expect the
contents of the data buffer to always be initialized before the call to `kctl->getopt`. Is there a
way to get that uninitialized memory to flow to a call to `copyout`?

The obvious candidate for `copyout` is the call to `sooptcopyout` just after `kctl->getopt`. But
there's a problem: `sooptcopyout` is passed the same `sopt` structure that was supplied to
`sooptcopyin`, which means it will try to write the uninitialized data to the same address from
which `sooptcopyin` tried to read the socket options earlier. And in order to force `sooptcopyin`
to fail we supplied it with an invalid address. So how do we make `sooptcopyout` succeed where
`sooptcopyin` failed?

At this point I remembered to consider parallelism. Would it be possible to make the memory address
valid in between the calls to `sooptcopyin` and `sooptcopyout`? To do that, we'd need to call
`getsockopt` with an unmapped address, and while `getsockopt` is running in the kernel, call
`mach_vm_allocate` on another thread to map that address. That way, the address would be unmapped
when `sooptcopyin` is called, causing it to fail, but mapped when `sooptcopyout` is called,
allowing the copyout of uninitialized kernel heap data to succeed.

However, there's one more thing we need to check: does the uninitialized heap data actually make it
all the way to the call to `sooptcopyout`? There's an intervening call to `kctl->getopt` which
could overwrite the uninitialized data or change the length of the data to copy out to userspace.
The actual implementation of `kctl->getopt` is determined by what type of control socket we're
operating on. Thus, in order to reach `sooptcopyout` with the uninitialized data intact, we need to
find a kernel control socket with a `getopt` implementation that:

1. does not overwrite the whole data buffer;
2. does not shorten the data buffer; and
3. returns success (that is, 0).

Fortunately, it didn't take much searching to find a candidate: the function `necp_ctl_getopt`,
which is the `getopt` implementation for NECP kernel control sockets, simply returns 0 without
processing the data buffer at all.

The primary limitation of this approach is our ability to reallocate the memory address between the
calls to `sooptcopyin` and `sooptcopyout`. Not a lot of work happens between those calls, meaning
the race window could be pretty tight. If the race window is too tight, it might take a large
number of tries to actually win the race.

## An alternative approach (that did not work)

While reviewing this bug later, it seemed like it should have been possible to trigger it without
any race at all by marking the memory write-only. That way, `sooptcopyin` would fail with `EFAULT`
(because the memory is not readable) but `sooptcopyout` would succeed. However, in my testing, this
simpler exploit strategy didn't work: `getsockopt` would fail with `EFAULT`. I'm not sure why this
happened.

## The final exploit

After figuring out a strategy to trigger the information leak, I implemented the exploit. The
high-level strategy is to open an NECP kernel control socket, launch a thread that will repeatedly
map and unmap the target memory address, and then repeatedly call `getsockopt` on the control
socket to try and trigger the leak. The complete exploit is available on my
[GitHub][ctl_ctloutput-leak].

[ctl_ctloutput-leak]: https://github.com/bazad/ctl_ctloutput-leak

Amazingly, it turned out that this was a pretty easy race to win. I performed tests on a 2015
Macbook Pro and an iPhone 7, and found that the median number of attempts to win the race on these
platforms was 5 and 2, respectively. (The distribution was rather uneven, with the mean number of
attempts on the Macbook sometimes rising as high as 600. However, this was primarily due to a few
very large outliers, where it would take tens of thousands of attempts to win the race.)

What's great about this infoleak is that it does not depend on a fixed leak size: you can use it to
leak data from arbitrary kernel heap zones by specifying different sizes to `getsockopt`. This
makes for a very useful exploit primitive when performing complex attacks on the kernel.

## The fix

I reported this issue to Apple on October 7, 2017, and it was assigned CVE-2017-13868. Apple fixed
the bug in [macOS 10.13.2] and [iOS 11.2].

[macOS 10.13.2]: https://support.apple.com/en-us/HT208331
[iOS 11.2]: https://support.apple.com/en-us/HT208334

Looking at the new [kern_control.c][10.13.2 kern_control.c], Apple decided to fix the bug by
wrapping the code after the call to `sooptcopyin` in an if statement that checks whether there has
been an error. I believe that this is the correct fix for this issue.

[10.13.2 kern_control.c]: https://opensource.apple.com/source/xnu/xnu-4570.31.3/bsd/kern/kern_control.c.auto.html
