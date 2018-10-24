---
layout: post
title: "Bypassing platform binary restrictions with task_threads()"
author: Brandon Azad
date: 2018-10-23 21:05:00 -0700
category: security
tags: [iOS]
description: >
  Apple introduced a mitigation against the use of task ports in exploits. In this post we examine
  the mitigation, find a loophole, and develop a new code injection library.
---

Because task ports have been abused in so many exploits over the years, Apple decided to add a
mitigation that protects platform binaries (i.e., binaries with an Apple code signature) from being
modified by non-platform binaries via task ports. However, there was a significant limitation to
this design: an API called `task_threads()` that would return the thread ports for all the threads
in the task. In this post, we'll look at the mitigation, the workaround, and implications for
exploitation. My [threadexec] library uses this technique to achieve code execution in platform
binaries via a task or thread port on macOS and iOS.

[threadexec]: https://github.com/bazad/threadexec

<!--more-->

## A brief history of task ports

A task port, or more precisely a send right to a task port, is basically just a send right to a
Mach port for which the kernel owns the receive right. What makes a task port special is that
when the kernel receives a message sent to a task port, rather than enqueueing the message, the
kernel will perform an action on the corresponding task. This means that userspace processes can
send messages to a task port in order to inspect or control the task. For example, the Mach trap
`mach_vm_allocate()` takes a task port as its first argument and allocates virtual memory in that
task, while `mach_vm_read()` and `mach_vm_write()` will directly read and write virtual memory in
the task.

While this API is has many legitimate uses in a microkernel system like Mach, it also happens to
make exploitation much easier: once we obtain the task port of a process, we own it. This fact has
made task ports a promising target for exploits, and Apple has taken note.

One relatively recent example is Ian Beer's [mach_portal], which exploited a kernel bug in order to
man-in-the-middle connections between the `com.apple.iohideventsystem` Mach service and its
clients. Mach_portal used this capability to get a copy of the task port of powerd, an unsandboxed
root process, which was being sent in a Mach message to `com.apple.iohideventsystem`. Once
mach_portal had powerd's task port, it effectively had powerd's privileges. Sometime after the
exploit was disclosed to Apple, unsandboxed root processes no longer sent their task ports in Mach
messages.

[mach_portal]: https://bugs.chromium.org/p/project-zero/issues/detail?id=965#c2

Not much later, Ian Beer released [triple_fetch], an exploit of a shared memory issue in libxpc.
This exploit relied heavily on abusing task ports in order to perform actions in other processes.
In particular, after getting the task port of `coreauthd`, triple_fetch could obtain the task port
of any other process on the system using the [`processor_set_tasks()` trick][processor_set_tasks],
meaning triple_fetch had complete control over every process in userspace. That is, frankly, a
shocking amount of privilege: it's not clear that _any_ process should have that level of control.

[triple_fetch]: https://bugs.chromium.org/p/project-zero/issues/detail?id=1247#c3
[processor_set_tasks]: http://newosxbook.com/articles/PST2.html

## The platform binary mitigation

As of iOS 11, Apple has introduced a mitigation designed to prevent such trivial abuse of task
ports in exploits. Like most mitigations it is not supposed to block all task port abuse, but it
should make the attacker's job much more difficult. In particular, it should prevent attackers from
being able to execute arbitrary code in a process given just a task port.

The mitigation consists of a new function called [`task_conversion_eval()`][ipc_tt.c] that gets
called when the kernel converts an `ipc_port` object to a `task` object using
`convert_port_to_task()`. Here's the code of this function; `caller` is the task that wants to
operate on the task port, and `victim` is the task being operated on:

[ipc_tt.c]: https://opensource.apple.com/source/xnu/xnu-4570.41.2/osfmk/kern/ipc_tt.c.auto.html

{% highlight C %}
kern_return_t
task_conversion_eval(task_t caller, task_t victim)
{
	/*
	 * Tasks are allowed to resolve their own task ports, and the kernel is
	 * allowed to resolve anyone's task port.
	 */
	if (caller == kernel_task) {
		return KERN_SUCCESS;
	}

	if (caller == victim) {
		return KERN_SUCCESS;
	}

	/*
	 * Only the kernel can can resolve the kernel's task port. We've established
	 * by this point that the caller is not kernel_task.
	 */
	if (victim == kernel_task) {
		return KERN_INVALID_SECURITY;
	}

#if CONFIG_EMBEDDED
	/*
	 * On embedded platforms, only a platform binary can resolve the task port
	 * of another platform binary.
	 */
	if ((victim->t_flags & TF_PLATFORM) && !(caller->t_flags & TF_PLATFORM)) {
#if SECURE_KERNEL
		return KERN_INVALID_SECURITY;
#else
		if (cs_relax_platform_task_ports) {
			return KERN_SUCCESS;
		} else {
			return KERN_INVALID_SECURITY;
		}
#endif /* SECURE_KERNEL */
	}
#endif /* CONFIG_EMBEDDED */

	return KERN_SUCCESS;
}
{% endhighlight %}

While the entire function is interesting (especially as it pertains to protecting `kernel_task`),
the part relevant to us is at the bottom, where it says: "On embedded platforms, only a platform
binary can resolve the task port of another platform binary." The subsequent check will deny access
if the victim is a platform binary while the calling task is not.

What does this mean in practice? A process is granted platform binary status based on its code
signature: in particular, it has to be signed by Apple[^1]. Since any exploit code we write will
obviously never be signed by Apple, our attacking process is not a platform binary, and hence
`task_conversion_eval()` will deny us from using `convert_port_to_task()` on the task port for a
platform binary.

Concretely, this means that we can no longer perform some operations on the task ports of
Apple-signed processes, which prevents us from using an ill-gotten task port to take control of the
process and elevate privileges. `mach_vm_*()` operations will all fail, as will other APIs like
`task_set_exception_ports()` and `thread_create_running()`. As prior code injection frameworks
relied on these functions, they were all effectively blocked by this mitigation.

## What does it actually protect?

I discovered this mitigation while developing an exploit for a system service on iOS 11.2. My
exploit payload would run in the context of a privileged process and then send the victim's task
port back to me, so that I could execute code in the victim without having to exploit the bug every
time. However, I noticed that operations like `mach_vm_read()` would fail on the returned task
port, and the investigation brought me to the aforementioned mitigation.

Any time you are confronted with a new mitigation, it is worth investigating. Why did they add this
mitigation? What is it designed to protect? How does it implement that protection? What does it
actually protect? The goal of these questions is to understand both the theory and the practice of
the mitigation, and to hopefully find areas where the two disagree.

In our case, that starts with understanding where `task_conversion_eval()` gets called.

## A task port's many faces

Let's construct the (reverse) call graph to find all the ways in which `task_conversion_eval()` can
be reached:

```
task_conversion_eval
├── convert_port_to_locked_task
│   ├── convert_port_to_space               intran ipc_space_t
│   └── convert_port_to_map                 intran vm_map_t
│       └── convert_port_entry_to_map       intran vm_task_entry_t (vm_map_t)
└── convert_port_to_task_with_exec_token
    ├── ipc_kobject_server
    │   └── ...
    └── convert_port_to_task                intran task_t
        ├── task_info_from_user
        └── port_name_to_task
            └── ...
```

The `intran` annotations indicate an implicit call site generated by MIG. When the kernel receives
a Mach message containing a special type of Mach port, it will automatically translate the
`ipc_port` object to the corresponding kernel object using a translation function specified in MIG
when the type was defined. For example, here's the definition of `task_t` in
[`mach_types.defs`][mach_types.defs]:

[mach_types.defs]: https://opensource.apple.com/source/xnu/xnu-4570.41.2/osfmk/mach/mach_types.defs.auto.html

```
type task_t = mach_port_t
#if	KERNEL_SERVER
		intran: task_t convert_port_to_task(mach_port_t)
		outtran: mach_port_t convert_task_to_port(task_t)
		destructor: task_deallocate(task_t)
#endif	/* KERNEL_SERVER */
		;
```

This definition tells the autogenerated MIG code in the kernel to convert `ipc_port` objects into
`task` objects using `convert_port_to_task()`. For example, here's the MIG definition for
`thread_create_running()`:

```
/*
 *      Create a new thread within the target task, returning
 *      the port representing that new thread.  The new thread 
 *	is not suspended; its initial execution state is given
 *	by flavor and new_state. Returns the port representing 
 *	the new thread.
 */
routine
#ifdef KERNEL_SERVER
thread_create_running_from_user(
#else
thread_create_running(
#endif
                parent_task     : task_t;
                flavor          : thread_state_flavor_t;
                new_state       : thread_state_t;
        out     child_act       : thread_act_t);
```

When a process calls `thread_create_running()` in userspace to create a new thread in a task, the
userspace MIG code will create a Mach message containing information about the operation and then
invoke the `mach_msg()` Mach trap to transfer control to the kernel. The kernel will see that the
destination port (`parent_task`) is owned by the kernel and handle the message itself, passing the
message to the MIG handler. The MIG handling routine will parse the contents of the message and
convert the in-kernel task port to the actual task object using `convert_port_to_task()`. Finally,
the MIG handler will call the in-kernel implementation of `thread_create_running_from_user()` to
perform the actual work.

Thus, any time the kernel handles a Mach message directed to a `task_t`, `ipc_space_t`, `vm_map_t`,
or `vm_task_entry_t`, the kernel will use a conversion function that eventually calls out to
`task_conversion_eval()` to check if the current process should be granted access.

Before we go further, it's worth discussing why a mitigation protecting task ports seems to involve
other types besides `task_t`. In userspace, `task_t`, `ipc_space_t`, `vm_map_t`, and
`vm_task_entry_t` are all identically `typedef`'d to `mach_port_t` (a 32-bit integer). In the
kernel, `task_t` is a pointer to a `struct task`, `ipc_space_t` is a pointer to a `struct
ipc_space`, and `vm_map_t` is a pointer to a `struct _vm_map`. (`vm_task_entry_t` actually doesn't
exist in the kernel; `convert_port_entry_to_map()` returns a `vm_map_t`.) However, these kernel
objects do not get distinct IPC port types: they are all represented by task ports. The reason for
this is that a `task_t` can be uniquely converted into a `vm_map_t` or `ipc_space_t`, so using a
task port in a place that expects either of the other types is unambiguous. The effect of this from
userspace is that even though `thread_create_running()` claims to take a `task_t` while
`mach_vm_read()` claims to take a `vm_map_t`, you pass a task port to both.

Going back to the mitigation, calling `task_conversion_eval()` when a process wants to operate on
these types seems like a robust defense; after all, every code injection library that operates on
task ports relies on at least one function that sends a message to one of the four restricted
types.

However, there are other types besides `ipc_space_t`, `vm_map_t`, and `vm_task_entry_t` to which a
task port can be converted: if you look in [`mach_types.defs`][mach_types.defs] and
[`ipc_tt.c`][ipc_tt.c], you'll see that a task port also has conversions defined for the MIG types
`task_name_t`, `task_inspect_t`, and `ipc_space_inspect_t`. A little digging reveals that these are
restricted versions of their more-powerful siblings: they are used for routines that will inspect a
task without modifying it in any way. You can see the difference in this example from
[`task.defs`][task.defs]:

[task.defs]: https://opensource.apple.com/source/xnu/xnu-4570.41.2/osfmk/mach/task.defs.auto.html

```
/*
 *	Returns the current value of the selected special port
 *	associated with the target task.
 */
routine task_get_special_port(
		task		: task_inspect_t;
		which_port	: int;
	out	special_port	: mach_port_t);

/*
 *	Set one of the special ports associated with the
 *	target task.
 */
routine task_set_special_port(
		task		: task_t;
		which_port	: int;
		special_port	: mach_port_t);
```

Here, `task_get_special_port()` is an inspection routine: it can be used to get a copy of a task's
special ports. On the other hand, `task_set_special_port()` is a modification routine: it can be
used to change the value of a task's special ports. The semantic distinction between the behavior
of these functions is encoded in the type of task port to which the message is sent. Since
`task_get_special_port()` operates on a `task_inspect_t`, this indicates that the function cannot
modify the task; conversely, since `task_set_special_port()` operates on a `task_t`, this indicates
that the function can modify the task.

Thus, we've discovered an important limitation of the mitigation: it does not restrict using a task
port in functions that take a `task_name_t`, `task_inspect_t`, or `ipc_space_inspect_t`. Thus,
while we could not call `mach_vm_read()` on the task port of a platform binary, we could call
`task_get_special_port()` on it.

## Where to search for workarounds

While ostensibly we can't use an inspection right to modify a task, there are 2 huge caveats.

First, it's important to note that the kernel itself makes no distinction between a `task_t` and a
`task_inspect_t`: they are both `typedef`s to a `struct task` pointer. Thus, the semantics of
`task_t` versus `task_inspect_t` govern how processes should expect the kernel to behave, not how
the kernel will necessarily behave in reality. Nothing prevents a kernel implementation of
`task_get_special_port()` that modifies the corresponding task. If we can find a MIG routine that
takes an inspection right and yet still modifies the task, then we may be able to bypass the
mitigation.

Second, even if a `task_inspect_t` cannot be used to modify a task directly, that does not mean
that it cannot be used to modify a task indirectly. For example, `task_get_special_port()` does not
modify the corresponding task, but it does give us a copy of the task's special ports, which could
in theory be used to modify the task (for example, by sending messages to a port used by the task).
If we can find a MIG routine that takes an inspection right and produces another object we can
control, then we may be able to bypass the mitigation.

This gives us a pretty good idea of how to search for bypasses to the mitigations: look at all MIG
routines that handle a `task_name_t`, `task_inspect_t`, or `ipc_space_inspect_t` and see whether
any of them modifies the task or produces a capability to modify the task.

## task_threads()

Early in this search I came across the function `task_threads()`:

```
/*
 *	Returns the set of threads belonging to the target task.
 */
routine task_threads(
		target_task	: task_inspect_t;
	out	act_list	: thread_act_array_t);
```

This function takes a `task_inspect_t` right and returns a list of thread ports for the threads in
a task. The returned threads are actually `thread_act_t` rights, not `thread_inspect_t` rights,
which means we can call functions like `thread_set_state()` on them. This is critical, since
`thread_set_state()` sets the values of the registers in a thread!

This means that we have a complete bypass to the platform binary task port mitigation: call
`task_threads()` on the task port to get a list of thread ports, then call `thread_set_state()` on
one of the returned thread ports to directly set the `pc` register in that thread.

## Arbitrary code execution via task ports on iOS 11

Of course, there's still a very practical gap between being able to set the `pc` register and being
able to call arbitrary functions with arbitrary arguments. To bridge that gap I wrote [threadexec].
The rest of this post describes how threadexec uses a task port to obtain arbitrary code execution
in that task.

For simplicity, I will refer to the context of the injecting process as "local" and the context of
the injected process as "remote".

Our goal is to use the task port of the remote process to:

1. call arbitrary functions with arbitrary arguments in the remote process and get the return
   value;
2. read and write memory in the remote process; and
3. transfer Mach ports (send or receive rights) between the local and remote tasks.

These capabilities are sufficient for most exploits.

## Step 1: Thread hijacking

The first thing we do is call `task_threads()` on the task port to get a list of threads in the
remote task and then choose one of them to hijack. Unlike traditional code injection frameworks, we
can't create a new remote thread because `thread_create_running()` will be blocked by the new
mitigation.

Hijacking an existing thread means that we will be interfering with the normal functionality of the
process into which we are injecting. However, this library was specifically designed to be used in
exploits where we don't care about breaking functionality of the victim.

Once we have the thread port of the remote thread we will hijack, we can call `thread_suspend()` to
stop the thread from running.

At this point, the only useful control we have over the remote thread is stopping it, starting it,
getting its register values, and setting its register values.[^2] In particular, we have no ability
to read or write memory in the remote thread, which is crucial for more complex tasks we may want
to make the victim process do. Thus, we will have to figure out how to gain full control of the
remote thread's memory by building some sort of execution primitive out of this access.

Fortunately, the arm64 architecture and calling convention make it easy to build a function calling
primitive even without a read/write primitive. The standard calling convention allows us to place
the first 8 (integral) arguments in registers; as long as the functions we want to call take no
more than 8 arguments (which is a very generous requirement), we do not have to set up the stack
prior to the call, allowing us to get by without a memory write capability. Also, the return value
is specified in a register (rather than on the stack like x86-64), which gives us an easy way to
control what happens after the executed function returns.

That being said, even if we don't write to its memory, we still need a valid stack pointer to begin
with. Fortunately, we hijacked a previously initialized and running thread, so the `sp` register
already points to a valid stack.

Thus, we can initiate a remote function call by setting registers `x0` through `x7` in the remote
thread to the arguments, setting `pc` to the function we want to execute, and starting the thread.
This will cause the remote thread to run the function with the supplied arguments, and then the
function will return. At this point, we need to detect the return and make sure that the thread
doesn't crash.

There are a few ways to go about this. One way would be to register and exception handler for the
remote thread using `thread_set_exception_ports()` and to set the return address register, `lr`, to
an invalid address before calling the function; that way, after the function runs an exception
would be generated and a message would be sent to our exception port, at which point we can inspect
the thread's state to retrieve the return value. However, for simplicity I copied the strategy used
in Ian Beer's triple_fetch exploit, which was to set `lr` to the address of an instruction that
would infinite loop and then poll the thread's registers repeatedly until `pc` pointed to that
instruction.

At this point we have a basic execution primitive: we can call arbitrary functions with up to 8
arguments and get the return value. However, we are still a long way from our goal.

## Step 2: Mach ports for communication

The next step is to create Mach ports over which we can communicate with the remote thread. These
Mach ports will be useful later in helping transfer arbitrary send and receive rights between the
tasks.

In order to establish bidirectional communication, we will need to create two Mach receive rights:
one in the local task and one in the remote task. Then, we will need to transfer a send right to
each port to the other task. This will give each task a way to send a message that can be received
by the other.

Let's first focus on setting up the local port, that is, the port to which the local task holds the
receive right. We can create the Mach port just like any other, by calling `mach_port_allocate()`.
The trick is to get a send right to that port into the remote task.

A convenient trick we can use to copy a send right from the current task into a remote task using
only a basic execute primitive is to stash a send right to our local port in the remote thread's
`THREAD_KERNEL_PORT` special port using `thread_set_special_port()`; then, we can make the remote
thread call `mach_thread_self()` to retrieve the send right.

Next we will set up the remote port, which is pretty much the inverse of what we just did. We can
make the remote thread allocate a Mach port by calling `mach_reply_port()`; we can't use
`mach_port_allocate()` because the latter returns the allocated port name in memory and we don't
yet have a read primitive. Once we have a port, we can create a send right by calling
`mach_port_insert_right()` in the remote thread. Then, we can stash the port in the kernel by
calling `thread_set_special_port()`. Finally, back in the local task, we can retrieve the port by
calling `thread_get_special_port()` on the remote thread, giving us a send right to the Mach port
just allocated in the remote task.

At this point, we have created the Mach ports we will use for bidirectional communication.

## Step 3: Basic memory read/write

Now we will use the execute primitive to create basic memory read and write primitives. These
primives won't be used for much (we will soon upgrade to much more powerful primitives), but they
are a key step in helping us to expand our control of the remote process.

In order to read and write memory using our execute primitive, we will be looking for functions
like these:

{% highlight C %}
uint64_t read_func(uint64_t *address) {
    return *address;
}
void write_func(uint64_t *address, uint64_t value) {
    *address = value;
}
{% endhighlight %}

They might correspond to the following assembly:

```
_read_func:
    ldr     x0, [x0]
    ret
_write_func:
    str     x1, [x0]
    ret
```

A quick scan of some common libraries revealed some good candidates. To read memory, we can use the
`property_getName()` function from the [Objective-C runtime library][objc4]:

[objc4]: https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html

{% highlight C %}
const char *property_getName(objc_property_t prop)
{
    return prop->name;
}
{% endhighlight %}

As it turns out, `prop` is the first field of `objc_property_t`, so this corresponds directly to
the hypothetical `read_func` above. We just need to perform a remote function call with the first
argument being the address we want to read, and the return value will be the data at that address.

Finding a pre-made function to write memory is slightly harder, but there are still great options
without undesired side effects. In libxpc, the `_xpc_int64_set_value()` function has the following
disassembly:

```
__xpc_int64_set_value:
    str     x1, [x0, #0x18]
    ret
```

Thus, to perform a 64-bit write at address `address`, we can perform the remote call:

{% highlight C %}
_xpc_int64_set_value(address - 0x18, value)
{% endhighlight %}

With these primitives in hand, we are ready to create shared memory.

## Step 4: Shared memory

Our next step is to create shared memory between the remote and local task. This will allow us to
more easily transfer data between the processes: with a shared memory region, arbitrary memory read
and write is as simple as a remote call to `memcpy()`. Additionally, having a shared memory region
will allow us to easily set up a stack so that we can call functions with more than 8 arguments.

To make things easier, we can reuse the shared memory features of libxpc. Libxpc provides an XPC
object type, `OS_xpc_shmem`, which allows establishing shared memory regions over XPC. By reversing
libxpc, we determine that `OS_xpc_shmem` is based on Mach memory entries, which are Mach ports that
represent a region of virtual memory. And since we already have shown how to send Mach ports to the
remote task, we can use this to easily set up our own shared memory.

First things first, we need to allocate the memory we will share using `mach_vm_allocate()`. We
need to use `mach_vm_allocate()` so that we can use `xpc_shmem_create()` to create an
`OS_xpc_shmem` object for the region. `xpc_shmem_create()` will take care of creating the Mach
memory entry for us and will store the Mach send right to the memory entry in the opaque
`OS_xpc_shmem` object at offset `0x18`.

Once we have the memory entry port, we will create an `OS_xpc_shmem` object in the remote process
representing the same memory region, allowing us to call `xpc_shmem_map()` to establish the shared
memory mapping. First, we perform a remote call to `malloc()` to allocate memory for the
`OS_xpc_shmem` and use our basic write primitive to copy in the contents of the local
`OS_xpc_shmem` object. Unfortunately, the resulting object isn't quite correct: its Mach memory
entry field at offset `0x18` contains the local task's name for the memory entry, not the remote
task's name. To fix this, we use the `thread_set_special_port()` trick to insert a send right to
the Mach memory entry into the remote task and then overwrite field `0x18` with the remote memory
entry's name. At this point, the remote `OS_xpc_shmem` object is valid and the memory mapping can
be established with a remote call to `xpc_shmem_remote()`.

## Step 5: Full control

With shared memory at a known address and an arbitrary execution primitive, we are basically done.
Arbitrary memory reads and writes are implemented by calling `memcpy()` to and from the shared
region, respectively. Function calls with more than 8 arguments are performed by laying out
additional arguments beyond the first 8 on the stack according to the calling convention.
Transferring arbitrary Mach ports between the tasks can be done by sending Mach messages over the
ports established earlier. We can even transfer file descriptors between the processes by using
fileports (special thanks to Ian Beer for demonstrating this technique in triple_fetch!).

In short, we now have full and easy control over the victim process. You can see the full
implementation and the exposed API in the [threadexec] library.

## Conclusion

This post has analyzed a new mitigation Apple implemented to prevent the abuse of task ports in
exploits and has shown how that mitigation can be bypassed with `task_threads()` to abuse task
ports once again. We have also seen a way to build a full-featured arbitrary code execution library
on top of the bare-bones execution primitive provided by the loophole. The full code is available
in my [threadexec] repository.

I reported this bypass to Apple on April 13, 2018, as part of my [blanket] exploit. 

[blanket]: https://github.com/bazad/blanket

## Footnotes

[^1]: There is a way to spawn non-Apple signed binaries with `TF_PLATFORM` if you have
    `task_for_pid-allow`; see amfidupe, which is part of [blanket].

[^2]: In fact, there's a lot more we could do, including messing with exception and debug state.
    However, I limited threadexec to execution-only primitives to show how it could be done.
