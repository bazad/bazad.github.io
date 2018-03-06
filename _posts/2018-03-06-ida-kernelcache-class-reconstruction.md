---
layout: post
title: "Reconstructing C++ classes in the iOS kernelcache using IDA Pro"
author: Brandon Azad
date: 2018-03-06 15:00:00 -0800
category: security
tags: [iOS]
description: >
  The ida_kernelcache IDA Pro toolkit now supports autogenerating class structs based on memory
  access patterns.
---

Last October I released [ida_kernelcache][ida_kernelcache], an IDA Pro toolkit for analyzing iOS
kernelcache files. My goal was to make working with kernelcaches in IDA a bit easier by improving
segment names, automatically converting some pointers into offsets, symbolicating virtual methods
and virtual method tables, and automatically renaming stub functions in kexts. Today, I'm releasing
what I've found to be the most useful part of the toolkit thus far: automatically reconstructing
class layouts and C structs via data flow analysis.

[ida_kernelcache]: https://github.com/bazad/ida_kernelcache

<!--more-->

I actually implemented this feature last November, and I've been using it since then to reverse
kernelcaches in search of vulnerabilities. However, I believe it's now time to release this work
publicly.

## Data flow analysis

The reason I started ida_kernelcache to begin with was to automatically determine the fields of
IOKit classes using observed access patterns. The idea is simple: based on how a virtual method
reads memory from the implicit `this` parameter (argument 0), it should be possible to reconstruct
the offsets and sizes of many of the class's fields. No such analysis can be perfect, of course, as
much crucial information has been lost during compilation. Nevertheless, even getting a rough idea
of the class layout can greatly aid in reverse engineering.

The key feature underlying class reconstruction is data flow analysis. There already exist many
data flow analysis frameworks, some of them quite sophisticated, but for the purposes of this
project it seemed easiest just to write a basic one myself. The implementation is available in the
file [`data_flow.py`][data_flow.py].

[data_flow.py]: https://github.com/bazad/ida_kernelcache/blob/e4f5ca3fc16564dd90ea2c2b627a0ef822e634b4/ida_kernelcache/data_flow.py

All this particular analysis does is take a set of registers and corresponding offsets into a
memory region and track what parts of the memory region are accessed by the code. For example,
consider the following fragment of assembly from `AppleKeyStoreUserClient`:

{% highlight assembly %}
FFFFFFF0069D97C0 ; AppleKeyStoreUserClient::registerNotificationPort(AppleKeyStoreUserClient __hidden *this, ipc_port *, unsigned int, unsigned int)
FFFFFFF0069D97C0 __ZN23AppleKeyStoreUserClient24registerNotificationPortEP8ipc_portjj
FFFFFFF0069D97C0
FFFFFFF0069D97C0                 LDRB            W8, [X0,#0xF8]
FFFFFFF0069D97C4                 TBZ             W8, #4, loc_FFFFFFF0069D9800
FFFFFFF0069D97C8                 LDR             X0, [X0,#0xD8]
FFFFFFF0069D97CC                 CMP             W3, #0x2B
FFFFFFF0069D97D0                 B.NE            loc_FFFFFFF0069D97FC
FFFFFFF0069D97D4                 STR             X1, [X0,#0xD0]
{% endhighlight %}

Since `AppleKeyStoreUserClient::registerNotificationPort` is a non-static C++ method, we know that
`x0` must be a pointer to an `AppleKeyStoreUserClient` instance on entry. Thus, we can gather
insight about the structure of the `AppleKeyStoreUserClient` class by observing accesses to the
memory region pointed to by `x0`. Tracing through the execution of the code, we see a 1-byte access
at offset `0xf8` into the region followed by an 8-byte access at offset `0xd8`. (The 8-byte store
to offset `0xd0` of register `x0` on the last line does not access the same region because `x0` is
clobbered on all paths that reach this instruction.) This tells us that `AppleKeyStoreUserClient`
probably has a 1-byte field at offset `0xf8` and an 8-byte field at offset `0xd8`.

Of course, there are many tricky situations that are difficult or impossible for the data flow
analysis to get right. One of these is loops. For example, what if a class contains an array of
values that are initialized using a `for` loop?. While it's possible to get quite sophisticated in
analyzing these types of scenarios, I've found that simply ignoring back edges in the control flow
graph seems to work well enough in practice.

## Automatic class generation

Once we've collected a set of accesses to a class, the next question is how we translate those
accesses into a representation of the C++ class in IDA. The problem is that C++ supports
inheritance while IDA (at least version 6.95) does not. This means that there is no native way to
define an IDA struct that extends the fields of another struct.

While thinking about how to represent C++ classes in IDA, I decided that any good solution must
automatically propagate changes to fields of a base class into all of the class's descendants.[^1]
I eventually settled on 2 representations: struct slices and unions. Struct slices are the default
representation, but if you prefer, you can tell ida_kernelcache to use unions when you first call
`kernelcache_process`.

In both representations, each C++ class `AClass` gets four structs: `AClass`, `AClass::vtable`,
`AClass::vmethods` and `AClass::fields`.

`AClass::vmethods` is a struct containing the virtual methods for `AClass` that are not present in
its direct superclass. `AClass::vtable` is a struct representing the virtual method table for
`AClass`, laid out as follows:

{% highlight c++ %}
struct AClass::vtable {
	struct ASuperClass1::vmethods ASuperClass1;
	struct ASuperClass2::vmethods ASuperClass2;
	/* ... */
	struct ASuperClassN::vmethods ASuperClassN;
	struct AClass::vmethods       AClass;
};
{% endhighlight %}

Here `ASuperClass1` through `ASuperClassN` are the chain of superclasses of `AClass` starting from
the root. (Since XNU's C++ does not have multiple inheritance, we only have one ancestor chain,
which makes everything much easier.)

In the struct slices representation, `AClass::fields` is a struct containing those fields in
`AClass` not present in its superclass, shifted to start at offset 0. We can then represent the C++
class `AClass` as an IDA struct as follows:

{% highlight c++ %}
struct AClass {
	struct AClass::vtable*      vtable;
	struct ASuperClass1::fields ASuperClass1;
	struct ASuperClass2::fields ASuperClass2;
	/* ... */
	struct ASuperClassN::fields ASuperClassN;
	struct AClass::fields       AClass;
};
{% endhighlight %}

In the unions representation, `AClass::fields` is also a struct containing the fields in `AClass`
not present in its superclass, however this time it is not shifted, so that the fields occur at the
same offset in `AClass::fields` as they do in the real `AClass` class in the kernel. `AClass` is
then a union organized as follows:

{% highlight c++ %}
union AClass {
	struct AClass::vtable*      vtable;
	struct ASuperClass1::fields ASuperClass1;
	struct ASuperClass2::fields ASuperClass2;
	/* ... */
	struct ASuperClassN::fields ASuperClassN;
	struct AClass::fields       AClass;
};
{% endhighlight %}

`kernelcache_process` will automatically run the data flow on all identified virtual methods and
reconstruct all known C++ classes participating in the `OSMetaClass` hierarchy. However,
ida_kernelcache cannot identify non-virtual methods to C++ classes, meaning that many class fields
will be missed. If you want to add class fields accessed by another C++ method, you can use the
script [`populate_struct.py`][populate_struct.py].

[populate_struct.py]: https://github.com/bazad/ida_kernelcache/blob/e4f5ca3fc16564dd90ea2c2b627a0ef822e634b4/scripts/populate_struct.py

## Reconstructing C structs

Of course, the exact same data flow analysis used to populate fields in C++ classes can also be
used to reconstruct ordinary C structs. If you give `populate_struct` a struct name (that is, any
identifier that is not a known C++ class), it will create and populate an ordinary C struct based
on the access patterns found in the assembly.

## The final result

ida_kernelcache's class reconstruction features really shine when using the Hex-Rays decompiler.
For example, this is the original decompilation of the
`AppleKeyStoreUserClient::registerNotificationPort` method:

{% highlight c++ %}
__int64 __fastcall AppleKeyStoreUserClient::registerNotificationPort(__int64 a1, ipc_port *a2, __int64 a3, int a4)
{
    __int64 v4; // x0@2

    if ( *(_BYTE *)(a1 + 248) & 0x10 )
    {
        v4 = *(_QWORD *)(a1 + 216);
        if ( a4 == 43 )
        {
            *(_QWORD *)(v4 + 208) = a2;
            if ( *(_BYTE *)(v4 + 0xE0) )
                sub_FFFFFFF0069D0AF4(v4, 0, 0);
        }
        else
        {
            *(_QWORD *)(v4 + 0xC8) = a2;
        }
    }
    return 0LL;
}
{% endhighlight %}

Here's the same decompilation after adding the reconstructed class types and a few minutes of
manual reversing:

{% highlight c++ %}
IOReturn __fastcall AppleKeyStoreUserClient::registerNotificationPort(AppleKeyStoreUserClient *this, ipc_port *port, unsigned int type, unsigned int refcon)
{
    AppleKeyStore *provider; // x0@2

    if ( this->AppleKeyStoreUserClient.entitlements_flags & 0x10 )
    {
        provider = this->AppleKeyStoreUserClient.provider;
        if ( refcon == 43 )
        {
            provider->AppleKeyStore.system_keybag_update_port = port;
            if ( provider->AppleKeyStore.field_e0 )
                AppleSEPKeyStore::tickle_system_keybag_update_port(provider, 0, 0);
        }
        else
        {
            provider->AppleKeyStore.notification_port = port;
        }
    }
    return 0;
}
{% endhighlight %}

Of course, decompilation will not always turn out this well, but in my experience, the extra type
information provided by ida_kernelcache's class reconstruction has proven a wonderful aid while
reversing.

## Future work

There are still many features I'd like to see added to ida_kernelcache. To name just a few:

* Automatically parsing XNU sources to construct a header file that can be imported into IDA.
* Generalizing the data flow analysis code for type flow analysis (i.e., type propagation).
* Fixing numerous bugs and limitations in the symbol processing code.
* Automatically adjusting the boundaries between classes when the metaclass information rounds
  class sizes.
* Fixing references to the first field in a class slice, or figuring out a way to get class unions
  to work.
* Developing ida_kernelcache into a proper IDA plugin.
* Jumping from virtual method calls to virtual method implementations.
* Bringing support for IDA 7 (ida_kernelcache currently only supports IDA 6.95).

## Footnotes

[^1]: We could just create one IDA struct for each class with all members for the class and its
      superclasses together. This approach is simple and presents most similarly to the original
      code, but synchronizing this representation across struct changes is complex, and in general
      not possible.

      For example, if a change is made to a field of the root class via a leaf class, we would
      need to propagate that change back to the root and then down to every subclass of the root
      class. And if along the way we found another change that was incompatible, there would be no
      way to automatically discover the right way to resolve the conflict. Perhaps this solution
      would work if we could ensure that the propagation code was run after every single structure
      change, so that there was no opportunity to develop conflicts, but at that point the solution
      is quite complex and requires support from IDA.

      Instead, I elected to use representations that force each field of each class to be defined
      in only one place. This has the downside that the resulting structures look less like the
      original C++, which complicates adding or looking up members by offset.
