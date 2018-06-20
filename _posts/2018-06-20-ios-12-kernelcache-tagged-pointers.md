---
layout: post
title: "Analyzing the iOS 12 kernelcache's tagged pointers"
author: Brandon Azad
date: 2018-06-20 08:35:00 -0700
category: security
tags: [iOS]
description: >
  Apple introduced a new kernelcache format for iOS 12 that includes what appear to be tagged
  kernel pointers. In this post I examine changes in the kernelcache layout and show what those
  tags represent to lay the groundwork for future iOS 12 kernelcache analysis.
---

Not long after the iOS 12 developer beta was released, I started analyzing the new kernelcaches in
IDA to look for interesting changes. I immediately noticed that [ida_kernelcache], my kernelcache
analysis toolkit, was failing on the iPhone 6 Plus kernelcache: it appeared that certain segments,
notably the prelink segments like `__PRELINK_TEXT`, were empty. Even stranger, when I started
digging around the kernelcache, I noticed that the pointers looked bizarre, starting with `0x0017`
instead of the traditional `0xffff`.

[ida_kernelcache]: https://github.com/bazad/ida_kernelcache

It appears that Apple may be making significant changes to the iOS kernelcache on some devices,
including abandoning the familiar split-kext design in favor of a monolithic Mach-O and introducing
some form of static pointer tagging, most likely as a space-saving optimization. In this post I'll
describe some of the changes I've found and share my analysis of the tagged pointers.

<!--more-->

## The new kernelcache format

The iOS 12 beta kernelcache comes in a new format for some devices. In particular, if you look at
build 16A5308e on the iPhone 6 Plus (iPhone7,1), you'll notice a few differences from iOS 11
kernelcaches:

* The `__TEXT`, `__DATA_CONST`, `__TEXT_EXEC`, `__DATA`, and `__LINKEDIT` segments are much bigger
  due to the integration of the corresponding segments from the kexts.
* There are several new sections:
    * `__TEXT.__fips_hmacs`
    * `__TEXT.__info_plist`
    * `__TEXT.__thread_starts`
    * `__TEXT_EXEC.initcode`
    * `__DATA.__kmod_init`, which is the combination of the kexts' `__mod_init_func` sections.
    * `__DATA.__kmod_term`, which is the combination of the kexts' `__mod_term_func` sections.
    * `__DATA.__firmware`
    * `__BOOTDATA.__data`
    * `__PRELINK_INFO.__kmod_info`
    * `__PRELINK_INFO.__kmod_start`
* The segments `__PRELINK_TEXT` and `__PLK_TEXT_EXEC`, `__PRELINK_DATA`, and `__PLK_DATA_CONST` are
  now 0 bytes long.
* The prelink info dictionary in the section `__PRELINK_INFO.__info` no longer has the
  `_PrelinkLinkKASLROffsets` and `_PrelinkKCID` keys; only the `_PrelinkInfoDictionary` key
  remains.
* There is no symbol information.

This new kernelcache is laid out like follows:

```
__TEXT.HEADER                 fffffff007004000 - fffffff007008c60  [  19K ]
__TEXT.__const                fffffff007008c60 - fffffff007216c18  [ 2.1M ]
__TEXT.__cstring              fffffff007216c18 - fffffff007448d11  [ 2.2M ]
__TEXT.__os_log               fffffff007448d11 - fffffff007473d6c  [ 172K ]
__TEXT.__fips_hmacs           fffffff007473d6c - fffffff007473d8c  [  32B ]
__TEXT.__thread_starts        fffffff007473d8c - fffffff007473fe4  [ 600B ]
__DATA_CONST.__mod_init_func  fffffff007474000 - fffffff007474220  [ 544B ]
__DATA_CONST.__mod_term_func  fffffff007474220 - fffffff007474438  [ 536B ]
__DATA_CONST.__const          fffffff007474440 - fffffff0076410a0  [ 1.8M ]
__TEXT_EXEC.__text            fffffff007644000 - fffffff0088893f0  [  18M ]
__TEXT_EXEC.initcode          fffffff0088893f0 - fffffff008889a48  [ 1.6K ]
__LAST.__mod_init_func        fffffff00888c000 - fffffff00888c008  [   8B ]
__KLD.__text                  fffffff008890000 - fffffff0088917cc  [ 5.9K ]
__KLD.__cstring               fffffff0088917cc - fffffff008891fa7  [ 2.0K ]
__KLD.__const                 fffffff008891fa8 - fffffff008892010  [ 104B ]
__KLD.__mod_init_func         fffffff008892010 - fffffff008892018  [   8B ]
__KLD.__mod_term_func         fffffff008892018 - fffffff008892020  [   8B ]
__KLD.__bss                   fffffff008892020 - fffffff008892021  [   1B ]
__DATA.__kmod_init            fffffff008894000 - fffffff0088965d0  [ 9.5K ]
__DATA.__kmod_term            fffffff0088965d0 - fffffff008898b28  [ 9.3K ]
__DATA.__data                 fffffff00889c000 - fffffff00890b6e0  [ 446K ]
__DATA.__sysctl_set           fffffff00890b6e0 - fffffff00890db28  [ 9.1K ]
__DATA.__firmware             fffffff00890e000 - fffffff0089867d0  [ 482K ]
__DATA.__common               fffffff008987000 - fffffff0089ed1c8  [ 408K ]
__DATA.__bss                  fffffff0089ee000 - fffffff008a1d6e8  [ 190K ]
__BOOTDATA.__data             fffffff008a20000 - fffffff008a38000  [  96K ]
__PRELINK_INFO.__kmod_info    fffffff008a38000 - fffffff008a38598  [ 1.4K ]
__PRELINK_INFO.__kmod_start   fffffff008a38598 - fffffff008a38b38  [ 1.4K ]
__PRELINK_INFO.__info         fffffff008a38b38 - fffffff008ae9613  [ 707K ]
```

Of particular consequence to those interested in reversing, the new kernelcaches are missing all
symbol information:

```
% nm kernelcache.iPhone7,1.16A5308e.decompressed | wc -l
       0
```

So far, Apple hasn't implemented this new format on all devices. The iPhone 7 (iPhone9,1)
kernelcache still has split kexts and the traditional ~4000 symbols.

However, even on devices with the traditional split-kext layout, Apple does appear to be tweaking
the format. The layout appears largely the same as before, but loading the kernelcache file into
IDA 6.95 generates numerous warnings:

```
Loading prelinked KEXTs
FFFFFFF005928300: loading com.apple.iokit.IONetworkingFamily
entries start past the end of the indirect symbol table (reserved1 field greater than the table size)
FFFFFFF005929E00: loading com.apple.iokit.IOTimeSyncFamily
entries start past the end of the indirect symbol table (reserved1 field greater than the table size)
FFFFFFF00592D740: loading com.apple.kec.corecrypto
entries start past the end of the indirect symbol table (reserved1 field greater than the table size)
...
```

Thus, there appear to be at least 3 distinct kernelcache formats:

* 11-normal: The format used on iOS 10 and 11. It has split kexts, untagged pointers, and
  about 4000 symbols.
* 12-normal: The format used on iOS 12 beta for iPhone9,1. It is similar to 11-normal, but with
  some structural changes that confuse IDA 6.95.
* 12-merged: The format used on iOS 12 beta for iPhone7,1. It is missing prelink segments, has
  merged kexts, uses tagged pointers, and, to the dismay of security researchers, is completely
  stripped.

## Unraveling the mystery of the tagged pointers

I first noticed that the pointers in the kernelcache looked weird when I jumped to
`__DATA_CONST.__mod_init_func` in IDA. In the iPhone 7,1 16A5308e kernelcache, this section looks
like this:

```
__DATA_CONST.__mod_init_func:FFFFFFF00748C000 ; Segment type: Pure data
__DATA_CONST.__mod_init_func:FFFFFFF00748C000                 AREA __DATA_CONST.__mod_init_func, DATA, ALIGN=3
__DATA_CONST.__mod_init_func:FFFFFFF00748C000 off_FFFFFFF00748C000 DCQ 0x0017FFF007C95908
__DATA_CONST.__mod_init_func:FFFFFFF00748C000                                         ; DATA XREF: sub_FFFFFFF00794B1F8+438o
__DATA_CONST.__mod_init_func:FFFFFFF00748C000                                         ; sub_FFFFFFF00794B1F8+4CC7w
__DATA_CONST.__mod_init_func:FFFFFFF00748C008                 DCQ 0x0017FFF007C963D0
__DATA_CONST.__mod_init_func:FFFFFFF00748C010                 DCQ 0x0017FFF007C99E14
__DATA_CONST.__mod_init_func:FFFFFFF00748C018                 DCQ 0x0017FFF007C9B7EC
__DATA_CONST.__mod_init_func:FFFFFFF00748C020                 DCQ 0x0017FFF007C9C854
__DATA_CONST.__mod_init_func:FFFFFFF00748C028                 DCQ 0x0017FFF007C9D6B4
```

This section should be filled with pointers to initialization functions; in fact, the values look
almost like pointers, except the first 2 bytes, which should read `0xffff`, have been replaced with
`0x0017`. Aside from that, the next 4 digits of the "pointer" are `fff0`, as expected, and the
pointed-to values are all multiples of 4, as required for function pointers on arm64.

This pattern of function pointers was repeated in the other sections. For example, all of
`__DATA.__kmod_init` and `__DATA.__kmod_term` have the same strange pointers:

```
__DATA.__kmod_init:FFFFFFF0088D4000 ; Segment type: Pure data
__DATA.__kmod_init:FFFFFFF0088D4000                 AREA __DATA.__kmod_init, DATA, ALIGN=3
__DATA.__kmod_init:FFFFFFF0088D4000                 DCQ 0x0017FFF007DD3DC0
__DATA.__kmod_init:FFFFFFF0088D4008                 DCQ 0x0017FFF007DD641C
...
__DATA.__kmod_init:FFFFFFF0088D6600                 DCQ 0x0017FFF0088C9E54
__DATA.__kmod_init:FFFFFFF0088D6608                 DCQ 0x0017FFF0088CA1D0
__DATA.__kmod_init:FFFFFFF0088D6610                 DCQ 0x0007FFF0088CA9E4
__DATA.__kmod_init:FFFFFFF0088D6610 ; __DATA.__kmod_init ends
__DATA.__kmod_term:FFFFFFF0088D6618 ; ===========================================================================
__DATA.__kmod_term:FFFFFFF0088D6618 ; Segment type: Pure data
__DATA.__kmod_term:FFFFFFF0088D6618                 AREA __DATA.__kmod_term, DATA, ALIGN=3
__DATA.__kmod_term:FFFFFFF0088D6618                 DCQ 0x0017FFF007DD3E68
__DATA.__kmod_term:FFFFFFF0088D6620                 DCQ 0x0017FFF007DD645C
```

However, if you look carefully, you'll see that the last pointer of `__kmod_init` actually begins
with `0x0007` rather than `0x0017`. After seeing this, I began to suspect that this was some form
of pointer tagging: that is, using the upper bits of the pointer to store additional information.
Thinking that this tagging could be due to some new kernel exploit mitigation Apple was about to
release, I decided to work out exactly what these tags mean to help understand what the mitigation
might be.

My next step was to look for different types of pointers to see if there were any other possible
tag values. I first checked the vtable for `AppleKeyStoreUserClient`. Since there are no symbols,
you can find the vtable using the following trick:

* Search for the "AppleKeyStoreUserClient" string in the Strings window.
* Look for cross-references to the string from an initializer function. In our case, there's only
  one xref, so we can jump straight there.
* The "AppleKeyStoreUserClient" string is being loaded into register `x1` as the first explicit
  argument in the call to to `OSMetaClass::OSMetaClass(char const*, OSMetaClass const*, unsigned
  int)`. The implicit `this` parameter passed in register `x0` refers to the global
  `AppleKeySoreUserClient::gMetaClass`, of type `AppleKeyStoreUserClient::MetaClass`, and its
  vtable is initialized just after the call. Follow the reference just after the call and you'll be
  looking at the vtable for `AppleKeyStoreUserClient::MetaClass`.
* From there, just look backwards to the first vtable before that one, and that'll be
  `AppleKeyStoreUserClient`'s vtable.

This is what those vtables look like in the new kernelcache:

```
__DATA_CONST.__const:FFFFFFF0075D7738 ; AppleKeyStoreUserClient vtable
__DATA_CONST.__const:FFFFFFF0075D7738 off_FFFFFFF0075D7738 DCQ 0, 0, 0x17FFF00844BE00, 0x17FFF00844BE04, 0x17FFF007C99514
__DATA_CONST.__const:FFFFFFF0075D7738                                         ; DATA XREF: sub_FFFFFFF00844BE28+287o
__DATA_CONST.__const:FFFFFFF0075D7738                                         ; sub_FFFFFFF00844BE28+2C0o
__DATA_CONST.__const:FFFFFFF0075D7738                 DCQ 0x17FFF007C99528, 0x17FFF007C99530, 0x17FFF007C99540
...
__DATA_CONST.__const:FFFFFFF0075D7738                 DCQ 0x17FFF007D68674, 0x17FFF007D6867C, 0x17FFF007D686B4
__DATA_CONST.__const:FFFFFFF0075D7738                 DCQ 0x17FFF007D686EC, 0x47FFF007D686F4, 0
__DATA_CONST.__const:FFFFFFF0075D7D18 ; AppleKeyStoreUserClient::MetaClass vtable
__DATA_CONST.__const:FFFFFFF0075D7D18 off_FFFFFFF0075D7D18 DCQ 0, 0, 0x17FFF00844BDF8, 0x17FFF0084502D0, 0x17FFF007C9636C
__DATA_CONST.__const:FFFFFFF0075D7D18                                         ; DATA XREF: sub_FFFFFFF0084502D4+887o
__DATA_CONST.__const:FFFFFFF0075D7D18                                         ; sub_FFFFFFF0084502D4+8C0o
__DATA_CONST.__const:FFFFFFF0075D7D18                 DCQ 0x17FFF007C96370, 0x17FFF007C96378, 0x17FFF007C9637C
__DATA_CONST.__const:FFFFFFF0075D7D18                 DCQ 0x17FFF007C96380, 0x17FFF007C963A0, 0x17FFF007C96064
__DATA_CONST.__const:FFFFFFF0075D7D18                 DCQ 0x17FFF007C963AC, 0x17FFF007C963B0, 0x17FFF007C963B4
__DATA_CONST.__const:FFFFFFF0075D7D18                 DCQ 0x57FFF00844BE28, 0, 0
```

As you can see, most of the pointers still have the `0x0017` tag, but there are also `0x0047` and
`0x0057` tags.

You may also notice that the last valid entry in the `AppleKeyStoreUserClient::MetaClass` vtable is
`0x0057fff00844be28`, which corresponds to the untagged pointer `0xfffffff00844be28`, which is the
address of the function `sub_FFFFFFF00844BE28` that references `AppleKeyStoreUserClient`'s vtable.
This supports the hypothesis that only the upper 2 bytes of each pointer are changed: the metaclass
method at index 14 should be `AppleKeyStoreUserClient::MetaClass::alloc`, which needs to reference
the `AppleKeyStoreUserClient` vtable when allocating a new instance of the class, and so everything
fits together as expected.

At this point, I decided to gather more comprehensive information about the tagged pointers. I
wrote a quick idapython script to search for 8-byte values that would be valid pointers except that
the first 2 bytes were not `0xffff`. Here's the distribution of tagged pointers by section:

```
Python>print_tagged_pointer_counts_per_section()
__DATA_CONST.__mod_init_func           68
__DATA_CONST.__mod_term_func           67
__DATA_CONST.__const               211000
__TEXT_EXEC.__text                    372
__LAST.__mod_init_func                  1
__KLD.__const                          12
__KLD.__mod_init_func                   1
__KLD.__mod_term_func                   1
__DATA.__kmod_init                   1219
__DATA.__kmod_term                   1205
__DATA.__data                       12649
__DATA.__sysctl_set                  1168
__PRELINK_INFO.__kmod_info            179
__PRELINK_INFO.__kmod_start           180
```

I also counted how many untagged (i.e. normal) pointers I found in each section:

```
Python>print_untagged_pointer_counts_per_section()
__TEXT.HEADER                          38
```

Looking at those untagged pointers in IDA, it was clear that all of them were found in the
kernelcache's Mach-O header. Every other pointer in the entire kernelcache file was tagged.

Next I decided to look at how many copies of each tag were found in each section:

```
Python>print_tagged_pointer_counts_by_tag_per_section()
__TEXT.HEADER                    ffff (38)
__DATA_CONST.__mod_init_func     0007 (1), 0017 (67)
__DATA_CONST.__mod_term_func     0007 (1), 0017 (66)
__DATA_CONST.__const             0007 (2), 0017 (201446), 0027 (4006), 0037 (1694), 0047 (3056), 0057 (514), 0067 (85), 0077 (26), 0087 (46), 0097 (8), 00a7 (12), 00b7 (13), 00c7 (6), 00d7 (1), 00f7 (4), 0107 (4), 0117 (1), 0137 (1), 0147 (4), 0177 (1), 0187 (3), 0197 (1), 01c7 (3), 01e7 (1), 01f7 (8), 0207 (3), 0227 (32), 02a7 (1), 02e7 (8), 0317 (1), 0337 (1), 0477 (1), 04e7 (2), 0567 (1), 0b27 (1), 15d7 (1), 1697 (1), 21d7 (1)
__TEXT_EXEC.__text               0007 (133), 0017 (11), 00a7 (180), 0107 (3), 0357 (1), 03b7 (1), 03e7 (1), 05e7 (1), 0657 (1), 0837 (1), 0bd7 (1), 0d97 (1), 0e37 (1), 1027 (1), 12a7 (1), 1317 (1), 1387 (1), 1417 (1), 1597 (1), 1687 (1), 18b7 (1), 18d7 (1), 1927 (1), 19c7 (1), 19f7 (1), 1ad7 (1), 1c87 (1), 1ce7 (1), 1da7 (1), 1eb7 (1), 2077 (1), 2777 (1), 2877 (1), 2987 (1), 29b7 (1), 2a27 (1), 2a37 (1), 2aa7 (1), 2ab7 (1), 2bd7 (1), 2cf7 (1), 32b7 (1), 3367 (1), 3407 (1), 3417 (1), 3567 (1), 3617 (1), 37c7 (1), 3cb7 (1)
__LAST.__mod_init_func           0007 (1)
__KLD.__const                    0007 (1), 0017 (11)
__KLD.__mod_init_func            0007 (1)
__KLD.__mod_term_func            0007 (1)
__DATA.__kmod_init               0007 (1), 0017 (1218)
__DATA.__kmod_term               0007 (1), 0017 (1204)
__DATA.__data                    0007 (3), 0017 (7891), 001f (23), 0027 (2326), 002f (6), 0037 (1441), 003f (1), 0047 (74), 0057 (306), 0067 (22), 0077 (77), 007f (3), 0087 (98), 0097 (15), 00a7 (23), 00b7 (13), 00bf (1), 00c7 (13), 00d7 (5), 00e7 (6), 00f7 (15), 0107 (1), 0117 (5), 0127 (7), 0137 (8), 0147 (1), 0167 (4), 0177 (2), 017f (89), 0187 (19), 018f (19), 0197 (6), 019f (5), 01a7 (2), 01af (1), 01b7 (2), 01bf (1), 01c7 (3), 01cf (4), 01d7 (1), 01e7 (1), 0207 (1), 0217 (4), 0247 (2), 025f (1), 0267 (2), 0277 (2), 0297 (1), 02a7 (1), 02b7 (2), 02c7 (1), 02d7 (1), 02e7 (1), 02ff (4), 0307 (14), 030f (2), 0317 (1), 031f (1), 0327 (1), 032f (1), 0337 (2), 0357 (2), 0367 (8), 0377 (1), 03c7 (3), 03cf (1), 03d7 (1), 0417 (1), 0427 (1), 0447 (1), 047f (1), 048f (1), 0497 (1), 04a7 (1), 04c7 (1), 04cf (1), 04d7 (2), 0517 (2), 052f (1), 0547 (1), 05f7 (1), 0607 (1), 060f (1), 0637 (1), 0667 (1), 06b7 (1), 0787 (1), 07cf (1), 08ff (1), 097f (1), 09bf (1), 09f7 (5), 0a87 (1), 0b97 (1), 0ba7 (1), 0cc7 (1), 1017 (1), 117f (1), 1847 (1), 2017 (1), 2047 (1), 2097 (1), 2817 (1), 2c37 (1), 306f (1), 33df (1)
__DATA.__sysctl_set              0007 (1), 0017 (1167)
__PRELINK_INFO.__kmod_info       0007 (1), 0017 (178)
__PRELINK_INFO.__kmod_start      0007 (1), 0017 (179)
```

While studying the results, it became obvious that the distribution of tags across the 2-byte tag
space (`0x0000` to `0xffff`) was not uniform: most of the tags seemed to use `0x0017`, and almost
all the tags started with the first digit `0`. Additionally, almost all tags ended in `7`, and the
rest ended in `f`; no tags ended in any other digit.

I next examined whether there was a pattern to what each tagged pointer referenced, under the
theory that the tags might describe the type of referred object. I wrote a script to print the
section being referenced by one tagged pointer chosen at random for each tag. Unfortunately, the
results didn't offer any particularly illuminating insights:

```
Python>print_references_for_tagged_pointers()
0007       149    fffffff007ff5380 __TEXT_EXEC.__text               ->  fffffff007ff53c8 __TEXT_EXEC.__text
0017    213438    fffffff0074c39d0 __DATA_CONST.__const             ->  fffffff00726d80e __TEXT.__cstring
001f        23    fffffff00893c584 __DATA.__data                    ->  fffffff00870956c __TEXT_EXEC.__text
0027      6332    fffffff007639418 __DATA_CONST.__const             ->  fffffff007420e84 __TEXT.__cstring
002f         6    fffffff0089183f4 __DATA.__data                    ->  fffffff0080a11f8 __TEXT_EXEC.__text
0037      3135    fffffff0089010e0 __DATA.__data                    ->  fffffff008a0dff0 __DATA.__common
003f         1    fffffff008937f24 __DATA.__data                    ->  fffffff008520d44 __TEXT_EXEC.__text
0047      3130    fffffff00757b0d0 __DATA_CONST.__const             ->  fffffff008149d68 __TEXT_EXEC.__text
0057       820    fffffff007490b08 __DATA_CONST.__const             ->  fffffff0077470e0 __TEXT_EXEC.__text
0067       107    fffffff00764b980 __DATA_CONST.__const             ->  fffffff00888d8b4 __TEXT_EXEC.__text
...
```

Finally, while looking at the examples of various tags given by the previous script, I noticed a
pattern: `0x0017` seemed to be found in the middle of sequences of pointers, while other tags
appeared at the ends of sequences, when the following value was not a pointer. On further
inspection, the second-to-last digit seemed to suggest how many (8-byte) words to skip before you'd
get to the next tagged pointer: `0x0017` meant the following value was a pointer, `0x0027` meant
value after next was a pointer, `0x0037` meant skip 2 values, etc.

After more careful analysis, I discovered that this pattern held for all tags I manually inspected:

* The tag `0x0007` was usually found at the end of a section.
* The tag `0x0017` was always directly followed by another pointer.
* The tag `0x001f` was followed by a pointer after 4 intermediate bytes.
* The tag `0x0027` was followed by a pointer after 8 bytes.
* The tag `0x0037` was followed by a pointer after 16 bytes.

Extrapolating from these points, I derived the following relation for tagged pointers: For a tagged
pointer `P` at address `A`, the subsequent pointer will occur at address `A + ((P >> 49) & ~0x3)`.

Even though tags as spans between pointers made little sense as a mitigation, I wrote a script to
check whether all the tagged pointers in the kernelcache followed this pattern. Sure enough, all
pointers except for those with tag `0x0007` were spot-on. The exceptions for `0x0007` tags occurred
when there was a large gap between adjacent pointers. Presumably, if the gap is too large, `0x0007`
is used even when the section has not ended to indicate that the gap cannot be represented by the
tag.

## Pointer tags as a kASLR optimization

So, the pointer tags describe the distance from each pointer to the next in the kernelcache, and
there's a formula that can compute the address of the next pointer given the address and tag of the
previous one, kind of like a linked list. We understand the meaning, but not the purpose. Why did
Apple implement this pointer tagging feature? Is it a security mitigation or something else?

Even though I initially thought that the tags would turn out to be a mitigation, the meaning of the
tags as links between pointers doesn't seem to support that theory.

In order to be a useful mitigation, you'd want the tag to describe properties of the referred-to
value. For example, the tag might describe the length of the memory region referred to by the
pointer so that out-of-bound accesses can be detected. Alternatively, the tag might describe the
type of object being referred to so that functions can check that they are being passed pointers of
the expected type.

Instead, these tags seem to describe properties of the address of the pointer rather than the value
referred to by the pointer. That is, the tag indicates the distance to the pointer following this
one regardless of to what or to where this pointer actually points. Such a property would be
impossible to maintain at runtime: adding a pointer to the middle of a data structure would require
searching backwards in memory for the pointer preceding it and updating that pointer's tag. Thus,
if this is a mitigation, it would be of very limited utility.

However, there's a much more plausible theory. Buried among the other changes, the new
kernelcache's prelink info dictionary has been thinned down by removing the
`_PrelinkLinkKASLROffsets` key. This key used to hold a data blob describing the offsets of all the
pointers in the kernelcache that needed to be slid in order to implement kASLR. In the new
kernelcache without the kASLR offsets, iBoot needs another way to identify where the pointers in
the kernelcache are, and it just so happens that the pointer tags connect each pointer to the next
in a linked list.

Thus, I suspect that the pointer tags are the new way for iBoot to find all the pointers in the
kernelcache that need to be updated with the kASLR slide, and are not part of a mitigation at all.
During boot, the tagged pointers would be replaced by untagged, slid pointers. This new
implementation saves space by removing the large list of pointer offsets that used to be stored in
the prelink info dictionary.

## Conclusion

The new kernelcache format and pointer tagging make analysis using IDA difficult, but now that I
have a plausible theory for what's going on, I plan on extending ida_kernelcache to make working
with these new kernelcaches easier. Since the tags are probably not present at runtime, it should
be safe to replace all the tagged pointers with their untagged values. This will allow IDA to
restore all the cross-references broken by the tags. Unfortunately, the loss of symbol information
will definitely make analysis more difficult. Future versions of ida_kernelcache may have to
incorporate known symbol lists or parse the XNU source to give meaningful names to labels.

