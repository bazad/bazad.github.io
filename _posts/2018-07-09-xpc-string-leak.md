---
layout: post
title: "Reading process memory using XPC strings"
author: Brandon Azad
date: 2018-07-09 14:32:00 -0700
category: security
tags: [iOS, macOS]
description: >
  The discovery and analysis of CVE-2018-4248, a vulnerability in Apple's libxpc library that could
  be used to read out-of-bounds heap data from certain XPC services, including diagnosticd.
---

This is a short post about another bug I discovered mostly by accident. While reversing libxpc, I
noticed that XPC string deserialization does not check whether the deserialized string is actually
as long as the serialized length claims: it could be shorter. That is, the serialized XPC message
might claim that the string is 1000 bytes long even though the string contains a null byte at
index 100. The resulting `OS_xpc_string` object will then think its C string on the heap is longer
than it actually is.

While directly exploitating this vulnerability to execute arbitrary code is difficult, there's
another path we can take. The length field of an `OS_xpc_string` object is trusted when serializing
the string into a message, so if we can get an XPC service to send us back the string it just
deserialized, it will over-read from the heap C-string buffer and send us all of that extra data in
the message, giving us a snapshot of that process's heap memory. The resulting exploit primitive is
similar to how the Heartbleed vulnerability could be used to over-read heap data from an
OpenSSL-powered server's memory.

<!--more-->

## (XP)C strings and null bytes

I was actually disassembling libxpc in order to understand the wire format when I noticed a
peculiarity about the string deserialization function, `_xpc_string_deserialize`:

{% highlight C %}
OS_xpc_string *__fastcall _xpc_string_deserialize(OS_xpc_serializer *xserializer)
{
    OS_xpc_string *xstring; // rbx@1
    char *string; // rax@4
    char *contents; // [rsp+8h] [rbp-18h]@1
    size_t size; // [rsp+10h] [rbp-10h]@1 MAPDST

    xstring = 0LL;
    contents = 0LL;
    size = 0LL;
    if ( _xpc_string_get_wire_value(xserializer, (const char **)&contents, &size) )
    {
        if ( contents[size - 1] || (string = _xpc_try_strdup(contents)) == 0LL )
        {
            xstring = 0LL;
        }
        else
        {
            xstring = _xpc_string_create(string, size - 1);
            LOBYTE(xstring->flags) |= 1u;
        }
    }
    return xstring;
}
{% endhighlight %}

If you look carefully, you'll notice that a particular check is missing. The function
`_xpc_string_get_wire_value` seems to get a pointer to the data bytes of the string and the
reported length of the string. The code then checks whether the byte at index `size - 1` is null
before duplicating the string and creating the actual `OS_xpc_string` object with
`_xpc_string_create`, passing the duplicated string and `size - 1`.

The check that `contents[size - 1]` is null does ensure that the serialized string is no longer
than `size` bytes, but it does not ensure that the string is not shorter than `size` bytes: there
could be a null byte earlier in the serialized string data. This is problematic because the
unchecked size value gets propagated to the resulting `OS_xpc_string` object through the function
`_xpc_string_create`, which leads to inconsistencies between the string object's reported length
and actual length on the heap.

## Exploitation by XPC message reflection

Any nontrivial exploit would have to leverage the disagreement between the resulting XPC string
object's length and the contents of its heap buffer. This means that we need to find code in some
XPC service that uses both length field and the string contents in a significant way.
Unfortunately, usage patterns that could lead to memory corruption seemed unlikely; you'd need to
write some pretty convoluted code to make a too-short string overwrite a buffer:

{% highlight C %}
xpc_object_t string = xpc_dictionary_get_value(message, "key");
char buf[strlen(xpc_string_get_string_ptr(string))];
memcpy(buf, xpc_string_get_string_ptr(string), xpc_string_get_length(string));
{% endhighlight %}

Not surprisingly, I couldn't find any iOS services that use XPC strings in a way that could lead to
memory corruption.

However, there's still another way to exploit this bug to perform useful work, and that's by
leveraging libxpc's own behavior in services that reflect XPC messages back to the client.

Even though no clients of libxpc use an `OS_xpc_string` object's length field in a significant way,
there are parts of the libxpc library itself that do: in particular, the XPC string serialization
code does trust the stored length field while copying the string contents into the XPC message.

This is the decompiled implementation of `_xpc_string_serialize`:

```C
void __fastcall _xpc_string_serialize(OS_xpc_string *string, OS_xpc_serializer *serializer)
{
    int type; // [rsp+8h] [rbp-18h]@1
    int size; // [rsp+Ch] [rbp-14h]@1

    type = *((_DWORD *)&OBJC_CLASS___OS_xpc_string + 10);
    _xpc_serializer_append(serializer, &type, 4uLL, 1, 0, 0);
    size = LODWORD(string->length) + 1;
    _xpc_serializer_append(serializer, &size, 4uLL, 1, 0, 0);
    _xpc_serializer_append(serializer, string->string, string->length + 1, 1, 0, 0);
}
```

The `OS_xpc_string`'s `length` parameter is trusted when serializing the string, causing that many
bytes to be copied from the heap into the serialized message. If the deserialized string was
shorter than its reported length, the message will be filled with out-of-bounds heap data.

Exploitation is still limited to XPC services that reflect some part of the XPC message back to the
client, but this is much more common.

## Targeting diagnosticd

On macOS and iOS, diagnosticd is a promising candidate for exploitation, not least because it is
unsandboxed, root, and `task_for_pid-allow`. Diagnosticd is responsible for processing diagnostic
messages (for example, messages generated by `os_log`) and streaming them to clients interested in
receiving these messages. By registering to receive our own diagnostic stream and then sending a
diagnostic message with a shorter than expected string, we can obtain a snapshot of some of the
data in diagnosticd's heap, which can aid in getting code execution in the process.

I wrote up a proof-of-concept exploit called [xpc-string-leak] that can be used to sample
arbitrarily-sized sections of out-of-bounds heap content from diagnosticd.

[xpc-string-leak]: https://github.com/bazad/xpc-string-leak

The exploit flow is fairly straightforward: we register a Mach port with diagnosticd to receive a
stream of diagnostic messages from our own process, generate a diagnostic message with a malformed
too-short string, then listen on the port we registered earlier for the message from diagnosticd
containing out-of-bounds heap data.

Interestingly, because diagnosticd receives logging messages from other processes, it is possible
that the out-of-bounds heap data might contain sensitive information from other processes as well.
Thus, there are user privacy implications to this bug even without achieving code execution in
diagnosticd.

## Timeline

I discovered this bug early in 2018 (January or February), but forgot to investigate it until
May. I reported the issue to Apple on May 9, and it was assigned CVE-2018-4248 and patched in [iOS
11.4.1] and [macOS 10.13.6] on July 9.

[iOS 11.4.1]: https://support.apple.com/en-us/HT208938
[macOS 10.13.6]: https://support.apple.com/en-us/HT208937

