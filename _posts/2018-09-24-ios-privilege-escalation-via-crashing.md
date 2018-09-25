---
layout: post
title: "iOS privilege escalation via crashing"
author: Brandon Azad
date: 2018-09-24 17:00:00 -0700
category: security
tags: [iOS]
description: >
  Blanket is an exploit for CVE-2018-4280, a Mach port replacement vulnerability in launchd, that
  can be used to take control of every process on an iOS device. iOS versions up to and including
  11.4 are vulnerable, but the exploit is specific to iOS 11.2.6.
---

Among the vulnerabilities fixed in [iOS 11.4.1] and [macOS 10.13.6] is CVE-2018-4280, a Mach port
replacement issue in launchd that was very similar to [CVE-2018-4206]. This vulnerability could be
exploited to impersonate system services, at which point it is possible to escape the sandbox and
elevate privileges.

[iOS 11.4.1]: https://support.apple.com/en-us/HT208938
[macOS 10.13.6]: https://support.apple.com/en-us/HT208937
[CVE-2018-4206]: https://bugs.chromium.org/p/project-zero/issues/detail?id=1529

I developed an exploit called [blanket] for this vulnerability earlier this year. The exploit
achieves code execution inside of ReportCrash, which is a highly privileged process, and then uses
these new privileges to disable codesigning and spawn a bind shell. All of this is achieved without
compromising the kernel in any way. (Sometimes the easiest way to win is not to play.) Even though
the vulnerability was only fixed in iOS 11.4.1, the exploit is specific to iOS 11.2.6 and will need
adjustment to work on later versions.

[blanket]: https://github.com/bazad/blanket

<!--more-->

I presented "Crashing to root: How to escape the iOS sandbox using abort()" about the vulnerability
at the [beVX] security conference in Hong Kong on September 21, 2018. You can find the slides
[here][slides] or in my [presentations] repository on GitHub. I also published the [source
code][blanket] of blanket, and you can find a writeup in the repository's [README].

[beVX]: https://www.beyondsecurity.com/bevxcon/
[slides]: /presentations/beVX-2018-Crashing-to-root.pdf
[presentations]: https://github.com/bazad/presentations
[README]: https://github.com/bazad/blanket/blob/master/README.md

I will be talking about this exploit in greater detail (including the steps involved in
post-exploitation) at [CODE BLUE] in Tokyo, and I'll also discuss the macOS variant at [Objective
by the Sea] in Maui.

[CODE BLUE]: https://codeblue.jp/2018/en/
[Objective by the Sea]: https://objectivebythesea.com

