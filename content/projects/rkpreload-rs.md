+++
title = "LD_PRELOAD Malware in Rust"
author = "yocvito"
authorTwitter = "" #do not include @
cover = ""
tags = ["project", "maldev", "rootkit", "userspace", "rust"]
keywords = ["project", "maldev", "rootkit", "userspace", "rust"]
description = "Implementing simple LD_PRELOAD malware in Rust"
showFullContent = false
readingTime = false
hideComments = false
date = 2024-12-15T00:04:38+01:00
+++

# rkpreload-rs

This is a simple Linux userspace rootkit in Rust, using `LD_PRELOAD` for injection.

This is mostly dedicated to use in KOTH CTFs.

⚠️  **WARNING** ⚠️

_This is a PoC. There is still many artifacts in the code that leak information about the malware to the user. Use at your own risk._


## Features

- **Mess with shell output** to slower other players
- **Mess with file listing**
- **Deny writing to `king.txt`**
- **Log shell commands to hidden files in /tmp** (these files are visible by other users on the system, except if they are pwned)
- **Persistence**
    - set `LD_PRELOAD` in environment variables of current process if it has been unset
    - pwn `.bashrc` file if injection has been removed
- **Hide files** prefixed by a certain string
- **eBPF loader** to load a rootkit when being run as root
    - allow loading several eBPF programs specified in `ebpf_programs` (no `map` support)
- **Collection of eBPF programs** to provide advanced rootkit capabilities
    - LSM program to better protect `king.txt` (with an alternative program if LSM isn't available)
    - program with advanced hiding capabilties (dynamically configurable through maps)
        - hide eBPF programs
        - hide pids
        - hide files
    - backdoor program: spawn a root shell when receiving a special packet
    - rootkit exfiltration program: exfiltrate objects loaded through `bpf_prog_load` and `load_module` (LKM) kernel functions (for now it exfiltrates to filesystem)
- **dropper**: send and execute files on target system 
    - use AES256-CGM for exchanging messages between attacker and dropper implant
    - performs fileless execution of binaries using `memfd_create` (local files passed as arguments are also mapped to memory and never touch disk)

## Repository Hierarchy

- `LD_PRELOAD`: holds the malicious library to inject into shells
- `eBPF`: collection of eBPF programs to provide rootkit capabilities
- `tools`: collection of usefull binaries (chattr, backdoor-cli, dropper-cli, etc.)
- `rkpreload-utils`: utility functions used in all code (anti-debug, etc.)
- `pwncat-weaponizing`: collection of scripts to install the library with `pwncat-cs`

### TODO features

- **other `root` bypass countermeasures
- **automatic exfiltrator** 
- **better hiding**
- **LKM loader** (without insmod, loading through `/dev/kmem`)

### eBPF backdoor demo

[![Watch the backdoor demo](https://img.youtube.com/vi/a3fbWpP_Ojs/hqdefault.jpg)](https://youtu.be/a3fbWpP_Ojs)



## Config file format

```toml
# enable perturbing process output (run verbose commands, print messages, etc.)
enable_perturbs = true
# enable keylogger
enable_keylogger = true
# hidden files prefix
hiding_prefix = "@"
# directory to store malware files
backup_dir = "/tmp/.@systemd-usocket-a3ef65a9"
# file for eBPF loader killswitch (allowing only one loader)
ebpf_killswitch = "/tmp/.@systemd-usocket-a3ef65a9/.@ssock"

# killswitch to disable LD_PRELOAD rootkit on current process
[killswitch]
Env = { key = "SK", val = "UTC1" }
```

Also take a look at [`ebpf_programs/king_protect.toml`](./ebpf_programs/king_protect.toml) to see how to generate a config for your ebpf programs.


## Compile

First, set `RUSTFLAGS` to remove information about your dev machine.
```shell
# bash/sh/zsh
export RUSTFLAGS="--remap-path-prefix=$HOME/=. --remap-path-prefix=$(pwd)/=."

# fish
set -lx RUSTFLAGS "--remap-path-prefix=$HOME/=. --remap-path-prefix=$(pwd)/=."
```

Then, you might want to generate the eBPF program and write it to the `ebpf_programs` dir before compiling the `LD_PRELOAD` library (see [sub-directory README for instructions](./lsm_king_protect/README.md))


```bash
cd rust_preload
# eventually edit the `config.toml` file before compiling
cargo build --release
cp target/release/librust_preload.so ./libperf.so
```

The `build.rs` file will also generate a `libpreload_install.sh` script, which is later used to pwn a user.


## How to use

We will assume you have getting access to the system and have download both the `libperf.so` and `libpreload_install.sh` files.
All commands provided following this assume to be running on attacked machine.

First, we pwn the `.bashrc` file to set `LD_PRELOAD`, to our malicious library, at startup.
```bash
./libpreload_install.sh
```

Alternatively if you are connected with `pwncat-cs` and have installed `rkpreload` modules, you can follow the instructions in [pwncat-weaponizing dir](./pwncat-weaponizing/README.md) to install the lib without having to manually upload files.

After that, anyone who starts a `bash` process, as the pwned user, will have our malicious library loaded.

To see what happens when your are pwned, run the following command (be carefull to remove malicious code in `.bashrc` after testing):
```bash
LD_PRELOAD=$(pwd)/libperf.so bash
```

Now you likely want to build the library for specific libc versions (in order to just upload the compiled library to the attacked machine). You can use Docker to achieve this goal.
