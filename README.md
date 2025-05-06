
# Safe Linking Backport for glibc

This repository provides backported **safe-linking** security mechanisms for older versions of the GNU C Library (glibc). Safe linking was introduced in **glibc 2.32** to mitigate heap-based memory corruption attacks. This project ports those protections to **glibc 2.26–2.31**.

Each version is maintained in a **dedicated branch** for easy usage and installation.

---



## 📚 What is Safe Linking?

**Safe Linking** is a security mechanism introduced in glibc's memory allocator (**ptmalloc**) to harden heap metadata against common exploitation techniques. It mitigates a class of heap-based vulnerabilities by obfuscating metadata pointers in singly-linked free lists.


### ✅ Security Threats Addressed
Safe Linking makes it significantly more difficult for attackers to conduct successful heap exploits such as:
- **Use-after-free (UAF)**
- **Double-free**
- **Heap buffer overflows**
- **Tcache poisoning**
- **Arbitrary pointer manipulation**

### ❌ Weaknesses in Older glibc Versions
Before glibc 2.32, heap exploitation was more straightforward due to the following reasons:

1. **Unprotected metadata** — Free-list pointers like `fd` were stored as raw addresses and could be overwritten by attackers.
2. **Lack of integrity checks** — Memory corruption could easily go undetected.
3. **Predictable layouts** — With a known memory map, attackers could manipulate the heap more reliably.

---


### Importance of safe linking
Before glibc 2.32, heap exploitation was relatively straightforward because:
1. **Free-list pointers were unprotected**, allowing attackers to overwrite them
2. **No integrity checks** were performed on heap metadata
3. **Predictable memory layouts** made exploitation reliable

Safe Linking introduces **pointer encryption** and **integrity checks** to disrupt these attack vectors.



## 🔐 How Safe Linking Works
The core mechanism protects the **single-linked lists** in ptmalloc (i.e., `tcache` and `fastbins`) by:
### 🧠 XOR-based Pointer Obfuscation
   - Every free-list pointer (`fd` in chunks) is stored as:  
	 
     `obfuscated_ptr = (address_of_current_ptr >> 12) XOR (actual_next_chunk_ptr)`

   - This prevents direct pointer tampering without knowing the obfuscation key
   - On allocation/deallocation, the pointer is deobfuscated as:  
     `actual_next_chunk_ptr = (address_of_obfuscated_ptr >> 12) XOR (obfuscated_ptr)`








### 🎲 Entropy from ASLR 
   - The `>> 12` (PAGE_SHIFT) operation introduces entropy from ASLR, making pointer leaks harder

### ✅ Implicit Integrity Check
- If an attacker tries to overwrite the `fd` with arbitrary data, the XOR-decryption will fail to produce a valid pointer, leading to a crash instead of exploitation. This acts as a built-in integrity check.

---

## 🚧 Limitations of Safe Linking
While Safe Linking provides significant hardening, it is not a comprehensive solution against all heap-based attacks:

- ❌ **Does not protect `bk` (backward) pointers** used in unsorted/small/large bins.
- ❌ **Ineffective without ASLR** — If ASLR is disabled or bypassed, the protection weakens.
- ❌ **No protection against type confusion, non-pointer overwrites, or logic bugs**.

Safe Linking should be seen as a **layer of defense** and used in conjunction with other hardening techniques available before glibc 2.32 such as:

### 🔐 Complementary Techniques (Pre-2.32)

#### 1. Full RELRO (Read-Only Relocations)
- **Protects the GOT** from being overwritten during exploitation.
- Enabled via compilation flags:

```bash
-Wl,-z,relro,-z,now
```

#### 2. Stack Canaries
- Protects against **stack-based** buffer overflows.
- Detected via `__stack_chk_fail` if a function's return address is overwritten.
- Enable using:

```bash
-fstack-protector-strong
```

#### 3. Address Space Layout Randomization (ASLR)
- Introduced as default in modern kernels and used before glibc 2.32.
- Randomizes base addresses of segments to increase entropy.
- Controlled via:

```bash
$ echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
```

These were widely used in glibc-based systems even before the introduction of Safe Linking.

---


## 📂 Repository Structure

Each glibc version is maintained in a **dedicated Git branch**:

| Branch        | glibc Version |
|---------------|---------------|
| `glibc-2.26`  | 2.26          |
| `glibc-2.27`  | 2.27          |
| `glibc-2.28`  | 2.28          |
| `glibc-2.29`  | 2.29          |
| `glibc-2.30`  | 2.30          |
| `main`        | 2.31          |


## 🛠️ Installation & Usage

### 🔧 Dependencies
Ensure that you have the following packages installed:

```bash
sudo apt install build-essential manpages-dev gcc-multilib g++-multilib gawk bison texinfo python3 python3-pip git
```

### 📦 Clone Specific Version
Clone the desired glibc version with Safe Linking backported:

For **glibc 2.26**:
```bash
$ git clone -b glibc-2.26 https://github.com/HMAhmadCS/safe-linking-backport.git`
```
For **glibc 2.27**:
```bash
$ git clone -b glibc-2.27 https://github.com/HMAhmadCS/safe-linking-backport.git
```
For **glibc 2.28**:
```bash### 🔨 Build Process
$ git clone -b glibc-2.28 https://github.com/HMAhmadCS/safe-linking-backport.git
```
For **glibc 2.29**:
```bash
$ git clone -b glibc-2.29 https://github.com/HMAhmadCS/safe-linking-backport.git
```
For **glibc 2.30**:
```bash
$ git clone -b glibc-2.30 https://github.com/HMAhmadCS/safe-linking-backport.git
```

For **glibc 2.31** (default Branch):
```bash
$ git clone https://github.com/HMAhmadCS/safe-linking-backport.git
```
OR:
```bash
$ git clone -b main https://github.com/HMAhmadCS/safe-linking-backport.git
```


### 🔨 Build Process

```bash
mkdir build && cd build
../configure --prefix=/opt/glibc --enable-obsolete-rpc
make -j$(nproc)

sudo make install
```

-   **`-j$(nproc)`**: Parallelizes the build (speeds up compilation).


 - `make install` Installs to  `/opt/glibc/`  with this structure:

	``` 
    /opt/glibc/
    ├── lib/       # Libraries (libc.so, libpthread.so, etc.)
    ├── include/   # Headers
    └── bin/       # Auxiliary tools (ldd, getconf)
	```


### 🧪 Test Installation
Create a wrapper script to run binaries with the custom glibc:

```bash
/opt/glibc/lib/ld-linux-x86-64.so.2 --library-path /opt/glibc/lib ./your_binary
```

You can verify it's using the correct glibc with:

```bash
ldd ./your_binary
```

---
### 🚀  **Using the Custom glibc**

#### **Method 1: Temporary Use (Per-Command)**

```
LD_LIBRARY_PATH=/opt/glibc/lib ./your_program
```
#### **Method 2: Persistent Use (Current Shell)**

```
export LD_LIBRARY_PATH=/opt/glibc/lib:$LD_LIBRARY_PATH ./your_program 
# Now uses the custom glibc
```
#### **Method 3: Patch Binary (Advanced)**

Use  `patchelf`  to hardcode the custom glibc path into a binary:

```
patchelf --set-interpreter /opt/glibc/lib/ld-linux-x86-64.so.2 ./your_program
patchelf --set-rpath /opt/glibc/lib ./your_program
```

### **Method 4: Compiling with custom glibc**

Add linker flags i.e. `--dynamic-linker` and `-rpath` while compiling with gcc using `-Wl`
```bash
gcc -Wl,--dynamic-linker=/opt/glibc/lib/ld-linux-x86-64.so.2 \
    -Wl,-rpath=/opt/glibc/lib \
    your_program.c -o your_program
```


 `--dynamic-linker`:

 - Sets the custom loader path (replaces  `/lib64/ld-linux-x86-64.so.2`)  
  - Equivalent to  `patchelf --set-interpreter`

        
  **`-rpath`**:
    

 - Embeds the custom glibc library path in the binary
  -   Equivalent to  `patchelf --set-rpath`

        

#### **Example**:

```bash
# Compile with custom glibc
gcc -Wl,--dynamic-linker=/opt/glibc/lib/ld-linux-x86-64.so.2 \
    -Wl,-rpath=/opt/glibc/lib \
    hello.c -o hello
```

#### **Verification**:
Check the linked interpreter and libraries:
		`ldd ./hello `



#### **When to Use This Method 4**:

-   For distributing binaries that  **must**  use your custom glibc
    
-   When you want to avoid setting  `LD_LIBRARY_PATH`  every time
    
-   For testing how programs behave with specific glibc versions
    

#### **Note**:

-   The binary becomes  **non-portable**  (fails on systems without the same glibc path)
    
-   Use only for testing/development, not production deployment
---

## ⚠️ Disclaimer

- This project is intended for **educational and research purposes only**.
- These builds are not tested for production environments.
- Do **not** overwrite your system glibc — use containers, chroots, or LD_LIBRARY_PATH for safe testing.

---

## 🧑‍💻 Authors

**Hafiz Muhammad Ahmad**  [GitHub](https://github.com/HMAhmadCS)

**Muhammad Faizan Abbas**  [GitHub](https://github.com/Faizanabbas5655)

**Aurangzeb Hassan**  [GitHub](https://github.com/AurangzebHassan)

**Muhammad Usama Akhtar**  [GitHub](https://github.com/usama090)

---

## 📜 License

This project is subject to the [GNU LGPL v2.1](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html) license from glibc.

---

## 📜 References
- [glibc malloc source](https://sourceware.org/git/?p=glibc.git;a=tree;f=malloc)
- [Safe-Linking Patch (glibc 2.32)](https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=62f03103ebf)
- [Hardened Malloc](https://github.com/GrapheneOS/hardened_malloc)
- [RELRO](https://book.hacktricks.xyz/linux-hardening/relro)
- [Stack Canaries Explained](https://mudongliang.github.io/2017/08/11/stack-canary.html)
