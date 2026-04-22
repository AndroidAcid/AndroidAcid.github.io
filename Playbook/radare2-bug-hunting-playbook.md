# Radare2 Bug Hunting Playbook

## Install

```bash
# From source (always fresher than packages)
git clone https://github.com/radareorg/radare2
cd radare2 && sys/install.sh

# Or via pip wrapper
pip install r2pipe
```

---

## Essential Commands Cheatsheet

```
?           help for any command (append to any command)
i           binary info
iI          imports
iE          exports
is          symbols
ii          libraries
iz          strings in data section
izz         strings everywhere
aa          analyze all (auto-detect functions)
aaa         deeper analysis (includes XREF, types, varflags)
afl         list all functions
pdf @sym.main   disassemble function
VV          visual graph mode
V!          visual panels mode (multi-pane)
s <addr>    seek to address
/           search
q           quit
```

---

## 1. Initial Recon

```bash
r2 target_binary
```

```
[0x00400000]> iI        # architecture, bits, canary, nx, pic, stripped
[0x00400000]> i         # full info block
[0x00400000]> ii        # imported libs and functions
[0x00400000]> iE        # exported symbols (useful for shared libs)
[0x00400000]> iz        # strings in .rodata — URLs, error messages, crypto hints
[0x00400000]> izz       # all strings including stack/heap artifacts in binary
```

Look for:
- `canary: false` → no stack cookie, classic stack overflow exploitable
- `nx: false` → no DEP, shellcode in stack is executable
- `pic: false` → no ASLR (fixed addresses, no need for leak)
- `stripped: true` → no symbols, harder but still doable

---

## 2. Load with Analysis

```bash
r2 -A target_binary     # equivalent to running aaa on entry
r2 -d target_binary     # attach debugger
r2 -D gdb target_binary # use GDB backend
```

```
[0x00400000]> aaa       # full analysis
[0x00400000]> afl       # list all found functions
[0x00400000]> afl | grep -i "main\|init\|parse\|read\|recv\|handle"
```

---

## 3. Find Dangerous Functions

```bash
# Search imports for known-dangerous libc functions
[0x00400000]> ii | grep -E "gets|strcpy|strcat|sprintf|scanf|recv|read|memcpy|memmove|system|popen|exec"
```

Each hit is a potential bug entry point. Seek to the PLT stub and find all callers:

```
[0x00400000]> axt sym.imp.gets     # find all XREFs to gets
[0x00400000]> pdf @<caller_addr>   # disassemble the calling function
```

---

## 4. Disassemble and Navigate

```bash
[0x00400000]> s main               # seek to main
[0x00400000]> pdf                  # print disassembly of function at current position
[0x00400000]> pdc                  # decompile to C-like pseudocode (with r2dec plugin)
[0x00400000]> pdg                  # decompile with Ghidra plugin (r2ghidra)
```

Install decompiler plugins:
```bash
r2pm -ci r2dec        # C pseudocode
r2pm -ci r2ghidra     # Ghidra decompiler backend
```

---

## 5. Visual Mode — Navigate Like a Human

```
[0x00400000]> VV       # control flow graph — use hjkl or arrows to move
                       # p = toggle between disasm/annotated/bytes
                       # u = undo seek
                       # q = back to prompt
```

```
[0x00400000]> V!       # multi-panel: disasm + stack + registers + hex
                       # Tab = switch panels
                       # : = enter command while in visual
```

---

## 6. Search for Patterns

```bash
# Find string references
[0x00400000]> / password
[0x00400000]> / http://

# Find byte sequences
[0x00400000]> /x 4889e5        # prologue bytes
[0x00400000]> /x 0f05          # syscall instruction (x86_64)
[0x00400000]> /x cd80          # int 0x80 (x86 syscall)

# Find ROP gadgets
[0x00400000]> /R pop rdi       # find all "pop rdi; ret" gadgets
[0x00400000]> /R/ ret          # all ret gadgets
```

---

## 7. Debug and Trace

```bash
r2 -d ./target_binary arg1 arg2
```

```
[0x00400000]> doo arg1 arg2    # reopen with args
[0x00400000]> db sym.main      # breakpoint at main
[0x00400000]> dc               # continue
[0x00400000]> ds               # step instruction
[0x00400000]> dso              # step over call
[0x00400000]> dr               # show all registers
[0x00400000]> dr rsp           # single register
[0x00400000]> px 64 @rsp       # hexdump 64 bytes at stack pointer
[0x00400000]> dbt              # backtrace
[0x00400000]> dmm              # memory maps
```

---

## 8. Stack Overflow — Find and Measure

```
[0x00400000]> pdf @sym.vuln_func   # disassemble target function
```

Look for:
```asm
push rbp
mov rbp, rsp
sub rsp, 0x40          ← buffer size is 0x40 (64 bytes)
lea rax, [rbp-0x40]
mov rdi, rax
call sym.imp.gets      ← unbounded read into 64-byte buffer
```

Calculate offset to return address:
```
buffer_start = rbp - 0x40
return_addr  = rbp + 0x8      (on x86_64: saved rbp=8, then ret addr)
offset       = 0x40 + 0x8 = 72 bytes
```

Verify in debugger:
```
[0x00400000]> db 0x<addr_after_gets>
[0x00400000]> dc
# send "AAAAAAAA..." * 80 as input
[0x00400000]> dr rsp
[0x00400000]> pxq 32 @rsp       # see what return address is now
```

---

## 9. Format String Bugs

```bash
# Find printf/fprintf/syslog with user-controlled first arg
[0x00400000]> axt sym.imp.printf
# Check each caller: is the first argument (rdi on x86_64) a writable buffer?
```

Test manually:
```bash
./target "%p.%p.%p.%p"          # leaks stack addresses
./target "%n"                   # may crash (write primitive)
./target "AAAA%7$n"             # write 4 to 7th argument on stack
```

In r2 debugger:
```
[0x00400000]> db @sym.imp.printf
[0x00400000]> dc
# on hit, check rdi:
[0x00400000]> psz @rdi          # print string at rdi — is it user input?
```

---

## 10. Heap Analysis

```bash
r2 -d ./target
[0x00400000]> dm              # list memory regions
[0x00400000]> dmh             # dump heap (requires MALLOC_CHECK_ or glibc debug)
```

Hook allocations with r2pipe:
```python
import r2pipe
r2 = r2pipe.open('./target', flags=['-d'])
r2.cmd('doo')
r2.cmd('db sym.imp.malloc')
r2.cmd('dc')
# on hit: check rdi (size arg)
size = r2.cmd('dr rdi')
print(f'malloc({size})')
r2.cmd('dc')
```

Look for:
- `free(ptr)` twice → use-after-free or double-free
- `malloc(user_controlled_size)` → integer overflow before malloc → heap overflow
- Write after `free()` without re-malloc → UAF write

---

## 11. Integer Overflow → Buffer Overflow

```
# Pattern: size is user-controlled, multiplied, then passed to malloc
mov esi, [user_input]
imul esi, 4           ← if user_input > 0x3fffffff → overflows to small number
mov edi, esi
call malloc           ← allocates tiny buffer
mov [heap_ptr], rax
# then copies user_input * 4 bytes in
```

Find these in r2:
```
[0x00400000]> /a imul       # find all imul instructions
```

Seek to each one and check if the result feeds into malloc.

---

## 12. Use r2pipe for Automated Scanning

```python
#!/usr/bin/env python3
import r2pipe, sys

DANGEROUS = ['gets','strcpy','strcat','sprintf','vsprintf',
             'scanf','fscanf','system','popen','execve','memcpy']

r2 = r2pipe.open(sys.argv[1])
r2.cmd('aaa')

imports = r2.cmdj('iij')  # imports as JSON
hits = [i for i in imports if i.get('name','').replace('sym.imp.','') in DANGEROUS]

for h in hits:
    name = h['name']
    addr = h['plt']
    print(f'\n[!] {name} @ {hex(addr)}')
    xrefs = r2.cmdj(f'axtj @ {hex(addr)}')
    for x in xrefs:
        caller = x.get('fcn_name', '?')
        call_addr = hex(x.get('from', 0))
        print(f'    called from {caller} @ {call_addr}')
        # print disassembly of caller
        print(r2.cmd(f'pdf @ {caller}'))
```

```bash
python3 scan.py ./target 2>&1 | less
```

---

## 13. Find ROP Gadgets for Exploit Chain

```bash
# Built-in gadget search
[0x00400000]> /R pop rdi
[0x00400000]> /R pop rsi
[0x00400000]> /R pop rdx
[0x00400000]> /R ret          # stack alignment gadget

# Save gadget addresses
[0x00400000]> /R pop rdi > /tmp/gadgets.txt
```

Or use ropper (faster for large binaries):
```bash
ropper --file ./target --search "pop rdi"
```

---

## 14. Patch and Re-test

```bash
# Open in write mode
r2 -w ./target_binary

# NOP out a check
[0x00400000]> s 0x<check_addr>
[0x00400000]> wa nop nop nop nop nop   # assemble NOPs in place
[0x00400000]> pd 5                      # verify

# Replace a conditional jump
[0x00400000]> wa jmp 0x<target>        # force unconditional jump

# Write raw bytes
[0x00400000]> wx 909090                # 3 NOPs
```

---

## 15. Android Native Library Analysis

```bash
# Extract .so from APK
unzip -o target.apk lib/x86_64/libtarget.so -d /tmp/apk_out/

r2 /tmp/apk_out/lib/x86_64/libtarget.so
```

```
[0x00000000]> aaa
[0x00000000]> iE | grep -i "Java_"    # JNI exported functions — all reachable from Java
[0x00000000]> s sym.Java_com_example_MyClass_nativeMethod
[0x00000000]> pdf
```

JNI function signature:
```c
// First two args are always: JNIEnv* env, jobject thiz
// Extra args = Java call args
// rdi = JNIEnv*, rsi = jobject, rdx = first Java arg
```

Look for native heap overflows, format strings, or command injection in `system()`/`popen()` calls with Java-supplied strings.

---

## Workflow Summary

```
1. r2 -A ./binary              → recon + analysis
2. ii | grep <dangerous funcs> → find attack surface
3. axt sym.imp.<func>          → trace callers
4. pdf @<caller>               → read disassembly
5. pdc / pdg                   → decompile to C
6. Measure buffer offsets       → calculate overflow padding
7. /R pop rdi ; /R ret         → build ROP chain if needed
8. r2 -d + breakpoints         → verify in debugger
9. Write exploit / fuzzer      → confirm with crash
```

---

## Quick Reference

| Goal | Command |
|------|---------|
| Binary metadata | `iI` |
| All strings | `izz` |
| Dangerous imports | `ii \| grep gets` |
| Callers of function | `axt sym.imp.gets` |
| Disassemble function | `pdf @sym.main` |
| Decompile | `pdc` or `pdg` |
| Control flow graph | `VV` |
| Set breakpoint | `db <addr>` |
| Continue | `dc` |
| Step | `ds` |
| Registers | `dr` |
| Stack dump | `px 64 @rsp` |
| ROP gadgets | `/R pop rdi` |
| Patch bytes | `wx 9090 @<addr>` |
| Automate | `r2pipe` Python |
