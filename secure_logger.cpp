// --- SecureLogger class ---
#include "secure_logger.h"

#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <ctime>
#include <memory>
#include <stdexcept>
#include <mutex>
#include <cctype>

#pragma comment(lib, "bcrypt")
#pragma comment(lib, "crypt32")
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

static BYTE g_aesKey[KEY_SIZE];
static bool g_keySet = false;
static std::mutex g_keyMutex;

std::string current_datetime_filename()
{
    time_t now = time(nullptr);
    struct tm t;
    localtime_s(&t, &now);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y%m%d_%H%M%S", &t);
    return std::string(buf);
}

std::string current_timestamp()
{
    time_t now = time(nullptr);
    struct tm t;
    localtime_s(&t, &now);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &t);
    return std::string(buf);
}

std::string to_hex(const BYTE* data, DWORD len)
{
    std::ostringstream oss;
    for (DWORD i = 0; i < len; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    return oss.str();
}

std::vector<BYTE> hex_to_bytes(const std::string &hex)
{
    std::vector<BYTE> bytes;
    for (size_t i = 0; i < hex.length(); i += 2)
        bytes.push_back((BYTE)strtol(hex.substr(i, 2).c_str(), nullptr, 16));
    return bytes;
}
bool is_valid_aes_key_string(const String &hexStr)
{
    if (hexStr.Length() != KEY_SIZE * 2)
        return false;

    AnsiString ansi = UTF8Encode(hexStr);
    for (int i = 1; i <= ansi.Length(); ++i) { // 1-based index in AnsiString
        if (!std::isxdigit(static_cast<unsigned char>(ansi[i])))
            return false;
    }

    return true;
}

// Convert 64-character hex String to BYTE[32]
bool hex_string_to_aes_key(const String &hexStr, BYTE out_key[KEY_SIZE])
{
    if (!is_valid_aes_key_string(hexStr))
        return false;

    AnsiString ansi = UTF8Encode(hexStr);
    for (size_t i = 0; i < KEY_SIZE; ++i) {
        char byte_chars[3] = { ansi[i * 2 + 1], ansi[i * 2 + 2],
            '\0' }; // AnsiString is 1-based
        out_key[i] = static_cast<BYTE>(std::strtoul(byte_chars, nullptr, 16));
    }

    return true;
}

bool set_aes_key(const BYTE* key_data, size_t key_len)
{
    if (!key_data || key_len != KEY_SIZE)
        return false;

    std::lock_guard<std::mutex> lock(g_keyMutex);
    memcpy(g_aesKey, key_data, KEY_SIZE);
    g_keySet = true;
    return true;
}

const BYTE* get_aes_key()
{
    std::lock_guard<std::mutex> lock(g_keyMutex);
    return g_keySet ? g_aesKey : nullptr;
}

bool encrypt_aes256_gcm(const std::string &plaintext, std::string &iv_hex,
    std::string &tag_hex, std::string &cipher_hex)
{
    const BYTE* aesKey = get_aes_key();
    if (!aesKey)
        return false; // AES key not set

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    DWORD cbKeyObject = 0, cbData = 0, cbCipherText = 0;
    PBYTE pbKeyObject = nullptr;
    BYTE iv[IV_SIZE], tag[TAG_SIZE];

    // Allocate memory for ciphertext using smart pointer
    std::unique_ptr<BYTE[]> cipherText(new BYTE[plaintext.size()]);
    if (!cipherText)
        return false;

    // Open the AES algorithm provider
    if (!NT_SUCCESS(
            BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0)))
        return false;

    // Set the algorithm to use GCM (Galois/Counter Mode)
    if (!NT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0)))
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // Get the size required for the key object buffer
    if (!NT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
            (PUCHAR)&cbKeyObject, sizeof(DWORD), &cbData, 0)))
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // Allocate key object memory
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (!pbKeyObject) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // Generate a symmetric key using the global AES key
    if (!NT_SUCCESS(BCryptGenerateSymmetricKey(
            hAlg, &hKey, pbKeyObject, cbKeyObject, g_aesKey, KEY_SIZE, 0)))
    {
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // Generate a random IV (nonce)
    if (!NT_SUCCESS(BCryptGenRandom(
            NULL, iv, IV_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
    {
        BCryptDestroyKey(hKey);
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // Prepare authenticated cipher mode info (GCM)
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = iv;
    authInfo.cbNonce = IV_SIZE;
    authInfo.cbTag = TAG_SIZE;
    authInfo.pbTag = tag;

    // Perform AES-GCM encryption
    if (!NT_SUCCESS(BCryptEncrypt(hKey, (PUCHAR)plaintext.data(),
            (ULONG)plaintext.length(), &authInfo, NULL, 0, cipherText.get(),
            (ULONG)plaintext.length(), &cbCipherText, 0)))
    {
        BCryptDestroyKey(hKey);
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // Convert IV, tag, and ciphertext to hex strings for storage
    iv_hex = to_hex(iv, IV_SIZE);
    tag_hex = to_hex(tag, TAG_SIZE);
    cipher_hex = to_hex(cipherText.get(), cbCipherText);

    // Cleanup
    BCryptDestroyKey(hKey);
    HeapFree(GetProcessHeap(), 0, pbKeyObject);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return true;
}

bool decrypt_aes256_gcm(const std::vector<BYTE> &iv,
    const std::vector<BYTE> &tag, const std::vector<BYTE> &ciphertext,
    std::string &plaintext_out)
{
    const BYTE* aesKey = get_aes_key();
    if (!aesKey)
        return false; // AES key not set

    if (iv.size() != IV_SIZE || tag.size() != TAG_SIZE || ciphertext.empty())
        return false;

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    PBYTE pbKeyObject = nullptr;
    DWORD cbKeyObject = 0, cbData = 0, cbPlaintext = 0;
    NTSTATUS status;

    std::vector<BYTE> plaintext(ciphertext.size());

    // Open AES algorithm provider
    if (!NT_SUCCESS(
            BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0)))
        return false;

    // Set chaining mode to GCM
    if (!NT_SUCCESS(BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0)))
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // Get size of key object
    if (!NT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
            (PUCHAR)&cbKeyObject, sizeof(DWORD), &cbData, 0)))
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // Allocate memory for key object
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (!pbKeyObject) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // Generate symmetric key
    if (!NT_SUCCESS(BCryptGenerateSymmetricKey(
            hAlg, &hKey, pbKeyObject, cbKeyObject, g_aesKey, KEY_SIZE, 0)))
    {
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // Prepare GCM authentication info
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)iv.data();
    authInfo.cbNonce = (ULONG)iv.size();
    authInfo.pbTag = (PUCHAR)tag.data();
    authInfo.cbTag = (ULONG)tag.size();

    // Perform decryption
    status = BCryptDecrypt(hKey, (PUCHAR)ciphertext.data(),
        (ULONG)ciphertext.size(), &authInfo, NULL, 0, plaintext.data(),
        (ULONG)plaintext.size(), &cbPlaintext, 0);

    // Cleanup resources
    if (pbKeyObject)
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    if (hKey)
        BCryptDestroyKey(hKey);
    if (hAlg)
        BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!NT_SUCCESS(status))
        return false;

    plaintext_out.assign(plaintext.begin(), plaintext.begin() + cbPlaintext);
    return true;
}

// Decrypt a single line in format: iv_hex|tag_hex|cipher_hex
String DecryptEncryptedLine(const String &encryptedLine)
{
    // if the input is empty, return an empty string
    if (encryptedLine.IsEmpty()) {
        return "";
    }

    std::string encoded = AnsiString(encryptedLine).c_str();

    size_t pos1 = encoded.find("|");
    size_t pos2 = encoded.find("|", pos1 + 1);

    if (pos1 == std::string::npos || pos2 == std::string::npos) {
        ShowMessage("Malformed encrypted line");
        return "";
    }

    std::string iv_hex = encoded.substr(0, pos1);
    std::string tag_hex = encoded.substr(pos1 + 1, pos2 - pos1 - 1);
    std::string cipher_hex = encoded.substr(pos2 + 1);

    std::vector<BYTE> iv = hex_to_bytes(iv_hex);
    std::vector<BYTE> tag = hex_to_bytes(tag_hex);
    std::vector<BYTE> cipher = hex_to_bytes(cipher_hex);

    std::string decrypted;
    if (!decrypt_aes256_gcm(iv, tag, cipher, decrypted)) {
        ShowMessage("Decryption failed");
        return "";
    }

    return String(decrypted.c_str());
}

SecureLogger::SecureLogger()
{
    session_log_filename = "log-" + current_datetime_filename() + ".enc";
    log_file.open(session_log_filename, std::ios::app);
}

SecureLogger::~SecureLogger()
{
    try {
        if (log_file.is_open()) {
            check_log_integrity();
            log_file.flush();
            log_file.close();
        }

        create_log_checksum();
    } catch (const std::exception &ex) {
        this->error(
            "Exception in SecureLogger destructor: " + std::string(ex.what()));
    } catch (...) {
        this->error("Unknown exception occurred in SecureLogger destructor.");
    }
}

void SecureLogger::create_log_checksum()
{
    try {
        std::ifstream in(session_log_filename, std::ios::binary);
        if (!in.is_open()) {
            this->error("Failed to open log file for checksum: " +
                        session_log_filename);
            return;
        }

        std::ostringstream oss;
        oss << in.rdbuf();
        std::string data = oss.str();
        in.close();

        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        BYTE hash[32];
        DWORD hashLen = sizeof(hash);

        if (!CryptAcquireContext(
                &hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            this->error("CryptAcquireContext failed for checksum.");
            return;
        }

        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            this->error("CryptCreateHash failed.");
            CryptReleaseContext(hProv, 0);
            return;
        }

        if (!CryptHashData(hHash, (BYTE*)data.data(), data.size(), 0)) {
            this->error("CryptHashData failed.");
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return;
        }

        if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
            this->error("CryptGetHashParam failed.");
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return;
        }

        std::ofstream sig(session_log_filename + ".sha256");
        if (!sig.is_open()) {
            this->error("Failed to create checksum file.");
        } else {
            sig << to_hex(hash, hashLen);
            sig.close();
        }

        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
    } catch (const std::exception &ex) {
        this->error(
            "Exception in create_log_checksum: " + std::string(ex.what()));
    } catch (...) {
        this->error("Unknown exception occurred in create_log_checksum.");
    }
}

void SecureLogger::check_log_integrity()
{
    try {
        std::ifstream reader(session_log_filename);
        if (!reader.is_open()) {
            this->error("Failed to open log file: " + session_log_filename);
            return;
        }

        std::string line;
        int line_num = 0;
        int sum = 0;
        while (std::getline(reader, line)) {
            sum++;
        }
        reader.clear(); // Clear EOF flag
        reader.seekg(0, std::ios::beg); // Reset stream to beginning
        
        while (line_num < sum && std::getline(reader, line)) {
            line_num++;
            std::istringstream iss(line);
            std::string timestamp, level, iv_hex, tag_hex, cipher_hex, message;

            std::getline(iss, timestamp, '|');
            std::getline(iss, level, '|');
            std::getline(iss, iv_hex, '|');
            std::getline(iss, tag_hex, '|');
            std::getline(iss, cipher_hex, '|');
            std::getline(iss, message); // may contain delimiter

            auto iv = hex_to_bytes(iv_hex);
            auto tag = hex_to_bytes(tag_hex);
            auto cipher = hex_to_bytes(cipher_hex);

            std::string decrypted;
            bool success = decrypt_aes256_gcm(iv, tag, cipher, decrypted);
            if (!success) {
                this->error(
                    "Decryption failed at line " + std::to_string(line_num));
            } else if (decrypted != message) {
                printf("Decrypted message does not match original at line %d\n",
                    line_num);
                this->error("Decrypted message does not match at line " +
                            std::to_string(line_num) + ": \"" + decrypted +
                            "\" (original) != \"" + message + "\" (modified)");
            }
        }

        reader.close();
    } catch (const std::exception &ex) {
        this->error(
            "Exception during log integrity check: " + std::string(ex.what()));
    } catch (...) {
        this->error("Unknown exception occurred during log integrity check.");
    }
}

void SecureLogger::write_log(
    const std::string &log_level, const std::string &message)
{
    std::string iv_hex, tag_hex, cipher_hex;
    if (encrypt_aes256_gcm(message, iv_hex, tag_hex, cipher_hex)) {
        log_file << current_timestamp() << "|" << log_level << "|" << iv_hex
                 << "|" << tag_hex << "|" << cipher_hex << "|" << message
                 << std::endl;
        log_file.flush();
    } else {
        std::cerr << "Encryption failed: " << message << "\n";
    }
}

void SecureLogger::info(const std::string &message)
{
    write_log("INFO", message);
    printf("INFO: %s\n", message.c_str()); // for testing on console output
}

void SecureLogger::error(const std::string &message)
{
    write_log("ERROR", message);
    printf("ERROR: %s\n", message.c_str()); // for testing on console output
}

void SecureLogger::db(const std::string &message)
{
    write_log("DEBUG", message);
    printf("DEBUG: %s\n", message.c_str()); // for testing on console output
}

