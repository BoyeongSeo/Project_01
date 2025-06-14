#ifndef SECURE_LOGGER_H
#define SECURE_LOGGER_H

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
const int KEY_SIZE = 32;
const int IV_SIZE = 12;
const int TAG_SIZE = 16;

bool set_aes_key(const BYTE* key_data, size_t key_len);
const BYTE* get_aes_key();

extern bool is_valid_aes_key_string(const String &hexStr);
extern bool hex_string_to_aes_key(const String &hexStr, BYTE out_key[KEY_SIZE]);

extern bool encrypt_aes256_gcm(const std::string &plaintext,
    std::string &iv_hex, std::string &tag_hex, std::string &cipher_hex);
extern bool decrypt_aes256_gcm(const std::vector<BYTE> &iv,
    const std::vector<BYTE> &tag, const std::vector<BYTE> &ciphertext,
    std::string &plaintext_out);
extern String DecryptEncryptedLine(const String &encryptedLine);
class SecureLogger
{
  public:
    SecureLogger();
    ~SecureLogger();

    void info(const std::string &message);
    void error(const std::string &message);
    void db(const std::string &message);
    void check_log_integrity();
  private:
    std::string current_date;
    std::ofstream log_file;
    std::string session_log_filename;

    void open_new_file_if_needed();
    void write_log(const std::string &log_level, const std::string &message);
    void create_log_checksum();
};

#endif // SECURE_LOGGER_H

