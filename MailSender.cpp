#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

//#include <IdSMTP.hpp>
//#include <IdMessage.hpp>
//#include <IdSSLOpenSSL.hpp>

SSL_CTX* init_ssl_ctx() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD* method = TLS_client_method(); // TLS 1.2 ÀÌ»ף
    return SSL_CTX_new(method);
}

SSL* connect_to_gmail_tls(SSL_CTX* ctx) {
    BIO* bio = BIO_new_ssl_connect(ctx);
    BIO_set_conn_hostname(bio, "smtp.gmail.com:465");

    SSL* ssl = nullptr;
    BIO_get_ssl(bio, &ssl);
    if (!ssl) {
        std::cerr << "Failed to get SSL object\n";
        return nullptr;
    }

    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    if (BIO_do_connect(bio) <= 0) {
        std::cerr << "Connection failed\n";
        return nullptr;
    }

    return ssl;
}

