#ifndef __MAIL_SENDER_H__
#define __MAIL_SENDER_H__

SSL_CTX* init_ssl_ctx();
SSL* connect_to_gmail_tls(SSL_CTX* ctx);

#endif