//
// Created by Markus Feldbacher on 13.01.17.
//

#ifndef NETGUARD_SSL_H
#define NETGUARD_SSL_H

#include <stdbool.h>
#include <sys/cdefs.h>
#include <sys/types.h>
#include <endian.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include "base64.h"

// Content types
#define CTYPE_CHANGE_CIPHER_SPEC 0x14
#define CTYPE_ALERT 0x15
#define CTYPE_HANDSHAKE 0x16
#define CTYPE_APPLICATION_DATA 0x17

// Handshake
#define HTYPE_HELLO_REQ 0x00
#define HTYPE_CLT_HELLO 0x01
#define HTYPE_SRV_HELLO 0x02
#define HTYPE_CERT 0x0b
#define HTYPE_SRV_KEY_EX 0x0c
#define HTYPE_CERT_REQ 0x0d
#define HTYPE_SRV_HELLO_DONE 0x0e
#define HTYPE_CERT_VERIFY 0x0f
#define HTYPE_CLT_KEY_EX 0x10
#define HTYPE_FIN 0x14

// TLS Versions
#define TLS_1_0 0x0301
#define TLS_1_1 0x0302
#define TLS_1_2 0x0303

// Alert severity
#define ALRT_WARN 0x01
#define ALRT_FATAL 0x02

struct sslhdr {
    __u8 type;
    __u16 version;
    __u16 length;
} __packed;

struct sslhnd {
    __u8 type;
    __u8 length[3];
} __packed;

struct sslData {
    __u16 version; // 1 = client hello
    __u8 ctype;
    __u8 htype; // TLS-Version
    __u16 cipher;
    __u16 hash;
};

bool is_valid_ssl_hdr(struct sslhdr * sslhdr);
uint16_t getCipherSuite(uint8_t * data);
void analyze_ssl(uint8_t *data, const size_t datalength, struct sslData *sslData);

#endif //NETGUARD_SSL_H
