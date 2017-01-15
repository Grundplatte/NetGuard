//
// Created by Markus Feldbacher on 13.01.17.
//

#include "ssl.h"
#include "netguard.h"

bool is_valid_ssl_hdr(struct sslhdr * sslhdr) {
    if(ntohs(sslhdr->version) != TLS_1_0 && ntohs(sslhdr->version) != TLS_1_1 && ntohs(sslhdr->version) != TLS_1_2) {
        return false;
    }

    if(sslhdr->type != CTYPE_HANDSHAKE && sslhdr->type != CTYPE_APPLICATION_DATA &&
            sslhdr->type != CTYPE_ALERT && sslhdr->type != CTYPE_CHANGE_CIPHER_SPEC) {
        return false;
    }

    return true;
}

uint16_t getCipherSuite(uint8_t * data) {
    //Server Hello
    // 0: type
    // 1-3: length
    // 5/6: tls version
    // 7-39: 32 byte random
    // 40: sessid length
    // 41+: sessid
    // xxx: 2 byte, cipher suite

    uint8_t sessid_length = *(data + 40);
    uint16_t cipher_suite = ntohs(*(data + 40 + sessid_length));

    return cipher_suite;
}