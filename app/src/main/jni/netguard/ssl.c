//
// Created by Markus Feldbacher on 13.01.17.
//

#include "ssl.h"
#include "netguard.h"

bool is_valid_ssl_hdr(struct sslhdr *sslhdr) {
    if(ntohs(sslhdr->version) != TLS_1_0 && ntohs(sslhdr->version) != TLS_1_1 && ntohs(sslhdr->version) != TLS_1_2) {
        return false;
    }

    if(sslhdr->type != CTYPE_HANDSHAKE && sslhdr->type != CTYPE_APPLICATION_DATA &&
            sslhdr->type != CTYPE_ALERT && sslhdr->type != CTYPE_CHANGE_CIPHER_SPEC) {
        return false;
    }

    return true;
}

uint16_t getCipherSuite(uint8_t *data) {
    //Server Hello
    // 0: type
    // 1-3: length
    // 4/5: tls version
    // 6-37: 32 byte random
    // 38: sessid length
    // 39+: sessid
    // xxx: 2 byte, cipher suite

    uint8_t sessid_length = *(data + 38);
    uint16_t cipher_suite = ntohs(*((u_int16_t *)(data + 39 + sessid_length)));

    return cipher_suite;
}

// only call
void analyze_ssl(uint8_t *data, const size_t datalength, struct sslData *sslData) {
        // check if its a TLS packet

        struct sslhdr *sslhdr = (struct sslhdr *) data;
        if(is_valid_ssl_hdr(sslhdr)) {

            //sslData->version = ntohs(sslhdr->version);
            sslData->ctype = sslhdr->type;

            switch(sslhdr->type) {
                case CTYPE_HANDSHAKE:
                    log_android(ANDROID_LOG_DEBUG, "TLS Handshake");

                    const uint8_t *hdata = data + sizeof(struct sslhdr);
                    struct sslhnd *handshake = (struct sslhnd *) (hdata);

                    sslData->htype = handshake->type;

                    switch(handshake->type) {
                        case HTYPE_CLT_HELLO:
                            sslData->version = ntohs(*((u_int16_t *)(hdata + sizeof(struct sslhnd))));
                            log_android(ANDROID_LOG_DEBUG, "Client Hello: version 0x%x", sslData->version);
                            break;

                        case HTYPE_SRV_HELLO:
                            sslData->version = ntohs(*((u_int16_t *)(hdata + sizeof(struct sslhnd))));
                            sslData->cipher = getCipherSuite(hdata);
                            log_android(ANDROID_LOG_DEBUG, "Server Hello: cipher 0x%x version 0x%x",
                                        sslData->cipher, sslData->version);
                            break;

                        case HTYPE_SRV_HELLO_DONE:
                            log_android(ANDROID_LOG_DEBUG, "Server Done");
                            break;

                        case HTYPE_CERT:
                            log_android(ANDROID_LOG_DEBUG, "Cert");
                            break;

                        case HTYPE_SRV_KEY_EX:
                            log_android(ANDROID_LOG_DEBUG, "Server Key Exchange");
                            break;

                        case HTYPE_CLT_KEY_EX:
                            log_android(ANDROID_LOG_DEBUG, "Client Kex Exchange");
                            break;

                        default:
                            log_android(ANDROID_LOG_DEBUG, "2 ERROR!");
                    }
                    break;

                case CTYPE_CHANGE_CIPHER_SPEC:
                    log_android(ANDROID_LOG_DEBUG, "CHANGE CIPHER SPEC");
                    break;

                case CTYPE_APPLICATION_DATA:
                    log_android(ANDROID_LOG_DEBUG, "App Data");
                    break;

                case CTYPE_ALERT:
                    log_android(ANDROID_LOG_DEBUG, "Alert");
                    break;
            }
        }
}