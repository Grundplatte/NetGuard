//
// Created by Markus Feldbacher on 14.01.17.
//

#ifndef NETGUARD_BASE64_H_H
#define NETGUARD_BASE64_H_H

#include <stdint.h>
#include <stdlib.h>

char *base64_encode(const unsigned char *data,
                    size_t input_length,
                    size_t *output_length);

unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length);

void build_decoding_table();

void base64_cleanup();

#endif //NETGUARD_BASE64_H_H
