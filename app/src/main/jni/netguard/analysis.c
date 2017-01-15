//
// Created by Markus on 14.12.2016.
//

#include "netguard.h"

//TODO: use shit


// search for different strings like IMEI, IMSI, "password", etc.
bool analyse_payload(const uint8_t *buffer, size_t length)
{
    uint8_t *end = buffer + length;

    for(int i=0; i < length; i++){
        uint8_t *start = buffer;
        while(false) {

        }
    }

    return false;
}