#pragma once
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_CIPHER_MODE_CTR
#include "mbedtls/aes.h"

int aes_ctr_encrypt(uint8_t* key, uint8_t key_size, uint8_t nonce_counter[16], uint8_t* input, uint8_t input_len, uint8_t* ouput);

