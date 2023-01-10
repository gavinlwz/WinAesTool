#include "pch.h"
#include "AesWrapper.h"

int aes_ctr_encrypt(uint8_t* key, uint8_t key_size, uint8_t nonce_counter[16], uint8_t* input, uint8_t input_len, uint8_t* ouput)
{
	size_t nc_off = 0;
	uint8_t block[16] = {0};
	mbedtls_aes_context ctx;
	mbedtls_aes_init(&ctx);
	mbedtls_aes_setkey_enc(&ctx, key, key_size * 8);

	int ret = mbedtls_aes_crypt_ctr(&ctx, input_len, &nc_off, nonce_counter, block, input, ouput);
	return ret;
}

int aes_ctr_decrypt(uint8_t* key, uint8_t key_size, uint8_t nonce_counter[16], uint8_t* input, uint8_t input_len, uint8_t* ouput)
{
	size_t nc_off = 0;
	uint8_t block[16] = { 0 };
	mbedtls_aes_context ctx;
	mbedtls_aes_init(&ctx);
	mbedtls_aes_setkey_dec(&ctx, key, key_size * 8);

	int ret = mbedtls_aes_crypt_ctr(&ctx, input_len, &nc_off, nonce_counter, block, input, ouput);
	return ret;
}
