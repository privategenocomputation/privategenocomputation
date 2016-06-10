#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/aes.h"
#include "../include/dkcipher.h"

struct ctr_state
{
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned int num;
    unsigned char ecount[AES_BLOCK_SIZE];
};
struct ctr_state state;

// a simple hex-print routine. could be modified to print 16 bytes-per-line
static void hex_print(const void* pv, size_t len)
{
    const unsigned char * p = (const unsigned char*)pv;
    if (NULL == pv)
        printf("NULL");
    else
    {
        size_t i = 0;
        for (; i<len;++i)
            printf("%c", *p++);
    }
    printf("\n");
}

// main entrypoint
int main(int argc, char **argv)
{
	// 128, 192 or 256
    int keylength = 128;
    /* generate a key with a given length */
    unsigned char aes_key[keylength/8];
    memset(aes_key, 0, keylength/8);


    size_t inputslength = 5;

    /* generate input with a given length */
    unsigned char aes_input[inputslength];
    aes_input[0] = 'h';
    aes_input[1] = 'a';
    aes_input[2] = 'l';
    aes_input[3] = 'l';
    aes_input[4] = 'o';

    unsigned char zeros[inputslength];
    memset(zeros, (char)0, inputslength);

    /* init vector */
    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);

    // buffers for encryption and decryption
    const size_t encslength = ((inputslength + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    unsigned char enc_out[encslength];
    unsigned char skey[encslength];
    //unsigned char dec_out[inputslength];
    memset(enc_out, 0, sizeof(enc_out));
    memset(skey, 0, sizeof(skey));
    //memset(dec_out, 0, sizeof(dec_out));

    // so i can do with this aes-cbc-128 aes-cbc-192 aes-cbc-256
    AES_KEY enc_key;
    AES_set_encrypt_key(aes_key, 16, &enc_key);

    state.num = 0;
    memset(state.ecount, 0, AES_BLOCK_SIZE);
    memcpy(state.ivec, iv, AES_BLOCK_SIZE);
    AES_ctr128_encrypt(aes_input, enc_out, inputslength, &enc_key, state.ivec, state.ecount, &state.num);

    state.num = 0;
    memset(state.ecount, 0, AES_BLOCK_SIZE);
    memcpy(state.ivec, iv, AES_BLOCK_SIZE);
    AES_ctr128_encrypt(zeros, skey, inputslength, &enc_key, state.ivec, state.ecount, &state.num);


    printf("cipher text:\t");
    hex_print(aes_input, sizeof(aes_input));

    printf("skey:\t");
    hex_print(skey, sizeof(enc_out));

    unsigned char res[inputslength];
    int i;
    for(i=0; i<inputslength;i++) {
    	res[i] = enc_out[i] ^ skey[i];
    }

    printf("res:\t");
    hex_print(res, sizeof(res));

    return 0;
}
