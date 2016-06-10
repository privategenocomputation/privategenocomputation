/*
 This file is part of JustGarble.

 JustGarble is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 JustGarble is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with JustGarble.  If not, see <http://www.gnu.org/licenses/>.

 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <math.h>
#include "../include/justGarble.h"
#include "../gwas/arith.c"
#include "../include/aes.h"
#include "../include/dkcipher.h"

struct ctr_state
{
    unsigned char ivec[AES_BLOCK_SIZE];
    unsigned int num;
    unsigned char ecount[AES_BLOCK_SIZE];
};

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

int main() {
	// CI -> AES PART
    int keylength = 128;
    unsigned char aes_key[keylength/8];
    memset(aes_key, 0, keylength/8);
    struct ctr_state state;

	int inputslength = 10;
	const size_t encslength = ((inputslength + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;

    unsigned char aes_input[inputslength];
    aes_input[0] = 'h';
    aes_input[1] = 'e';
    aes_input[2] = 'l';
    aes_input[3] = 'o';
    aes_input[4] = ' ';
    aes_input[5] = 'i';
    aes_input[6] = 't';
    aes_input[7] = 's';
    aes_input[8] = 'm';
    aes_input[9] = 'e';

    unsigned char zeros[inputslength];
    memset(zeros, (char)0, inputslength);

    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);

    unsigned char enc_out[encslength];
    unsigned char skey[encslength];
    memset(enc_out, 0, sizeof(enc_out));
    memset(skey, 0, sizeof(skey));

    AES_KEY enc_key;
    AES_set_encrypt_key(aes_key, AES_BLOCK_SIZE, &enc_key);

    state.num = 0;
    memset(state.ecount, 0, AES_BLOCK_SIZE);
    memcpy(state.ivec, iv, AES_BLOCK_SIZE);
    AES_ctr128_encrypt(aes_input, enc_out, inputslength, &enc_key, state.ivec, state.ecount, &state.num);

    state.num = 0;
    memset(state.ecount, 0, AES_BLOCK_SIZE);
    memcpy(state.ivec, iv, AES_BLOCK_SIZE);
    AES_ctr128_encrypt(zeros, skey, inputslength, &enc_key, state.ivec, state.ecount, &state.num);
    int i,j;

    //printf("temp:\t");
    //hex_print(temp, sizeof(temp));

    // SPU -> GC building part
	GarbledCircuit garbledCircuit;
	GarblingContext garblingContext;

	int inputsNb = encslength*2*32;
	int wiresNb = 50000;
	int gatesNb = 50000;
	int outputsNb = encslength*32;

	//Create a circuit.
	block labels[2 * inputsNb];
	createInputLabels(labels, inputsNb);
	InputLabels inputLabels = labels;
	createEmptyGarbledCircuit(&garbledCircuit, inputsNb, outputsNb, gatesNb,
			wiresNb, inputLabels);
	startBuilding(&garbledCircuit, &garblingContext);

	int outputs[outputsNb];
	int *inp = (int *) malloc(sizeof(int) * inputsNb);
	countToN(inp, inputsNb);

	XORCircuit(&garbledCircuit, &garblingContext, inputsNb, inp, outputs);

	block *outputbs = (block*) malloc(sizeof(block) * outputsNb);
	OutputMap outputMap = outputbs;
	finishBuilding(&garbledCircuit, &garblingContext, outputMap, outputs);
	garbleCircuit(&garbledCircuit, inputLabels, outputMap);

	// MU -> Evaluation part
	block extractedLabels[inputsNb];

	int extractedInputs[inputsNb];
	chars_into_pointer2(enc_out,skey,encslength,extractedInputs);

	extractLabels(extractedLabels, inputLabels, extractedInputs, inputsNb);
	block computedOutputMap[outputsNb];
	evaluate(&garbledCircuit, extractedLabels, computedOutputMap);
	int outputVals[outputsNb];
	mapOutputs(outputMap, computedOutputMap, outputVals, outputsNb);
	char res[encslength];
	ints_to_chars(outputVals,encslength,res);
	hex_print(res,inputslength);
	return 0;
}

