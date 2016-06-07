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

int *final;

#define AES_CIRCUIT_FILE_NAME "./aesCircuit"

int checkfn(int *a, int *outputs, int n) {
	outputs[0] = a[0] ^ a[1];
	return outputs[0];
}

void print128_num(__m128i var)
{
    uint16_t *val = (uint16_t*) &var;
    printf("Numerical: %i %i %i %i %i %i %i %i \n",
           val[0], val[1], val[2], val[3], val[4], val[5],
           val[6], val[7]);
}

int main() {
	int inputsNb = 16;
	int outputsNb = 8;
	int wiresNb = 24;
	int gatesNb = 8;
	GarbledCircuit garbledCircuit;
	GarblingContext garblingContext;
	block labels[2*inputsNb];


	block *outputbs = (block*) malloc(sizeof(block) * outputsNb);
	OutputMap outputMap = outputbs;
	int outputs[outputsNb];
	int *inp = (int *) malloc(sizeof(int) * inputsNb);
	countToN(inp, inputsNb);
	int b;

	//Create a circuit.
	createInputLabels(labels, inputsNb);
	InputLabels inputLabels = labels;
	createEmptyGarbledCircuit(&garbledCircuit, inputsNb, outputsNb, gatesNb, wiresNb, inputLabels);
	startBuilding(&garbledCircuit, &garblingContext);
	XORCircuit(&garbledCircuit, &garblingContext, 2, inp, outputs);
	finishBuilding(&garbledCircuit, &garblingContext, outputMap, outputs);
	garbleCircuit(&garbledCircuit, inputLabels, outputMap);
	//

	/*block extractedLabels[inputsNb];
	int extractedInputs[inputsNb];
	int input1 = 12;
	int input2 = 16;
	int i;
	for (i = 0; i < 8; i++) {
		extractedInputs[i] = (input1 >> (7-i)) % 2;
	}
	for (i = 8; i < 16; i++) {
		extractedInputs[i] = (input2 >> (7-(i-8))) % 2;
	}
	block computedOutputMap[outputsNb];
	int outputVals[outputsNb];

	extractLabels(extractedLabels, inputLabels, extractedInputs, inputsNb);
	evaluate(&garbledCircuit, extractedLabels, computedOutputMap);
	mapOutputs(outputMap, computedOutputMap, outputVals, outputsNb);

	int res = 0;
	for (i = 0; i < 8; i++) {
		res += outputVals[i]*pow(2,i);
	}*/
	printf("RESULT IS : %d\n", 0);
	return 0;
}

