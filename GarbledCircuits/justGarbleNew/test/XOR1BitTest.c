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
	int inputsNb = 2;
	int outputsNb = 1;
	int wiresNb = 4;
	int gatesNb = 1;
	GarbledCircuit garbledCircuit;
	GarblingContext garblingContext;
	block labels[2*inputsNb];


	block *outputbs = (block*) malloc(sizeof(block) * outputsNb);
	OutputMap outputMap = outputbs;
	int outputs[1];
	int *inp = (int *) malloc(sizeof(int) * inputsNb);
	countToN(inp, inputsNb);
	int b;
	/*for (b = 0; b < inputsNb; b++) {
		printf("%d\n", inp[b]);
	}*/

	//Create a circuit.
	createInputLabels(labels, inputsNb);
	InputLabels inputLabels = labels;
	createEmptyGarbledCircuit(&garbledCircuit, inputsNb, outputsNb, gatesNb, wiresNb, inputLabels);
	/*int z;
	for (z = 0; z < 3; z++) {
		printf("Wire %d\n", z);
		print128_num(garbledCircuit.wires[z].label0);
		print128_num(garbledCircuit.wires[z].label1);
	}
	for (z = 0; z < 4; z++) {
		print128_num(inputLabels[z]);
	}*/
	startBuilding(&garbledCircuit, &garblingContext);
	XORCircuit(&garbledCircuit, &garblingContext, 2, inp, outputs);
	finishBuilding(&garbledCircuit, &garblingContext, outputMap, outputs);
	garbleCircuit(&garbledCircuit, inputLabels, outputMap);
	//

	block extractedLabels[inputsNb];
	int extractedInputs[inputsNb];
	extractedInputs[0] = 1;
	extractedInputs[1] = 0;
	block computedOutputMap[outputsNb];
	int outputVals[outputsNb];

	extractLabels(extractedLabels, inputLabels, extractedInputs, inputsNb);
	evaluate(&garbledCircuit, extractedLabels, computedOutputMap);
	mapOutputs(outputMap, computedOutputMap, outputVals, outputsNb);

	printf("RESULT IS : %d\n", outputVals[0]);
	return 0;
}

