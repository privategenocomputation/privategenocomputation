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
#include "../gwas/genoreader.c"
#include "../gwas/arith.c"

typedef struct {
	int size_names;
} CI_Params;

CI_Params* CI() {
	CI_Params* param = malloc(sizeof(CI_Params));
	read_names();
	read_ids();
	param->size_names = size_of_names();
	return param;
}

int main() {

	char* refId = "rs189842693";
	int phenotypeId = 2;
	int ancestryId = 2;

	// CI part

	int i, j;

	CI_Params* params = CI();
	int size_names = params->size_names;

	int refId_id = find_ids_id(refId);

	read_encs();
	char encC[size_names];
	for (i = 0; i < size_names; i++) {
		encC[i] = get_char_in_enc((size_names * refId_id) + i);
	}
	read_skeys();
	char skeyC[size_names];
	for (i = 0; i < size_names; i++) {
		skeyC[i] = get_char_in_skeys((size_names * refId_id) + i);
	}
	read_phens();
	char phenC[size_names];
	for (i = 0; i < size_names; i++) {
		phenC[i] = get_char_in_phens((size_names * phenotypeId) + i);
	}
	read_phensSkeys();
	char phenskeyC[size_names];
	for (i = 0; i < size_names; i++) {
		phenskeyC[i] = get_char_in_phensSkeys((size_names * phenotypeId) + i);
	}
	read_ancs();
	char ancC[size_names];
	for (i = 0; i < size_names; i++) {
		ancC[i] = get_char_in_anc((size_names * ancestryId) + i);
	}
	read_ancSkeys();
	char ancskeyC[size_names];
	for (i = 0; i < size_names; i++) {
		ancskeyC[i] = get_char_in_ancSkeys((size_names * ancestryId) + i);
	}

	// SPU -> GC building part

	GarbledCircuit garbledCircuit;
	GarblingContext garblingContext;

	int inputsNb = size_names * 4;
	int wiresNb = 100000;
	int gatesNb = 100000;
	int outputsNb = log(size_names) +1;

	//Create a circuit.
	block labels[2 * inputsNb];
	createInputLabels(labels, inputsNb);
	InputLabels inputLabels = labels;
	createEmptyGarbledCircuit(&garbledCircuit, inputsNb, outputsNb, gatesNb,
			wiresNb, inputLabels);
	startBuilding(&garbledCircuit, &garblingContext);

	// Transform generator's input into fixed wire
	int zero = fixedZeroWire(&garbledCircuit, &garblingContext);
	int one = fixedOneWire(&garbledCircuit, &garblingContext);

	int onewire = getNextWire(&garblingContext);
	NOTGate(&garbledCircuit, &garblingContext, zero, onewire);

	int zerowire = getNextWire(&garblingContext);
	NOTGate(&garbledCircuit, &garblingContext, one, zerowire);

	int outputs[outputsNb];

	int inp[inputsNb * 2];
	countToN(inp, inputsNb);

	int bits[inputsNb];
	chars_to_ints2bits(encC, size_names, bits);
	chars_to_ints1bits(phenC, size_names, bits + 2 * size_names);
	chars_to_ints1bits(ancC, size_names, bits + 3 * size_names);
	for (i = 0; i < inputsNb; i++) {
		if (bits[i]) {
			inp[inputsNb + i] = onewire;
		} else {
			inp[inputsNb + i] = zerowire;
		}
	}
	int tempOutPut[inputsNb];
	XORCircuit(&garbledCircuit, &garblingContext, inputsNb * 2, inp,
			tempOutPut);

	for (i = 0; i < outputsNb; i++) {
		outputs[i] = zerowire;
	}
	//sum(&garbledCircuit, &garblingContext, tempOutPut, size_names, 2, outputs);
	sumLinGWAS(&garbledCircuit,&garblingContext,tempOutPut,tempOutPut+2*size_names,tempOutPut+3*size_names,size_names,2,zerowire,outputsNb,outputs);

	block outputbs[outputsNb];
	OutputMap outputMap = outputbs;
	finishBuilding(&garbledCircuit, &garblingContext, outputMap, outputs);
	garbleCircuit(&garbledCircuit, inputLabels, outputMap);
	writeCircuitToFile(&garbledCircuit, "./SumLinTest");

	// MU -> Evaluation part
	GarbledCircuit aesCircuit;
	readCircuitFromFile(&aesCircuit, "./SumLinTest");
	block extractedLabels[inputsNb];

	int extractedInputs[inputsNb];
	chars_to_ints2bits(skeyC, size_names, extractedInputs);
	chars_to_ints1bits(phenskeyC, size_names, extractedInputs + 2 * size_names);
	chars_to_ints1bits(ancskeyC, size_names, extractedInputs + 3 * size_names);
	extractLabels(extractedLabels, inputLabels, extractedInputs, inputsNb);
	block computedOutputMap[outputsNb];
	evaluate(&garbledCircuit, extractedLabels, computedOutputMap);
	int outputVals[outputsNb];
	mapOutputs(outputMap, computedOutputMap, outputVals, outputsNb);

	free_names();
	free_enc();
	free_skeys();
	free_phen();
	free_phensSkeys();
	free_anc();
	free_ancSkeys();
	free_ids();
	int res = 0;
	for(i = 0; i < outputsNb; i++) {
		res += (outputVals[i] << i);
	}
	printf("RES IS : %d\n", res);

	return 0;
}

