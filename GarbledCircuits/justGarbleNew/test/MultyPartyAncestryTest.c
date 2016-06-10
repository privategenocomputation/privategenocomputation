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


int main() {

	int ancestryId = 1;
	int ancestrySize = 10;

	// CI part

    int i,j;
    read_names();
    int size_names = size_of_names();

    read_ancs();
    char ancC[size_names];
    for (i= 0; i< size_names;i++) {
    	ancC[i] = get_char_in_anc((size_names*ancestryId)+i);
    }
    read_ancSkeys();
    char skeyC[size_names];
    for (i= 0; i< size_names;i++) {
    	skeyC[i] = get_char_in_ancSkeys((size_names*ancestryId)+i);
    }

    // SPU -> GC building part

	GarbledCircuit garbledCircuit;
	GarblingContext garblingContext;

	int inputsNb = 32*size_names;
	int wiresNb = 120000;
	int gatesNb = 120000;
	int outputsNb = 32;

	//Create a circuit.
	block labels[2 * inputsNb];
	createInputLabels(labels, inputsNb);
	InputLabels inputLabels = labels;
	createEmptyGarbledCircuit(&garbledCircuit, inputsNb, outputsNb, gatesNb,
			wiresNb, inputLabels);
	startBuilding(&garbledCircuit, &garblingContext);

	// Transform generator's input into fixed wire
	int zero = fixedZeroWire(&garbledCircuit,&garblingContext);
	int one = fixedOneWire(&garbledCircuit,&garblingContext);

	int onewire = getNextWire(&garblingContext);
	NOTGate(&garbledCircuit,&garblingContext,zero,onewire);

	int zerowire = getNextWire(&garblingContext);
	NOTGate(&garbledCircuit,&garblingContext,one,zerowire);

	int outputs[outputsNb];
	int *inp = (int *) malloc(sizeof(int) * inputsNb*2);
	countToN(inp, inputsNb);
	//countToN(outputs, inputsNb);

	int bits[inputsNb];
	chars_to_ints(ancC,size_names,bits);

	for (i = 0; i < inputsNb; i++) {
		if (bits[i]) {
			inp[inputsNb+i] = onewire;
		} else {
			inp[inputsNb+i] = zerowire;
		}
	}
	int tempOutPut[inputsNb];
	XORCircuit(&garbledCircuit, &garblingContext, inputsNb*2, inp, tempOutPut);


	sum(&garbledCircuit, &garblingContext, tempOutPut, size_names, 32, outputs);


	block *outputbs = (block*) malloc(sizeof(block) * outputsNb);
	OutputMap outputMap = outputbs;
	finishBuilding(&garbledCircuit, &garblingContext, outputMap, outputs);
	garbleCircuit(&garbledCircuit, inputLabels, outputMap);

	// MU -> Evaluation part
	block extractedLabels[inputsNb];

	int extractedInputs[inputsNb];
	chars_to_ints(skeyC,size_names,extractedInputs);

	extractLabels(extractedLabels, inputLabels, extractedInputs, inputsNb);
	block computedOutputMap[outputsNb];
	evaluate(&garbledCircuit, extractedLabels, computedOutputMap);
	int outputVals[outputsNb];
	mapOutputs(outputMap, computedOutputMap, outputVals, outputsNb);
	//TODO
	int res = ints_into_int(outputVals);
	printf("RESULT IS : %d\n",res);
	return 0;
}

