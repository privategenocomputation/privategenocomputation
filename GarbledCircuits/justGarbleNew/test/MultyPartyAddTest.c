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

int main() {
	int inputsNb = 16;
	int outputsNb = inputsNb;
	int wiresNb = 5000;
	int gatesNb = 5000;
	GarbledCircuit garbledCircuit;
	GarblingContext garblingContext;
	block labels[2*inputsNb];


	//Create a circuit.
	createInputLabels(labels, inputsNb);
	InputLabels inputLabels = labels;
	createEmptyGarbledCircuit(&garbledCircuit, inputsNb, outputsNb, gatesNb, wiresNb, inputLabels);
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

	int input1 = 23;
	int i;
	for (i = 0; i < inputsNb; i++) {
		int temp = (input1 >> (i)) % 2;
		if (temp) {
			inp[inputsNb+i] = onewire;
		} else {
			inp[inputsNb+i] = zerowire;
		}
	}

	ADDCircuit(&garbledCircuit, &garblingContext, inputsNb*2, inp, outputs);

	block *outputbs = (block*) malloc(sizeof(block) * outputsNb);
	OutputMap outputMap = outputbs;
	finishBuilding(&garbledCircuit, &garblingContext, outputMap, outputs);
	garbleCircuit(&garbledCircuit, inputLabels, outputMap);


	block extractedLabels[inputsNb];
	int extractedInputs[inputsNb];
	int input2 = 41;
	for (i = 0; i < inputsNb; i++) {
		extractedInputs[i] = (input2 >> (i)) % 2;
	}
	block computedOutputMap[outputsNb];
	int outputVals[outputsNb];

	extractLabels(extractedLabels, inputLabels, extractedInputs, inputsNb);
	evaluate(&garbledCircuit, extractedLabels, computedOutputMap);
	mapOutputs(outputMap, computedOutputMap, outputVals, outputsNb);


    int res = 0;
	for (i = 0; i < 8; i++) {
		res+= outputVals[i]*pow(2,(i));
	}
	printf("RESULT IS : %d\n",res);
	return 0;
}
