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

int main() {
	int i, j;
	GarbledCircuit garbledCircuit;
	GarblingContext garblingContext;

	int inputsNb = 32;
	int wiresNb = 50000;
	int gatesNb = 50000;
	int outputsNb = 16;

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
	int outputsTemp[outputsNb*2];
	mul(inputsNb/2, &garbledCircuit, &garblingContext, inp, outputsTemp);
	mul(inputsNb/2, &garbledCircuit, &garblingContext, inp+inputsNb/2, outputsTemp+outputsNb);
	ADDCircuit(&garbledCircuit, &garblingContext, outputsNb*2, outputsTemp, outputs);

	block *outputbs = (block*) malloc(sizeof(block) * outputsNb);
	OutputMap outputMap = outputbs;
	finishBuilding(&garbledCircuit, &garblingContext, outputMap, outputs);
	garbleCircuit(&garbledCircuit, inputLabels, outputMap);

	// Evaluation
	block extractedLabels[inputsNb];
	int extractedInputs[inputsNb];
	inputs_into_pointer4(2,19,3,20,inputsNb,extractedInputs);

	extractLabels(extractedLabels, inputLabels, extractedInputs, inputsNb);
	block computedOutputMap[outputsNb];
	evaluate(&garbledCircuit, extractedLabels, computedOutputMap);
	int outputVals[outputsNb];
	mapOutputs(outputMap, computedOutputMap, outputVals, outputsNb);
	int resN = 0;
	for (i = 0; i < outputsNb; i++) {
		resN += outputVals[i] * pow(2, (i));
	}

	printf("RESULT IS : %d\n", resN);
	return 0;
}

