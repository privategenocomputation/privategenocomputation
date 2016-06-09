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

int main() {
	GarbledCircuit garbledCircuit;
	GarblingContext garblingContext;
	int inputsNb = 10 * 32;
	int wiresNb = 1000000;
	int gatesNb = 1000000;
	int outputsNb = 32*4;

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
	countToN(outputs, outputsNb);

	int zero = fixedZeroWire(&garbledCircuit, &garblingContext);
	int internalWire = getNextWire(&garblingContext);
	NOTGate(&garbledCircuit, &garblingContext, zero, internalWire);
	int internalWire2 = getNextWire(&garblingContext);
	NOTGate(&garbledCircuit, &garblingContext, internalWire, internalWire2);

	//sum(&garbledCircuit, &garblingContext,inp,10,32,outputs);
	sumLin(&garbledCircuit, &garblingContext, inp, inp, inp,10, 32, internalWire2, outputs);

	block *outputbs = (block*) malloc(sizeof(block) * outputsNb);
	OutputMap outputMap = outputbs;
	finishBuilding(&garbledCircuit, &garblingContext, outputMap, outputs);
	garbleCircuit(&garbledCircuit, inputLabels, outputMap);
	// MU -> Evaluation part
	block extractedLabels[inputsNb];

	int extractedInputs[inputsNb];
	char a[10];
	a[0] = 1;
	a[1] = 1;
	a[2] = 1;
	a[3] = 0;
	a[4] = 1;
	a[5] = 0;
	a[6] = 1;
	a[7] = 1;
	a[8] = 0;
	a[9] = '\0';

	chars_to_ints(a, 10, extractedInputs);
	extractLabels(extractedLabels, inputLabels, extractedInputs, inputsNb);
	block computedOutputMap[outputsNb];
	evaluate(&garbledCircuit, extractedLabels, computedOutputMap);
	int outputVals[outputsNb];
	mapOutputs(outputMap, computedOutputMap, outputVals, outputsNb);

	int res = ints_into_int(outputVals);
	printf("RES IS %d\n", res);
	return 0;
}

