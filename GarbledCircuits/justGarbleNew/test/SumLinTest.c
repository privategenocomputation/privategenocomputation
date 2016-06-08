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
	int inputsNb = 3 * 3 * 32;
	int wiresNb = 480000;
	int gatesNb = 480000;
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

	sumLin(&garbledCircuit, &garblingContext, inp, inp + (3 * 32), inp + (2 * 3 * 32), 3, 32, internalWire2, outputs);

	block *outputbs = (block*) malloc(sizeof(block) * outputsNb);
	OutputMap outputMap = outputbs;
	finishBuilding(&garbledCircuit, &garblingContext, outputMap, outputs);
	garbleCircuit(&garbledCircuit, inputLabels, outputMap);
	// MU -> Evaluation part
	block extractedLabels[inputsNb];

	int extractedInputs[inputsNb];
	int a1 = 1;
	int a2 = 3;
	int a3 = 4;

	int b1 = 2;
	int b2 = 1;
	int b3 = 4;

	int c1 = 3;
	int c2 = 3;
	int c3 = 2;

	inputs_into_pointer3(a1, a2, a3, extractedInputs);
	inputs_into_pointer3(b1, b2, b3, extractedInputs + (3 * 32));
	inputs_into_pointer3(c1, c2, c3, extractedInputs + (2 * 3 * 32));

	extractLabels(extractedLabels, inputLabels, extractedInputs, inputsNb);
	block computedOutputMap[outputsNb];
	evaluate(&garbledCircuit, extractedLabels, computedOutputMap);
	int outputVals[outputsNb];
	mapOutputs(outputMap, computedOutputMap, outputVals, outputsNb);

	int res = ints_into_int(outputVals);
	printf("RES IS %d\n", res);
	return 0;
}

