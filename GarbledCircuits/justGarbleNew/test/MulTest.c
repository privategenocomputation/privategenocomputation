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

int muxInt(int x, int y, int c, GarbledCircuit* gc1, GarblingContext* gc2) {
	int internalWire = getNextWire(gc2);
	XORGate(gc1, gc2, x, y, internalWire);
	int internalWire2 = getNextWire(gc2);
	ANDGate(gc1, gc2, internalWire, c, internalWire2);
	int internalWire3 = getNextWire(gc2);
	XORGate(gc1, gc2, internalWire2, x, internalWire3);
	return internalWire3;
}

int mux(int* x, int* y, int c, GarbledCircuit* gc1, GarblingContext* gc2, int n,
		int* output) {
	int i;
	for (i = 0; i < n; i++) {
		output[i] = muxInt(x[i], y[i], c, gc1, gc2);
	}
	return 0;
}

int mul(int inputsNb, GarbledCircuit* garbledCircuit,
		GarblingContext* garblingContext, int* inp, int* outputs) {
	int i;
	int j;
	int yLength = inputsNb / 2;
	int xLength = inputsNb / 2;
	int zeros[inputsNb/2];
	int zero = fixedZeroWire(garbledCircuit, garblingContext);
	for (i = 0; i < inputsNb/2; i++) {
		int internalWire = getNextWire(garblingContext);
		NOTGate(garbledCircuit,garblingContext,zero,internalWire);
		int internalWire2 = getNextWire(garblingContext);
		NOTGate(garbledCircuit,garblingContext,internalWire,internalWire2);
		zeros[i] = internalWire2;
	}
	for (i = 0; i < 2 * xLength; i++) {
		outputs[i] = zeros[0];
	}

	int tempMux[xLength];
	mux(zeros, inp, inp[xLength], garbledCircuit, garblingContext, xLength,
			tempMux);

	//int tempLine[2*xLength];

	for (i = 0; i < 2 * xLength; i++) {
		outputs[i] = zeros[0];
	}

	for (i = 0; i < xLength; i++) {
		outputs[i] = tempMux[i];
	}

	for (i = 1; i < yLength; i++) {
		int tempMux2[xLength];
		mux(zeros,inp, inp[xLength + i], garbledCircuit, garblingContext, xLength,
				tempMux2);

		int tempLine[2 * xLength];

		for (j = 0; j < 2 * xLength; j++) {
			tempLine[j] = zeros[0];
		}
		for (j = i; j < xLength + i; j++) {
			tempLine[j] = tempMux2[j - i];
		}

		int tempAdd[4 * xLength];
		for (j = 0; j < 2 * xLength; j++) {
			tempAdd[j] = tempLine[j];
		}
		for (j = 2 * xLength; j < 4 * xLength; j++) {
			tempAdd[j] = outputs[j - 2 * xLength];
		}
		ADDCircuit(garbledCircuit, garblingContext, 4 * xLength, tempAdd,
				outputs);
	}

	return 0;
}

int main() {
	int i, j;
	GarbledCircuit garbledCircuit;
	GarblingContext garblingContext;

	int inputsNb = 16;
	int wiresNb = 50000;
	int gatesNb = 50000;
	int outputsNb = inputsNb;

	//Create a circuit.
	block labels[2 * inputsNb];
	createInputLabels(labels, inputsNb);
	InputLabels inputLabels = labels;
	createEmptyGarbledCircuit(&garbledCircuit, inputsNb, outputsNb, gatesNb,
			wiresNb, inputLabels);
	startBuilding(&garbledCircuit, &garblingContext);
	int outputs[outputsNb];
	int zeros[inputsNb];
	int zero = fixedZeroWire(&garbledCircuit, &garblingContext);
	for (i = 0; i < inputsNb; i++) {
		int internalWire = getNextWire(&garblingContext);
		NOTGate(&garbledCircuit,&garblingContext,zero,internalWire);
		int internalWire2 = getNextWire(&garblingContext);
		NOTGate(&garbledCircuit,&garblingContext,internalWire,internalWire2);
		zeros[i] = internalWire2;
		outputs[i] = internalWire2;
	}
	int *inp = (int *) malloc(sizeof(int) * inputsNb);
	countToN(inp, inputsNb);

	//countToN(outputs, outputsNb);
	mul(inputsNb,&garbledCircuit,&garblingContext,inp,outputs);

	//mux(zeros,inp, inp[inputsNb/2], &garbledCircuit, &garblingContext, inputsNb/2,outputs);

	//mux(zeros,inp, inp[0], &garbledCircuit, &garblingContext, inputsNb,outputs);

	block *outputbs = (block*) malloc(sizeof(block) * outputsNb);
	OutputMap outputMap = outputbs;
	finishBuilding(&garbledCircuit, &garblingContext, outputMap, outputs);
	garbleCircuit(&garbledCircuit, inputLabels, outputMap);
	block extractedLabels[inputsNb];
	int extractedInputs[inputsNb];
	int input1 = 13;
	int input2 = 3;
	//int input3 = 4;
	//int input4 = 5;
	for (i = 0; i < inputsNb / 4; i++) {
		extractedInputs[i] = (input1 >> (i)) % 2;
	}
	for (i = inputsNb / 4; i < inputsNb / 2; i++) {
		extractedInputs[i] = 0;
	}
	for (i = inputsNb / 2; i < inputsNb / 2 + inputsNb / 4; i++) {
		extractedInputs[i] = (input2 >> ((i - inputsNb / 2))) % 2;
	}
	for (i = inputsNb / 2 + inputsNb / 4; i < inputsNb; i++) {
		extractedInputs[i] = 0;
	}/*
	 for (i = inputsNb/2; i < inputsNb / 2 + inputsNb/8; i++) {
	 extractedInputs[i] = (input3 >> (i - inputsNb / 2)) % 2;
	 }
	 for (i = inputsNb / 2 + inputsNb/8; i < inputsNb/2 + inputsNb / 4; i++) {
	 extractedInputs[i] = 0;
	 }
	 for (i =  inputsNb/2 + inputsNb / 4; i < inputsNb/2 + inputsNb / 4 + inputsNb / 8; i++) {
	 extractedInputs[i] = (input4 >> ((i - (inputsNb/2 + inputsNb / 4)))) % 2;
	 }
	 for (i = inputsNb/2 + inputsNb / 4 + inputsNb / 8; i < inputsNb; i++) {
	 extractedInputs[i] = 0;
	 }
	 for (i = 0; i < 4; i++) {
	 for (j=0; j < inputsNb/4; j++) {
	 printf("%d", extractedInputs[(i * inputsNb/4) + j]);
	 }
	 printf("\n");
	 }*/

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

