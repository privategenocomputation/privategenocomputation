#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <math.h>

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

int sum(GarbledCircuit* garbledCircuit,
		GarblingContext* garblingContext, int* inp, int inputNb, int inputsize, int* outputs) {
	int i;
	ADDCircuit(garbledCircuit, garblingContext, 2 * inputsize, inp, outputs);
	for(i=2; i<inputNb;i++) {
		int temp[2*inputsize];
		int j;
		for(j = 0; j < inputsize; j++) {
			temp[j] = outputs[j];
		}
		for(j=inputsize; j < inputsize*2; j++) {
			temp[j] = inp[(inputsize*(i)) + j - inputsize];
		}
		ADDCircuit(garbledCircuit, garblingContext, 2 * inputsize, temp, outputs);
	}
	return 0;
}

int sumLin(GarbledCircuit* garbledCircuit,
		GarblingContext* garblingContext, int* a, int* b, int* c, int inputNumber, int inputsize, int zerowire, int* outputs) {
	int i,j;
	int tempMulRes[inputsize*4*inputNumber];
	for (i = 0; i < inputNumber; i++) {
		int tempMul1[inputsize*2];
		int tempRes1[inputsize*2];
		for (j=0;j<inputsize;j++){
			tempMul1[j] = a[(i*inputsize) +j];
		}
		for (j=inputsize;j<inputsize*2;j++){
			tempMul1[j] = b[(i*inputsize) + j - inputsize];
		}
		mul(inputsize*2,garbledCircuit,garblingContext,tempMul1,tempRes1);

		int tempMul2[inputsize*4];
		int tempRes2[inputsize*4];
		for(j=0;j<inputsize*2;j++){
			tempMul2[j] = tempRes1[j];
		}
		for(j=inputsize*2;j<inputsize*3;j++){
			tempMul2[j] = c[(i*inputsize)+j-(inputsize*2)];
		}
		for(j=inputsize*3;j<inputsize*4;j++){
			tempMul2[j] = zerowire;
		}
		mul(inputsize*4,garbledCircuit,garblingContext,tempMul2,tempRes2);
		for(j=0;j<inputsize*4;j++) {
			tempMulRes[(i*inputsize*4) + j] = tempRes2[j];
		}
	}
	sum(garbledCircuit,garblingContext,tempMulRes,inputNumber,inputsize*4,outputs);
	return 0;

}

int int_into_ints(int input, int* out) {
	int i;
	for(i = 0; i < 32; i++) {
		out[i] = (input >> i) % 2;
	}
	return 0;
}

int ints_into_int(int* input) {
	int i;
	int res = 0;
	for(i = 0; i < 32; i++) {
		res += (input[i] << i);
	}
	return res;
}

int ints_into_ints(int* input, int input_number, int* out) {
	int i;
	for(i = 0; i < input_number; i++) {
		int_into_ints(input[0], out+(i*input_number));
	}
	return 0;
}

int inputs_into_pointer3(int input1, int input2, int input3, int* out) {
	int temp[3];
	temp[0] = input1;
	temp[1] = input2;
	temp[2] = input3;
	int i;
	for (i=0; i < 3; i++) {
		int_into_ints(temp[i],out+(i*32));
	}
	return 0;
}

int inputs_into_pointer4(int input1, int input2, int input3, int input4, int inputsNb, int* out) {
	int i;
	for (i = 0; i < inputsNb / 4; i++) {
		out[i] = (input1 >> (i)) % 2;
	}
	for (i = inputsNb / 4; i < inputsNb / 2; i++) {
		out[i] = (input2 >> ((i - inputsNb / 4))) % 2;
	}
	for (i = inputsNb / 2; i < inputsNb / 2 + inputsNb / 4; i++) {
		out[i] = (input3 >> (i - inputsNb / 2)) % 2;
	}
	for (i = inputsNb / 2 + inputsNb / 4;
			i < inputsNb; i++) {
		out[i] = (input4 >> ((i - (inputsNb / 2 + inputsNb / 4))))
				% 2;
	}
	return 0;
}

int char_to_ints(char c, int* out) {
	int i;
	for (i = 0; i < 32; i++) {
		out[i] = (c >> i) % 2;
	}
	return 0;
}

int chars_to_ints(char* c, int chars_length, int* out) {
	int i;
	for (i = 0; i < chars_length; i++){
		char_to_ints(c[i], out + (32*i));
	}
	return 0;
}


int chars_into_pointer2(char* input1, char* input2, int sizeChar, int* out) {
	int i,j;
	chars_to_ints(input1,sizeChar,out);
	chars_to_ints(input2,sizeChar,out+(sizeChar*32));
	return 0;
}

char ints_to_char(int* input) {
	int i;
	char c = (char)0;
	for (i = 0; i < 32; i++) {
		c += (input[i] << i);
	}
	return c;
}

int ints_to_chars(int* input, int chars_length, char* out) {
	int i;
	for(i=0; i < chars_length;i++){
		out[i] = ints_to_char(input+(i*32));
	}
	return 0;
}


