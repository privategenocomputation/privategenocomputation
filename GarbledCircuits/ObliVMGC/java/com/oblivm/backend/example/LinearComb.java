package com.oblivm.backend.example;

import gwas.Crypto;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.util.Arrays;
import java.util.BitSet;
import java.util.List;

import javax.crypto.spec.SecretKeySpec;

import com.oblivm.backend.circuits.CircuitLib;
import com.oblivm.backend.circuits.arithmetic.IntegerLib;
import com.oblivm.backend.flexsc.CompEnv;
import com.oblivm.backend.gc.BadLabelException;
import com.oblivm.backend.util.EvaRunnable;
import com.oblivm.backend.util.GenRunnable;
import com.oblivm.backend.util.Utils;

public class LinearComb {
	
	
	static public<T> T[] compute(CompEnv<T> gen, T[] inputA, T[] inputB){
		T[] inputAM1 = Arrays.copyOfRange(inputA, 0, 8);
		/*T[] inputAM2 = Arrays.copyOfRange(inputA, 8,16);
		T[] inputAY1 = Arrays.copyOfRange(inputA, 16,24);
		T[] inputAY2 = Arrays.copyOfRange(inputA, 24,32);*/
		T[] inputBM1 = Arrays.copyOfRange(inputB, 0, 8);
		/*T[] inputBM2 = Arrays.copyOfRange(inputB, 8,16);
		T[] inputBY1 = Arrays.copyOfRange(inputB, 16,24);
		T[] inputBY2 = Arrays.copyOfRange(inputB, 24,32);
		T[] circuit1 = new CircuitLib<T>(gen).xor(inputAM1, inputBM1);
		T[] circuit2 = new CircuitLib<T>(gen).xor(inputAM2, inputBM2);
		T[] circuit3 = new CircuitLib<T>(gen).xor(inputAY1, inputBY1);
		T[] circuit4 = new CircuitLib<T>(gen).xor(inputAY2, inputBY2);
		IntegerLib<T> circuit5 = new IntegerLib<T>(gen);
		IntegerLib<T> circuit6 = new IntegerLib<T>(gen);
		//return new IntegerLib<T>(gen).add(circuit5.add(circuit1, circuit3), circuit6.add(circuit2, circuit4));*/
		return new CircuitLib<T>(gen).xor(inputAM1, inputBM1);
	}
	
	static public boolean[] toBooleanArray(byte[] bytes) {
	    BitSet bits = BitSet.valueOf(bytes);
	    boolean[] bools = new boolean[bytes.length * 8];
	    for (int i = bits.nextSetBit(0); i != -1; i = bits.nextSetBit(i+1)) {
	        bools[i] = true;
	    }
	    return bools;
	}
	
	static public byte[] toByteArray(boolean[] bools) {
	    BitSet bits = new BitSet(bools.length);
	    for (int i = 0; i < bools.length; i++) {
	        if (bools[i]) {
	            bits.set(i);
	        }
	    }
	    return bits.toByteArray();
	}
	
	public static class Generator<T> extends GenRunnable<T> {

		T[] inputA;
		T[] inputB;
		T[] scResult;
		byte[] IV1;
		byte[] IV2;
		byte[] IV3;
		byte[] IV4;
		Key key;
		
		@Override
		public void prepareInput(CompEnv<T> gen) {

			Path path = Paths.get(args[0]);
			try {
				key = new SecretKeySpec(Files.readAllBytes(path), "AES");
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			path = Paths.get(args[1]);
			try {
				IV1 = Files.readAllBytes(path);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			path = Paths.get(args[2]);
			try {
				IV2 = Files.readAllBytes(path);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			path = Paths.get(args[3]);
			try {
				IV3 = Files.readAllBytes(path);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			path = Paths.get(args[4]);
			try {
				IV4 = Files.readAllBytes(path);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			byte[] m1 = args[5].getBytes();
			byte[] m2 = args[6].getBytes();
			byte[] y1 = args[7].getBytes();
			byte[] y2 = args[8].getBytes();
			
			byte[] m1Cipher = Crypto.SEnc(key, m1, IV1); // SKEY1 XOR M1
			byte[] m2Cipher = Crypto.SEnc(key, m2, IV2); // SKEY2 XOR M2
			byte[] y1Cipher = Crypto.SEnc(key, y1, IV3); // SKEY3 XOR Y1
			byte[] y2Cipher = Crypto.SEnc(key, y2, IV4); // SKEY4 XOR Y4
			
			boolean[] inputM1 = toBooleanArray(m1Cipher);
			boolean[] inputM2 = toBooleanArray(m2Cipher);
			boolean[] inputY1 = toBooleanArray(y1Cipher);
			boolean[] inputY2 = toBooleanArray(y2Cipher);
			
			boolean[] totalInput = new boolean[4*8];
			
			System.arraycopy(inputM1, 0, totalInput, 0, 8);
			System.arraycopy(inputM2, 0, totalInput, 8, 8);
			System.arraycopy(inputY1, 0, totalInput, 16, 8);
			System.arraycopy(inputY2, 0, totalInput, 24, 8);
			
			System.out.println("TOTAL LENGTH IS " + totalInput.length);
			
			inputA = gen.inputOfAlice(totalInput);
			gen.flush();
			inputB = gen.inputOfBob(new boolean[4*8]);
		}
		
		@Override
		public void secureCompute(CompEnv<T> gen) {
			scResult = compute(gen, inputA, inputB);
		}
		
		@Override
		public void prepareOutput(CompEnv<T> gen) throws BadLabelException {
			boolean[] res = gen.outputToAlice(scResult);
			System.out.println(Utils.toInt(res));

		}
	}
	
	public static class Evaluator<T> extends EvaRunnable<T> {
		T[] inputA;
		T[] inputB;
		T[] scResult;
		byte[] IV1;
		byte[] IV2;
		byte[] IV3;
		byte[] IV4;
		Key key;
		
		@Override
		public void prepareInput(CompEnv<T> gen) {
			Path path = Paths.get(args[0]);
			try {
				key = new SecretKeySpec(Files.readAllBytes(path), "AES");
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			path = Paths.get(args[1]);
			try {
				IV1 = Files.readAllBytes(path);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			path = Paths.get(args[2]);
			try {
				IV2 = Files.readAllBytes(path);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			path = Paths.get(args[3]);
			try {
				IV3 = Files.readAllBytes(path);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			path = Paths.get(args[4]);
			try {
				IV4 = Files.readAllBytes(path);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			byte[] dump = new byte[16];
			for (int i = 0; i < 16; i++) {
				dump[i] = 0;
			}
			
			byte[] m1Cipher = Crypto.SEnc(key, dump, IV1); // SKEY1
			byte[] m2Cipher = Crypto.SEnc(key, dump, IV2); // SKEY2
			byte[] y1Cipher = Crypto.SEnc(key, dump, IV3); // SKEY3
			byte[] y2Cipher = Crypto.SEnc(key, dump, IV4); // SKEY4
			
			boolean[] inputM1 = toBooleanArray(m1Cipher);
			boolean[] inputM2 = toBooleanArray(m2Cipher);
			boolean[] inputY1 = toBooleanArray(y1Cipher);
			boolean[] inputY2 = toBooleanArray(y2Cipher);
			
			boolean[] totalInput = new boolean[4*8];
			
			System.arraycopy(inputM1, 0, totalInput, 0, 8);
			System.arraycopy(inputM2, 0, totalInput, 8, 8);
			System.arraycopy(inputY1, 0, totalInput, 16, 8);
			System.arraycopy(inputY2, 0, totalInput, 24, 8);
			
			
			inputA = gen.inputOfAlice(new boolean[4*8]);
			gen.flush();
			inputB = gen.inputOfBob(totalInput);
		}
		
		@Override
		public void secureCompute(CompEnv<T> gen) {
			scResult = compute(gen, inputA, inputB);
		}
		
		@Override
		public void prepareOutput(CompEnv<T> gen) throws BadLabelException {
			gen.outputToAlice(scResult);
		}
	}
}
