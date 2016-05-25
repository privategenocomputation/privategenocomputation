package com.oblivm.backend.example;

import gwas.Crypto;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.util.BitSet;

import javax.crypto.spec.SecretKeySpec;

import com.oblivm.backend.circuits.CircuitLib;
import com.oblivm.backend.flexsc.CompEnv;
import com.oblivm.backend.gc.BadLabelException;
import com.oblivm.backend.util.EvaRunnable;
import com.oblivm.backend.util.GenRunnable;

public class LinearCombEnc {

	static public <T> T[] compute(CompEnv<T> gen, T[] inputA, T[] inputB) {
		return new CircuitLib<T>(gen).xor(inputA, inputB);
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
		byte[] IV;
		Key key;

		@Override
		public void prepareInput(CompEnv<T> gen) {
			
			Path path = Paths.get(args[0]);
			try {
				IV = Files.readAllBytes(path);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			path = Paths.get(args[1]);
			try {
				key = new SecretKeySpec(Files.readAllBytes(path), "AES");
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}			
			byte[] dump = new byte[6];
			for (int i = 0; i < 6; i++) {
				dump[i] = 0;
			}
			byte[] dumpCipher = Crypto.SEnc(key, dump, IV); // SKEY
			boolean[] input = toBooleanArray(dumpCipher);
			
			System.out.println("LENGTH IS " + input.length);
			inputA = gen.inputOfAlice(input);
			gen.flush();
			inputB = gen.inputOfBob(new boolean[48]);
		}
				

		@Override
		public void secureCompute(CompEnv<T> gen) {
			scResult = compute(gen, inputA, inputB);
		}

		@Override
		public void prepareOutput(CompEnv<T> gen) throws BadLabelException {
			boolean[] res = gen.outputToAlice(scResult);
			System.out.println(new String(toByteArray(res)));
		}
		
		public void setParams(byte[] IV, Key key) {
			this.key = key;
			this.IV = IV;
		}
	}

	public static class Evaluator<T> extends EvaRunnable<T> {
		T[] inputA;
		T[] inputB;
		T[] scResult;
		byte[] IV;
		Key key;

		@Override
		public void prepareInput(CompEnv<T> gen) {
			
			Path path = Paths.get(args[0]);
			try {
				IV = Files.readAllBytes(path);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			path = Paths.get(args[1]);
			try {
				key = new SecretKeySpec(Files.readAllBytes(path), "AES");
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			byte[] m = args[2].getBytes();
			byte[] mCipher = Crypto.SEnc(key, m, IV); // SKEY XOR M
			boolean[] input = toBooleanArray(mCipher);
			System.out.println("LENGTH of input is " + m.length);
			System.out.println("LENGTH IS " + input.length);
			
			
			inputA = gen.inputOfAlice(new boolean[48]);
			gen.flush();
			inputB = gen.inputOfBob(input);
		}

		@Override
		public void secureCompute(CompEnv<T> gen) {
			scResult = compute(gen, inputA, inputB);
		}

		@Override
		public void prepareOutput(CompEnv<T> gen) throws BadLabelException {
			gen.outputToAlice(scResult);
		}
		
		public void setParams(byte[] IV, Key key) {
			this.key = key;
			this.IV = IV;
		}
	}
}
