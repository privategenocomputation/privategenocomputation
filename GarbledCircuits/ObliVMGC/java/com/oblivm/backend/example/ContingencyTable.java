package com.oblivm.backend.example;


import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.List;

import com.oblivm.backend.circuits.CircuitLib;
import com.oblivm.backend.circuits.arithmetic.IntegerLib;
import com.oblivm.backend.flexsc.CompEnv;
import com.oblivm.backend.gc.BadLabelException;
import com.oblivm.backend.util.EvaRunnable;
import com.oblivm.backend.util.GenRunnable;
import com.oblivm.backend.util.Utils;

public class ContingencyTable {
	
	
	static public<T> T[] compute(CompEnv<T> gen, T[] inputA, T[] inputB){
		//return new IntegerLib<T>(gen).numberOfOnes(new CircuitLib<T>(gen).xor(inputA, inputB));
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
		String id;
		
		@Override
		public void prepareInput(CompEnv<T> gen) {
			List<byte[]> inputs = new ArrayList<byte[]>();
			id = args[1];
			try (BufferedReader br = new BufferedReader(new FileReader(args[0]))) {
				// read the VCF File
				int i = 0;
				String line;
				while (((line = br.readLine()) != null)) {
					i++;
					if (i == 2) {
						String[] vals = line.split(";");
						if (vals[1].equals(id)) {
							inputs.add(vals[2].getBytes());
						}
					}
				}
				br.close();
				byte[] totalInput = new byte[inputs.size()];
				for (i = 0; i < inputs.size(); i++) {
					System.arraycopy(inputs.get(i), 0, totalInput, i, 1);
				}
				boolean[] totalInputBits = toBooleanArray(totalInput);
				System.out.println("GENE LENGTH IS " + totalInputBits.length);
				inputA = gen.inputOfAlice(totalInputBits);
				gen.flush();
				inputB = gen.inputOfBob(new boolean[totalInputBits.length]);
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
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
		
		@Override
		public void prepareInput(CompEnv<T> gen) {
			List<byte[]> inputs = new ArrayList<byte[]>();
			try (BufferedReader br = new BufferedReader(new FileReader(args[0]))) {
				// read the VCF File
				int i = 0;
				String line;
				while (((line = br.readLine()) != null)) {
					i++;
					if (i == 2) {
						String[] vals = line.split(";");
						inputs.add(vals[1].getBytes());
					}
				}
				br.close();
				byte[] totalInput = new byte[1];
				for (i = 0; i < inputs.size(); i++) {
					System.arraycopy(inputs.get(i), 0, totalInput, i, 1);
				}
				boolean[] totalInputBits = toBooleanArray(totalInput);
				System.out.println(new String(totalInput));
				System.out.println("EVA LENGTH IS " + totalInputBits.length);
				inputA = gen.inputOfAlice(new boolean[totalInputBits.length]);
				gen.flush();
				inputB = gen.inputOfBob(totalInputBits);
			} catch (FileNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
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
