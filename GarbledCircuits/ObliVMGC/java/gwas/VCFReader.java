package gwas;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.Key;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class VCFReader {
	private static Map<Integer, List<String>> GTs = new HashMap<Integer, List<String>>();
	private static Map<Integer, List<String>> DSs = new HashMap<Integer, List<String>>();
	private static Map<Integer, List<String>> GL1s = new HashMap<Integer, List<String>>();
	private static Map<Integer, List<String>> GL2s = new HashMap<Integer, List<String>>();
	private static Map<Integer, List<String>> GL3s = new HashMap<Integer, List<String>>();
	private static String[] names;
	private static Key[] keys;
	private static byte[][] IVs;
	private static byte[][] skeys;
	private static byte[][] ciphers;
	private static List<String> chrms = new ArrayList<String>();
	private static List<String> poss = new ArrayList<String>();
	private static List<String> ids = new ArrayList<String>();
	private static List<String> refs = new ArrayList<String>();
	private static List<String> alts = new ArrayList<String>();

	public static void main(String[] args) {
		try (BufferedReader br = new BufferedReader(new FileReader(
				"data200.vcf"))) {
			// read the VCF File
			int i = 0;
			boolean stop = false;
			String line;
			while (((line = br.readLine()) != null) && !stop) {
				i++;
				if (i == 30) {
					String[] lines = line.split("\t");
					names = new String[lines.length - 6];
					for (int j = 6; j < lines.length; j++) {
						names[j-6] = lines[j];
						GTs.put(j-6, new ArrayList<String>());
						DSs.put(j-6, new ArrayList<String>());
						GL1s.put(j-6, new ArrayList<String>());
						GL2s.put(j-6, new ArrayList<String>());
						GL3s.put(j-6, new ArrayList<String>());
					}
				}
				if (i > 30 && line != null) {
					String[] vals = line.split("\t");
					if (vals[5].substring(0, 2).equals("GT")) {
						chrms.add(vals[0]);
						poss.add(vals[1]);
						ids.add(vals[2]);
						refs.add(vals[3]);
						alts.add(vals[4]);
						for (int j = 6; j < vals.length; j++) {
							String[] participantVals = vals[j].split(":");
							
							if (participantVals[0].equals("0|0")) {
								GTs.get(j-6).add("0");
							} else if (participantVals[0].equals("1|1")) {
								GTs.get(j-6).add("2");
							} else {
								GTs.get(j-6).add("1");
							}
							DSs.get(j-6).add(participantVals[1]);
							String[] participantValsNumber = participantVals[2].split(",");
							GL1s.get(j-6).add(participantValsNumber[0]);
							GL2s.get(j-6).add(participantValsNumber[1]);
							GL3s.get(j-6).add(participantValsNumber[2]);
						}
					}
				}
				

			}
			br.close();
			
			// Computations of Keys, IVs and SKEYs
			byte[] dump = new byte[1];
			for (i = 0; i < 1; i++) {
				dump[i] = 0;
			}
			IVs = new byte[names.length][];
			keys = new Key[names.length];
			skeys = new byte[names.length][];
			for (i = 0; i < names.length; i++) {
				keys[i] = Crypto.generateKey();
				IVs[i] = Crypto.getIV();
				skeys[i] = Crypto.SEnc(keys[i], dump, IVs[i]);
			}
			// Write the genotype tables
			PrintWriter writer = new PrintWriter("genotype_table.txt", "UTF-8");
			writer.println("P_ID;ID;ENC_GT");
			for (i = 0; i < chrms.size(); i++) {
				for (int j = 0; j < names.length; j++) {
					writer.println(names[j] + ";" + ids.get(i) + ";" + new String(Crypto.SEnc(keys[j], GTs.get(j).get(i).getBytes(), IVs[j])) + ";");
				}
				
			}
			writer.close();
			// Write the skeys tables
			writer = new PrintWriter("skeys_table.txt", "UTF-8");
			writer.println("ID;SKEY");
			for (i = 0; i < skeys.length; i++) {
				writer.println(names[i] + ";" + new String(skeys[i]) + ";");			
			}
			writer.close();
			// Write the variants table
			writer = new PrintWriter("variant_table.txt", "UTF-8");
			writer.println("CHROM;POS;ID;REF;ALT");
			for (i = 0; i < chrms.size(); i++) {
				writer.println(chrms.get(i) + ";" + poss.get(i) + ";" + ids.get(i) + ";" + refs.get(i) + ";" + alts.get(i) + ";");			
			}
			writer.close();			
		} catch (FileNotFoundException e) {
			System.err.println("ERROR : File data200.vcf not found !");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
