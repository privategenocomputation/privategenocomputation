package gwas;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.Key;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import org.apache.commons.io.IOUtils;

public class VCFReader {
	private static Map<Integer, List<Integer>> GTs = new HashMap<Integer, List<Integer>>();
	private static Map<Integer, List<String>> DSs = new HashMap<Integer, List<String>>();
	private static Map<Integer, List<String>> GL1s = new HashMap<Integer, List<String>>();
	private static Map<Integer, List<String>> GL2s = new HashMap<Integer, List<String>>();
	private static Map<Integer, List<String>> GL3s = new HashMap<Integer, List<String>>();
	private static String[] names;
	private static Key[] keys;
	private static Key[] phenKeys;
	private static Key[] ancKeys;
	private static byte[][] IVs;
	private static byte[][] phenIVs;
	private static byte[][] ancIVs;
	private static byte[][] skeys;
	private static byte[][] phenSkeys;
	private static byte[][] ancSkeys;
	private static byte[][] ciphers;
	private static byte[][] phenCiphers;
	private static byte[][] ancCiphers;
	private static List<String> chrms = new ArrayList<String>();
	private static List<String> poss = new ArrayList<String>();
	private static List<String> ids = new ArrayList<String>();
	private static List<String> refs = new ArrayList<String>();
	private static List<String> alts = new ArrayList<String>();

	private static int phenotypeSize = 10;
	private static int[][] phenotypes;

	private static int ancestryGroupsSize = 10;
	private static int[][] ancestries;

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
						names[j - 6] = lines[j];
						GTs.put(j - 6, new ArrayList<Integer>());
						DSs.put(j - 6, new ArrayList<String>());
						GL1s.put(j - 6, new ArrayList<String>());
						GL2s.put(j - 6, new ArrayList<String>());
						GL3s.put(j - 6, new ArrayList<String>());
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
								GTs.get(j - 6).add(0);
							} else if (participantVals[0].equals("1|1")) {
								GTs.get(j - 6).add(2);
							} else {
								GTs.get(j - 6).add(1);
							}
							DSs.get(j - 6).add(participantVals[1]);
							String[] participantValsNumber = participantVals[2]
									.split(",");
							GL1s.get(j - 6).add(participantValsNumber[0]);
							GL2s.get(j - 6).add(participantValsNumber[1]);
							GL3s.get(j - 6).add(participantValsNumber[2]);
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
			IVs = new byte[names.length * chrms.size()][];
			keys = new Key[names.length * chrms.size()];
			skeys = new byte[names.length * chrms.size()][];
			ciphers = new byte[names.length * chrms.size()][];
			for (i = 0; i < names.length * chrms.size(); i++) {
				keys[i] = Crypto.generateKey();
				IVs[i] = Crypto.getIV();
				skeys[i] = Crypto.SEnc(keys[i], dump, IVs[i]);
			}
			PrintWriter writer = new PrintWriter("names_table.txt", "UTF-8");
			for (int j = 0; j < names.length; j++) {
				writer.println(names[j] + ";");
			}
			writer.close();
			writer = new PrintWriter("ids_table.txt", "UTF-8");
			for (i = 0; i < chrms.size(); i++) {
				writer.println(ids.get(i) + ";");

			}
			writer.close();
			FileOutputStream output = new FileOutputStream(new File(
					"genotype_table"));
			for (i = 0; i < chrms.size(); i++) {
				for (int j = 0; j < names.length; j++) {
					byte[] tempData = new byte[1];
					tempData[0] = GTs
							.get(j).get(i).byteValue();
					byte[] data = Crypto.SEnc(keys[(i * names.length) + j], tempData, IVs[(i * names.length)
							+ j]);
					IOUtils.write(data, output);
					ciphers[(i * names.length) + j] = data;
				}

			}
			output.close();
			output = new FileOutputStream(new File("skeys_table"));
			for (i = 0; i < chrms.size(); i++) {
				for (int j = 0; j < names.length; j++) {
					IOUtils.write(skeys[(i * names.length) + j], output);
				}

			}
			output.close();
			byte[][] xored = new byte[chrms.size() * names.length][skeys[0].length];
			for (i = 0; i < chrms.size() * names.length; i++) {
				for (int j = 0; j < skeys[0].length; j++) {
					xored[i][j] = (byte) (skeys[i][j] ^ ciphers[i][j]);
				}
			}

			writer = new PrintWriter("test_table.txt", "UTF-8");
			for (i = 0; i < chrms.size(); i++) {
				for (int j = 0; j < names.length; j++) {
					byte[] data = xored[(i * names.length) + j];
					writer.println(names[j] + ";" + ids.get(i) + ";"
							+ new String(data));
				}

			}
			writer.close();
			// Write the variants table
			writer = new PrintWriter("variant_table.txt", "UTF-8");
			writer.println("CHROM;POS;ID;REF;ALT");
			for (i = 0; i < chrms.size(); i++) {
				writer.println(chrms.get(i) + ";" + poss.get(i) + ";"
						+ ids.get(i) + ";" + refs.get(i) + ";" + alts.get(i)
						+ ";");
			}
			writer.close();
			phenotypes = new int[phenotypeSize][names.length];
			Random rand = new Random();
			for (i = 0; i < phenotypeSize; i++) {
				for (int j = 0; j < names.length; j++) {
					phenotypes[i][j] = rand.nextInt(2);
					if (phenotypes[i][j] == 2) {
						System.out.println("PROBLEM\n");
					}
				}
			}
			phenIVs = new byte[names.length * phenotypeSize][];
			phenKeys = new Key[names.length * phenotypeSize];
			phenSkeys = new byte[names.length * phenotypeSize][];
			phenCiphers = new byte[names.length * phenotypeSize][];
			for (i = 0; i < names.length * phenotypeSize; i++) {
				phenKeys[i] = Crypto.generateKey();
				phenIVs[i] = Crypto.getIV();
				phenSkeys[i] = Crypto.SEnc(phenKeys[i], dump, phenIVs[i]);
			}
			output = new FileOutputStream(new File(
					"phenotype_table"));
			for (i = 0; i < phenotypeSize; i++) {
				for (int j = 0; j < names.length; j++) {
					byte[] tempData = new byte[1];
					tempData[0] = new Integer(phenotypes[i][j]).byteValue();
					byte[] data = Crypto.SEnc(phenKeys[(i * names.length) + j], tempData, phenIVs[(i * names.length)
							+ j]);
					IOUtils.write(data, output);
					phenCiphers[(i * names.length) + j] = data;
				}

			}
			output.close();
			output = new FileOutputStream(new File(
					"skeys_phenotype_table"));
			for (i = 0; i < phenotypeSize; i++) {
				for (int j = 0; j < names.length; j++) {
					IOUtils.write(phenSkeys[(i * names.length) + j], output);
				}

			}
			output.close();
			byte[][] phenXored = new byte[names.length * phenotypeSize][phenSkeys[0].length];
			for (i = 0; i < names.length * phenotypeSize; i++) {
				for (int j = 0; j < phenSkeys[0].length; j++) {
					phenXored[i][j] = (byte) (phenSkeys[i][j] ^ phenCiphers[i][j]);
				}
			}
			writer = new PrintWriter("test_phenotype_table.txt", "UTF-8");
			for (i = 0; i < phenotypeSize; i++) {
				for (int j = 0; j < names.length; j++) {
					byte[] data = phenXored[(i * names.length) + j];
					writer.println(names[j] + ";" + new String(data));
				}

			}
			writer.close();
			ancestries = new int[ancestryGroupsSize][names.length];
			for (i = 0; i < ancestryGroupsSize; i++) {
				for (int j = 0; j < names.length; j++) {
					ancestries[i][j] = rand.nextInt(2);
					if (ancestries[i][j] == 2) {
						System.out.println("PROBLEM\n");
					}
				}
			}
			ancIVs = new byte[names.length * ancestryGroupsSize][];
			ancKeys = new Key[names.length * ancestryGroupsSize];
			ancSkeys = new byte[names.length * ancestryGroupsSize][];
			ancCiphers = new byte[names.length * ancestryGroupsSize][];
			for (i = 0; i < names.length * ancestryGroupsSize; i++) {
				ancKeys[i] = Crypto.generateKey();
				ancIVs[i] = Crypto.getIV();
				ancSkeys[i] = Crypto.SEnc(ancKeys[i], dump, ancIVs[i]);
			}
			output = new FileOutputStream(new File(
					"ancestry_table"));
			for (i = 0; i < ancestryGroupsSize; i++) {
				for (int j = 0; j < names.length; j++) {
					byte[] tempData = new byte[1];
					tempData[0] = new Integer(ancestries[i][j]).byteValue();
					byte[] data = Crypto.SEnc(ancKeys[(i * names.length) + j], tempData, ancIVs[(i * names.length)
							+ j]);
					IOUtils.write(data, output);
					ancCiphers[(i * names.length) + j] = data;
				}

			}
			output.close();
			output = new FileOutputStream(new File(
					"skeys_ancestry_table"));
			for (i = 0; i < ancestryGroupsSize; i++) {
				for (int j = 0; j < names.length; j++) {
					IOUtils.write(ancSkeys[(i * names.length) + j], output);
				}

			}
			output.close();
			byte[][] ancXored = new byte[names.length * ancestryGroupsSize][ancSkeys[0].length];
			for (i = 0; i < names.length * ancestryGroupsSize; i++) {
				for (int j = 0; j < ancSkeys[0].length; j++) {
					ancXored[i][j] = (byte) (ancSkeys[i][j] ^ ancCiphers[i][j]);
				}
			}
			writer = new PrintWriter("test_ancestry_table.txt", "UTF-8");
			for (i = 0; i < ancestryGroupsSize; i++) {
				for (int j = 0; j < names.length; j++) {
					byte[] data = ancXored[(i * names.length) + j];
					writer.println(names[j] + ";" + new String(data));
				}

			}
			writer.close();
			
			/*ancestries = new int[names.length][ancestryGroupsSize];
			for (i = 0; i < names.length; i++) {
				for (int j = 0; j < ancestryGroupsSize; j++) {
					ancestries[i][j] = rand.nextInt(2);
					if (ancestries[i][j] == 2) {
						System.out.println("PROBLEM\n");
					}
				}
			}*/
		} catch (FileNotFoundException e) {
			System.err.println("ERROR : File data200.vcf not found !");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
