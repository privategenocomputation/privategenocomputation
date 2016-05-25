package gwas;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public class Crypto {

	public static byte[] SEnc(Key kcm, byte[] data, byte[] IV) {
		IvParameterSpec IVparam = new IvParameterSpec(IV);
		Cipher cipher;
		byte[] result = null;
		try {
			cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, kcm, IVparam);
			result = cipher.doFinal(data);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return result;
	}

	public static byte[] SDec(Key kcm, byte[] data, byte[] IV) {
		IvParameterSpec IVparam = new IvParameterSpec(IV);
		Cipher cipher;
		byte[] result = null;
		try {
			cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, kcm, IVparam);
			result = cipher.doFinal(data);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return result;
	}

	private static byte getByte() {
		Random rand = new Random();
		return new Integer(rand.nextInt()).byteValue();
	}
	
	public static byte[] getIV() {
		byte[] iv = new byte[16];
		for (int i = 0; i < 16; i++) {
			iv[i] = getByte();
		}
		return iv;
	}

	public static Key generateKey() {

		KeyGenerator generator;
		try {
			generator = KeyGenerator.getInstance("AES");
			generator.init(new SecureRandom());
			return generator.generateKey();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
	}

}
