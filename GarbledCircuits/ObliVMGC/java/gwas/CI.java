package gwas;

import java.io.File;
import java.io.IOException;
import java.security.Key;

import org.apache.commons.io.FileUtils;

public class CI {
	
	private static Key key;
	
	public static void main(String[] args) {
		key = Crypto.generateKey();
		byte[] IV1 = Crypto.getIV();
		byte[] IV2 = Crypto.getIV();
		byte[] IV3 = Crypto.getIV();
		byte[] IV4 = Crypto.getIV();
		try {
			FileUtils.writeByteArrayToFile(new File("key"), key.getEncoded());
			FileUtils.writeByteArrayToFile(new File("IV1"), IV1);
			FileUtils.writeByteArrayToFile(new File("IV2"), IV2);
			FileUtils.writeByteArrayToFile(new File("IV3"), IV3);
			FileUtils.writeByteArrayToFile(new File("IV4"), IV4);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
