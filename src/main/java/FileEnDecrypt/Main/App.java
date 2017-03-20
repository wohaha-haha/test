package FileEnDecrypt.Main;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Enumeration;
import java.util.Map;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.apache.commons.codec.binary.Base64;

/**
 * Hell54247254
 *
 */
public class App {
	public static String keyGenerator_Model = "AES"; // optional value AES/DES/DESede
	public static String CIPHER_ALGORITHM = "AES"; // optional value
	public static Key getSecretKey(String key) throws Exception {
		SecretKey securekey = null;
		if (key == null) {
			key = "";
		}
		KeyGenerator keyGenerator = KeyGenerator.getInstance(keyGenerator_Model);
		keyGenerator.init(new SecureRandom(key.getBytes()));
		securekey = keyGenerator.generateKey();
		return securekey;
	}
	public static void main(String[] args) throws Exception {
		System.out.println("Hello World!");
		 Properties pps = new Properties();
	    pps.load(new InputStreamReader (new FileInputStream(System.getProperty("user.dir")+"/config/FileEnDecrypt.properties"),"UTF-8"));
		String password = pps.getProperty("password");
		String flag = pps.getProperty("model");
		String fileName = pps.getProperty("filePath");
		byte[] encryptResult;
		byte[] decryptResult;
		File inFile;
		File outFile;
		BufferedOutputStream out;
		BufferedInputStream in;

		byte[] buffer = null;
		try {
			if (flag.equalsIgnoreCase("E")) {
				inFile = new File(fileName);
				in = new BufferedInputStream(new FileInputStream(fileName));
				buffer = new byte[(int) inFile.length()];
				String tmpFileName = inFile.getName();
				encryptResult = encrypt(tmpFileName.getBytes(), password);
				String tmpFile = inFile.getParent() + "/" + System.currentTimeMillis() + "." + encryptResult.length;
				outFile = new File(tmpFile);
				outFile.createNewFile();
				out = new BufferedOutputStream(new FileOutputStream(outFile));
				out.write(encryptResult);
				in.read(buffer);
				encryptResult = encrypt(buffer, password);
				out.write(encryptResult);
				in.close();
				out.flush();
				out.close();
			}
			if (flag.equalsIgnoreCase("D")) {
				inFile = new File(fileName);
				in = new BufferedInputStream(new FileInputStream(fileName));
				String tmpFileName = inFile.getName();
				int fileLen = Integer.valueOf(tmpFileName.split("\\.")[1]);
				buffer = new byte[fileLen];
				in.read(buffer);
				decryptResult = decrypt(buffer, password);
				String tmpFile = inFile.getParent() + "/" + new String(decryptResult) + "x";
				outFile = new File(tmpFile);
				outFile.createNewFile();
				buffer = new byte[(int) (inFile.length() - fileLen)];
				out = new BufferedOutputStream(new FileOutputStream(outFile));
				in.read(buffer);
				decryptResult = decrypt(buffer, password);
				out.write(decryptResult);
				in.close();
				out.flush();
				out.close();
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * 加密
	 * 
	 * @param content
	 *            需要加密的内容
	 * @param password
	 *            加密密码
	 * @return
	 */
	public static byte[] encrypt(byte[] byteContent, String password) {
		try {
			SecureRandom sr = new SecureRandom();
			Key securekey = getSecretKey(password);
			Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
			cipher.init(Cipher.ENCRYPT_MODE, securekey, sr);
			byte[] result = Base64.encodeBase64(cipher.doFinal(byteContent));
			return result; // 加密
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	/**
	 * 解密
	 * 
	 * @param content
	 *            待解密内容
	 * @param password
	 *            解密密钥
	 * @return
	 */
	public static byte[] decrypt(byte[] content, String password) {
		try {
			SecureRandom sr = new SecureRandom();
			Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
			Key securekey = getSecretKey(password);
			cipher.init(Cipher.DECRYPT_MODE, securekey, sr);
			byte[] result = cipher.doFinal(Base64.decodeBase64(content));
			return result; // 加密
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

}
