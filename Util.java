package cristianMarian.radu.ism.sap;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

public class Util {
	
	public static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}
	
	public static String getHex(byte[] array) {
		String output = "";
		for(byte value : array) {
			output += String.format("%02x", value);
		}
		return output;
	}
	
	public static boolean checkProvider(String providerName) {
		Provider provider = Security.getProvider(providerName);
		if(provider != null) {
			return true;
		}
		else{
			return false;
		}
	}
	
	public static void loadBCProvider() {
		Provider provider = Security.getProvider("BC");
		if(provider == null) {
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		}
	}
	
	public static byte[] getRandomBytes(int noBytes, byte[] seed) throws NoSuchAlgorithmException {
		SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
		if (seed != null) {
			secureRandom.setSeed(seed);
		}
		byte[] randomBytes = new byte[noBytes];
		secureRandom.nextBytes(randomBytes);

		return randomBytes;
	}
}
