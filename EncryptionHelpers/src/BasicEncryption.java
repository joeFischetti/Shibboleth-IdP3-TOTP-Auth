package live.pinger.shibboleth.helper;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.SecureRandom;
import java.security.Key;
import org.apache.commons.lang3.RandomStringUtils;
import com.warrenstrange.googleauth.GoogleAuthenticator;


public class BasicEncryption{

private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
private static GoogleAuthenticator gAuth;



public static void main(String args[]) throws Exception{

	String plaintext, encryptedSeed, oldkey, newkey, argument, iv;
	int token;

	if(args.length == 0){
		System.err.println("No seed provided, generating a new one");
		//generateKey2();
		//plaintext = "G24YUKCHHXRDWCPR";
		plaintext = generateKey2();
		iv = generateKey2();


		System.err.println("The plaintext (for the client device):  " + plaintext);
		System.err.println("The iv for this run is:  " + iv);
		String cipherText = encrypt2(plaintext, "somerandomkey");
		System.err.println("The ciphertext (store in the directory): totpseed=(" + cipherText + ")");
		System.err.println("The plaintext  (to verify decryption):  " + decrypt2(cipherText, "somerandomkey"));
		System.out.println("otpauth://totp/Shibboleth?secret=" + plaintext);


	}
	else{
		encryptedSeed = new String();
		oldkey = new String();
		newkey = new String();
		plaintext = new String();
		token = 0;
		boolean quiet = false;
		boolean tokenValidate = false;

		gAuth = new GoogleAuthenticator();

		for(int i = 0; i < args.length; i++){
			argument = args[i].toLowerCase();
			if(argument.indexOf("--") == 0){
				//System.out.println("Processing: " + argument.substring(2));
				switch(argument.substring(2)){
					case "encryptedseed":
						encryptedSeed = args[i+1];
						//System.out.println("Encrypted Seed provided:  " + encryptedSeed);
						break;
					case "oldkey":
						oldkey = args[i+1];
						//System.out.println("Old Key Provided: " + oldkey);
						break;
					case "newkey":
						newkey = args[i+1];
						//System.out.println("New Key Privided: " + newkey);
						break;
					case "quiet":
						quiet = true;
						break;
					case "tokenvalidate":
						tokenValidate = true;
						break;
					case "seed":
						plaintext = args[i+1];
						break;
					case "token":
						token = Integer.parseInt(args[i+1]);
						break;
				}
			}
		}

		if(tokenValidate){
			if(validateToken(plaintext,token)){
				System.out.println("true");
				if(!newkey.equals("")){
					System.out.println("totpseed=(" + encrypt2(plaintext,newkey) + ")");
				}
			}
			else{
				System.out.println("false");
			}
			return;
		}

		if(encryptedSeed.equals("")){
			//System.out.println("No encrypted seed provided, generating new seed");
			plaintext = generateKey2();
		}
		else{
			plaintext = decrypt2(encryptedSeed, oldkey);
		}
		
		String newCipher = encrypt2(plaintext, newkey);
		
		if(!quiet){
			System.out.println(plaintext);
			System.out.println("totpseed=(" + newCipher + ")");
		}
		else{
			System.out.println(newCipher);
		}
	}
	
}

public static String encrypt2(String plaintext, String strkey) throws Exception{
   SecretKeySpec key = new SecretKeySpec(strkey.getBytes("UTF-8"), "Blowfish");
        Cipher cipher = Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
        if ( cipher == null || key == null) {
            throw new Exception("Invalid key or cypher");
        }
        cipher.init(Cipher.ENCRYPT_MODE, key);
	return bytesToHex(cipher.doFinal(plaintext.getBytes("UTF-8")));


}

/*public static String encryptAES(String plaintext, String strkey, String iv) throws Exception{
    SecretKeySpec key = new SecretKeySpec(strkey.getBytes("UTF-8"), "AES");
    Cipher cipher = Cipher.getInstance("AES");
    if(cipher == null || key == null || iv == null){
        throw new Exception("Invalid key, cipher, or iv");
    }
    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    return bytesToHex(cipher.doFinal(plaintext.getBytes("UTF-8")));
}
*/
public static String decrypt2(String ciphertext, String strkey) throws Exception{

	SecretKeySpec key = new SecretKeySpec(strkey.getBytes("UTF-8"), "Blowfish");
         Cipher cipher = Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
         cipher.init(Cipher.DECRYPT_MODE, key);
         byte[] decrypted = cipher.doFinal(hexToBytes(ciphertext));
         return new String(decrypted);


}	

public static boolean validateToken(String seed, int token) {
	System.out.println("seed: " + seed + " and token: " + token);
	if (seed.length() == 16) {
		return gAuth.authorize(seed, token);
	}
	return false;
}

public static byte[] hexToBytes(String s) {
                int len = s.length();
                byte[] data = new byte[len/2];

                for(int i = 0; i < len; i+=2){
                    data[i/2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
                }

                return data;
            }


public static String bytesToHex(byte[] bytes) {
    char[] hexChars = new char[bytes.length * 2];
    for (int j = 0; j < bytes.length; j++) {
        int v = bytes[j] & 0xFF;
        hexChars[j * 2] = HEX_ARRAY[v >>> 4];
        hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
    }
    return new String(hexChars);
}

    public static String ASCIItoHEX(String ascii) 
    { 
        // Initialize final String 
        String hex = ""; 
  
        // Make a loop to iterate through 
        // every character of ascii string 
        for (int i = 0; i < ascii.length(); i++) { 
  
            // take a char from 
            // position i of string 
            char ch = ascii.charAt(i); 
  
            // cast char to integer and 
            // find its ascii value 
            int in = (int)ch; 
  
            // change this ascii value 
            // integer to hexadecimal value 
            String part = Integer.toHexString(in); 
  
            // add this hexadecimal value 
            // to final string. 
            hex += part; 
        } 
        // return the final string hex 
        return hex; 
    } 


    public static String HEXtoASCII(String hex){

      if(hex.length()%2!=0){
         System.err.println("Invlid hex string.");
	 System.out.println("Length: " + hex.length());
         return "Invalid";
      }
      
      StringBuilder builder = new StringBuilder();

      for (int i = 0; i < hex.length(); i = i + 2) {
         // Step-1 Split the hex string into two character group
         String s = hex.substring(i, i + 2);
         // Step-2 Convert the each character group into integer using valueOf method
         int n = Integer.valueOf(s, 16);
         // Step-3 Cast the integer value to char
         builder.append((char)n);
      }


        return builder.toString();
    }


public static String generateKey() throws Exception{
      //Creating a KeyGenerator object
      KeyGenerator keyGen = KeyGenerator.getInstance("DESede");
      
      //Creating a SecureRandom object
      SecureRandom secRandom = new SecureRandom();
      
      //Initializing the KeyGenerator
      keyGen.init(secRandom);
      
      //Creating/Generating a key
      Key key = keyGen.generateKey();
      
      System.out.println(key.getEncoded());      
      //Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");      
      //cipher.init(cipher.ENCRYPT_MODE, key);      

      //String msg = new String("Hi how are you");
      //byte[] bytes = cipher.doFinal(msg.getBytes());      
      //System.out.println(bytes);      


	return "done";
   }


public static String generateKey2(){

    int length = 16;
    boolean useLetters = true;
    boolean useNumbers = false;
    String generatedString = RandomStringUtils.random(length, useLetters, useNumbers);
 
    //System.out.println(generatedString.toUpperCase());

	return generatedString.toUpperCase();

}


}
