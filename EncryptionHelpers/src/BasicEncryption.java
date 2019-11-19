package helper;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.SecureRandom;
import java.security.Key;
import org.apache.commons.lang3.RandomStringUtils;


public class BasicEncryption{

private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();


public static void main(String args[]) throws Exception{

	String plaintext;

	if(args.length == 0){
		System.err.println("No seed provided, generating a new one");
		//generateKey2();
		//plaintext = "G24YUKCHHXRDWCPR";
		plaintext = generateKey2();
	}
	else{

		System.err.println("New seed provided as argument:  " + args[0]);
		plaintext = new String(args[0]);
	}
	
	System.err.println("The plaintext (for the client device):  " + plaintext);

	String cipherText = encrypt2(plaintext, "somerandomkey");

	//System.out.println("The ciphertext:  " + ASCIItoHEX(cipherText));
	System.err.println("The ciphertext (store in the directory): totpseed=(" + cipherText + ")");

	//String ct = "FE599E8D0E176594181B4326EBDB84307E83056FB0668CC6";

	//System.out.println("The ciphertext: " + HEXtoASCII(ct));
	System.err.println("The plaintext  (to verify decryption):  " + decrypt2(cipherText, "somerandomkey"));

	System.out.println("otpauth://totp/Shibboleth?secret=" + plaintext);

}

public static String encrypt2(String plaintext, String strkey) throws Exception{
   SecretKeySpec key = new SecretKeySpec(strkey.getBytes("UTF-8"), "Blowfish");
        Cipher cipher = Cipher.getInstance("Blowfish");
        if ( cipher == null || key == null) {
            throw new Exception("Invalid key or cypher");
        }
        cipher.init(Cipher.ENCRYPT_MODE, key);
	return bytesToHex(cipher.doFinal(plaintext.getBytes("UTF-8")));


}

public static String decrypt2(String ciphertext, String strkey) throws Exception{

	SecretKeySpec key = new SecretKeySpec(strkey.getBytes("UTF-8"), "Blowfish");
         Cipher cipher = Cipher.getInstance("Blowfish");
         cipher.init(Cipher.DECRYPT_MODE, key);
         byte[] decrypted = cipher.doFinal(hexToBytes(ciphertext));
         return new String(decrypted);


}	

public static byte[] encrypt(String strClearText,String strKey) throws Exception{
	String strData="";
	byte[] encrypted;
	
	try {
		SecretKeySpec skeyspec=new SecretKeySpec(strKey.getBytes(),"Blowfish");
		Cipher cipher=Cipher.getInstance("Blowfish");
		cipher.init(Cipher.ENCRYPT_MODE, skeyspec);
		 encrypted=cipher.doFinal(strClearText.getBytes());
		strData=new String(encrypted);
		//strData = bytesToHex(encrypted);
		
	} catch (Exception e) {
		e.printStackTrace();
		throw new Exception(e);
	}
	return encrypted;
}



public static String decrypt(String strEncrypted,String strKey) throws Exception{
	String strData="";
	
	try {
		SecretKeySpec skeyspec=new SecretKeySpec(strKey.getBytes(),"Blowfish");
		Cipher cipher=Cipher.getInstance("Blowfish");
		cipher.init(Cipher.DECRYPT_MODE, skeyspec);
		byte[] decrypted=cipher.doFinal(strEncrypted.getBytes());
		strData=new String(decrypted);
		//strData = bytesToHex(decrypted);
		
	} catch (Exception e) {
		e.printStackTrace();
		throw new Exception(e);
	}
	return strData;
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
