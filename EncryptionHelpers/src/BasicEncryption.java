package live.pinger.shibboleth.helper;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.SecureRandom;
import java.security.Key;
import org.apache.commons.lang3.RandomStringUtils;
import com.warrenstrange.googleauth.GoogleAuthenticator;


public class BasicEncryption{

private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
private static GoogleAuthenticator gAuth;

private static String algo, mode, padding;

public static void main(String args[]) throws Exception{

	String key, plaintext, encryptedSeed, oldkey, newkey, argument, iv;
	int token;

	algo = new String("Blowfish");
	mode = new String("ECB");
	padding = new String("PKCS5Padding");



	if(args.length < 2){

		System.out.println("This program must be run with command line arguments");
		System.out.println("At the very least, you must specify a key to generate a new seed/encrypted value");
		System.out.println("java -cp... live.pinger.helpers.BasicEncryption --key somekey\n\n");
		String instructions = new String("Other arguments include:\n");
		instructions += "	-- encryptedSeed SOMEENCRYPTEDSEEDVALUE\n";
		instructions += "		Used when performing seed decryption\n\n";
		instructions += "	-- oldkey oldkeyvalue\n";
		instructions += "		The old key to use when performing key rollover\n\n";
		instructions += "	-- newkey newkeyvalue\n";
		instructions += "		The new key to use when performing key rollover\n\n";
		instructions += "	-- quiet\n";
		instructions += "		Quietly output only the action that was performed\n\n";
		instructions += "	-- algo\n";
		instructions += "		Define the algorithm used for encryption/decryption\n";
		instructions += "		Defaults to \"Blowfish\"\n\n";
		instructions += "	-- mode\n";
		instructions += "		Define the mode used for encryption/decryption\n";
		instructions += "		Defaults to \"ECB\"\n\n";


		System.out.println(instructions);

	}

	else if(args.length == 2){

		key = new String();

		for(int i = 0; i < args.length; i++){
			argument = args[i].toLowerCase();
			if(argument.indexOf("--") == 0){
				//System.out.println("Processing: " + argument.substring(2));
				switch(argument.substring(2)){
					case "key":
						key = args[i+1];
						break;
				}
			}
		}



		System.err.println("No seed provided, generating a new one");
		//generateKey2();
		//plaintext = "G24YUKCHHXRDWCPR";
		plaintext = generateKey2();
		iv = generateKey2();


		System.err.println("The plaintext (for the client device):  " + plaintext);
		String cipherText = encrypt2(plaintext, key);
		System.err.println("The ciphertext (store in the directory): totpseed=(" + cipherText + ")");
		System.err.println("The plaintext  (to verify decryption):  " + decrypt2(cipherText, key));
		System.out.println("otpauth://totp/Shibboleth?secret=" + plaintext);
	}
	else{
		encryptedSeed = new String();
		oldkey = new String();
		newkey = new String();
		plaintext = new String();
		token = 0;
		key = new String();
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
					case "key":
						key = args[i+1];
						break;
					case "algo":
						algo = args[i+1];
						break;
					case "mode":
						mode = args[i+1];
						break;
					case "padding":
						padding = args[i+1];
						break;
				}
			}
		}

		if(tokenValidate){
			if(validateToken(plaintext,token)){
				System.out.println("true");
				if(!key.equals("")){
					System.out.println("totpseed=(" + encrypt2(plaintext,key) + ")");
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
			System.out.println("Encrypted seed provided:  " + encryptedSeed);
			plaintext = decrypt2(encryptedSeed, key);
		}
		
		String newCipher = encrypt2(plaintext, key);
		
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
    SecretKeySpec key = new SecretKeySpec(strkey.getBytes("UTF-8"), algo);
        Cipher cipher = Cipher.getInstance(algo + "/" + mode + "/" + padding);
        if ( cipher == null || key == null) {
            throw new Exception("Invalid key or cypher");
        }
        cipher.init(Cipher.ENCRYPT_MODE, key);

	String ciphertext = new String(bytesToHex(cipher.doFinal(plaintext.getBytes("UTF-8"))));

	if(cipher.getIV() != null){
		System.out.println("Used IV");
		return new String(bytesToHex(cipher.getIV()) + ":" + ciphertext);
	}
	else{
		return ciphertext;
	}

}

public static String decrypt2(String ciphertext, String strkey) throws Exception{

	//define a key (get the key from the arguments)
	//  Use the global algorithm defined above
	//  Same for the cipher (global algo, mode, and padding)
	SecretKeySpec key = new SecretKeySpec(strkey.getBytes("UTF-8"), algo);
	Cipher cipher = Cipher.getInstance(algo + "/" + mode + "/" + padding);
         
	//Declare the variable for the decrypted byte array
	byte[] decrypted;

	//If there's a : in the string, we have an ecrypted seed stored as
	//  iv:ciphertext
	//  We'll need to split it apart and then decrypt it
	if(ciphertext.indexOf(":") != -1){
		String iv = ciphertext.split(":")[0];
		String ct = ciphertext.split(":")[1];

		IvParameterSpec ivParams = new IvParameterSpec(hexToBytes(iv));
		cipher.init(Cipher.DECRYPT_MODE, key, ivParams);

		decrypted = cipher.doFinal(hexToBytes(ct));
	}

	//If there was no iv defined, then just decrypt it (mode should be ECB)
	else{
		cipher.init(Cipher.DECRYPT_MODE, key);
		decrypted = cipher.doFinal(hexToBytes(ciphertext));
	}

	//Return the decrypted value
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


/**
 * Encodes data into an AEAD-encrypted blob, gzip(exp|data)
 *
 * <ul>
 * <li>exp = expiration time of the data; 8 bytes; Big-endian</li>
 * <li>data = the data; a UTF-8-encoded string</li>
 * </ul>
 *
 * <p>As part of encryption, the key alias is supplied as additional authenticated data
 * to the cipher. Afterwards, the encrypted data is prepended by the IV and then again by the alias
 * (in length-prefixed UTF-8 format), which identifies the key used. Finally the result is base64-encoded.</p>
 *
 * @param data the data to wrap
 * @param exp expiration time
 * @return the encoded blob
 * @throws DataSealerException if the wrapping operation fails
 */
@Nonnull public String wrap(@Nonnull @NotEmpty final String data, @Nonnull final Instant exp)
        throws DataSealerException {

    if (data == null || data.length() == 0) {
        throw new IllegalArgumentException("Data must be supplied for the wrapping operation");
    }

    try {
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        final byte[] iv = new byte[cipher.getBlockSize()];
        random.nextBytes(iv);
        final GCMParameterSpec params = new GCMParameterSpec(128, iv);

        final Pair<String,SecretKey> defaultKey = keyStrategy.getDefaultKey();

        cipher.init(Cipher.ENCRYPT_MODE, defaultKey.getSecond(), params);
        cipher.updateAAD(defaultKey.getFirst().getBytes());

        final ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        final GZIPOutputStream compressedStream = new GZIPOutputStream(byteStream);
        final DataOutputStream dataStream = new DataOutputStream(compressedStream);

        dataStream.writeLong(exp.toEpochMilli());

        int count = 0;
        int start = 0;
        final int dataLength = data.length();
        while (start < dataLength) {
            dataStream.writeUTF(data.substring(start, start + Math.min(dataLength - start, CHUNK_SIZE)));
            start += Math.min(dataLength - start, CHUNK_SIZE);
            log.trace("Wrote chunk #{} to output stream", ++count);
        }

        dataStream.flush();
        compressedStream.flush();
        compressedStream.finish();
        byteStream.flush();

        final byte[] plaintext = byteStream.toByteArray();

        final byte[] encryptedData = new byte[cipher.getOutputSize(plaintext.length)];
        int outputLen = cipher.update(plaintext, 0, plaintext.length, encryptedData, 0);
        outputLen += cipher.doFinal(encryptedData, outputLen);

        final ByteArrayOutputStream finalByteStream = new ByteArrayOutputStream();
        final DataOutputStream finalDataStream = new DataOutputStream(finalByteStream);
        finalDataStream.writeUTF(defaultKey.getFirst());
        finalDataStream.write(iv);
        finalDataStream.write(encryptedData, 0, outputLen);
        finalDataStream.flush();
        finalByteStream.flush();

        return new String(encoder.encode(finalByteStream.toByteArray()), StandardCharsets.UTF_8);

    } catch (final Exception e) {
        log.error("Exception wrapping data: {}", e.getMessage());
        throw new DataSealerException("Exception wrapping data", e);
    }

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
