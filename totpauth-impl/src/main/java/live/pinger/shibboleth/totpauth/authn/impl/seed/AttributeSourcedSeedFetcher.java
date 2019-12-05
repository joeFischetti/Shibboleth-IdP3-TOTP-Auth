package live.pinger.shibboleth.totpauth.authn.impl.seed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.ArrayList;
import java.util.Map;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import live.pinger.shibboleth.totpauth.api.authn.SeedFetcher;
import live.pinger.shibboleth.totpauth.api.authn.context.TokenUserContext;
import org.opensaml.profile.context.ProfileRequestContext;
import javax.annotation.Nonnull;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;

import net.shibboleth.idp.attribute.ScopedStringAttributeValue;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.attribute.context.AttributeContext;
import net.shibboleth.idp.attribute.resolver.context.AttributeResolutionContext;
import net.shibboleth.idp.attribute.resolver.AttributeResolver;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.utilities.java.support.service.ReloadableService;


public class AttributeSourcedSeedFetcher implements SeedFetcher {

	//Set up the logger
	private final Logger log = LoggerFactory.getLogger(LdapSeedFetcher.class);

	//Local variables for attribute resolution
	//  seedAttribute - is the attribute that stores the seed
	//  encryptionKey - is the stringvariable used for encrypting (in this case decrypting)
	//  	they key that was retrieved from the directory
	//  attrRes - the attribute resolver service
	private String seedAttribute;
	private String encryptionKey;
	private ReloadableService<AttributeResolver> attrRes;

	//public AttributeSourcedSeedFetcher(String seedAttribute) {
	//	this.seedAttribute = seedAttribute;
	//}
	
	//Setter methods used by spring
	public void setSeedAttribute(String seedAttribute){
		this.seedAttribute = seedAttribute;
	}
	public void setEncryptionKey(String encryptionKey){
		this.encryptionKey = encryptionKey;
	}
	public void setAttrRes(ReloadableService attrRes){
		this.attrRes = attrRes;
	}


	@Override
	public void getSeed(String username, TokenUserContext tokenUserCtx, String logPrefix,
			@Nonnull final ProfileRequestContext profileRequestContext){

		//Define the AttributeResolutionContext so we can resolve attributes using the IdP
		AttributeResolutionContext resCtx = (AttributeResolutionContext)profileRequestContext.getSubcontext(AttributeResolutionContext.class, true);

		//Set the principal for the Attributeresolver to the username
		resCtx.setPrincipal(username);

		//Log output	
		log.debug("{} Performing attribute resolution for user {}", logPrefix, username);
		log.debug("{} Looking for attribute defined in xml:  {}", logPrefix, seedAttribute);

		//The resolver needs to receive an arraylist of values to look up.  Put the attrname
		//	into an arraylist, and pass that to the resolver
		ArrayList<String> seedAttributeList = new ArrayList<String>();
		seedAttributeList.add(seedAttribute);
		resCtx.setRequestedIdPAttributeNames(seedAttributeList);

		//Resolve the attributes
		resCtx.resolveAttributes(attrRes);

		//Get the resolved attributes and put them in a map
		Map<String,IdPAttribute> attributeResults = resCtx.getResolvedIdPAttributes();

		//From the map, get the attribute that matches the one we're looking for
		IdPAttribute attribute = attributeResults.get(seedAttribute);

		//If we actually got attributes back, we'll need to look through them
		//	for a valid value.  In our case, it's totpseed=(...)
		if (attribute != null) {

			//Step through the values we got back
			for(int i = 0; i < attribute.getValues().size(); i++){

				//Log output for debugging
				log.debug("{} Attribute Value found:  {}", logPrefix, attribute.getValues().get(i).getDisplayValue());

				//If the attribute contains our tag (totpseed=(...))
				if( attribute.getValues().get(i).getDisplayValue().indexOf("totpseed") != -1){

					//seedEncrypted is everything between the (...) after totpseed
					String seedEncrypted = extractSeed(attribute.getValues().get(i).getDisplayValue());

					//Log output that we found it
					log.debug("{} Found seed (encrypted) value:  {}", logPrefix, seedEncrypted);

					//Try to decrypt the seed using the encryption key from the config file
					try{
						//Debugging output
						log.debug("{} Unencrypted Seed Value  {}", logPrefix, decrypt2(seedEncrypted, encryptionKey));

						//Set the tokenUserCtx token seed to the decrypted seed.
						tokenUserCtx.setTokenSeed(decrypt2(seedEncrypted, encryptionKey));
					}

					//Handle a failure to decrypt key
					catch(Exception e){
						log.debug("{} Error while decrypting seed value: {}", logPrefix, e);
					}
				}
			}
		}

		else{
			//Log output
			log.debug("{} No attributes found in local variable", logPrefix);
		}

		//Unpin the attribute resolver so it can be used again
		profileRequestContext.removeSubcontext(resCtx);

		//Setters for debugging purposes
		//tokenUserCtx.setTokenSeed("G24YUKCHHXRDWCPR");
		//tokenUserCtx.setTokenSeed("DEFAULTDEFAULTDE");

		//Log output
		log.info("{} Returning AttibuteSourced seed for user {}", logPrefix, username);


	}


	//Function used to decrypt the key we got using Blowfish
	private String decrypt2(String ciphertext, String strkey) throws Exception{

		//Set the secret key that we'll use to decrypt
		SecretKeySpec key = new SecretKeySpec(strkey.getBytes("UTF-8"), "Blowfish");

		//Use the blowfish cipher
		Cipher cipher = Cipher.getInstance("Blowfish");

		//Set the mode to decryption, using the key
		cipher.init(Cipher.DECRYPT_MODE, key);

		//decrypted will be a byte array.  Our encryption scheme creates a byte
		//	array and then bytesToHex that byte array (to make it easy to store
		//	as a string or display).  We need to convert hex from the attribute back into a byte
		//	array AND THEN decrypt it
		byte[] decrypted = cipher.doFinal(hexToBytes(ciphertext));

		//Return
		return new String(decrypted);

	}

	//Converts a string in hex notation to a byte array
	private byte[] hexToBytes(String s) throws Exception{

		//Length of the string
		int len = s.length();

		//Data with length half as long as the hex string
		byte[] data = new byte[len/2];

		for(int i = 0; i < len; i+=2){
			//Read through every 2 characters in the hex string and convert them to a byte
			data[i/2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
		}

		//Return the byte array equivalent to the hex string
		return data;
	}

	//Function to extract the seed from the attribute that was passed in
	private String extractSeed(String input){
		//build a pattern to use for matching the seed
		String pattern = "(.*)totpseed=\\((.*?)\\)(.*)";
		Pattern r = Pattern.compile(pattern);

		//Matcher for the pattern to the input
		Matcher m = r.matcher(input);


		//Find the pattern in the input, and return the second capture group
		// Which based on our pattern, is the totpseed
		if(m.find( )){
			return m.group(2);
		}

		else{
			return "NoSeed";
		}
	}


}
