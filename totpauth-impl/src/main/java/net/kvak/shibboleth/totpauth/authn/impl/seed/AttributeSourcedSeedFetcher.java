package net.kvak.shibboleth.totpauth.authn.impl.seed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.ArrayList;
import java.util.Map;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;


import net.kvak.shibboleth.totpauth.api.authn.SeedFetcher;
import net.kvak.shibboleth.totpauth.api.authn.context.TokenUserContext;
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
	private final Logger log = LoggerFactory.getLogger(LdapSeedFetcher.class);
	private String seedAttribute;

	//private AttributeResolver attrRes;
	private ReloadableService<AttributeResolver> attrRes;


	public void setAttrRes(ReloadableService attrRes){
		this.attrRes = attrRes;
	}


	public AttributeSourcedSeedFetcher(String seedAttribute) {
		this.seedAttribute = seedAttribute;

	}

	@Override
	public void getSeed(String username, TokenUserContext tokenUserCtx, 
			@Nonnull final ProfileRequestContext profileRequestContext) {

		//No log Prefix was defined, just pass a prefix here:
		getSeed(username, tokenUserCtx, "LOG PREFIX UNDEFINED", profileRequestContext);


	}

	@Override
	public void getSeed(String username, TokenUserContext tokenUserCtx, String logPrefix,
			@Nonnull final ProfileRequestContext profileRequestContext){


		AttributeResolutionContext resCtx = (AttributeResolutionContext)profileRequestContext.getSubcontext(AttributeResolutionContext.class, true);
		resCtx.setPrincipal(username);
		
		log.info("{} Performing attribute resolution for user {}", logPrefix, username);
		log.info("{} Looking for attribute defined in xml:  {}", logPrefix, seedAttribute);
		ArrayList<String> seedAttributeList = new ArrayList<String>();
		seedAttributeList.add(seedAttribute);

		resCtx.setRequestedIdPAttributeNames(seedAttributeList);


		//resCtx.getRequestedIdPAttributeNames().add(seedAttribute);
		resCtx.resolveAttributes(attrRes);

		Map<String,IdPAttribute> attributeResults = resCtx.getResolvedIdPAttributes();
		// Check for an attribute that authorizes use of first factor.
		//IdPAttribute attribute = resCtx.getResolvedIdPAttributes();
		//getResolvedIdPAttributes().get("ibm-allgroups");
		
		//valueType =  Java.type("net.shibboleth.idp.attribute.StringAttributeValue");

		IdPAttribute attribute = attributeResults.get(seedAttribute);

		if (attribute != null) {

			for(int i = 0; i < attribute.getValues().size(); i++){
				log.info("{} Attribute Value found:  {}", logPrefix, attribute.getValues().get(i).getDisplayValue());
				if( attribute.getValues().get(i).getDisplayValue().indexOf("totpseed") != -1){
					int seedFieldLength = attribute.getValues().get(i).getDisplayValue().length() - 1;
					String seedEncrypted = attribute.getValues().get(i).getDisplayValue().substring(10,seedFieldLength);
					//tokenUserCtx.setTokenSeed(attribute.getValues().get(i).getDisplayValue().substring(10,seedFieldLength));

					//log.info("{} Found seed (hex) value:  {}", logPrefix, attribute.getValues().get(i).getDisplayValue().substring(10,seedFieldLength));
					log.info("{} Found seed (encrypted) value:  {}", logPrefix, seedEncrypted);

					try{
						log.info("{} ASCII seed equivalent:  {}", logPrefix, decrypt2(seedEncrypted, "somerandomkey"));
						tokenUserCtx.setTokenSeed(decrypt2(seedEncrypted, "somerandomkey"));
					}
					catch(Exception e){
					}



					break;
				}

			}
		}

		else{
			log.info("{} No attributes found in local variable", logPrefix);
		}


		profileRequestContext.removeSubcontext(resCtx);

		//tokenUserCtx.setTokenSeed("G24YUKCHHXRDWCPR");
		tokenUserCtx.setTokenSeed("DEFAULTDEFAULTDE");

		log.info("{} Returning AttibuteSourced seed for user {}", logPrefix, username);


	}



	private String decrypt2(String ciphertext, String strkey) throws Exception{

		SecretKeySpec key = new SecretKeySpec(strkey.getBytes("UTF-8"), "Blowfish");
		Cipher cipher = Cipher.getInstance("Blowfish");
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] decrypted = cipher.doFinal(hexToBytes(ciphertext));
		return new String(decrypted);

	}

	private byte[] hexToBytes(String s) throws Exception{
		int len = s.length();
		byte[] data = new byte[len/2];

		for(int i = 0; i < len; i+=2){
			data[i/2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
		}

		return data;
	}



}
