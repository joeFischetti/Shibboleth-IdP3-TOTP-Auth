package net.kvak.shibboleth.totpauth.authn.impl.seed;

import net.kvak.shibboleth.totpauth.api.authn.SeedFetcher;
import net.kvak.shibboleth.totpauth.api.authn.context.TokenUserContext;
import org.opensaml.profile.context.ProfileRequestContext;
import javax.annotation.Nonnull;


public class FileBasedSeedFetcher implements SeedFetcher {

	public FileBasedSeedFetcher() {
		// TODO Auto-generated constructor stub
	}

	@Override
	public void getSeed(String username, TokenUserContext tokenUserCtx, 
			@Nonnull final ProfileRequestContext profileRequestContext) {
		// TODO Auto-generated method stub
	}

	@Override
	public void getSeed(String username, TokenUserContext tokenUserCtx, String logPrefix,
			@Nonnull final ProfileRequestContext profileRequestContext){}



}
