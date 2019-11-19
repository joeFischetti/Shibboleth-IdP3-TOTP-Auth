package net.kvak.shibboleth.totpauth.api.authn;

import net.kvak.shibboleth.totpauth.api.authn.context.TokenUserContext;

import org.opensaml.profile.context.ProfileRequestContext;

public interface SeedFetcher {
	
	public void getSeed(String username, TokenUserContext tokenUserCtx, String logPrefix,
			ProfileRequestContext profileRequestContext);

}
