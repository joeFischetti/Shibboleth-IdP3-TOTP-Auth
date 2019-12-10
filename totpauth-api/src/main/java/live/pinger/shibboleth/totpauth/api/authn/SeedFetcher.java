package live.pinger.shibboleth.totpauth.api.authn;

import live.pinger.shibboleth.totpauth.api.authn.context.TokenUserContext;

import org.opensaml.profile.context.ProfileRequestContext;

@SuppressWarnings("rawtypes")
public interface SeedFetcher {
	
	public void getSeed(String username, TokenUserContext tokenUserCtx, String logPrefix,
			ProfileRequestContext profileRequestContext);

}
