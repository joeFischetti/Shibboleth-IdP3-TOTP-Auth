package live.pinger.shibboleth.totpauth.authn.impl.seed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import live.pinger.shibboleth.totpauth.api.authn.SeedFetcher;
import live.pinger.shibboleth.totpauth.api.authn.context.TokenUserContext;
import org.opensaml.profile.context.ProfileRequestContext;
import javax.annotation.Nonnull;


public class DummySeedFetcher implements SeedFetcher {
	private final Logger log = LoggerFactory.getLogger(DummySeedFetcher.class);


	public DummySeedFetcher() {
		// TODO Auto-generated constructor stub
	}

	@Override
	public void getSeed(String username, TokenUserContext tokenUserCtx, String logPrefix,
			@Nonnull final ProfileRequestContext profileRequestContext){

		// Dummy seed for testing
		tokenUserCtx.setTokenSeed("G24YUKCHHXRDWCPR");
		log.info("Returning default seed for user {}", username);

	}


}
