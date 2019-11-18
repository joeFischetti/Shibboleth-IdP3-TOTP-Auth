package net.kvak.shibboleth.totpauth.authn.impl.seed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.kvak.shibboleth.totpauth.api.authn.SeedFetcher;
import net.kvak.shibboleth.totpauth.api.authn.context.TokenUserContext;

public class DummySeedFetcher implements SeedFetcher {
	private final Logger log = LoggerFactory.getLogger(LdapSeedFetcher.class);


	public DummySeedFetcher() {
		// TODO Auto-generated constructor stub
	}

	@Override
	public void getSeed(String username, TokenUserContext tokenUserCtx) {
		// Dummy seed for testing
		tokenUserCtx.setTokenSeed("G24YUKCHHXRDWCPR");
		log.info("Returning default seed for user {}", username);

	}
}
