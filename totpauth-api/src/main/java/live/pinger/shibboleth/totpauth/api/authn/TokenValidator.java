package live.pinger.shibboleth.totpauth.api.authn;

public interface TokenValidator {
	
	public boolean validateToken(String seed, int token);

}
