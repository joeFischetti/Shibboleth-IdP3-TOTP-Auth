package net.kvak.shibboleth.totpauth.authn.impl;

import java.util.ArrayList;
import java.util.Iterator;

import javax.annotation.Nonnull;
import javax.security.auth.Subject;

import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.base.Function;
import com.warrenstrange.googleauth.GoogleAuthenticator;

import net.kvak.shibboleth.totpauth.api.authn.SeedFetcher;
import net.kvak.shibboleth.totpauth.api.authn.TokenValidator;
import net.kvak.shibboleth.totpauth.api.authn.context.TokenUserContext;
import net.kvak.shibboleth.totpauth.api.authn.context.TokenUserContext.AuthState;
import net.shibboleth.idp.session.context.SessionContext;
import net.shibboleth.idp.session.context.navigate.CanonicalUsernameLookupStrategy;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.authn.AbstractValidationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.SubjectContext;
import net.shibboleth.idp.authn.context.UsernamePasswordContext;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

/**
 * Validates users TOTP token code against injected authenticator
 * 
 * An action that checks for a {@link TokenCodeContext} and directly produces an
 * {@link net.shibboleth.idp.authn.AuthenticationResult} based on submitted
 * tokencode and username
 * 
 * @author korteke
 *
 */
@SuppressWarnings({ "rawtypes", "unchecked" })
public class TotpTokenValidator extends AbstractValidationAction implements TokenValidator {

	/** Class logger. */
	@Nonnull
	@NotEmpty
	private final Logger log = LoggerFactory.getLogger(TotpTokenValidator.class);

	/** Google Authenticator **/
	@Nonnull
	@NotEmpty
	private GoogleAuthenticator gAuth;

	/** Username context for username **/
	@Nonnull
	@NotEmpty
	private UsernamePasswordContext upCtx;

	/** Injected seedFetcher **/
	@Nonnull
	@NotEmpty
	private SeedFetcher seedFetcher;


	private String username;
	private Function<ProfileRequestContext,String> usernameLookupStrategy;


	private boolean result = false;

	/** Inject seedfetcher **/
	public void setseedFetcher(@Nonnull @NotEmpty final SeedFetcher seedFetcher) {
		this.seedFetcher = seedFetcher;
	}

	/** Inject token authenticator **/
	public void setgAuth(@Nonnull @NotEmpty final GoogleAuthenticator gAuth) {
		this.gAuth = gAuth;
	}

	/** Constructor **/
	public TotpTokenValidator() {
		super();

	}

    @Override
    protected boolean doPreExecute(
            @Nonnull ProfileRequestContext profileRequestContext,
            @Nonnull AuthenticationContext authenticationContext) {

        if (!super.doPreExecute(profileRequestContext, authenticationContext)) {
            return false;
        }


	usernameLookupStrategy = new CanonicalUsernameLookupStrategy();
	username = usernameLookupStrategy.apply(profileRequestContext);
	

        if (username == null) {
        	log.info("{} No previous SubjectContext or Principal is set", getLogPrefix());
        	handleError(profileRequestContext, authenticationContext, "NoCredentials", AuthnEventIds.NO_CREDENTIALS);
        	return false;
        }
        
    	log.info("{} PrincipalName from SubjectContext is {}", getLogPrefix(), username);
        return true;
    }

	@Override
	protected Subject populateSubject(Subject subject) {
		log.info("{} TokenValidator populateSubject is called", getLogPrefix());		
		if (StringSupport.trimOrNull(username) != null) {
			log.info("{} Populate subject {}", getLogPrefix(), username);
			subject.getPrincipals().add(new UsernamePrincipal(username));
			return subject;
		}
		return null;
	}

	@Override
	protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
			@Nonnull final AuthenticationContext authenticationContext) {
		log.info("{} Entering totpValidator for username: {}", getLogPrefix(),username);

		try {

			TokenUserContext tokenCtx = authenticationContext.getSubcontext(TokenUserContext.class, true);
			//upCtx = authenticationContext.getSubcontext(UsernamePasswordContext.class, true);
			log.info("{} Validating for user:  {}", getLogPrefix(), username);

			/* Add seeds from repository to tokenUserContext */
			seedFetcher.getSeed(username, tokenCtx);
			log.info("{} Received the following user token:  {}", getLogPrefix(),tokenCtx.getTokenCode());

			if (tokenCtx.getState() == AuthState.OK) {
				log.info("{} Validating user: {} provided token:  {} against seed", getLogPrefix(), username, tokenCtx.getTokenSeed());
				
				/* Get seeds from tokenUserContext */
				ArrayList<String> seeds = tokenCtx.getTokenSeed();

				/* Iterate over seeds and try to validate them */
				Iterator<String> it = seeds.iterator();
				while (it.hasNext()) {
					result = validateToken(it.next(), tokenCtx.getTokenCode());
					if (result) {
						log.info("{} Token authentication success for user: {}", getLogPrefix(), username);
						tokenCtx.setState(AuthState.OK);
						//buildAuthenticationResult(profileRequestContext, authenticationContext);
						return;
					}
				}
			}
			else{
				log.info("{} Failed to get tokenCtx state", getLogPrefix());
			}
			
			if (tokenCtx.getState() == AuthState.REGISTER) {
				log.info("{} User: {} has not registered token", getLogPrefix(), username);
				handleError(profileRequestContext, authenticationContext, "RegisterToken",
						AuthnEventIds.ACCOUNT_ERROR);
				return;
			}

			if (!result) {
				log.info("{} Token authentication failed for user: {}", getLogPrefix(), username);
				tokenCtx.setState(AuthState.CANT_VALIDATE);
				handleError(profileRequestContext, authenticationContext, "InvalidCredentials",
						AuthnEventIds.INVALID_CREDENTIALS);
				return;
			}

		} catch (Exception e) {
			log.warn("{} Login by {} produced exception", getLogPrefix(), username, e);
			handleError(profileRequestContext, authenticationContext, "InvalidCredentials",
					AuthnEventIds.INVALID_CREDENTIALS);
		}

	}

	@Override
	public boolean validateToken(String seed, int token) {
		log.info("{} Entering validatetoken", getLogPrefix());

		if (seed.length() == 16) {
			log.info("{} authorize {} - {} ", getLogPrefix(), seed, token);
			return gAuth.authorize(seed, token);
		}
		log.info("{} Token code validation failed. Seed is not 16 char long", getLogPrefix());
		return false;
	}
	
}
