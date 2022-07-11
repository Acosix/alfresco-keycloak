package de.acosix.alfresco.keycloak.repo.authentication;

import org.alfresco.repo.security.authentication.AbstractAuthenticationComponent;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

/**
 * Instances of this interface are used to process access tokens from Keycloak authenticated users. All instances of this
 * interface in the Keycloak authentication subsystem will be consulted in the order of the priority field, followed by the
 * order the beans are defined in the Spring application context.
 *
 * @author Brian Long
 */
public interface TokenProcessor extends Comparable<TokenProcessor> {
	
	/**
	 * A name of the processor for logging and reference purposes.
	 * @return A processor name.
	 */
	String getName();
	
	/**
	 * A priority for sorting beans for execution order.
	 * @return
	 */
	default int getPriority() {
		return 0;
	}

    /**
     * Handles access tokens from Keycloak.
     *
     * @param accessToken
     *            the Keycloak access token for the authenticated user
     * @param idToken
     *            the Keycloak ID token for the authenticated user - may be {@code null} if not contained in the authentication response
     * @param freshLogin
     *            {@code true} if the tokens are fresh, that is have just been obtained from an initial login, {@code false} otherwise
     */
	void handleUserTokens(
			final AbstractAuthenticationComponent authComponent,
			final AccessToken accessToken,
			final IDToken idToken,
			final boolean freshLogin);
	
	@Override
	default int compareTo(TokenProcessor o) {
		return Integer.compare(this.getPriority(), o.getPriority());
	}

}
