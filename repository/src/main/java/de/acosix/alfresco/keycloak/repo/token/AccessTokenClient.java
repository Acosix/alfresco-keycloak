package de.acosix.alfresco.keycloak.repo.token;

import com.fasterxml.jackson.core.JsonParseException;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.function.Consumer;

import org.alfresco.util.ParameterCheck;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicNameValuePair;
import org.keycloak.OAuth2Constants;
import org.keycloak.TokenVerifier;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.ServerRequest;
import org.keycloak.adapters.ServerRequest.HttpFailure;
import org.keycloak.adapters.rotation.AdapterTokenVerifier;
import org.keycloak.adapters.rotation.AdapterTokenVerifier.VerifiedTokens;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.common.util.Time;
import org.keycloak.constants.ServiceUrlConstants;
import org.keycloak.protocol.oidc.client.authentication.ClientCredentialsProviderUtils;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.util.JsonSerialization;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.acosix.alfresco.keycloak.repo.util.NameValueMapAdapter;
import de.acosix.alfresco.keycloak.repo.util.RefreshableAccessTokenHolder;

/**
 * Instances of this class provide the most common, low-level access token client logic that may be used across multiple higher-level
 * components in this module.
 *
 * @author Axel Faust
 */
public class AccessTokenClient
{

    private static final Logger LOGGER = LoggerFactory.getLogger(AccessTokenClient.class);

    protected final KeycloakDeployment deployment;

    public AccessTokenClient(final KeycloakDeployment deployment)
    {
        ParameterCheck.mandatory("deployment", deployment);
        this.deployment = deployment;
    }

    /**
     * Obtains an access token for the service account of the client used to integrate this Alfresco isntance with Keycloak. This requires
     * that a service account has been enabled / configured in Keycloak.
     *
     * @param scopes
     *     the optional scopes to request for the access token
     * @return the access token
     * @throws AccessTokenException
     *     if the access token cannot be obtained
     */
    public RefreshableAccessTokenHolder obtainAccessToken(final Collection<String> scopes)
    {
        ParameterCheck.mandatory("scopes", scopes);
        LOGGER.debug("Obtaining client access token with (optional) scopes {}", scopes);
        try
        {
            final AccessTokenResponse response = this.getAccessTokenImpl(formParams -> {
                formParams.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, OAuth2Constants.CLIENT_CREDENTIALS));
                this.processScopes(scopes, formParams);
            });
            final VerifiedTokens verifiedTokens = this.verifyAccessTokenResponse(response);
            final RefreshableAccessTokenHolder refreshableToken = new RefreshableAccessTokenHolder(response, verifiedTokens);
            LOGGER.debug("Obtained client access token {}", response.getToken());
            return refreshableToken;
        }
        catch (final IOException ioex)
        {
            throw new AccessTokenException("Failed to obtain accses token", ioex);
        }
    }

    /**
     * Obtains an access token for a specific user using a direct access grant. This requires that the client used to integrate this
     * Alfresco instance with Keycloak is configured to allow direct access grants.
     *
     * @param user
     *     the name of the user
     * @param password
     *     the password provided by / for the user
     * @param scopes
     *     the optional scopes to request for the access token
     * @return the access token
     * @throws AccessTokenException
     *     if the access token cannot be obtained
     */
    public RefreshableAccessTokenHolder obtainAccessToken(final String user, final String password, final Collection<String> scopes)
    {
        ParameterCheck.mandatoryString("user", user);
        ParameterCheck.mandatoryString("password", password);
        ParameterCheck.mandatory("scopes", scopes);

        LOGGER.debug("Obtaining access token for user {} with (optional) scopes {}", user, scopes);
        try
        {
            final AccessTokenResponse response = this.getAccessTokenImpl(formParams -> {
                formParams.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, OAuth2Constants.PASSWORD));
                formParams.add(new BasicNameValuePair("username", user));
                formParams.add(new BasicNameValuePair("password", password));
                this.processScopes(scopes, formParams);
            });
            final VerifiedTokens verifiedTokens = this.verifyAccessTokenResponse(response);
            final RefreshableAccessTokenHolder refreshableToken = new RefreshableAccessTokenHolder(response, verifiedTokens);
            LOGGER.debug("Obtained user access token {}", response.getToken());
            return refreshableToken;
        }
        catch (final IOException ioex)
        {
            throw new AccessTokenException("Failed to obtain accses token", ioex);
        }
    }

    /**
     * Exchanges an access token provided by a client / end user to this service for an access token to another client / service, retaining
     * the original identity but enabling that client / service to know the access is being delegated through this Alfresco instance.
     *
     * @param accessToken
     *     the access token to exchange
     * @param client
     *     the client / service for which to obtain an access token
     * @param scopes
     *     the optional scopes to request for the access token
     * @return the access token to the requested client / service
     * @throws AccessTokenException
     *     if the token cannot be exchanged
     */
    public RefreshableAccessTokenHolder exchangeToken(final String accessToken, final String client, final Collection<String> scopes)
    {
        ParameterCheck.mandatoryString("accessToken", accessToken);
        ParameterCheck.mandatoryString("client", client);
        ParameterCheck.mandatory("scopes", scopes);

        LOGGER.debug("Exchanging {} for access token to client {} with (optional) scopes {}", accessToken, client, scopes);
        try
        {
            final AccessTokenResponse response = this.getAccessTokenImpl(formParams -> {
                formParams.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, OAuth2Constants.TOKEN_EXCHANGE_GRANT_TYPE));
                formParams.add(new BasicNameValuePair(OAuth2Constants.AUDIENCE, client));
                formParams.add(new BasicNameValuePair(OAuth2Constants.REQUESTED_TOKEN_TYPE, OAuth2Constants.REFRESH_TOKEN_TYPE));
                this.processScopes(scopes, formParams);
            });
            final VerifiedTokens verifiedTokens = this.verifyAccessTokenResponse(response, client);
            final RefreshableAccessTokenHolder refreshableToken = new RefreshableAccessTokenHolder(response, verifiedTokens);
            LOGGER.debug("Obtained exchanged token {}", response.getToken());
            return refreshableToken;
        }
        catch (final IOException ioex)
        {
            throw new AccessTokenException("Failed to exchange accses token", ioex);
        }
    }

    /**
     * Refreshes an access token via a previously obtained refresh token.
     *
     * @param refreshToken
     *     the refresh token with which to retrieve a fresh access token
     * @return the fresh access token
     * @throws AccessTokenRefreshException
     *     if the refresh failed
     */
    public RefreshableAccessTokenHolder refreshAccessToken(final String refreshToken)
    {
        LOGGER.debug("Performing direct refresh via refresh token {}", refreshToken);
        try
        {
            final AccessTokenResponse response = ServerRequest.invokeRefresh(this.deployment, refreshToken);
            final VerifiedTokens verifiedTokens = this.verifyAccessTokenResponse(response);
            final RefreshableAccessTokenHolder refreshableToken = new RefreshableAccessTokenHolder(response, verifiedTokens);
            LOGGER.debug("Refreshed access token {}", response.getToken());
            return refreshableToken;
        }
        catch (final IOException | HttpFailure ioex)
        {
            LOGGER.debug("Failed direct refresh due to {}", ioex.getMessage());
            throw new AccessTokenRefreshException("Failed to refresh access token due HTTP / IO error", ioex);
        }
        catch (final AccessTokenVerificationException verex)
        {
            LOGGER.debug("Failed direct refresh due to {}", verex.getMessage());
            throw new AccessTokenRefreshException("Failed to refresh access token due to verification error", verex);
        }
    }

    protected void processScopes(final Collection<String> scopes, final List<NameValuePair> formParams)
    {
        if (!scopes.isEmpty())
        {
            final StringBuilder sb = new StringBuilder(scopes.size() * 16);
            for (final String scope : scopes)
            {
                if (sb.length() > 0)
                {
                    sb.append(' ');
                }
                sb.append(scope);
            }
            formParams.add(new BasicNameValuePair(OAuth2Constants.SCOPE, sb.toString()));
        }
    }

    protected VerifiedTokens verifyAccessTokenResponse(final AccessTokenResponse response)
    {
        final VerifiedTokens tokens;
        try
        {
            tokens = AdapterTokenVerifier.verifyTokens(response.getToken(), response.getIdToken(), this.deployment);
        }
        catch (final VerificationException vex)
        {
            throw new AccessTokenVerificationException("Failed to verify token", vex);
        }

        if ((tokens.getAccessToken().getExp() - this.deployment.getTokenMinimumTimeToLive()) <= Time.currentTime())
        {
            throw new AccessTokenVerificationException(
                    "Failed to retrieve / refresh the access token with a longer time-to-live than the minimum");
        }

        return tokens;
    }

    protected VerifiedTokens verifyAccessTokenResponse(final AccessTokenResponse response, final String client)
    {
        final VerifiedTokens tokens;
        try
        {
            final TokenVerifier<AccessToken> tokenVerifier = AdapterTokenVerifier.createVerifier(response.getToken(), this.deployment, true,
                    AccessToken.class);
            tokenVerifier.audience(client);
            tokenVerifier.issuedFor(this.deployment.getResourceName());

            tokens = new VerifiedTokens(tokenVerifier.verify().getToken(), null);
        }
        catch (final VerificationException vex)
        {
            throw new AccessTokenVerificationException("Failed to verify token", vex);
        }

        if ((tokens.getAccessToken().getExp() - this.deployment.getTokenMinimumTimeToLive()) <= Time.currentTime())
        {
            throw new AccessTokenVerificationException(
                    "Failed to retrieve / refresh the access token with a longer time-to-live than the minimum");
        }

        return tokens;
    }

    /**
     * Retrieves an OIDC access token with the specific token request parameter up to the caller to define via the provided consumer.
     *
     * @param postParamProvider
     *     a provider of HTTP POST parameters for the access token request
     * @return the access token
     * @throws IOException
     *     when errors occur in the HTTP interaction
     */
    // implementing this method locally avoids having the dependency on Keycloak authz-client
    // authz-client does not support refresh, so would be of limited value anyway
    protected AccessTokenResponse getAccessTokenImpl(final Consumer<List<NameValuePair>> postParamProvider) throws IOException
    {
        AccessTokenResponse tokenResponse = null;
        final HttpClient client = this.deployment.getClient();

        final HttpPost post = new HttpPost(KeycloakUriBuilder.fromUri(this.deployment.getAuthServerBaseUrl())
                .path(ServiceUrlConstants.TOKEN_PATH).build(this.deployment.getRealm()));
        final List<NameValuePair> formParams = new LinkedList<>();

        postParamProvider.accept(formParams);
        
        final List<Header> headers = new LinkedList<>();

        ClientCredentialsProviderUtils.setClientCredentials(
        		this.deployment.getAdapterConfig(),
        		this.deployment.getClientAuthenticator(),
        		new NameValueMapAdapter<>(headers, BasicHeader.class),
        		new NameValueMapAdapter<>(formParams, BasicNameValuePair.class));

        for (Header header : headers)
            post.addHeader(header);
        final UrlEncodedFormEntity form = new UrlEncodedFormEntity(formParams, "UTF-8");
        post.setEntity(form);

        final HttpResponse response = client.execute(post);
        final int status = response.getStatusLine().getStatusCode();
        final HttpEntity entity = response.getEntity();
        if (status != 200)
        {
            final String statusReason = response.getStatusLine().getReasonPhrase();
            if (entity != null)
            {
                final ErrorResponse error = this.readResponseEntity(entity, ErrorResponse.class);
                if ("unauthorized_client".equals(error.getError()))
                {
                    // configuration error
                    LOGGER.error("Unable to retrieve access token due to invalid client configuration: {}", error.getErrorDescription());
                    throw new AccessTokenUnsupportedException(error.getErrorDescription());
                }
                // TODO Other types of more specific exceptions
                LOGGER.debug("Failed to retrieve access token due to {}: {}", error.getError(), error.getErrorDescription());
                throw new AccessTokenException("{0}: {1}", new Object[] { error.getError(), error.getErrorDescription() });
            }
            LOGGER.debug("Failed to retrieve access token due to HTTP {}: {}", status, statusReason);
            throw new AccessTokenException("Failed to retrieve access token due to HTTP " + status + ": " + statusReason);
        }
        if (entity == null)
        {
            throw new AccessTokenException("Response to access token request did not contain a response body");
        }

        tokenResponse = this.readResponseEntity(entity, AccessTokenResponse.class);

        return tokenResponse;
    }

    protected <T> T readResponseEntity(final HttpEntity entity, final Class<T> responseCls) throws IOException
    {
        final InputStream is = entity.getContent();
        try
        {
            return JsonSerialization.readValue(is, responseCls);
        }
        catch (final JsonParseException jpe)
        {
            throw new AccessTokenException("Failed to parse access token response", jpe);
        }
        finally
        {
            try
            {
                is.close();
            }
            catch (final IOException e)
            {
                LOGGER.trace("Error closing entity stream", e);
            }
        }
    }
}
