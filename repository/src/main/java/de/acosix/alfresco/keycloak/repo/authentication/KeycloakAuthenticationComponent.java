/*
 * Copyright 2019 - 2020 Acosix GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.acosix.alfresco.keycloak.repo.authentication;

import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.alfresco.repo.management.subsystems.ActivateableBean;
import org.alfresco.repo.security.authentication.AbstractAuthenticationComponent;
import org.alfresco.repo.security.authentication.AuthenticationException;
import org.alfresco.repo.transaction.AlfrescoTransactionSupport;
import org.alfresco.repo.transaction.AlfrescoTransactionSupport.TxnReadState;
import org.alfresco.service.cmr.repository.NodeRef;
import org.alfresco.service.cmr.repository.NodeService;
import org.alfresco.service.namespace.QName;
import org.alfresco.util.PropertyCheck;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

import de.acosix.alfresco.keycloak.repo.deps.keycloak.OAuth2Constants;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.adapters.KeycloakDeployment;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.adapters.ServerRequest;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.adapters.authentication.ClientCredentialsProviderUtils;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.adapters.rotation.AdapterTokenVerifier;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.adapters.rotation.AdapterTokenVerifier.VerifiedTokens;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.common.VerificationException;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.common.util.KeycloakUriBuilder;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.constants.ServiceUrlConstants;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.representations.AccessToken;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.representations.AccessTokenResponse;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.representations.IDToken;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.util.JsonSerialization;
import de.acosix.alfresco.keycloak.repo.util.AlfrescoCompatibilityUtil;
import de.acosix.alfresco.keycloak.repo.util.RefreshableAccessTokenHolder;
import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;

/**
 * @author Axel Faust
 */
public class KeycloakAuthenticationComponent extends AbstractAuthenticationComponent
        implements InitializingBean, ActivateableBean, ApplicationContextAware
{

    private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakAuthenticationComponent.class);

    protected final ThreadLocal<Boolean> lastTokenResponseStoreEnabled = new ThreadLocal<>();

    protected final ThreadLocal<RefreshableAccessTokenHolder> lastTokenResponse = new ThreadLocal<>();

    protected boolean active;

    protected ApplicationContext applicationContext;

    protected boolean allowUserNamePasswordLogin;

    protected boolean failExpiredTicketTokens;

    protected boolean allowGuestLogin;

    protected boolean mapAuthorities;

    protected boolean mapPersonPropertiesOnLogin;

    protected KeycloakDeployment deployment;

    protected Collection<AuthorityExtractor> authorityExtractors;

    protected Collection<UserProcessor> userProcessors;

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet()
    {
        PropertyCheck.mandatory(this, "applicationContext", this.applicationContext);
        PropertyCheck.mandatory(this, "keycloakDeployment", this.deployment);

        this.authorityExtractors = Collections
                .unmodifiableList(new ArrayList<>(this.applicationContext.getBeansOfType(AuthorityExtractor.class, false, true).values()));
        this.userProcessors = Collections
                .unmodifiableList(new ArrayList<>(this.applicationContext.getBeansOfType(UserProcessor.class, false, true).values()));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isActive()
    {
        return this.active;
    }

    /**
     * @param active
     *            the active to set
     */
    public void setActive(final boolean active)
    {
        this.active = active;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setApplicationContext(final ApplicationContext applicationContext)
    {
        this.applicationContext = applicationContext;
    }

    /**
     * @param allowUserNamePasswordLogin
     *            the allowUserNamePasswordLogin to set
     */
    public void setAllowUserNamePasswordLogin(final boolean allowUserNamePasswordLogin)
    {
        this.allowUserNamePasswordLogin = allowUserNamePasswordLogin;
    }

    /**
     * @param failExpiredTicketTokens
     *            the failExpiredTicketTokens to set
     */
    public void setFailExpiredTicketTokens(final boolean failExpiredTicketTokens)
    {
        this.failExpiredTicketTokens = failExpiredTicketTokens;
    }

    /**
     * @param allowGuestLogin
     *            the allowGuestLogin to set
     */
    public void setAllowGuestLogin(final boolean allowGuestLogin)
    {
        this.allowGuestLogin = allowGuestLogin;
        super.setAllowGuestLogin(Boolean.valueOf(allowGuestLogin));
    }

    /**
     * @param allowGuestLogin
     *            the allowGuestLogin to set
     */
    @Override
    public void setAllowGuestLogin(final Boolean allowGuestLogin)
    {
        this.setAllowGuestLogin(Boolean.TRUE.equals(allowGuestLogin));
    }

    /**
     * @param mapAuthorities
     *            the mapAuthorities to set
     */
    public void setMapAuthorities(final boolean mapAuthorities)
    {
        this.mapAuthorities = mapAuthorities;
    }

    /**
     * @param mapPersonPropertiesOnLogin
     *            the mapPersonPropertiesOnLogin to set
     */
    public void setMapPersonPropertiesOnLogin(final boolean mapPersonPropertiesOnLogin)
    {
        this.mapPersonPropertiesOnLogin = mapPersonPropertiesOnLogin;
    }

    /**
     * @param deployment
     *            the deployment to set
     */
    public void setDeployment(final KeycloakDeployment deployment)
    {
        this.deployment = deployment;
    }

    /**
     * Enables the thread-local storage of the last access token response and verified tokens beyond the internal needs of
     * {@link #authenticateImpl(String, char[]) authenticateImpl}.
     */
    public void enableLastTokenStore()
    {
        this.lastTokenResponseStoreEnabled.set(Boolean.TRUE);
    }

    /**
     * Disables the thread-local storage of the last access token response and verified tokens beyond the internal needs of
     * {@link #authenticateImpl(String, char[]) authenticateImpl}.
     */
    public void disableLastTokenStore()
    {
        this.lastTokenResponseStoreEnabled.remove();
        this.lastTokenResponse.remove();
    }

    /**
     * Retrieves the last access token response kept in the thread-local storage. This will only return a result if the thread is currently
     * in the process of {@link #authenticateImpl(String, char[]) authenticating a user} or {@link #enableLastTokenStore() storage of the
     * last response is currently enabled}.
     *
     * @return the last token response or {@code null} if no response is stored in the thread local for the current thread
     */
    public RefreshableAccessTokenHolder getLastTokenResponse()
    {
        return this.lastTokenResponse.get();
    }

    /**
     * Checks a refreshable access token associated with an authentication ticket, refreshing it if necessary, and failing if the token has
     * expired and the component has been configured to not accept expired tokens.
     *
     * @param ticketToken
     *            the refreshable access token to refresh
     * @return the refreshed access token if a refresh was possible AND necessary, and a new access token has been retrieved from Keycloak -
     *         will be {@code null} if no refresh has taken place
     */
    public RefreshableAccessTokenHolder checkAndRefreshTicketToken(final RefreshableAccessTokenHolder ticketToken)
            throws AuthenticationException
    {
        RefreshableAccessTokenHolder result = null;
        if (ticketToken.canRefresh() && ticketToken.shouldRefresh(this.deployment.getTokenMinimumTimeToLive()))
        {
            try
            {
                final AccessTokenResponse response = ServerRequest.invokeRefresh(this.deployment, ticketToken.getRefreshToken());
                final VerifiedTokens tokens = AdapterTokenVerifier.verifyTokens(response.getToken(), response.getIdToken(),
                        this.deployment);

                result = new RefreshableAccessTokenHolder(response, tokens);
            }
            catch (final ServerRequest.HttpFailure httpFailure)
            {
                LOGGER.error("Error refreshing Keycloak authentication - {} {}", httpFailure.getStatus(), httpFailure.getError());
                throw new AuthenticationException(
                        "Failed to refresh Keycloak authentication: " + httpFailure.getStatus() + " " + httpFailure.getError());
            }
            catch (final VerificationException vex)
            {
                LOGGER.error("Error refreshing Keycloak authentication - access token verification failed", vex);
                throw new AuthenticationException("Failed to refresh Keycloak authentication", vex);
            }
            catch (final IOException ioex)
            {
                LOGGER.error("Error refreshing Keycloak authentication - unexpected IO exception", ioex);
                throw new AuthenticationException("Failed to refresh Keycloak authentication", ioex);
            }
        }
        else if (this.failExpiredTicketTokens && !ticketToken.isActive())
        {
            throw new AuthenticationException("Keycloak access token has expired - authentication ticket is no longer valid");
        }

        if (result != null || ticketToken.isActive())
        {
            // this may be triggered later via KeycloakAuthenticationListener anyway but since Alfresco is inconsistent about when
            // AuthenticationListener's are called, do it manually
            this.handleUserTokens(result != null ? result.getAccessToken() : ticketToken.getAccessToken(),
                    result != null ? result.getIdToken() : ticketToken.getIdToken(), false);
        }

        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void authenticateImpl(final String userName, final char[] password) throws AuthenticationException
    {
        if (!this.allowUserNamePasswordLogin)
        {
            throw new AuthenticationException("Simple login via user name + password is not allowed");
        }

        final AccessTokenResponse response;
        final VerifiedTokens tokens;
        String realUserName = userName;
        try
        {
            response = this.getAccessTokenImpl(userName, new String(password));
            tokens = AdapterTokenVerifier.verifyTokens(response.getToken(), response.getIdToken(), this.deployment);

            realUserName = tokens.getAccessToken().getPreferredUsername();

            // for potential one-off authentication, we do not care particularly about the token TTL - so no validation here

            if (Boolean.TRUE.equals(this.lastTokenResponseStoreEnabled.get()))
            {
                this.lastTokenResponse.set(new RefreshableAccessTokenHolder(response, tokens));
            }
        }
        catch (final VerificationException vex)
        {
            LOGGER.error("Error authenticating against Keycloak - access token verification failed", vex);
            throw new AuthenticationException("Failed to authenticate against Keycloak", vex);
        }
        catch (final IOException ioex)
        {
            LOGGER.error("Error authenticating against Keycloak - unexpected IO exception", ioex);
            throw new AuthenticationException("Failed to authenticate against Keycloak", ioex);
        }

        // TODO Override setCurrentUser to perform user existence validation and role retrieval for non-Keycloak logins (e.g. via public API
        // setCurrentUser)
        this.setCurrentUser(realUserName);
        this.handleUserTokens(tokens.getAccessToken(), tokens.getIdToken(), true);
    }

    /**
     * Processes tokens for authenticated users, mapping them to Alfresco person properties or granted authorities as configured for this
     * instance.
     *
     * @param accessToken
     *            the access token
     * @param idToken
     *            the ID token
     * @param freshLogin
     *            {@code true} if the tokens are fresh, that is have just been obtained from an initial login, {@code false} otherwise -
     *            Alfresco person node properties will only be mapped for fresh tokens, while granted authorities processors will always be
     *            handled if enabled
     */
    public void handleUserTokens(final AccessToken accessToken, final IDToken idToken, final boolean freshLogin)
    {
        if (this.mapAuthorities)
        {
            LOGGER.debug("Mapping Keycloak access token to user authorities");

            final Set<String> mappedAuthorities = new HashSet<>();
            this.authorityExtractors.stream().map(extractor -> extractor.extractAuthorities(accessToken))
                    .forEach(mappedAuthorities::addAll);

            LOGGER.debug("Mapped user authorities from access token: {}", mappedAuthorities);

            if (!mappedAuthorities.isEmpty())
            {
                final Authentication currentAuthentication = this.getCurrentAuthentication();
                if (currentAuthentication instanceof UsernamePasswordAuthenticationToken)
                {
                    GrantedAuthority[] grantedAuthorities = currentAuthentication.getAuthorities();

                    final List<GrantedAuthority> grantedAuthoritiesL = mappedAuthorities.stream().map(GrantedAuthorityImpl::new)
                            .collect(Collectors.toList());
                    grantedAuthoritiesL.addAll(Arrays.asList(grantedAuthorities));

                    grantedAuthorities = grantedAuthoritiesL.toArray(new GrantedAuthority[0]);
                    ((UsernamePasswordAuthenticationToken) currentAuthentication).setAuthorities(grantedAuthorities);
                }
                else
                {
                    LOGGER.warn(
                            "Authentication for user is not of the expected type {} - Keycloak access token cannot be mapped to granted authorities",
                            UsernamePasswordAuthenticationToken.class);
                }
            }
        }

        if (freshLogin && this.mapPersonPropertiesOnLogin)
        {
            final boolean requiresNew = AlfrescoTransactionSupport.getTransactionReadState() == TxnReadState.TXN_READ_ONLY;
            this.getTransactionService().getRetryingTransactionHelper().doInTransaction(() -> {
                this.updatePerson(accessToken, idToken);
                return null;
            }, false, requiresNew);
        }
    }

    /**
     * Updates the person for the current user with data mapped from the Keycloak tokens.
     *
     * @param accessToken
     *            the access token
     * @param idToken
     *            the ID token
     */
    protected void updatePerson(final AccessToken accessToken, final IDToken idToken)
    {
        final String userName = this.getCurrentUserName();

        LOGGER.debug("Mapping person property updates for user {}", AlfrescoCompatibilityUtil.maskUsername(userName));

        final NodeRef person = this.getPersonService().getPerson(userName);

        final Map<QName, Serializable> updates = new HashMap<>();
        this.userProcessors.forEach(processor -> processor.mapUser(accessToken, idToken != null ? idToken : accessToken, updates));

        LOGGER.debug("Determined property updates for person node of user {}", AlfrescoCompatibilityUtil.maskUsername(userName));

        final Set<QName> propertiesToRemove = updates.keySet().stream().filter(k -> updates.get(k) == null).collect(Collectors.toSet());
        updates.keySet().removeAll(propertiesToRemove);

        final NodeService nodeService = this.getNodeService();
        final Map<QName, Serializable> currentProperties = nodeService.getProperties(person);

        propertiesToRemove.retainAll(currentProperties.keySet());
        if (!propertiesToRemove.isEmpty())
        {
            // there is no bulk-remove, so we need to use setProperties to achieve a single update event
            final Map<QName, Serializable> newProperties = new HashMap<>(currentProperties);
            newProperties.putAll(updates);
            newProperties.keySet().removeAll(propertiesToRemove);
            nodeService.setProperties(person, newProperties);
        }
        else if (!updates.isEmpty())
        {
            nodeService.addProperties(person, updates);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected boolean implementationAllowsGuestLogin()
    {
        return this.allowGuestLogin;
    }

    /**
     * Retrieves an OIDC access token with the specific token request parameter up to the caller to define via the provided consumer.
     *
     * @param userName
     *            the user to use for synchronisation access
     * @param password
     *            the password of the user
     * @return the access token
     * @throws IOException
     *             when errors occur in the HTTP interaction
     */
    // implementing this method locally avoids having the dependency on Keycloak authz-client
    // authz-client does not support refresh, so would be of limited value anyway
    protected AccessTokenResponse getAccessTokenImpl(final String userName, final String password) throws IOException
    {
        AccessTokenResponse tokenResponse = null;
        final HttpClient client = this.deployment.getClient();

        final HttpPost post = new HttpPost(KeycloakUriBuilder.fromUri(this.deployment.getAuthServerBaseUrl())
                .path(ServiceUrlConstants.TOKEN_PATH).build(this.deployment.getRealm()));
        final List<NameValuePair> formParams = new ArrayList<>();

        formParams.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, OAuth2Constants.PASSWORD));
        formParams.add(new BasicNameValuePair("username", userName));
        formParams.add(new BasicNameValuePair("password", password));

        ClientCredentialsProviderUtils.setClientCredentials(this.deployment, post, formParams);

        final UrlEncodedFormEntity form = new UrlEncodedFormEntity(formParams, "UTF-8");
        post.setEntity(form);

        final HttpResponse response = client.execute(post);
        final int status = response.getStatusLine().getStatusCode();
        final HttpEntity entity = response.getEntity();

        if (status != 200)
        {
            final String statusReason = response.getStatusLine().getReasonPhrase();
            LOGGER.debug("Failed to retrieve access token due to HTTP {}: {}", status, statusReason);
            EntityUtils.consumeQuietly(entity);

            LOGGER.debug("Failed to authenticate user against Keycloak. Status: {} Reason: {}", status, statusReason);
            throw new AuthenticationException("Failed to authenticate against Keycloak - Status: " + status + ", Reason: " + statusReason);
        }

        if (entity == null)
        {
            LOGGER.debug("Failed to authenticate against Keycloak - Response did not contain a message body");
            throw new AuthenticationException("Failed to authenticate against Keycloak - Response did not contain a message body");
        }

        final InputStream is = entity.getContent();
        try
        {
            tokenResponse = JsonSerialization.readValue(is, AccessTokenResponse.class);
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

        return tokenResponse;
    }
}
