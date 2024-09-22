/*
 * Copyright 2019 - 2021 Acosix GmbH
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
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.alfresco.repo.SessionUser;
import org.alfresco.repo.cache.SimpleCache;
import org.alfresco.repo.management.subsystems.ActivateableBean;
import org.alfresco.repo.security.authentication.AuthenticationException;
import org.alfresco.repo.security.authentication.Authorization;
import org.alfresco.repo.web.auth.BasicAuthCredentials;
import org.alfresco.repo.web.auth.TicketCredentials;
import org.alfresco.repo.web.auth.UnknownCredentials;
import org.alfresco.repo.web.filter.beans.DependencyInjectedFilter;
import org.alfresco.repo.webdav.auth.AuthenticationDriver;
import org.alfresco.repo.webdav.auth.BaseAuthenticationFilter;
import org.alfresco.repo.webdav.auth.BaseSSOAuthenticationFilter;
import org.alfresco.rest.api.PublicApiTenantWebScriptServletRuntime;
import org.alfresco.util.PropertyCheck;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.AuthenticatedActionsHandler;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.OidcKeycloakAccount;
import org.keycloak.adapters.PreAuthActionsHandler;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.adapters.servlet.FilterRequestAuthenticator;
import org.keycloak.adapters.servlet.OIDCFilterSessionStore;
import org.keycloak.adapters.servlet.OIDCServletHttpFacade;
import org.keycloak.adapters.spi.AuthOutcome;
import org.keycloak.adapters.spi.AuthenticationError;
import org.keycloak.adapters.spi.KeycloakAccount;
import org.keycloak.adapters.spi.SessionIdMapper;
import org.keycloak.adapters.spi.UserSessionManagement;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.representations.AccessToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.extensions.webscripts.Description.RequiredAuthentication;
import org.springframework.extensions.webscripts.Match;
import org.springframework.extensions.webscripts.RuntimeContainer;

import de.acosix.alfresco.keycloak.repo.util.AlfrescoCompatibilityUtil;
import de.acosix.alfresco.keycloak.repo.util.RefreshableAccessTokenHolder;

/**
 * This class provides a Keycloak-based authentication filter which can be used in the role of both global and WebDAV authentication filter.
 *
 * This class does not use the Alfresco default base {@link BaseSSOAuthenticationFilter SSO} filter class as a base class for inheritance
 * since these classes are extremely NTLM / Kerberos centric and would require extremely weird hacks / workarounds to use its constraints to
 * implement a Keycloak-based authentication.
 *
 * @author Axel Faust
 */
public class KeycloakAuthenticationFilter extends BaseAuthenticationFilter
        implements InitializingBean, ActivateableBean, DependencyInjectedFilter
{

    private static final int FRESH_TOKEN_AGE_LIMIT_MS = 2000;

    // copied from WebScriptRequestImpl due to accessible constraints
    private static final String ARG_GUEST = "guest";

    // copied from BasicHttpAuthenticator (inline literal constant)
    private static final String ARG_ALF_TICKET = "alf_ticket";

    // copied from base class - inaccessible there
    private static final String LOGIN_EXTERNAL_AUTH = "_alfExternalAuth";

    private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakAuthenticationFilter.class);

    private static final String HEADER_AUTHORIZATION = "Authorization";

    private static final String API_SERVLET_PATH = "/api";

    private static final String KEYCLOAK_ACTION_URL_PATTERN = "^(?:/wcs(?:ervice)?)?/keycloak/k_[^/]+$";

    private static final int DEFAULT_BODY_BUFFER_LIMIT = 32 * 1024;// 32 KiB

    protected boolean active;

    protected boolean allowTicketLogon;

    protected boolean allowHttpBasicLogon;

    protected boolean handlePublicApi;

    protected String loginPageUrl;

    protected String originalRequestUrlHeaderName;

    protected String noKeycloakHandlingHeaderName;

    protected int bodyBufferLimit = DEFAULT_BODY_BUFFER_LIMIT;

    protected KeycloakDeployment keycloakDeployment;

    protected SessionIdMapper sessionIdMapper;

    protected AdapterDeploymentContext deploymentContext;

    protected KeycloakAuthenticationComponent keycloakAuthenticationComponent;

    protected SimpleCache<String, RefreshableAccessTokenHolder> keycloakTicketTokenCache;

    protected RuntimeContainer publicApiRuntimeContainer;

    /**
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet()
    {
        PropertyCheck.mandatory(this, "keycloakDeployment", this.keycloakDeployment);
        PropertyCheck.mandatory(this, "sessionIdMapper", this.sessionIdMapper);
        PropertyCheck.mandatory(this, "keycloakAuthenticationComponent", this.keycloakAuthenticationComponent);
        PropertyCheck.mandatory(this, "keycloakTicketTokenCache", this.keycloakTicketTokenCache);
        PropertyCheck.mandatory(this, "publicApiRuntimeContainer", this.publicApiRuntimeContainer);

        PropertyCheck.mandatory(this, "noKeycloakHandlingHeaderName", this.noKeycloakHandlingHeaderName);

        // parent class does not check, so we do
        PropertyCheck.mandatory(this, "authenticationService", this.authenticationService);
        PropertyCheck.mandatory(this, "authenticationComponent", this.authenticationComponent);
        PropertyCheck.mandatory(this, "authenticationListener", this.authenticationListener);
        PropertyCheck.mandatory(this, "personService", this.personService);
        PropertyCheck.mandatory(this, "nodeService", this.nodeService);
        PropertyCheck.mandatory(this, "transactionService", this.transactionService);

        // basic is handled ourselves
        this.keycloakDeployment.setEnableBasicAuth(false);
        this.deploymentContext = new AdapterDeploymentContext(this.keycloakDeployment);
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
     *     the active to set
     */
    public void setActive(final boolean active)
    {
        this.active = active;
    }

    /**
     * @param allowTicketLogon
     *     the allowTicketLogon to set
     */
    public void setAllowTicketLogon(final boolean allowTicketLogon)
    {
        this.allowTicketLogon = allowTicketLogon;
    }

    /**
     * @param allowHttpBasicLogon
     *     the allowHttpBasicLogon to set
     */
    public void setAllowHttpBasicLogon(final boolean allowHttpBasicLogon)
    {
        this.allowHttpBasicLogon = allowHttpBasicLogon;
    }

    /**
     * @param handlePublicApi
     *     the handlePublicApi to set
     */
    public void setHandlePublicApi(final boolean handlePublicApi)
    {
        this.handlePublicApi = handlePublicApi;
    }

    /**
     * @param loginPageUrl
     *     the loginPageUrl to set
     */
    public void setLoginPageUrl(final String loginPageUrl)
    {
        this.loginPageUrl = loginPageUrl;
    }

    /**
     * @param originalRequestUrlHeaderName
     *     the originalRequestUrlHeaderName to set
     */
    public void setOriginalRequestUrlHeaderName(final String originalRequestUrlHeaderName)
    {
        this.originalRequestUrlHeaderName = originalRequestUrlHeaderName;
    }

    /**
     * @param noKeycloakHandlingHeaderName
     *     the noKeycloakHandlingHeaderName to set
     */
    public void setNoKeycloakHandlingHeaderName(final String noKeycloakHandlingHeaderName)
    {
        this.noKeycloakHandlingHeaderName = noKeycloakHandlingHeaderName;
    }

    /**
     * @param bodyBufferLimit
     *     the bodyBufferLimit to set
     */
    public void setBodyBufferLimit(final int bodyBufferLimit)
    {
        this.bodyBufferLimit = bodyBufferLimit;
    }

    /**
     * @param keycloakDeployment
     *     the keycloakDeployment to set
     */
    public void setKeycloakDeployment(final KeycloakDeployment keycloakDeployment)
    {
        this.keycloakDeployment = keycloakDeployment;
    }

    /**
     * @param sessionIdMapper
     *     the sessionIdMapper to set
     */
    public void setSessionIdMapper(final SessionIdMapper sessionIdMapper)
    {
        this.sessionIdMapper = sessionIdMapper;
    }

    /**
     * @param keycloakAuthenticationComponent
     *     the keycloakAuthenticationComponent to set
     */
    public void setKeycloakAuthenticationComponent(final KeycloakAuthenticationComponent keycloakAuthenticationComponent)
    {
        this.keycloakAuthenticationComponent = keycloakAuthenticationComponent;
    }

    /**
     * @param keycloakTicketTokenCache
     *     the keycloakTicketTokenCache to set
     */
    public void setKeycloakTicketTokenCache(final SimpleCache<String, RefreshableAccessTokenHolder> keycloakTicketTokenCache)
    {
        this.keycloakTicketTokenCache = keycloakTicketTokenCache;
    }

    /**
     * @param publicApiRuntimeContainer
     *     the publicApiRuntimeContainer to set
     */
    public void setPublicApiRuntimeContainer(final RuntimeContainer publicApiRuntimeContainer)
    {
        this.publicApiRuntimeContainer = publicApiRuntimeContainer;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void doFilter(final ServletContext context, final ServletRequest request, final ServletResponse response,
            final FilterChain chain) throws IOException, ServletException
    {
        final HttpServletRequest req = (HttpServletRequest) request;
        final HttpServletResponse res = (HttpServletResponse) response;

        final KeycloakUriBuilder authUrl = this.keycloakDeployment.getAuthUrl();
        final boolean keycloakDeploymentReady = authUrl != null;
        if (!keycloakDeploymentReady)
        {
            LOGGER.warn("Cannot process Keycloak-specifics as Keycloak library was unable to resolve relative URLs from {}",
                    this.keycloakDeployment.getAuthServerBaseUrl());
        }

        final boolean skip = !keycloakDeploymentReady || this.checkForSkipCondition(context, req, res);

        if (skip)
        {
            chain.doFilter(request, response);
        }
        else
        {
            if (!this.checkAndProcessHttpBasicAuthentication(req))
            {
                this.processKeycloakAuthenticationAndActions(context, req, res, chain);
            }
            else
            {
                chain.doFilter(request, response);
            }
        }
    }

    /**
     * Checks and processes any HTTP Basic authentication if allowed.
     *
     * @param req
     *     the servlet request
     *
     * @throws IOException
     *     if any error occurs during processing of HTTP Basic authentication
     * @throws ServletException
     *     if any error occurs during processing of HTTP Basic authentication
     *
     * @return {@code true} if an existing HTTP Basic authentication header was successfully processed, {@code false} otherwise
     */
    protected boolean checkAndProcessHttpBasicAuthentication(final HttpServletRequest req) throws IOException, ServletException
    {
        boolean basicAuthSucessfull = false;
        final String authHeader = req.getHeader(HEADER_AUTHORIZATION);
        if (authHeader != null && authHeader.toLowerCase(Locale.ENGLISH).startsWith("basic "))
        {
            final String[] authorizationParts = authHeader.split(" ");
            final String decodedAuthorisation = new String(Base64.decodeBase64(authorizationParts[1]), StandardCharsets.UTF_8);
            final Authorization auth = new Authorization(decodedAuthorisation);

            try
            {
                if (auth.isTicket())
                {
                    if (this.allowTicketLogon)
                    {
                        LOGGER.trace("Performing HTTP Basic ticket validation");
                        this.authenticationService.validate(auth.getTicket());

                        this.createUserEnvironment(req.getSession(), this.authenticationService.getCurrentUserName(),
                                this.authenticationService.getCurrentTicket(), false);

                        LOGGER.debug("Authenticated user {} via HTTP Basic authentication using an authentication ticket",
                                AlfrescoCompatibilityUtil.maskUsername(this.authenticationService.getCurrentUserName()));

                        this.authenticationListener.userAuthenticated(new TicketCredentials(auth.getTicket()));

                        basicAuthSucessfull = true;
                    }
                    else
                    {
                        LOGGER.debug("Ticket in HTTP Basic authentication header detected but ticket logon is disabled");
                    }
                }
                else if (this.allowHttpBasicLogon)
                {
                    LOGGER.trace("Performing HTTP Basic user authentication");

                    this.authenticationService.authenticate(auth.getUserName(), auth.getPasswordCharArray());

                    this.createUserEnvironment(req.getSession(), this.authenticationService.getCurrentUserName(),
                            this.authenticationService.getCurrentTicket(), false);

                    LOGGER.debug("Authenticated user {} via HTTP Basic authentication",
                            AlfrescoCompatibilityUtil.maskUsername(this.authenticationService.getCurrentUserName()));

                    this.authenticationListener.userAuthenticated(new BasicAuthCredentials(auth.getUserName(), auth.getPassword()));

                    basicAuthSucessfull = true;
                }
            }
            catch (final AuthenticationException e)
            {
                LOGGER.debug("HTTP Basic authentication failed", e);

                if (auth.isTicket())
                {
                    this.authenticationListener.authenticationFailed(new TicketCredentials(auth.getTicket()), e);
                }
                else
                {
                    this.authenticationListener.authenticationFailed(new BasicAuthCredentials(auth.getUserName(), auth.getPassword()), e);
                }
            }
        }
        return basicAuthSucessfull;
    }

    /**
     * Processes Keycloak authentication and potential action operations. If a Keycloak action has been processed, the request processing
     * will be terminated. Otherwise processing may continue with the filter chain (if still applicable).
     *
     * @param context
     *     the servlet context
     * @param req
     *     the servlet request
     * @param res
     *     the servlet response
     * @param chain
     *     the filter chain
     * @throws IOException
     *     if any error occurs during Keycloak authentication or processing of the filter chain
     * @throws ServletException
     *     if any error occurs during Keycloak authentication or processing of the filter chain
     */
    protected void processKeycloakAuthenticationAndActions(final ServletContext context, final HttpServletRequest req,
            final HttpServletResponse res, final FilterChain chain) throws IOException, ServletException
    {
        LOGGER.trace("Processing Keycloak authentication and actions on request to {}", req.getRequestURL());

        final OIDCServletHttpFacade facade = new OIDCServletHttpFacade(req, res)
        {

            /**
             *
             * {@inheritDoc}
             */
            @Override
            public Request getRequest()
            {
                Request result;
                if (KeycloakAuthenticationFilter.this.originalRequestUrlHeaderName != null
                        && !KeycloakAuthenticationFilter.this.originalRequestUrlHeaderName.trim().isEmpty())
                {
                    result = new RequestFacade()
                    {

                        /**
                         *
                         * {@inheritDoc}
                         */
                        @Override
                        public String getURI()
                        {
                            String uri;
                            // if originalRequestUrlHeader is provided (e.g. to transport the original URL before a transparent rewrite
                            // within a reverse proxy), it must contain the same value as getRequestURL() would, that means schema, host and
                            // request path, but no query string
                            final String originalRequestUrl = this
                                    .getHeader(KeycloakAuthenticationFilter.this.originalRequestUrlHeaderName);
                            if (originalRequestUrl != null && !originalRequestUrl.trim().isEmpty())
                            {
                                uri = originalRequestUrl;

                                final String queryString = request.getQueryString();
                                if (queryString != null)
                                {
                                    uri += '?' + queryString;
                                }
                            }
                            else
                            {
                                uri = super.getURI();
                            }
                            return uri;
                        }
                    };
                }
                else
                {
                    result = this.requestFacade;
                }
                return result;
            }
        };

        final String servletPath = req.getServletPath();
        final String pathInfo = req.getPathInfo();
        final String servletRequestUri = servletPath + (pathInfo != null ? pathInfo : "");
        if (servletRequestUri.matches(KEYCLOAK_ACTION_URL_PATTERN))
        {
            LOGGER.trace("Applying Keycloak pre-auth actions handler");
            final PreAuthActionsHandler preActions = new PreAuthActionsHandler(new UserSessionManagement()
            {

                /**
                 *
                 * {@inheritDoc}
                 */
                @Override
                public void logoutAll()
                {
                    KeycloakAuthenticationFilter.this.sessionIdMapper.clear();
                }

                /**
                 *
                 * {@inheritDoc}
                 */
                @Override
                public void logoutHttpSessions(final List<String> ids)
                {
                    ids.forEach(KeycloakAuthenticationFilter.this.sessionIdMapper::removeSession);
                }
            }, this.deploymentContext, facade);

            if (preActions.handleRequest())
            {
                LOGGER.debug("Keycloak pre-auth actions processed the request - stopping filter chain execution");
                return;
            }
        }

        final OIDCFilterSessionStore tokenStore = new OIDCFilterSessionStore(req, facade,
                this.bodyBufferLimit > 0 ? this.bodyBufferLimit : DEFAULT_BODY_BUFFER_LIMIT, this.keycloakDeployment, this.sessionIdMapper);

        final int sslPort = this.determineLikelySslPort(req);

        final FilterRequestAuthenticator authenticator = new FilterRequestAuthenticator(this.keycloakDeployment, tokenStore, facade, req,
                sslPort);
        final AuthOutcome authOutcome = authenticator.authenticate();

        if (authOutcome == AuthOutcome.AUTHENTICATED)
        {
            this.onKeycloakAuthenticationSuccess(context, req, res, chain, facade, tokenStore);
        }
        else if (authOutcome == AuthOutcome.NOT_ATTEMPTED)
        {
            LOGGER.trace("No authentication took place - sending authentication challenge");
            authenticator.getChallenge().challenge(facade);
        }
        else if (authOutcome == AuthOutcome.FAILED)
        {
            this.onKeycloakAuthenticationFailure(context, req, res);

            LOGGER.trace("Sending authentication challenge from failure");
            authenticator.getChallenge().challenge(facade);
        }
    }

    /**
     * Processes a sucessfull authentication via Keycloak.
     *
     * @param context
     *     the servlet context
     * @param req
     *     the servlet request
     * @param res
     *     the servlet response
     * @param chain
     *     the filter chain
     * @param facade
     *     the Keycloak HTTP facade
     * @param tokenStore
     *     the Keycloak token store
     * @throws IOException
     *     if any error occurs during Keycloak authentication or processing of the filter chain
     * @throws ServletException
     *     if any error occurs during Keycloak authentication or processing of the filter chain
     */
    protected void onKeycloakAuthenticationSuccess(final ServletContext context, final HttpServletRequest req,
            final HttpServletResponse res, final FilterChain chain, final OIDCServletHttpFacade facade,
            final OIDCFilterSessionStore tokenStore) throws IOException, ServletException
    {
        final HttpSession session = req.getSession();
        final Object keycloakAccount = session.getAttribute(KeycloakAccount.class.getName());
        if (keycloakAccount instanceof OidcKeycloakAccount)
        {
            final KeycloakSecurityContext keycloakSecurityContext = ((OidcKeycloakAccount) keycloakAccount).getKeycloakSecurityContext();
            final AccessToken accessToken = keycloakSecurityContext.getToken();
            final String userId = accessToken.getPreferredUsername();

            LOGGER.debug("User {} successfully authenticated via Keycloak", AlfrescoCompatibilityUtil.maskUsername(userId));

            final SessionUser sessionUser = this.createUserEnvironment(session, userId);
            this.keycloakAuthenticationComponent.handleUserTokens(accessToken, keycloakSecurityContext.getIdToken(), true);
            this.authenticationListener.userAuthenticated(new KeycloakCredentials(accessToken));

            // store tokens in cache as well for ticket validation
            // -> necessary i.e. because web script RemoteUserAuthenticator is "evil"
            // it throws away any authentication from authentication filters like this,
            // and re-validates via the ticket in the session user

            final RefreshableAccessTokenHolder tokenHolder = new RefreshableAccessTokenHolder(keycloakSecurityContext.getToken(),
                    keycloakSecurityContext.getIdToken(), keycloakSecurityContext.getTokenString(),
                    keycloakSecurityContext instanceof RefreshableKeycloakSecurityContext
                            ? ((RefreshableKeycloakSecurityContext) keycloakSecurityContext).getRefreshToken()
                            : null);
            this.keycloakTicketTokenCache.put(sessionUser.getTicket(), tokenHolder);
        }

        if (facade.isEnded())
        {
            LOGGER.debug("Keycloak authenticator processed the request - stopping filter chain execution");
            return;
        }

        final String servletPath = req.getServletPath();
        final String pathInfo = req.getPathInfo();
        final String servletRequestUri = servletPath + (pathInfo != null ? pathInfo : "");

        if (servletRequestUri.matches(KEYCLOAK_ACTION_URL_PATTERN))
        {
            LOGGER.trace("Applying Keycloak authenticated actions handler");
            final AuthenticatedActionsHandler actions = new AuthenticatedActionsHandler(this.keycloakDeployment, facade);
            if (actions.handledRequest())
            {
                LOGGER.debug("Keycloak authenticated actions processed the request - stopping filter chain execution");
                return;
            }
        }

        LOGGER.trace("Continueing with filter chain processing");
        final HttpServletRequestWrapper requestWrapper = tokenStore.buildWrapper();
        chain.doFilter(requestWrapper, res);
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    protected SessionUser createUserEnvironment(final HttpSession session, final String userName) throws IOException, ServletException
    {
        final SessionUser sessionUser = super.createUserEnvironment(session, userName);

        // ensure all common attribute names are mapped
        // Alfresco is really inconsistent with these attribute names
        session.setAttribute(AuthenticationDriver.AUTHENTICATION_USER, sessionUser);
        session.setAttribute(BaseAuthenticationFilter.AUTHENTICATION_USER, sessionUser);

        return sessionUser;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    protected SessionUser createUserEnvironment(final HttpSession session, final String userName, final String ticket,
            final boolean externalAuth) throws IOException, ServletException
    {
        final SessionUser sessionUser = super.createUserEnvironment(session, userName, ticket, externalAuth);

        // ensure all common attribute names are mapped
        // Alfresco is really inconsistent with these attribute names
        session.setAttribute(AuthenticationDriver.AUTHENTICATION_USER, sessionUser);
        session.setAttribute(BaseAuthenticationFilter.AUTHENTICATION_USER, sessionUser);

        return sessionUser;
    }

    /**
     * Processes a failed authentication via Keycloak.
     *
     * @param context
     *     the servlet context
     * @param req
     *     the servlet request
     * @param res
     *     the servlet response
     *
     * @throws IOException
     *     if any error occurs during processing of the filter chain
     * @throws ServletException
     *     if any error occurs during processing of the filter chain
     */
    protected void onKeycloakAuthenticationFailure(final ServletContext context, final HttpServletRequest req,
            final HttpServletResponse res) throws IOException, ServletException
    {
        final Object authenticationError = req.getAttribute(AuthenticationError.class.getName());
        if (authenticationError != null)
        {
            LOGGER.warn("Keycloak authentication failed due to {}", authenticationError);
        }
        LOGGER.trace("Resetting session and state cookie before continueing with filter chain");

        try
        {
            req.getSession().invalidate();
        }
        catch (final IllegalStateException ignore)
        {
            // Keycloak authenticator may have already invalidated it - no way to check and avoid exception
        }

        this.resetStateCookies(context, req, res);

        this.authenticationListener.authenticationFailed(new UnknownCredentials());
    }

    /**
     * Checks if processing of the filter must be skipped for the specified request.
     *
     * @param context
     *     the servlet context
     * @param req
     *     the servlet request to check for potential conditions to skip
     * @param res
     *     the servlet response on which potential updates of cookies / response headers need to be set
     * @return {@code true} if processing of the {@link #doFilter(ServletContext, ServletRequest, ServletResponse, FilterChain) filter
     * operation} must be skipped, {@code false} otherwise
     *
     * @throws IOException
     *     if any error occurs during inspection of the request
     * @throws ServletException
     *     if any error occurs during inspection of the request
     */
    protected boolean checkForSkipCondition(final ServletContext context, final HttpServletRequest req, final HttpServletResponse res)
            throws IOException, ServletException
    {
        boolean skip = false;

        final String authHeader = req.getHeader(HEADER_AUTHORIZATION);
        final String noKeycloakHandlingRedirectHeader = req.getHeader(this.noKeycloakHandlingHeaderName);

        final String servletPath = req.getServletPath();
        final String pathInfo = req.getPathInfo();
        final String servletRequestUri = servletPath + (pathInfo != null ? pathInfo : "");

        SessionUser sessionUser = this.getSessionUser(context, req, res, true);
        HttpSession session = req.getSession(false);

        final boolean publicRestApi = API_SERVLET_PATH.equals(servletPath);
        final boolean noAuthPublicRestApiWebScript = publicRestApi
                && this.isNoAuthPublicRestApiWebScriptRequest(req, servletPath, pathInfo);

        // check for back-channel logout (sessionIdMapper should now of all authenticated sessions)
        if (this.active && sessionUser != null && session.getAttribute(KeycloakAccount.class.getName()) != null
                && !this.sessionIdMapper.hasSession(session.getId()))
        {
            LOGGER.debug("Session {} for Keycloak-authenticated user {} was invalidated by back-channel logout", session.getId(),
                    AlfrescoCompatibilityUtil.maskUsername(sessionUser.getUserName()));
            this.invalidateSession(req);
            sessionUser = null;
            session = req.getSession(false);
        }

        if (!this.active)
        {
            LOGGER.trace("Skipping processKeycloakAuthenticationAndActions as filter is not active");
            skip = true;
        }
        else if (servletRequestUri.matches(KEYCLOAK_ACTION_URL_PATTERN))
        {
            LOGGER.trace("Explicitly not skipping processKeycloakAuthenticationAndActions as Keycloak action URL is being called");
        }
        else if (req.getParameter("state") != null && req.getParameter("code") != null && this.hasStateCookie(req))
        {
            LOGGER.trace(
                    "Explicitly not skipping processKeycloakAuthenticationAndActions as state and code query parameters of OAuth2 redirect as well as state cookie are present");
        }
        else if (publicRestApi && !this.handlePublicApi)
        {
            LOGGER.trace(
                    "Explicitly skipping processKeycloakAuthenticationAndActions as filter is configured not to handle authentication on public API servlet");
            skip = true;
        }
        else if (authHeader != null && authHeader.toLowerCase(Locale.ENGLISH).startsWith("bearer "))
        {
            // even though we provide a remote user mapper, it may not be the first in the chain, so Bearer might not be processed (yet) and
            // thus session not initialised
            final AccessToken accessToken = session != null ? (AccessToken) session.getAttribute(KeycloakRemoteUserMapper.class.getName())
                    : null;
            if (accessToken != null)
            {
                if (accessToken.isActive())
                {
                    LOGGER.trace(
                            "Skipping processKeycloakAuthenticationAndActions as Bearer authorization header for {} has already been processed by remote user mapper",
                            AlfrescoCompatibilityUtil.maskUsername(accessToken.getPreferredUsername()));

                    // cannot rely on session.isNew() to determine if this is a fresh login
                    // consider "fresh" login if issued within age limit (implicitly include any token refreshes performed client-side)
                    final boolean isFreshLogin = accessToken.getIat() * 1000l > (System.currentTimeMillis() - FRESH_TOKEN_AGE_LIMIT_MS);
                    this.keycloakAuthenticationComponent.handleUserTokens(accessToken, accessToken, isFreshLogin);

                    // sessionUser should be guaranteed here, but still check - we need it for the cache key
                    if (sessionUser != null)
                    {
                        final String bearerToken = authHeader.substring("bearer ".length());
                        this.keycloakTicketTokenCache.put(sessionUser.getTicket(),
                                new RefreshableAccessTokenHolder(accessToken, accessToken, bearerToken, null));
                    }

                    skip = true;
                }
                else
                {
                    LOGGER.trace(
                            "Explicitly not skipping processKeycloakAuthenticationAndActions as processed Bearer authorization token for {} has expired",
                            AlfrescoCompatibilityUtil.maskUsername(accessToken.getPreferredUsername()));
                }
            }
            else
            {
                LOGGER.trace(
                        "Explicitly not skipping processKeycloakAuthenticationAndActions as unprocessed Bearer authorization header is present");
            }
        }
        else if (authHeader != null && authHeader.toLowerCase(Locale.ENGLISH).startsWith("basic "))
        {
            LOGGER.trace("Explicitly not skipping processKeycloakAuthenticationAndActions as Basic authorization header is present");
        }
        else if (authHeader != null)
        {
            LOGGER.trace("Skipping processKeycloakAuthenticationAndActions as non-OIDC / non-Basic authorization header is present");
            skip = true;
        }
        else if (this.allowTicketLogon && this.checkForTicketParameter(context, req, res))
        {
            LOGGER.trace("Skipping processKeycloakAuthenticationAndActions as user was authenticated by ticket URL parameter");
            skip = true;
        }
        // if user was already authenticated, validate
        else if (sessionUser != null)
        {
            final KeycloakAccount keycloakAccount = (KeycloakAccount) session.getAttribute(KeycloakAccount.class.getName());
            final AccessToken accessToken = (AccessToken) session.getAttribute(KeycloakRemoteUserMapper.class.getName());
            if (keycloakAccount != null)
            {
                skip = this.validateAndRefreshKeycloakAuthentication(req, res, sessionUser.getUserName());

                if (!skip)
                {
                    if (noAuthPublicRestApiWebScript)
                    {
                        LOGGER.trace(
                                "Skipping processKeycloakAuthenticationAndActions as request is aimed at a Public v1 ReST API which does not require authentication");
                        skip = true;
                    }
                    // check no-auth flag (derived e.g. from checking if target web script requires authentication) only after all
                    // pre-emptive auth
                    // request details have been checked
                    else if (Boolean.TRUE.equals(req.getAttribute(NO_AUTH_REQUIRED)))
                    {
                        LOGGER.trace(
                                "Skipping processKeycloakAuthenticationAndActions as filter higher up in chain determined authentication as not required");
                        skip = true;
                    }
                }
            }
            else if (accessToken != null)
            {
                if (accessToken.isActive())
                {
                    LOGGER.trace(
                            "Skipping processKeycloakAuthenticationAndActions as access token in session from previous Bearer authorization for {} is still valid",
                            AlfrescoCompatibilityUtil.maskUsername(sessionUser.getUserName()));
                    // accessToken may have already been handled by getSessionUser(), but don't count on it
                    this.keycloakAuthenticationComponent.handleUserTokens(accessToken, accessToken, false);
                    skip = true;
                }
                else
                {
                    LOGGER.debug("Access token in session from previous Bearer authorization for {} has expired - invalidating session",
                            AlfrescoCompatibilityUtil.maskUsername(sessionUser.getUserName()));
                    this.invalidateSession(req);

                    if (noAuthPublicRestApiWebScript)
                    {
                        LOGGER.trace(
                                "Skipping processKeycloakAuthenticationAndActions as request is aimed at a Public v1 ReST API which does not require authentication");
                        skip = true;
                    }

                    // check no-auth flag (derived e.g. from checking if target web script requires authentication) as last resort to see if
                    // we need to force authentication after invalidating session
                    else if (Boolean.TRUE.equals(req.getAttribute(NO_AUTH_REQUIRED)))
                    {
                        LOGGER.trace(
                                "Skipping processKeycloakAuthenticationAndActions as filter higher up in chain determined authentication as not required");
                        skip = true;
                    }
                    else
                    {
                        LOGGER.trace(
                                "Explicitly not skipping processKeycloakAuthenticationAndActions due to expired Bearer authorization for {}",
                                AlfrescoCompatibilityUtil.maskUsername(sessionUser.getUserName()));
                    }
                }
            }
            else
            {
                LOGGER.trace(
                        "Skipping processKeycloakAuthenticationAndActions as non-Keycloak-authenticated session is already established");
                skip = true;
            }
        }
        else if (noAuthPublicRestApiWebScript)
        {
            LOGGER.trace(
                    "Skipping processKeycloakAuthenticationAndActions as request is aimed at a Public v1 ReST API which does not require authentication");
            skip = true;
        }
        // check no-auth flag (derived e.g. from checking if target web script requires authentication) only after all pre-emptive auth
        // request details have been checked
        else if (Boolean.TRUE.equals(req.getAttribute(NO_AUTH_REQUIRED)))
        {
            LOGGER.trace(
                    "Skipping processKeycloakAuthenticationAndActions as filter higher up in chain determined authentication as not required");
            skip = true;
        }
        else if (Boolean.parseBoolean(noKeycloakHandlingRedirectHeader))
        {
            LOGGER.trace(
                    "Skipping processKeycloakAuthenticationAndActions as client provided custom 'no Keycloak handling' header {} with value that resolves to 'true'",
                    this.noKeycloakHandlingHeaderName);
            skip = true;
        }
        // TODO Check for login page URL (rarely configured since Repository by default has no login page since 5.0)

        return skip;
    }

    /**
     *
     * {@inheritDoc}
     */
    // mostly copied from base class
    // overridden / patched to avoid forced session initialisation
    @Override
    protected SessionUser getSessionUser(final ServletContext servletContext, final HttpServletRequest httpServletRequest,
            final HttpServletResponse httpServletResponse, final boolean externalAuth)
    {
        String userId = null;
        if (this.remoteUserMapper != null
                && (!(this.remoteUserMapper instanceof ActivateableBean) || ((ActivateableBean) this.remoteUserMapper).isActive()))
        {
            userId = this.remoteUserMapper.getRemoteUser(httpServletRequest);
            LOGGER.trace("Found a remote user: {}", AlfrescoCompatibilityUtil.maskUsername(userId));
        }

        final String sessionAttrib = this.getUserAttributeName();
        // deviation: don't force session
        HttpSession session = httpServletRequest.getSession(false);
        SessionUser sessionUser = session != null ? (SessionUser) session.getAttribute(sessionAttrib) : null;

        if (sessionUser != null)
        {
            try
            {
                LOGGER.trace("Found a session user: {}", AlfrescoCompatibilityUtil.maskUsername(sessionUser.getUserName()));
                this.authenticationService.validate(sessionUser.getTicket());
                if (externalAuth)
                {
                    session.setAttribute(LOGIN_EXTERNAL_AUTH, Boolean.TRUE);
                }
                else
                {
                    session.removeAttribute(LOGIN_EXTERNAL_AUTH);
                }
            }
            catch (final AuthenticationException e)
            {
                LOGGER.debug("The ticket may have expired or the person could have been removed, invalidating session.", e);
                this.invalidateSession(httpServletRequest);
                sessionUser = null;
            }
        }

        if (userId != null)
        {
            if (sessionUser != null && !sessionUser.getUserName().equals(userId))
            {
                LOGGER.debug("Session user does not match mapped remote user - invalidating session.");
                session.removeAttribute(sessionAttrib);
                session.invalidate();
                sessionUser = null;
            }

            if (sessionUser == null)
            {
                LOGGER.debug("Propagating through the user identity: {}", AlfrescoCompatibilityUtil.maskUsername(userId));
                this.keycloakAuthenticationComponent.setCurrentUser(userId);
                session = httpServletRequest.getSession();

                try
                {
                    sessionUser = this.createUserEnvironment(session, this.authenticationService.getCurrentUserName(),
                            this.authenticationService.getCurrentTicket(), true);
                }
                catch (final Throwable e)
                {
                    LOGGER.debug("Error during ticket validation and user creation: {}", e.getMessage(), e);
                }
            }
        }

        return sessionUser;
    }

    /**
     * Checks whether a particular request is aimed at a Public v1 ReST API web script which does not require any authentication.
     *
     * @param req
     *     the request to check
     * @param servletPath
     *     the path to the servlet matching the request
     * @param pathInfo
     *     the request path following the servlet path
     * @return {@code true} if the request targets a Public v1 ReST API web script which does not require authentication, {@code false}
     * otherwise
     */
    protected boolean isNoAuthPublicRestApiWebScriptRequest(final HttpServletRequest req, final String servletPath, final String pathInfo)
    {
        // due to how default Alfresco web.xml wires up authentication filters, we have to check for v1 ReST API no-auth web scripts
        // ourselves (cannot rely on a pre-handling filter like for regular web scripts)
        boolean noAuthPublicRestApiWebScript = false;
        if (API_SERVLET_PATH.equals(servletPath))
        {
            LOGGER.debug("Checking Public v1 ReST API for required auth status on request to {}", pathInfo);

            // utility to properly resolve script URL without duplicating some of the specifics here
            final PublicApiWebScriptUtilityRuntime publicApiRuntime = new PublicApiWebScriptUtilityRuntime(this.publicApiRuntimeContainer,
                    req);
            final String scriptUrl = publicApiRuntime.getScriptUrl();

            final Match match = this.publicApiRuntimeContainer.getRegistry().findWebScript(req.getMethod(), scriptUrl);
            if (match != null && match.getWebScript() != null)
            {
                final RequiredAuthentication reqAuth = match.getWebScript().getDescription().getRequiredAuthentication();

                if (RequiredAuthentication.none == reqAuth)
                {
                    LOGGER.debug("Found webscript with no authentication");
                    noAuthPublicRestApiWebScript = true;
                }
                // guest isn't really supported / used at all by Public v1 ReST API, but technically possible
                else if (RequiredAuthentication.guest == reqAuth && Boolean.parseBoolean(req.getParameter(ARG_GUEST)))
                {
                    LOGGER.debug("Found webscript with guest authentication and request with set guest parameter");
                    noAuthPublicRestApiWebScript = true;
                }
            }
        }
        return noAuthPublicRestApiWebScript;
    }

    /**
     * Processes an existing Keycloak authentication, verifying the state of the underlying access token and potentially refreshing it if
     * necessary or configured.
     *
     * @param req
     *     the HTTP servlet request
     * @param res
     *     the HTTP servlet response
     * @param userId
     *     the ID of the authenticated user
     * @return {@code true} if processing of the {@link #doFilter(ServletContext, ServletRequest, ServletResponse, FilterChain) filter
     * operation} can be skipped as the account represents a valid and still active authentication, {@code false} otherwise
     */
    protected boolean validateAndRefreshKeycloakAuthentication(final HttpServletRequest req, final HttpServletResponse res,
            final String userId)
    {
        final OIDCServletHttpFacade facade = new OIDCServletHttpFacade(req, res);

        final OIDCFilterSessionStore tokenStore = new OIDCFilterSessionStore(req, facade,
                this.bodyBufferLimit > 0 ? this.bodyBufferLimit : DEFAULT_BODY_BUFFER_LIMIT, this.keycloakDeployment, null)
        {

            /**
             *
             * {@inheritDoc}
             */
            @Override
            public void refreshCallback(final RefreshableKeycloakSecurityContext securityContext)
            {
                // store tokens in cache as well for ticket validation
                // -> necessary i.e. because web script RemoteUserAuthenticator is "evil"
                // it throws away any authentication from authentication filters like this,
                // and re-validates via the ticket in the session user

                final SessionUser user = (SessionUser) req.getSession()
                        .getAttribute(KeycloakAuthenticationFilter.this.getUserAttributeName());
                if (user != null)
                {
                    final RefreshableAccessTokenHolder tokenHolder = new RefreshableAccessTokenHolder(securityContext.getToken(),
                            securityContext.getIdToken(), securityContext.getTokenString(), securityContext.getRefreshToken());
                    KeycloakAuthenticationFilter.this.keycloakTicketTokenCache.put(user.getTicket(), tokenHolder);
                }
            }
        };

        final String oldSessionId = req.getSession().getId();

        tokenStore.checkCurrentToken();

        final HttpSession currentSession = req.getSession(false);

        boolean skip = false;
        if (currentSession != null)
        {
            final Object keycloakAccount = currentSession.getAttribute(KeycloakAccount.class.getName());
            if (keycloakAccount instanceof OidcKeycloakAccount)
            {
                final KeycloakSecurityContext keycloakSecurityContext = ((OidcKeycloakAccount) keycloakAccount)
                        .getKeycloakSecurityContext();
                this.keycloakAuthenticationComponent.handleUserTokens(keycloakSecurityContext.getToken(),
                        keycloakSecurityContext.getIdToken(), false);
            }

            LOGGER.trace("Skipping doFilter as Keycloak-authentication session is still valid");
            skip = true;
        }
        else
        {
            this.sessionIdMapper.removeSession(oldSessionId);
            LOGGER.debug("Keycloak-authenticated session for user {} was invalidated after token expiration",
                    AlfrescoCompatibilityUtil.maskUsername(userId));
        }
        return skip;
    }

    /**
     * Check if the request has specified a ticket parameter to bypass the standard authentication.
     *
     * @param context
     *     the servlet context
     * @param req
     *     the request
     * @param resp
     *     the response
     *
     * @throws IOException
     *     if any error occurs during ticket processing
     * @throws ServletException
     *     if any error occurs during ticket processing
     *
     * @return boolean
     */
    // copied + adapted from BaseSSOAuthenticationFilter
    protected boolean checkForTicketParameter(final ServletContext context, final HttpServletRequest req, final HttpServletResponse resp)
            throws IOException, ServletException
    {
        boolean ticketValid = false;
        // prefer ticket over alf_ticket, as default Alfresco filters only handle ticket
        String ticket = req.getParameter(ARG_TICKET);
        if (ticket == null)
        {
            ticket = req.getParameter(ARG_ALF_TICKET);
        }

        if (ticket != null && ticket.length() != 0)
        {
            LOGGER.trace("Logon via ticket from {} ({}:{}) ticket={}", req.getRemoteHost(), req.getRemoteAddr(), req.getRemotePort(),
                    ticket);

            try
            {
                // implicitly validates the ticket of the session user is still valid
                SessionUser user = this.getSessionUser(context, req, resp, true);

                if (user != null && !ticket.equals(user.getTicket()))
                {
                    LOGGER.debug("Invalidating current session as URL-provided authentication ticket does not match");
                    this.invalidateSession(req);
                    user = null;
                }

                if (user == null)
                {
                    this.authenticationService.validate(ticket);

                    LOGGER.debug("Authenticated user {} via URL-provided authentication ticket",
                            AlfrescoCompatibilityUtil.maskUsername(this.authenticationService.getCurrentUserName()));

                    this.authenticationListener.userAuthenticated(new TicketCredentials(ticket));
                }

                ticketValid = true;
            }
            catch (final AuthenticationException authErr)
            {
                LOGGER.debug("Failed to authenticate user ticket: {}", authErr.getMessage(), authErr);

                this.authenticationListener.authenticationFailed(new TicketCredentials(ticket), authErr);
            }
        }

        return ticketValid;
    }

    /**
     * Checks if the HTTP request has set the Keycloak state cookie.
     *
     * @param req
     *     the HTTP request to check
     * @return {@code true} if the state cookie is set, {@code false} otherwise
     */
    protected boolean hasStateCookie(final HttpServletRequest req)
    {
        final String stateCookieName = this.keycloakDeployment.getStateCookieName();
        final Cookie[] cookies = req.getCookies();
        final boolean hasStateCookie = cookies != null
                ? Arrays.asList(cookies).stream().map(Cookie::getName).filter(stateCookieName::equals).findAny().isPresent()
                : false;
        return hasStateCookie;
    }

    /**
     * Resets any Keycloak-related state cookies present in the current request.
     *
     * @param context
     *     the servlet context
     * @param req
     *     the servlet request
     * @param res
     *     the servlet response
     */
    protected void resetStateCookies(final ServletContext context, final HttpServletRequest req, final HttpServletResponse res)
    {
        final Cookie[] cookies = req.getCookies();
        if (cookies != null)
        {
            final String stateCookieName = this.keycloakDeployment.getStateCookieName();
            Arrays.asList(cookies).stream().filter(cookie -> stateCookieName.equals(cookie.getName())).findAny().ifPresent(cookie -> {
                final Cookie resetCookie = new Cookie(cookie.getName(), "");
                resetCookie.setPath(context.getContextPath());
                resetCookie.setMaxAge(0);
                resetCookie.setHttpOnly(true);
                resetCookie.setSecure(req.isSecure());
                res.addCookie(resetCookie);
            });
        }
    }

    /**
     * Determines the likely SSL port to be used in redirects from the incoming request. This operation should only be used to determine a
     * technical default value in lieu of an explicitly configured value.
     *
     * @param req
     *     the incoming request
     * @return the assumed SSL port to be used in redirects
     */
    protected int determineLikelySslPort(final HttpServletRequest req)
    {
        int rqPort = req.getServerPort();
        final String forwardedPort = req.getHeader("X-Forwarded-Port");
        if (forwardedPort != null && forwardedPort.matches("^\\d+$"))
        {
            rqPort = Integer.parseInt(forwardedPort);
        }
        final int sslPort;
        if (rqPort == 80 || rqPort == 443)
        {
            sslPort = 443;
        }
        else if (req.isSecure() && "https".equals(req.getScheme()))
        {
            sslPort = rqPort;
        }
        else
        {
            sslPort = 8443;
        }
        return sslPort;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected Log getLogger()
    {
        // ugh, Commons Logging - we don't use it ourselves, but base class requires it
        return LogFactory.getLog(KeycloakAuthenticationFilter.class);
    }

    /**
     * This derivation of the Public v1 ReST API servlet runtime exists solely to access the internal script URL resolution functionality to
     * avoid lookup duplication when determining whether the called API operation requires authentication or not.
     *
     * @author Axel Faust
     */
    protected static class PublicApiWebScriptUtilityRuntime extends PublicApiTenantWebScriptServletRuntime
    {

        protected PublicApiWebScriptUtilityRuntime(final RuntimeContainer container, final HttpServletRequest req)
        {
            super(container, null, req, null, null, null);
        }

        /**
         *
         * {@inheritDoc}
         */
        @Override
        protected String getScriptUrl()
        {
            return super.getScriptUrl();
        }
    }
}
