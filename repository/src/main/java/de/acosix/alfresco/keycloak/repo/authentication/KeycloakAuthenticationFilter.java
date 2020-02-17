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
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import javax.servlet.FilterChain;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

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
import org.alfresco.util.PropertyCheck;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

import de.acosix.alfresco.keycloak.repo.deps.keycloak.KeycloakSecurityContext;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.adapters.AdapterDeploymentContext;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.adapters.AuthenticatedActionsHandler;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.adapters.KeycloakDeployment;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.adapters.OidcKeycloakAccount;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.adapters.PreAuthActionsHandler;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.adapters.RefreshableKeycloakSecurityContext;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.adapters.servlet.FilterRequestAuthenticator;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.adapters.servlet.OIDCFilterSessionStore;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.adapters.servlet.OIDCServletHttpFacade;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.adapters.spi.AuthOutcome;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.adapters.spi.AuthenticationError;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.adapters.spi.KeycloakAccount;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.adapters.spi.SessionIdMapper;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.adapters.spi.UserSessionManagement;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.common.util.KeycloakUriBuilder;
import de.acosix.alfresco.keycloak.repo.deps.keycloak.representations.AccessToken;
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

    private static final String HEADER_AUTHORIZATION = "Authorization";

    private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakAuthenticationFilter.class);

    private static final String KEYCLOAK_ACTION_URL_PATTERN = "^(?:/wcs(?:ervice)?)?/keycloak/k_[^/]+$";

    private static final int DEFAULT_BODY_BUFFER_LIMIT = 32 * 1024;// 32 KiB

    protected boolean active;

    protected boolean allowTicketLogon;

    protected boolean allowLocalBasicLogon;

    protected String loginPageUrl;

    protected int bodyBufferLimit = DEFAULT_BODY_BUFFER_LIMIT;

    // use 8443 as default SSL redirect based on Tomcat default server.xml configuration
    // can't rely on SysAdminParams#getAlfrescoPort either because that may be proxied / non-SSL
    protected int sslRedirectPort = 8443;

    protected KeycloakDeployment keycloakDeployment;

    protected SessionIdMapper sessionIdMapper;

    protected AdapterDeploymentContext deploymentContext;

    protected KeycloakAuthenticationComponent keycloakAuthenticationComponent;

    protected SimpleCache<String, RefreshableAccessTokenHolder> keycloakTicketTokenCache;

    /**
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet()
    {
        PropertyCheck.mandatory(this, "keycloakDeployment", this.keycloakDeployment);
        PropertyCheck.mandatory(this, "sessionIdMapper", this.sessionIdMapper);
        PropertyCheck.mandatory(this, "keycloakTicketTokenCache", this.keycloakTicketTokenCache);
        PropertyCheck.mandatory(this, "keycloakAuthenticationComponent", this.keycloakAuthenticationComponent);

        // parent class does not check, so we do
        PropertyCheck.mandatory(this, "authenticationService", this.authenticationService);
        PropertyCheck.mandatory(this, "authenticationComponent", this.authenticationComponent);
        PropertyCheck.mandatory(this, "authenticationListener", this.authenticationListener);
        PropertyCheck.mandatory(this, "personService", this.personService);
        PropertyCheck.mandatory(this, "nodeService", this.nodeService);
        PropertyCheck.mandatory(this, "transactionService", this.transactionService);

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
     *            the active to set
     */
    public void setActive(final boolean active)
    {
        this.active = active;
    }

    /**
     * @param allowTicketLogon
     *            the allowTicketLogon to set
     */
    public void setAllowTicketLogon(final boolean allowTicketLogon)
    {
        this.allowTicketLogon = allowTicketLogon;
    }

    /**
     * @param allowLocalBasicLogon
     *            the allowLocalBasicLogon to set
     */
    public void setAllowLocalBasicLogon(final boolean allowLocalBasicLogon)
    {
        this.allowLocalBasicLogon = allowLocalBasicLogon;
    }

    /**
     * @param loginPageUrl
     *            the loginPageUrl to set
     */
    public void setLoginPageUrl(final String loginPageUrl)
    {
        this.loginPageUrl = loginPageUrl;
    }

    /**
     * @param bodyBufferLimit
     *            the bodyBufferLimit to set
     */
    public void setBodyBufferLimit(final int bodyBufferLimit)
    {
        this.bodyBufferLimit = bodyBufferLimit;
    }

    /**
     * @param sslRedirectPort
     *            the sslRedirectPort to set
     */
    public void setSslRedirectPort(final int sslRedirectPort)
    {
        this.sslRedirectPort = sslRedirectPort;
    }

    /**
     * @param keycloakDeployment
     *            the keycloakDeployment to set
     */
    public void setKeycloakDeployment(final KeycloakDeployment keycloakDeployment)
    {
        this.keycloakDeployment = keycloakDeployment;
    }

    /**
     * @param sessionIdMapper
     *            the sessionIdMapper to set
     */
    public void setSessionIdMapper(final SessionIdMapper sessionIdMapper)
    {
        this.sessionIdMapper = sessionIdMapper;
    }

    /**
     * @param keycloakAuthenticationComponent
     *            the keycloakAuthenticationComponent to set
     */
    public void setKeycloakAuthenticationComponent(final KeycloakAuthenticationComponent keycloakAuthenticationComponent)
    {
        this.keycloakAuthenticationComponent = keycloakAuthenticationComponent;
    }

    /**
     * @param keycloakTicketTokenCache
     *            the keycloakTicketTokenCache to set
     */
    public void setKeycloakTicketTokenCache(final SimpleCache<String, RefreshableAccessTokenHolder> keycloakTicketTokenCache)
    {
        this.keycloakTicketTokenCache = keycloakTicketTokenCache;
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
            if (!this.checkAndProcessLocalBasicAuthentication(req))
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
     * Checks and processes any HTTP Basic authentication against the local Alfresco authentication services if allowed.
     *
     * @param req
     *            the servlet request
     *
     * @throws IOException
     *             if any error occurs during processing of HTTP Basic authentication
     * @throws ServletException
     *             if any error occurs during processing of HTTP Basic authentication
     *
     * @return {@code true} if an existing HTTP Basic authentication header was successfully processed against the local Alfresco
     *         authentication services, {@code false} otherwise
     */
    protected boolean checkAndProcessLocalBasicAuthentication(final HttpServletRequest req) throws IOException, ServletException
    {
        boolean basicAuthSucessfull = false;
        final String authHeader = req.getHeader(HEADER_AUTHORIZATION);
        if (authHeader != null && authHeader.toLowerCase(Locale.ENGLISH).startsWith("basic "))
        {
            final String basicAuth = new String(Base64.decodeBase64(authHeader.substring(6).getBytes(StandardCharsets.UTF_8)),
                    StandardCharsets.UTF_8);

            String userName;
            String password = "";

            final int pos = basicAuth.indexOf(":");
            if (pos != -1)
            {
                userName = basicAuth.substring(0, pos);
                password = basicAuth.substring(pos + 1);
            }
            else
            {
                userName = basicAuth;
            }

            try
            {
                if (userName.equalsIgnoreCase(Authorization.TICKET_USERID))
                {
                    if (this.allowTicketLogon)
                    {
                        LOGGER.trace("Performing HTTP Basic ticket validation");
                        this.authenticationService.validate(password);

                        this.createUserEnvironment(req.getSession(), this.authenticationService.getCurrentUserName(),
                                this.authenticationService.getCurrentTicket(), false);

                        LOGGER.debug("Authenticated user {} via HTTP Basic authentication using an authentication ticket",
                                AlfrescoCompatibilityUtil.maskUsername(this.authenticationService.getCurrentUserName()));

                        this.authenticationListener.userAuthenticated(new TicketCredentials(password));

                        basicAuthSucessfull = true;
                    }
                    else
                    {
                        LOGGER.debug("Ticket in HTTP Basic authentication header detected but ticket logon is disabled");
                    }
                }
                else if (this.allowLocalBasicLogon)
                {
                    LOGGER.trace("Performing HTTP Basic user authentication against local Alfresco services");

                    this.authenticationService.authenticate(userName, password.toCharArray());

                    this.createUserEnvironment(req.getSession(), this.authenticationService.getCurrentUserName(),
                            this.authenticationService.getCurrentTicket(), false);

                    LOGGER.debug("Authenticated user {} via HTTP Basic authentication using locally stored credentials",
                            AlfrescoCompatibilityUtil.maskUsername(this.authenticationService.getCurrentUserName()));

                    this.authenticationListener.userAuthenticated(new BasicAuthCredentials(userName, password));

                    basicAuthSucessfull = true;
                }
            }
            catch (final AuthenticationException e)
            {
                LOGGER.debug("HTTP Basic authentication against local Alfresco services failed", e);

                if (userName.equalsIgnoreCase(Authorization.TICKET_USERID))
                {
                    this.authenticationListener.authenticationFailed(new TicketCredentials(password), e);
                }
                else
                {
                    this.authenticationListener.authenticationFailed(new BasicAuthCredentials(userName, password), e);
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
     *            the servlet context
     * @param req
     *            the servlet request
     * @param res
     *            the servlet response
     * @param chain
     *            the filter chain
     * @throws IOException
     *             if any error occurs during Keycloak authentication or processing of the filter chain
     * @throws ServletException
     *             if any error occurs during Keycloak authentication or processing of the filter chain
     */
    protected void processKeycloakAuthenticationAndActions(final ServletContext context, final HttpServletRequest req,
            final HttpServletResponse res, final FilterChain chain) throws IOException, ServletException
    {
        LOGGER.trace("Processing Keycloak authentication and actions on request to {}", req.getRequestURL());

        final OIDCServletHttpFacade facade = new OIDCServletHttpFacade(req, res);

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
        final FilterRequestAuthenticator authenticator = new FilterRequestAuthenticator(this.keycloakDeployment, tokenStore, facade, req,
                this.sslRedirectPort);
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
     *            the servlet context
     * @param req
     *            the servlet request
     * @param res
     *            the servlet response
     * @param chain
     *            the filter chain
     * @param facade
     *            the Keycloak HTTP facade
     * @param tokenStore
     *            the Keycloak token store
     * @throws IOException
     *             if any error occurs during Keycloak authentication or processing of the filter chain
     * @throws ServletException
     *             if any error occurs during Keycloak authentication or processing of the filter chain
     */
    protected void onKeycloakAuthenticationSuccess(final ServletContext context, final HttpServletRequest req,
            final HttpServletResponse res, final FilterChain chain, final OIDCServletHttpFacade facade,
            final OIDCFilterSessionStore tokenStore) throws IOException, ServletException
    {
        final HttpSession session = req.getSession();
        final Object keycloakAccount = session != null ? session.getAttribute(KeycloakAccount.class.getName()) : null;
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
     *            the servlet context
     * @param req
     *            the servlet request
     * @param res
     *            the servlet response
     *
     * @throws IOException
     *             if any error occurs during processing of the filter chain
     * @throws ServletException
     *             if any error occurs during processing of the filter chain
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

        req.getSession().invalidate();

        this.resetStateCookies(context, req, res);

        this.authenticationListener.authenticationFailed(new UnknownCredentials());
    }

    /**
     * Checks if processing of the filter must be skipped for the specified request.
     *
     * @param context
     *            the servlet context
     * @param req
     *            the servlet request to check for potential conditions to skip
     * @param res
     *            the servlet response on which potential updates of cookies / response headers need to be set
     * @return {@code true} if processing of the {@link #doFilter(ServletContext, ServletRequest, ServletResponse, FilterChain) filter
     *         operation} must be skipped, {@code false} otherwise
     *
     * @throws IOException
     *             if any error occurs during inspection of the request
     * @throws ServletException
     *             if any error occurs during inspection of the request
     */
    protected boolean checkForSkipCondition(final ServletContext context, final HttpServletRequest req, final HttpServletResponse res)
            throws IOException, ServletException
    {
        boolean skip = false;

        final String authHeader = req.getHeader(HEADER_AUTHORIZATION);

        final String servletPath = req.getServletPath();
        final String pathInfo = req.getPathInfo();
        final String servletRequestUri = servletPath + (pathInfo != null ? pathInfo : "");

        final SessionUser sessionUser = this.getSessionUser(context, req, res, true);
        HttpSession session = req.getSession();

        // check for back-channel logout (sessionIdMapper should now of all authenticated sessions)
        if (this.active && sessionUser != null && session.getAttribute(KeycloakAccount.class.getName()) != null
                && !this.sessionIdMapper.hasSession(session.getId()))
        {
            LOGGER.debug("Session {} for Keycloak-authenticated user {} was invalidated by back-channel logout", session.getId(),
                    AlfrescoCompatibilityUtil.maskUsername(sessionUser.getUserName()));
            this.invalidateSession(req);
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
        else if (authHeader != null && authHeader.toLowerCase(Locale.ENGLISH).startsWith("bearer "))
        {
            final AccessToken accessToken = (AccessToken) session.getAttribute(KeycloakRemoteUserMapper.class.getName());
            if (accessToken != null)
            {
                if (accessToken.isActive())
                {
                    LOGGER.trace(
                            "Skipping processKeycloakAuthenticationAndActions as Bearer authorization header for {} has already been processed by remote user mapper",
                            AlfrescoCompatibilityUtil.maskUsername(accessToken.getPreferredUsername()));
                    this.keycloakAuthenticationComponent.handleUserTokens(accessToken, accessToken, session.isNew());

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
        // check no-auth flag (derived e.g. from checking if target web script requires authentication) only after all pre-emptive auth
        // request details have been checked
        else if (Boolean.TRUE.equals(req.getAttribute(NO_AUTH_REQUIRED)))
        {
            LOGGER.trace(
                    "Skipping processKeycloakAuthenticationAndActions as filter higher up in chain determined authentication as not required");
            skip = true;
        }
        else if (sessionUser != null)
        {
            final KeycloakAccount keycloakAccount = (KeycloakAccount) session.getAttribute(KeycloakAccount.class.getName());
            final AccessToken accessToken = (AccessToken) session.getAttribute(KeycloakRemoteUserMapper.class.getName());
            if (keycloakAccount != null)
            {
                skip = this.validateAndRefreshKeycloakAuthentication(req, res, sessionUser.getUserName());
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
                    LOGGER.trace(
                            "Explicitly not skipping processKeycloakAuthenticationAndActions as access token in session from previous Bearer authorization for {} has expired",
                            AlfrescoCompatibilityUtil.maskUsername(sessionUser.getUserName()));
                    this.invalidateSession(req);
                }
            }
            else
            {
                LOGGER.trace(
                        "Skipping processKeycloakAuthenticationAndActions as non-Keycloak-authenticated session is already established");
                skip = true;
            }
        }
        // TODO Check for login page URL (rarely configured since Repository by default has no login page since 5.0)

        return skip;
    }

    /**
     * Processes an existing Keycloak authentication, verifying the state of the underlying access token and potentially refreshing it if
     * necessary or configured.
     *
     * @param req
     *            the HTTP servlet request
     * @param res
     *            the HTTP servlet response
     * @param userId
     *            the ID of the authenticated user
     * @return {@code true} if processing of the {@link #doFilter(ServletContext, ServletRequest, ServletResponse, FilterChain) filter
     *         operation} can be skipped as the account represents a valid and still active authentication, {@code false} otherwise
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
     *            the servlet context
     * @param req
     *            the request
     * @param resp
     *            the response
     *
     * @throws IOException
     *             if any error occurs during ticket processing
     * @throws ServletException
     *             if any error occurs during ticket processing
     *
     * @return boolean
     */
    // copied + adapted from BaseSSOAuthenticationFilter
    protected boolean checkForTicketParameter(final ServletContext context, final HttpServletRequest req, final HttpServletResponse resp)
            throws IOException, ServletException
    {
        boolean ticketValid = false;
        final String ticket = req.getParameter(ARG_TICKET);

        if (ticket != null && ticket.length() != 0)
        {
            LOGGER.trace("Logon via ticket from {} ({}:{}) ticket={}", req.getRemoteHost(), req.getRemoteAddr(), req.getRemotePort(),
                    ticket);

            try
            {
                final SessionUser user = this.getSessionUser(context, req, resp, true);

                if (user != null && !ticket.equals(user.getTicket()))
                {
                    LOGGER.debug("Invalidating current session as URL-provided authentication ticket does not match");
                    this.invalidateSession(req);
                }

                if (user == null)
                {
                    this.authenticationService.validate(ticket);

                    this.createUserEnvironment(req.getSession(), this.authenticationService.getCurrentUserName(),
                            this.authenticationService.getCurrentTicket(), true);

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
     *            the HTTP request to check
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
     *            the servlet context
     * @param req
     *            the servlet request
     * @param res
     *            the servlet response
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
                resetCookie.setHttpOnly(false);
                resetCookie.setSecure(false);
                res.addCookie(resetCookie);
            });
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected Log getLogger()
    {
        return LogFactory.getLog(KeycloakAuthenticationFilter.class);
    }

}
