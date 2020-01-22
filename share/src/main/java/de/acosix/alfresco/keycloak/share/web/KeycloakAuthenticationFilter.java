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
package de.acosix.alfresco.keycloak.share.web;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

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

import org.alfresco.util.PropertyCheck;
import org.alfresco.web.site.servlet.SSOAuthenticationFilter;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.AuthenticatedActionsHandler;
import org.keycloak.adapters.HttpClientBuilder;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.OAuthRequestAuthenticator;
import org.keycloak.adapters.OidcKeycloakAccount;
import org.keycloak.adapters.PreAuthActionsHandler;
import org.keycloak.adapters.servlet.FilterRequestAuthenticator;
import org.keycloak.adapters.servlet.OIDCFilterSessionStore;
import org.keycloak.adapters.servlet.OIDCServletHttpFacade;
import org.keycloak.adapters.spi.AuthOutcome;
import org.keycloak.adapters.spi.AuthenticationError;
import org.keycloak.adapters.spi.KeycloakAccount;
import org.keycloak.adapters.spi.SessionIdMapper;
import org.keycloak.adapters.spi.UserSessionManagement;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.extensions.config.ConfigService;
import org.springframework.extensions.config.RemoteConfigElement;
import org.springframework.extensions.config.RemoteConfigElement.EndpointDescriptor;
import org.springframework.extensions.surf.RequestContext;
import org.springframework.extensions.surf.RequestContextUtil;
import org.springframework.extensions.surf.ServletUtil;
import org.springframework.extensions.surf.UserFactory;
import org.springframework.extensions.surf.exception.ConnectorServiceException;
import org.springframework.extensions.surf.mvc.PageViewResolver;
import org.springframework.extensions.surf.site.AuthenticationUtil;
import org.springframework.extensions.surf.types.Page;
import org.springframework.extensions.surf.types.PageType;
import org.springframework.extensions.webscripts.Description.RequiredAuthentication;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.connector.Connector;
import org.springframework.extensions.webscripts.connector.ConnectorService;
import org.springframework.extensions.webscripts.servlet.DependencyInjectedFilter;

import de.acosix.alfresco.keycloak.share.config.KeycloakAdapterConfigElement;
import de.acosix.alfresco.keycloak.share.config.KeycloakAuthenticationConfigElement;
import de.acosix.alfresco.keycloak.share.config.KeycloakConfigConstants;
import de.acosix.alfresco.keycloak.share.remote.BearerTokenAwareSlingshotAlfrescoConnector;

/**
 * Keycloak-based authentication filter class which can act as a standalone filter or a facade to the default {@link SSOAuthenticationFilter
 * SSO filter}.
 *
 * @author Axel Faust
 */
public class KeycloakAuthenticationFilter implements DependencyInjectedFilter, InitializingBean, ApplicationContextAware
{

    private static final String HEADER_AUTHORIZATION = "Authorization";

    private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakAuthenticationFilter.class);

    private static final String PROXY_URL_PATTERN = "^(?:/page)?/proxy/([^/]+)(-noauth)?/.+$";

    private static final String KEYCLOAK_ACTION_URL_PATTERN = "^(?:/page)?/keycloak/k_[^/]+$";

    private static final Pattern PROXY_URL_PATTERN_COMPILED = Pattern.compile(PROXY_URL_PATTERN);

    private static final String PAGE_SERVLET_PATH = "/page";

    private static final String LOGIN_PAGE_TYPE_PARAMETER_VALUE = "login";

    private static final String PAGE_TYPE_PARAMETER_NAME = "pt";

    private static final String LOGIN_PATH_INFORMATION = "/dologin";

    private static final String LOGOUT_PATH_INFORMATION = "/dologout";

    private static final int DEFAULT_BODY_BUFFER_LIMIT = 32 * 1024;// 32 KiB

    private static final ThreadLocal<String> LOGIN_REDIRECT_URL = new ThreadLocal<>();

    protected ApplicationContext applicationContext;

    protected DependencyInjectedFilter defaultSsoFilter;

    protected ConfigService configService;

    protected ConnectorService connectorService;

    protected PageViewResolver pageViewResolver;

    protected SessionIdMapper sessionIdMapper;

    protected String primaryEndpoint;

    protected List<String> secondaryEndpoints;

    protected boolean externalAuthEnabled = false;

    protected boolean filterEnabled = false;

    protected boolean loginFormEnhancementEnabled = false;

    protected boolean forceSso = false;

    protected KeycloakDeployment keycloakDeployment;

    protected AdapterDeploymentContext deploymentContext;

    /**
     * Retrieves the Keycloak login redirect URI set in the current thread's scope for use in any lazy redirect handling, e.g. as an action
     * in the login form.
     *
     * @return the login redirect URL, or {@code null} if no URL was set in the current thread's scope.
     */
    public static String getLoginRedirectUrl()
    {
        return LOGIN_REDIRECT_URL.get();
    }

    /**
     * Utility method to check if the current user has been authenticated by this filter / via Keycloak.
     *
     * @return {@code true} if the currently logged in user was authenticated by Keycloak, {@code false} otherwise
     */
    public static boolean isAuthenticatedByKeycloak()
    {
        final HttpServletRequest req = ServletUtil.getRequest();
        boolean authenticatedByKeycloak = false;

        if (req != null)
        {
            final HttpSession currentSession = req.getSession(false);
            authenticatedByKeycloak = currentSession != null && AuthenticationUtil.isAuthenticated(req)
                    && currentSession.getAttribute(KeycloakAccount.class.getName()) != null;
        }
        return authenticatedByKeycloak;
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
     *
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet()
    {
        PropertyCheck.mandatory(this, "primaryEndpoint", this.primaryEndpoint);
        PropertyCheck.mandatory(this, "configService", this.configService);
        PropertyCheck.mandatory(this, "connectorService", this.connectorService);
        PropertyCheck.mandatory(this, "pageViewResolver", this.pageViewResolver);
        PropertyCheck.mandatory(this, "sessionIdMapper", this.sessionIdMapper);

        LOGGER.info("Setting up filter for primary endpoint {} and secondary endpoints {}", this.primaryEndpoint, this.secondaryEndpoints);

        final RemoteConfigElement remoteConfig = (RemoteConfigElement) this.configService.getConfig("Remote").getConfigElement("remote");
        if (remoteConfig != null)
        {
            final EndpointDescriptor endpoint = remoteConfig.getEndpointDescriptor(this.primaryEndpoint);
            if (endpoint != null)
            {
                this.externalAuthEnabled = endpoint.getExternalAuth();
            }
            else
            {
                LOGGER.error("Endpoint {} has not been defined in the application configuration", this.primaryEndpoint);
            }

            if (this.secondaryEndpoints != null)
            {
                this.secondaryEndpoints = this.secondaryEndpoints.stream().filter(secondaryEndpoint -> {
                    final boolean endpointExists = remoteConfig.getEndpointDescriptor(secondaryEndpoint) != null;
                    if (!endpointExists)
                    {
                        LOGGER.info("Excluding configured secondary endpoint {} which is not defined in the application configuration",
                                secondaryEndpoint);
                    }
                    return endpointExists;
                }).collect(Collectors.toList());
            }
        }
        else
        {
            LOGGER.error("No remote configuration has been defined for the application");
        }

        final KeycloakAdapterConfigElement keycloakAdapterConfig = (KeycloakAdapterConfigElement) this.configService
                .getConfig(KeycloakConfigConstants.KEYCLOAK_CONFIG_SECTION_NAME).getConfigElement(KeycloakAdapterConfigElement.NAME);
        if (keycloakAdapterConfig != null)
        {
            final AdapterConfig adapterConfiguration = keycloakAdapterConfig.buildAdapterConfiguration();

            // disable any CORS handling (if CORS is relevant, it should be handled by Share / Surf)
            adapterConfiguration.setCors(false);
            // BASIC authentication should never be used
            adapterConfiguration.setEnableBasicAuth(false);

            this.keycloakDeployment = KeycloakDeploymentBuilder.build(adapterConfiguration);

            // even in newer version than used by ACS 6.x does Keycloak lib not allow timeout configuration
            if (this.keycloakDeployment.getClient() != null)
            {
                final Long connectionTimeout = keycloakAdapterConfig.getConnectionTimeout();
                final Long socketTimeout = keycloakAdapterConfig.getSocketTimeout();

                HttpClientBuilder httpClientBuilder = new HttpClientBuilder();
                if (connectionTimeout != null && connectionTimeout.longValue() >= 0)
                {
                    httpClientBuilder = httpClientBuilder.establishConnectionTimeout(connectionTimeout.longValue(), TimeUnit.MILLISECONDS);
                }
                if (socketTimeout != null && socketTimeout.longValue() >= 0)
                {
                    httpClientBuilder = httpClientBuilder.socketTimeout(socketTimeout.longValue(), TimeUnit.MILLISECONDS);
                }
                this.keycloakDeployment.setClient(httpClientBuilder.build(adapterConfiguration));
            }

            this.deploymentContext = new AdapterDeploymentContext(this.keycloakDeployment);
        }
        else
        {
            LOGGER.error("No Keycloak adapter configuration has been defined for the application");
        }

        final KeycloakAuthenticationConfigElement keycloakAuthConfig = (KeycloakAuthenticationConfigElement) this.configService
                .getConfig(KeycloakConfigConstants.KEYCLOAK_CONFIG_SECTION_NAME).getConfigElement(KeycloakAuthenticationConfigElement.NAME);
        if (keycloakAuthConfig != null)
        {
            this.filterEnabled = Boolean.TRUE.equals(keycloakAuthConfig.getEnableSsoFilter());
            this.loginFormEnhancementEnabled = Boolean.TRUE.equals(keycloakAuthConfig.getEnhanceLoginForm());
            this.forceSso = Boolean.TRUE.equals(keycloakAuthConfig.getForceKeycloakSso());
        }
        else
        {
            LOGGER.error("No Keycloak authentication configuration has been defined for the application");
        }

        if (this.filterEnabled && !this.keycloakDeployment.isConfigured())
        {
            throw new IllegalStateException("The Keycloak adapter has not been properly configured");
        }
    }

    /**
     * @param defaultSsoFilter
     *            the defaultSsoFilter to set
     */
    public void setDefaultSsoFilter(final DependencyInjectedFilter defaultSsoFilter)
    {
        this.defaultSsoFilter = defaultSsoFilter;
    }

    /**
     * @param configService
     *            the configService to set
     */
    public void setConfigService(final ConfigService configService)
    {
        this.configService = configService;
    }

    /**
     * @param connectorService
     *            the connectorService to set
     */
    public void setConnectorService(final ConnectorService connectorService)
    {
        this.connectorService = connectorService;
    }

    /**
     * @param pageViewResolver
     *            the pageViewResolver to set
     */
    public void setPageViewResolver(final PageViewResolver pageViewResolver)
    {
        this.pageViewResolver = pageViewResolver;
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
     * @param primaryEndpoint
     *            the primaryEndpoint to set
     */
    public void setPrimaryEndpoint(final String primaryEndpoint)
    {
        this.primaryEndpoint = primaryEndpoint;
    }

    /**
     * @param secondaryEndpoints
     *            the secondaryEndpoints to set
     */
    public void setSecondaryEndpoints(final List<String> secondaryEndpoints)
    {
        this.secondaryEndpoints = secondaryEndpoints != null ? new ArrayList<>(secondaryEndpoints) : null;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void doFilter(final ServletContext context, final ServletRequest request, final ServletResponse response,
            final FilterChain chain) throws IOException, ServletException
    {
        try
        {
            final HttpServletRequest req = (HttpServletRequest) request;
            final HttpServletResponse res = (HttpServletResponse) response;
            LOGGER.debug("Entered doFilter for {}", req);

            if (this.isLogoutRequest(req))
            {
                this.processLogout(context, req, res, chain);
            }
            else
            {
                final boolean skip = this.checkForSkipCondition(req, res);

                if (skip)
                {
                    if (!AuthenticationUtil.isAuthenticated(req) && this.loginFormEnhancementEnabled && this.isLoginPage(req))
                    {
                        this.prepareLoginFormEnhancement(context, req, res);
                    }

                    this.continueFilterChain(context, request, response, chain);
                }
                else
                {
                    this.processKeycloakAuthenticationAndActions(context, req, res, chain);
                }
            }
        }
        finally
        {
            LOGIN_REDIRECT_URL.remove();
        }
    }

    protected void processLogout(final ServletContext context, final HttpServletRequest req, final HttpServletResponse res,
            final FilterChain chain) throws IOException, ServletException
    {
        final HttpSession currentSession = req.getSession(false);

        if (currentSession != null && AuthenticationUtil.isAuthenticated(req)
                && currentSession.getAttribute(KeycloakAccount.class.getName()) != null
                && this.sessionIdMapper.hasSession(currentSession.getId()))
        {
            LOGGER.debug("Processing logout for Keycloak-authenticated user {} in session {}", AuthenticationUtil.getUserId(req),
                    currentSession.getId());

            final KeycloakAuthenticationConfigElement keycloakAuthConfig = (KeycloakAuthenticationConfigElement) this.configService
                    .getConfig(KeycloakConfigConstants.KEYCLOAK_CONFIG_SECTION_NAME)
                    .getConfigElement(KeycloakAuthenticationConfigElement.NAME);

            final OIDCServletHttpFacade facade = new OIDCServletHttpFacade(req, res);
            final Integer bodyBufferLimit = keycloakAuthConfig.getBodyBufferLimit();
            final OIDCFilterSessionStore tokenStore = new OIDCFilterSessionStore(req, facade,
                    bodyBufferLimit != null ? bodyBufferLimit.intValue() : DEFAULT_BODY_BUFFER_LIMIT, this.keycloakDeployment, null);

            tokenStore.logout();

            chain.doFilter(req, res);
        }
        else
        {
            this.continueFilterChain(context, req, res, chain);
        }
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
        LOGGER.debug("Processing Keycloak authentication on request to {}", req.getRequestURL());

        final KeycloakAuthenticationConfigElement keycloakAuthConfig = (KeycloakAuthenticationConfigElement) this.configService
                .getConfig(KeycloakConfigConstants.KEYCLOAK_CONFIG_SECTION_NAME).getConfigElement(KeycloakAuthenticationConfigElement.NAME);

        final Integer bodyBufferLimit = keycloakAuthConfig.getBodyBufferLimit();
        final Integer sslRedirectPort = keycloakAuthConfig.getSslRedirectPort();

        final OIDCServletHttpFacade facade = new OIDCServletHttpFacade(req, res);

        final String servletPath = req.getServletPath();
        final String pathInfo = req.getPathInfo();
        final String servletRequestUri = servletPath + (pathInfo != null ? pathInfo : "");
        if (servletRequestUri.matches(KEYCLOAK_ACTION_URL_PATTERN))
        {
            LOGGER.debug("Applying Keycloak pre-auth actions handler");
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
                bodyBufferLimit != null ? bodyBufferLimit.intValue() : DEFAULT_BODY_BUFFER_LIMIT, this.keycloakDeployment,
                this.sessionIdMapper);

        // use 8443 as default SSL redirect based on Tomcat default server.xml configuration
        final FilterRequestAuthenticator authenticator = new FilterRequestAuthenticator(this.keycloakDeployment, tokenStore, facade, req,
                sslRedirectPort != null ? sslRedirectPort.intValue() : 8443);
        final AuthOutcome authOutcome = authenticator.authenticate();

        if (authOutcome == AuthOutcome.AUTHENTICATED)
        {
            this.onKeycloakAuthenticationSuccess(context, req, res, chain, facade, tokenStore);
        }
        else if (authOutcome == AuthOutcome.NOT_ATTEMPTED && this.forceSso)
        {
            LOGGER.debug("No authentication took place - sending authentication challenge");
            authenticator.getChallenge().challenge(facade);
        }
        else if (authOutcome == AuthOutcome.FAILED)
        {
            this.onKeycloakAuthenticationFailure(context, req, res, chain);
        }
        else
        {

            if (authOutcome == AuthOutcome.NOT_ATTEMPTED)
            {
                LOGGER.debug("No authentication took place - continueing with filter chain processing");

                if (this.loginFormEnhancementEnabled)
                {
                    this.prepareLoginFormEnhancement(context, req, res, authenticator);
                }
            }
            else
            {
                LOGGER.warn("Unexpected authentication outcome {} - continueing with filter chain processing", authOutcome);
            }

            this.continueFilterChain(context, req, res, chain);
        }
    }

    /**
     * Sets up the necessary state to enhance the login form customisation to provide an action to perform a Keycloak login via a redirect.
     *
     * @param context
     *            the servlet context
     * @param req
     *            the HTTP servlet request being processed
     * @param res
     *            the HTTP servlet response being processed
     * @param authenticator
     *            the authenticator holding the challenge for a login redirect
     */
    protected void prepareLoginFormEnhancement(final ServletContext context, final HttpServletRequest req, final HttpServletResponse res,
            final FilterRequestAuthenticator authenticator)
    {
        final ResponseHeaderCookieCaptureServletHttpFacade captureFacade = new ResponseHeaderCookieCaptureServletHttpFacade(req);

        authenticator.getChallenge().challenge(captureFacade);

        // reset existing cookies
        this.resetStateCookies(context, req, res);

        captureFacade.getCookies().stream().map(cookie -> {
            cookie.setPath(context.getContextPath());
            return cookie;
        }).forEach(res::addCookie);

        final List<String> redirects = captureFacade.getHeaders().get("Location");
        if (redirects != null && !redirects.isEmpty())
        {
            LOGIN_REDIRECT_URL.set(redirects.get(0));
        }
    }

    /**
     * Sets up the necessary state to enhance the login form customisation to provide an action to perform a Keycloak login via a redirect.
     *
     * @param context
     *            the servlet context
     * @param req
     *            the HTTP servlet request being processed
     * @param res
     *            the HTTP servlet response being processed
     */
    protected void prepareLoginFormEnhancement(final ServletContext context, final HttpServletRequest req, final HttpServletResponse res)
    {
        final KeycloakAuthenticationConfigElement keycloakAuthConfig = (KeycloakAuthenticationConfigElement) this.configService
                .getConfig(KeycloakConfigConstants.KEYCLOAK_CONFIG_SECTION_NAME).getConfigElement(KeycloakAuthenticationConfigElement.NAME);

        final Integer bodyBufferLimit = keycloakAuthConfig.getBodyBufferLimit();
        final Integer sslRedirectPort = keycloakAuthConfig.getSslRedirectPort();

        // fake a request that will yield a redirect
        final HttpServletRequest wrappedReq = new HttpServletRequestWrapper(req)
        {

            /**
             * {@inheritDoc}
             */
            @Override
            public String getQueryString()
            {
                // no query parameters, so no code= and no error=
                // this will cause login redirect challenge to be generated
                return "";
            }

        };

        final ResponseHeaderCookieCaptureServletHttpFacade captureFacade = new ResponseHeaderCookieCaptureServletHttpFacade(wrappedReq);

        final OIDCFilterSessionStore tokenStore = new OIDCFilterSessionStore(req, captureFacade,
                bodyBufferLimit != null ? bodyBufferLimit.intValue() : DEFAULT_BODY_BUFFER_LIMIT, this.keycloakDeployment, null);

        // use 8443 as default SSL redirect based on Tomcat default server.xml configuration
        final OAuthRequestAuthenticator authenticator = new OAuthRequestAuthenticator(null, captureFacade, this.keycloakDeployment,
                sslRedirectPort != null ? sslRedirectPort.intValue() : 8443, tokenStore);

        final AuthOutcome authOutcome = authenticator.authenticate();
        if (authOutcome != AuthOutcome.NOT_ATTEMPTED)
        {
            LOGGER.error("OAuthRequestAuthenticator yielded unexpected auth outcome {}", authOutcome);
            res.setStatus(Status.STATUS_INTERNAL_SERVER_ERROR);
            throw new IllegalStateException("OAuthRequestAuthenticator did not generate login redirect");
        }
        authenticator.getChallenge().challenge(captureFacade);

        // reset existing cookies
        this.resetStateCookies(context, req, res);

        captureFacade.getCookies().stream().map(cookie -> {
            // always scope to context path - otherwise we end up getting multiple cookies for multiple paths
            cookie.setPath(context.getContextPath());
            return cookie;
        }).forEach(res::addCookie);

        final List<String> redirects = captureFacade.getHeaders().get("Location");
        if (redirects != null && !redirects.isEmpty())
        {
            LOGIN_REDIRECT_URL.set(redirects.get(0));
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
            LOGGER.debug("User {} successfully authenticated via Keycloak", userId);

            final String accessTokenString = keycloakSecurityContext.getTokenString();
            this.updateEndpointConnectorBearerToken(this.primaryEndpoint, userId, session, accessTokenString);
            if (this.secondaryEndpoints != null)
            {
                this.secondaryEndpoints.forEach(endpoint -> {
                    this.updateEndpointConnectorBearerToken(endpoint, userId, session, accessTokenString);
                });
            }

            session.setAttribute(UserFactory.SESSION_ATTRIBUTE_EXTERNAL_AUTH, Boolean.TRUE);
            session.setAttribute(UserFactory.SESSION_ATTRIBUTE_KEY_USER_ID, userId);
        }

        if (facade.isEnded())
        {
            LOGGER.debug("Authenticator already handled response");
            return;
        }

        final String servletPath = req.getServletPath();
        final String pathInfo = req.getPathInfo();
        final String servletRequestUri = servletPath + (pathInfo != null ? pathInfo : "");
        if (servletRequestUri.matches(KEYCLOAK_ACTION_URL_PATTERN))
        {
            LOGGER.debug("Applying Keycloak authenticated actions handler");
            final AuthenticatedActionsHandler actions = new AuthenticatedActionsHandler(this.keycloakDeployment, facade);
            if (actions.handledRequest())
            {
                LOGGER.debug("Keycloak authenticated actions processed the request - stopping filter chain execution");
                return;
            }
        }

        LOGGER.debug("Continueing with filter chain processing");
        final HttpServletRequestWrapper requestWrapper = tokenStore.buildWrapper();
        this.continueFilterChain(context, requestWrapper, res, chain);
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
     * @param chain
     *            the filter chain
     * @throws IOException
     *             if any error occurs during processing of the filter chain
     * @throws ServletException
     *             if any error occurs during processing of the filter chain
     */
    protected void onKeycloakAuthenticationFailure(final ServletContext context, final HttpServletRequest req,
            final HttpServletResponse res, final FilterChain chain) throws IOException, ServletException
    {
        LOGGER.warn("Keycloak authentication failed due to {}", req.getAttribute(AuthenticationError.class.getName()));
        LOGGER.debug("Resetting session and state cookie before continueing with filter chain");

        req.getSession().invalidate();

        this.resetStateCookies(context, req, res);

        this.continueFilterChain(context, req, res, chain);
    }

    /**
     * Continues processing the filter chain, either directly or by delegating to the facaded default SSO filter.
     *
     * @param context
     *            the servlet context
     * @param request
     *            the current request
     * @param response
     *            the response to the current request
     * @param chain
     *            the filter chain
     * @throws IOException
     *             if any exception is propagated by a filter in the chain or the actual request processing
     * @throws ServletException
     *             if any exception is propagated by a filter in the chain or the actual request processing
     */
    protected void continueFilterChain(final ServletContext context, final ServletRequest request, final ServletResponse response,
            final FilterChain chain) throws IOException, ServletException
    {
        final HttpSession session = ((HttpServletRequest) request).getSession(false);
        final Object keycloakAccount = session != null ? session.getAttribute(KeycloakAccount.class.getName()) : null;

        // no point in forwarding to default SSO filter if already authenticated
        if (this.defaultSsoFilter != null && keycloakAccount == null)
        {
            this.defaultSsoFilter.doFilter(context, request, response, chain);
        }
        else
        {
            chain.doFilter(request, response);
        }
    }

    /**
     * Checks if processing of the filter must be skipped for the specified request.
     *
     * @param req
     *            the servlet request to check for potential conditions to skip
     * @param res
     *            the servlet response on which potential updates of cookies / response headers need to be set
     * @return {@code true} if processing of the {@link #doFilter(ServletContext, ServletRequest, ServletResponse, FilterChain) filter
     *         operation} must be skipped, {@code false} otherwise
     * @throws ServletException
     *             if any error occurs during inspection of the request
     */
    protected boolean checkForSkipCondition(final HttpServletRequest req, final HttpServletResponse res) throws ServletException
    {
        boolean skip = false;

        final String authHeader = req.getHeader(HEADER_AUTHORIZATION);

        final String servletPath = req.getServletPath();
        final String pathInfo = req.getPathInfo();
        final String servletRequestUri = servletPath + (pathInfo != null ? pathInfo : "");

        final Matcher proxyMatcher = PROXY_URL_PATTERN_COMPILED.matcher(servletRequestUri);

        HttpSession currentSession = req.getSession(false);

        // check for back-channel logout (sessionIdMapper should now of all authenticated sessions)
        if (this.externalAuthEnabled && this.filterEnabled && this.keycloakDeployment != null && currentSession != null
                && AuthenticationUtil.isAuthenticated(req) && currentSession.getAttribute(KeycloakAccount.class.getName()) != null
                && !this.sessionIdMapper.hasSession(currentSession.getId()))
        {
            LOGGER.debug("Session {} for Keycloak-authenticated user {} was invalidated by back-channel logout", currentSession.getId(),
                    AuthenticationUtil.getUserId(req));
            currentSession.invalidate();
            currentSession = req.getSession(false);
        }

        if (!this.externalAuthEnabled || !this.filterEnabled)
        {
            LOGGER.debug("Skipping doFilter as filter and/or external authentication are not enabled");
            skip = true;
        }
        else if (this.keycloakDeployment == null)
        {
            LOGGER.debug("Skipping doFilter as Keycloak adapter was not properly initialised");
            skip = true;
        }
        else if (servletRequestUri.matches(KEYCLOAK_ACTION_URL_PATTERN))
        {
            LOGGER.debug("Explicitly not skipping doFilter as Keycloak action URL is being called");
        }
        else if (req.getParameter("state") != null && req.getParameter("code") != null && this.hasStateCookie(req))
        {
            LOGGER.debug(
                    "Explicitly not skipping doFilter as state and code query parameters of OAuth2 redirect as well as state cookie are present");
        }
        else if (authHeader != null && authHeader.toLowerCase(Locale.ENGLISH).startsWith("bearer "))
        {
            LOGGER.debug("Explicitly not skipping doFilter as Bearer authorization header is present");
        }
        else if (authHeader != null && authHeader.toLowerCase(Locale.ENGLISH).startsWith("basic "))
        {
            LOGGER.debug("Explicitly not skipping doFilter as Basic authorization header is present");
        }
        else if (authHeader != null)
        {
            LOGGER.debug("Skipping doFilter as non-OIDC / non-Basic authorization header is present");
            skip = true;
        }
        else if (currentSession != null && AuthenticationUtil.isAuthenticated(req))
        {
            final KeycloakAccount keycloakAccount = (KeycloakAccount) currentSession.getAttribute(KeycloakAccount.class.getName());
            if (keycloakAccount != null)
            {
                skip = this.validateAndRefreshKeycloakAuthentication(req, res, AuthenticationUtil.getUserId(req), keycloakAccount);
            }
            else
            {
                LOGGER.debug("Skipping doFilter as non-Keycloak-authenticated session is already established");
                skip = true;
            }
        }
        else if (proxyMatcher.matches())
        {
            final String endpoint = proxyMatcher.group(1);
            final String noauth = proxyMatcher.group(2);
            if (noauth != null && !noauth.trim().isEmpty())
            {
                LOGGER.debug("Skipping doFilter as proxy servlet to noauth endpoint {} is being called");
                skip = true;
            }
            else if (!endpoint.equals(this.primaryEndpoint)
                    && (this.secondaryEndpoints == null || !this.secondaryEndpoints.contains(endpoint)))
            {
                LOGGER.debug(
                        "Skipping doFilter on proxy servlet call as endpoint {} has not been configured as a primary / secondary endpoint to handle");
                skip = true;
            }
        }
        else if (PAGE_SERVLET_PATH.equals(servletPath) && (LOGIN_PATH_INFORMATION.equals(pathInfo)
                || (pathInfo == null && LOGIN_PAGE_TYPE_PARAMETER_VALUE.equals(req.getParameter(PAGE_TYPE_PARAMETER_NAME)))))
        {
            LOGGER.debug("Skipping doFilter as login page was explicitly requested");
            skip = true;
        }
        else if (this.isNoAuthPage(req))
        {
            LOGGER.debug("Skipping doFilter as requested page does not require authentication");
            skip = true;
        }

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
     * @param keycloakAccount
     *            the Keycloak account object
     * @return {@code true} if processing of the {@link #doFilter(ServletContext, ServletRequest, ServletResponse, FilterChain) filter
     *         operation} can be skipped as the account represents a valid and still active authentication, {@code false} otherwise
     */
    protected boolean validateAndRefreshKeycloakAuthentication(final HttpServletRequest req, final HttpServletResponse res,
            final String userId, final KeycloakAccount keycloakAccount)
    {
        HttpSession currentSession;
        final OIDCServletHttpFacade facade = new OIDCServletHttpFacade(req, res);

        final KeycloakAuthenticationConfigElement keycloakAuthConfig = (KeycloakAuthenticationConfigElement) this.configService
                .getConfig(KeycloakConfigConstants.KEYCLOAK_CONFIG_SECTION_NAME).getConfigElement(KeycloakAuthenticationConfigElement.NAME);

        final Integer bodyBufferLimit = keycloakAuthConfig.getBodyBufferLimit();
        final OIDCFilterSessionStore tokenStore = new OIDCFilterSessionStore(req, facade,
                bodyBufferLimit != null ? bodyBufferLimit.intValue() : DEFAULT_BODY_BUFFER_LIMIT, this.keycloakDeployment, null);

        tokenStore.checkCurrentToken();

        currentSession = req.getSession(false);
        boolean skip = false;
        if (currentSession != null)
        {
            LOGGER.debug("Skipping doFilter as Keycloak-authentication session is still valid");
            skip = true;

            if (keycloakAccount instanceof OidcKeycloakAccount)
            {
                final KeycloakSecurityContext keycloakSecurityContext = ((OidcKeycloakAccount) keycloakAccount)
                        .getKeycloakSecurityContext();

                final String accessTokenString = keycloakSecurityContext.getTokenString();

                final HttpSession effectiveSession = currentSession;
                this.updateEndpointConnectorBearerToken(this.primaryEndpoint, userId, effectiveSession, accessTokenString);
                if (this.secondaryEndpoints != null)
                {
                    this.secondaryEndpoints.forEach(endpoint -> {
                        this.updateEndpointConnectorBearerToken(endpoint, userId, effectiveSession, accessTokenString);
                    });
                }
            }
        }
        else
        {
            LOGGER.debug("Keycloak-authenticated session for user {} was invalidated after token expiration", userId);
        }
        return skip;
    }

    /**
     * Checks if the requested page does not require user authentication.
     *
     * @param req
     *            the servlet request for which to check the authentication requirement of the target page
     * @return {@code true} if the requested page does not require user authentication,
     *         {@code false} otherwise (incl. failure to resolve the request to a target page)
     * @throws ServletException
     *             if any error occurs during inspection of the request
     */
    protected boolean isNoAuthPage(final HttpServletRequest req) throws ServletException
    {
        final String pathInfo = req.getPathInfo();
        RequestContext context = null;
        try
        {
            context = RequestContextUtil.initRequestContext(this.applicationContext, req, true);
        }
        catch (final Exception ex)
        {
            LOGGER.error("Error calling initRequestContext", ex);
            throw new ServletException(ex);
        }

        Page page = context.getPage();
        if (page == null && pathInfo != null)
        {
            try
            {
                if (this.pageViewResolver.resolveViewName(pathInfo, null) != null)
                {
                    page = context.getPage();
                }
            }
            catch (final Exception e)
            {
                LOGGER.warn("Error during resolution of requested page view", e);
            }
        }

        boolean noAuthPage = false;
        if (page != null && page.getAuthentication() == RequiredAuthentication.none)
        {
            noAuthPage = true;
        }
        return noAuthPage;
    }

    /**
     * Checks if the requested page is a login page.
     *
     * @param req
     *            the request for which to check the type of page
     * @return {@code true} if the requested page is a login page,
     *         {@code false} otherwise (incl. failure to resolve the request to a target page)
     * @throws ServletException
     *             if any error occurs during inspection of the request
     */
    protected boolean isLoginPage(final HttpServletRequest req) throws ServletException
    {
        final String servletPath = req.getServletPath();
        final String pathInfo = req.getPathInfo();

        boolean isLoginPage;
        if (PAGE_SERVLET_PATH.equals(servletPath)
                && (pathInfo == null && LOGIN_PAGE_TYPE_PARAMETER_VALUE.equals(req.getParameter(PAGE_TYPE_PARAMETER_NAME))))
        {
            isLoginPage = true;
        }
        else
        {
            // check for custom login page
            RequestContext context = null;
            try
            {
                context = RequestContextUtil.initRequestContext(this.applicationContext, req, true);
            }
            catch (final Exception ex)
            {
                LOGGER.error("Error calling initRequestContext", ex);
                throw new ServletException(ex);
            }

            Page page = context.getPage();
            if (page == null && pathInfo != null)
            {
                try
                {
                    if (this.pageViewResolver.resolveViewName(pathInfo, null) != null)
                    {
                        page = context.getPage();
                    }
                }
                catch (final Exception e)
                {
                    LOGGER.warn("Error during resolution of requested page view", e);
                }
            }

            isLoginPage = false;
            if (page != null && page.getPageType(context) != null && PageType.PAGETYPE_LOGIN.equals(page.getPageType(context).getId()))
            {
                isLoginPage = true;
            }
        }
        return isLoginPage;
    }

    /**
     * Checks if the requested URL indicates a logout request.
     *
     * @param req
     *            the request to check
     * @return {@code true} if the request is a request for logout,
     *         {@code false} otherwise
     * @throws ServletException
     *             if any error occurs during inspection of the request
     */
    protected boolean isLogoutRequest(final HttpServletRequest req) throws ServletException
    {
        final String servletPath = req.getServletPath();
        final String pathInfo = req.getPathInfo();
        final boolean isLogoutRequest = PAGE_SERVLET_PATH.equals(servletPath) && LOGOUT_PATH_INFORMATION.equals(pathInfo);
        return isLogoutRequest;
    }

    protected void updateEndpointConnectorBearerToken(final String endpoint, final String userId, final HttpSession session,
            final String tokenString)
    {
        try
        {
            final Connector conn = this.connectorService.getConnector(endpoint, userId, session);
            conn.getConnectorSession().setParameter(BearerTokenAwareSlingshotAlfrescoConnector.CS_PARAM_BEARER_TOKEN, tokenString);
        }
        catch (final ConnectorServiceException e)
        {
            LOGGER.warn("Endpoint {} has not been defined", endpoint);
        }
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
}
