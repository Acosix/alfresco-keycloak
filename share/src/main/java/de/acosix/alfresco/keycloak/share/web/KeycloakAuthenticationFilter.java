/*
 * Copyright 2019 - 2025 Acosix GmbH
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

import static org.alfresco.web.site.SlingshotPageView.REDIRECT_QUERY;
import static org.alfresco.web.site.SlingshotPageView.REDIRECT_URI;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Callable;
import java.util.function.BiFunction;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.alfresco.error.AlfrescoRuntimeException;
import org.alfresco.util.EqualsHelper;
import org.alfresco.util.PropertyCheck;
import org.alfresco.web.site.servlet.SSOAuthenticationFilter;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.params.ConnRoutePNames;
import org.apache.http.conn.params.ConnRouteParams;
import org.apache.http.conn.routing.HttpRoute;
import org.apache.http.conn.routing.HttpRoutePlanner;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.OAuth2Constants;
import org.keycloak.TokenVerifier;
import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.AuthenticatedActionsHandler;
import org.keycloak.adapters.BearerTokenRequestAuthenticator;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.OAuthRequestAuthenticator;
import org.keycloak.adapters.OIDCAuthenticationError;
import org.keycloak.adapters.OidcKeycloakAccount;
import org.keycloak.adapters.PreAuthActionsHandler;
import org.keycloak.adapters.rotation.AdapterTokenVerifier;
import org.keycloak.adapters.rotation.AdapterTokenVerifier.VerifiedTokens;
import org.keycloak.adapters.servlet.FilterRequestAuthenticator;
import org.keycloak.adapters.servlet.OIDCFilterSessionStore;
import org.keycloak.adapters.servlet.OIDCServletHttpFacade;
import org.keycloak.adapters.spi.AuthOutcome;
import org.keycloak.adapters.spi.AuthenticationError;
import org.keycloak.adapters.spi.KeycloakAccount;
import org.keycloak.adapters.spi.SessionIdMapper;
import org.keycloak.adapters.spi.UserSessionManagement;
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
import org.springframework.extensions.surf.support.ThreadLocalRequestContext;
import org.springframework.extensions.surf.types.Page;
import org.springframework.extensions.surf.types.PageType;
import org.springframework.extensions.surf.util.URLEncoder;
import org.springframework.extensions.webscripts.Description.RequiredAuthentication;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.connector.Connector;
import org.springframework.extensions.webscripts.connector.ConnectorContext;
import org.springframework.extensions.webscripts.connector.ConnectorService;
import org.springframework.extensions.webscripts.connector.Response;
import org.springframework.extensions.webscripts.servlet.DependencyInjectedFilter;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import de.acosix.alfresco.keycloak.share.config.ExtendedAdapterConfig;
import de.acosix.alfresco.keycloak.share.config.KeycloakAdapterConfigElement;
import de.acosix.alfresco.keycloak.share.config.KeycloakAuthenticationConfigElement;
import de.acosix.alfresco.keycloak.share.config.KeycloakConfigConstants;
import de.acosix.alfresco.keycloak.share.remote.AccessTokenAwareSlingshotAlfrescoConnector;
import de.acosix.alfresco.keycloak.share.util.HttpClientBuilder;
import de.acosix.alfresco.keycloak.share.util.NameValueMapAdapter;
import de.acosix.alfresco.keycloak.share.util.RefreshableAccessTokenHolder;
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

/**
 * Keycloak-based authentication filter class which can act as a standalone filter or a facade to the default {@link SSOAuthenticationFilter
 * SSO filter}.
 *
 * @author Axel Faust
 */
@SuppressWarnings("deprecation")
public class KeycloakAuthenticationFilter implements DependencyInjectedFilter, InitializingBean, ApplicationContextAware
{

    public static final String KEYCLOAK_AUTHENTICATED_COOKIE = "Acosix." + KeycloakAuthenticationFilter.class.getSimpleName();

    public static final String KEYCLOAK_ACCOUNT_SESSION_KEY = KeycloakAccount.class.getName();

    public static final String ACCESS_TOKEN_SESSION_KEY = AccessToken.class.getName();

    public static final String BACKEND_ACCESS_TOKEN_SESSION_KEY = AccessTokenAwareSlingshotAlfrescoConnector.class.getName();

    // copied from SSOAuthenticationFilter (inaccessible constant there)
    public static final String ERROR_PARAMETER = "error";

    // well known values - need not be accessible to other classes
    private static final String HEADER_AUTHORIZATION = "Authorization";

    private static final String HEADER_WWWAUTHENTICATE = "WWW-Authenticate";

    private static final String HEADER_ACCEPT_LANGUAGE = "Accept-Language";

    private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakAuthenticationFilter.class);

    private static final String PROXY_URL_PATTERN = "^(?:/page)?/proxy/([^/]+)(-noauth)?/.+$";

    private static final String KEYCLOAK_ACTION_URL_PATTERN = "^(?:/page)?/keycloak/k_[^/]+$";

    private static final Pattern PROXY_URL_PATTERN_COMPILED = Pattern.compile(PROXY_URL_PATTERN);

    private static final String PAGE_SERVLET_PATH = "/page";

    private static final String LOGIN_PAGE_TYPE_PARAMETER_VALUE = "login";

    private static final String PAGE_TYPE_PARAMETER_NAME = "pt";

    // used on some login page redirects - see PageView ALF_REDIRECT_URL constant
    private static final String ALF_REDIRECT_URL = "alfRedirectUrl";

    private static final String LOGIN_PATH_INFORMATION = "/dologin";

    private static final String LOGOUT_PATH_INFORMATION = "/dologout";

    private static final String LOGOUT_SERVICE_PATH = "/service/dologout";

    private static final int DEFAULT_BODY_BUFFER_LIMIT = 32 * 1024;// 32 KiB

    private static final ThreadLocal<String> LOGIN_REDIRECT_URL = new ThreadLocal<>();

    private static final BiFunction<HttpServletRequest, HttpServletResponse, ServletRequestAttributes> SERVLET_REQUEST_ATTRIBUTES_FACTORY;

    static
    {
        BiFunction<HttpServletRequest, HttpServletResponse, ServletRequestAttributes> factory;

        try
        {
            // try and use the overloaded constructor available in newer versions
            final Constructor<ServletRequestAttributes> ctor = ServletRequestAttributes.class.getConstructor(HttpServletRequest.class,
                    HttpServletResponse.class);
            factory = (req, res) -> {
                try
                {
                    return ctor.newInstance(req, res);
                }
                catch (final InstantiationException | IllegalAccessException | InvocationTargetException e)
                {
                    throw new AlfrescoRuntimeException("Failed to construct servlet request attributes", e);
                }
            };
        }
        catch (final NoSuchMethodException nsme)
        {
            // fallback to constructor that's available in all Share versions
            factory = (req, res) -> new ServletRequestAttributes(req);
        }

        SERVLET_REQUEST_ATTRIBUTES_FACTORY = factory;
    }

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

    protected boolean rememberSso = false;

    protected boolean ignoreDefaultFilter = false;

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
                    && currentSession.getAttribute(KEYCLOAK_ACCOUNT_SESSION_KEY) != null;
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
        PropertyCheck.mandatory(this, "applicationContext", this.applicationContext);
        PropertyCheck.mandatory(this, "primaryEndpoint", this.primaryEndpoint);
        PropertyCheck.mandatory(this, "configService", this.configService);
        PropertyCheck.mandatory(this, "connectorService", this.connectorService);
        PropertyCheck.mandatory(this, "pageViewResolver", this.pageViewResolver);
        PropertyCheck.mandatory(this, "sessionIdMapper", this.sessionIdMapper);

        LOGGER.info("Setting up filter for primary endpoint {} and secondary endpoints {}", this.primaryEndpoint, this.secondaryEndpoints);

        final RemoteConfigElement remoteConfig = (RemoteConfigElement) this.configService.getConfig("Remote").getConfigElement("remote");
        if (remoteConfig != null)
        {
            this.initFromRemoteEndpointConfig(remoteConfig);
        }
        else
        {
            LOGGER.error("No remote configuration has been defined for the application");
        }

        final KeycloakAdapterConfigElement keycloakAdapterConfig = (KeycloakAdapterConfigElement) this.configService
                .getConfig(KeycloakConfigConstants.KEYCLOAK_CONFIG_SECTION_NAME).getConfigElement(KeycloakAdapterConfigElement.NAME);
        if (keycloakAdapterConfig != null)
        {
            this.initFromAdapterConfig(keycloakAdapterConfig);
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
            this.rememberSso = Boolean.TRUE.equals(keycloakAuthConfig.getRememberKeycloakSso());
            this.ignoreDefaultFilter = Boolean.TRUE.equals(keycloakAuthConfig.getIgnoreDefaultFilter());
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
     *     the defaultSsoFilter to set
     */
    public void setDefaultSsoFilter(final DependencyInjectedFilter defaultSsoFilter)
    {
        this.defaultSsoFilter = defaultSsoFilter;
    }

    /**
     * @param configService
     *     the configService to set
     */
    public void setConfigService(final ConfigService configService)
    {
        this.configService = configService;
    }

    /**
     * @param connectorService
     *     the connectorService to set
     */
    public void setConnectorService(final ConnectorService connectorService)
    {
        this.connectorService = connectorService;
    }

    /**
     * @param pageViewResolver
     *     the pageViewResolver to set
     */
    public void setPageViewResolver(final PageViewResolver pageViewResolver)
    {
        this.pageViewResolver = pageViewResolver;
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
     * @param primaryEndpoint
     *     the primaryEndpoint to set
     */
    public void setPrimaryEndpoint(final String primaryEndpoint)
    {
        this.primaryEndpoint = primaryEndpoint;
    }

    /**
     * @param secondaryEndpoints
     *     the secondaryEndpoints to set
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

            final KeycloakUriBuilder authUrl = this.keycloakDeployment.getAuthUrl();
            final boolean keycloakDeploymentReady = authUrl != null;
            if (!keycloakDeploymentReady)
            {
                LOGGER.warn("Cannot process Keycloak-specifics as Keycloak library was unable to resolve relative URLs from {}",
                        this.keycloakDeployment.getAuthServerBaseUrl());
            }

            RequestContextHolder.setRequestAttributes(SERVLET_REQUEST_ATTRIBUTES_FACTORY.apply(req, res));
            // Alfresco handling of RequestContext / ServletUtil / any other context holder is so immensely broken, it isn't even funny
            // this request context is for any handling that needs it until it gets nuked / bulldozed by RequestContextInterceptor
            // ...after which we will have to enhance that class' partially initialised context
            RequestContext requestContext;
            try
            {
                requestContext = RequestContextUtil.initRequestContext(this.applicationContext, req, true);
            }
            catch (final Exception ex)
            {
                LOGGER.error("Error calling initRequestContext", ex);
                throw new ServletException(ex);
            }

            try
            {
                if (keycloakDeploymentReady && this.isLogoutRequest(req))
                {
                    this.processLogout(context, req, res, chain);
                }
                else
                {
                    final boolean skip = !keycloakDeploymentReady || this.checkForSkipCondition(req, res);

                    if (skip)
                    {
                        final boolean authenticated = AuthenticationUtil.isAuthenticated(req);
                        if (authenticated)
                        {
                            this.completeRequestContext(req);
                        }
                        else if (keycloakDeploymentReady && this.loginFormEnhancementEnabled && this.isLoginPage(req))
                        {
                            this.prepareLoginFormEnhancement(context, req, res);
                        }

                        this.continueFilterChain(context, request, response, chain);
                    }
                    else if (res.isCommitted())
                    {
                        LOGGER.debug("Response has already been committed by skip condition-check - not processing it any further");
                    }
                    else
                    {
                        this.processKeycloakAuthenticationAndActions(context, req, res, chain);
                    }
                }
            }
            finally
            {
                requestContext.release();
                RequestContextHolder.resetRequestAttributes();
            }
        }
        finally
        {
            LOGIN_REDIRECT_URL.remove();
        }
    }

    protected void initFromRemoteEndpointConfig(final RemoteConfigElement remoteConfig)
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

    protected void initFromAdapterConfig(final KeycloakAdapterConfigElement keycloakAdapterConfig)
    {
        final ExtendedAdapterConfig adapterConfiguration = keycloakAdapterConfig.buildAdapterConfiguration();
        this.keycloakDeployment = KeycloakDeploymentBuilder.build(adapterConfiguration);

        final String forcedRouteUrl = adapterConfiguration.getForcedRouteUrl();
        if (forcedRouteUrl != null && !forcedRouteUrl.isBlank())
        {
            // we need to recreate the HttpClient to configure the forced route URL
            this.keycloakDeployment.setClient(new Callable<HttpClient>()
            {
                private HttpClient client;

                @Override
                public HttpClient call() throws Exception
                {
                    if (this.client == null)
                    {
                        synchronized (this)
                        {
                            if (this.client == null)
                            {
                                this.client = new HttpClientBuilder()
                                        .routePlanner(KeycloakAuthenticationFilter.this.createForcedRoutePlanner(adapterConfiguration))
                                        .build(adapterConfiguration);
                            }
                        }
                    }
                    return this.client;
                }
            });
        }

        this.deploymentContext = new AdapterDeploymentContext(this.keycloakDeployment);
    }

    protected void processLogout(final ServletContext context, final HttpServletRequest req, final HttpServletResponse res,
            final FilterChain chain) throws IOException, ServletException
    {
        final HttpSession currentSession = req.getSession(false);

        if (currentSession != null && AuthenticationUtil.isAuthenticated(req)
                && currentSession.getAttribute(KEYCLOAK_ACCOUNT_SESSION_KEY) != null
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

            if (this.rememberSso)
            {
                final Cookie keycloakCookie = new Cookie(KEYCLOAK_AUTHENTICATED_COOKIE, "false");
                keycloakCookie.setPath(context.getContextPath());
                keycloakCookie.setMaxAge(0);
                keycloakCookie.setHttpOnly(true);
                keycloakCookie.setSecure(req.isSecure());
                res.addCookie(keycloakCookie);
            }

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
        LOGGER.debug("Processing Keycloak authentication on request to {}", req.getRequestURL());

        final KeycloakAuthenticationConfigElement keycloakAuthConfig = (KeycloakAuthenticationConfigElement) this.configService
                .getConfig(KeycloakConfigConstants.KEYCLOAK_CONFIG_SECTION_NAME).getConfigElement(KeycloakAuthenticationConfigElement.NAME);

        final Integer bodyBufferLimit = keycloakAuthConfig.getBodyBufferLimit();

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

        final String authHeader = req.getHeader(HEADER_AUTHORIZATION);
        if (authHeader != null && authHeader.toLowerCase(Locale.ENGLISH).startsWith("bearer "))
        {
            this.processBearerAuthentication(context, req, res, chain, keycloakAuthConfig.getPerformTokenExchange(), facade);
        }
        else
        {
            this.processFilterAuthentication(context, req, res, chain, bodyBufferLimit, facade);
        }
    }

    /**
     * Processes authentication when an explicit "Bearer" authentication header is present in a request. Such authentication is only
     * supported when Share is not using OAuth2 token exchange with the Repository backend, and requires a bit of special handling due to
     * Keycloak library access restrictions, in order to obtain the access token for validation and passing on to the Repository-tier.
     *
     * @param context
     *     the servlet context
     * @param req
     *     the servlet request
     * @param res
     *     the servlet response
     * @param chain
     *     the filter chain
     * @param performTokenExchange
     *     whether Share has been configured to perform OAuth2 token exchange to authenticate against the Repository backend
     * @param facade
     *     the Keycloak HTTP facade
     * @throws IOException
     *     if any error occurs during Keycloak authentication or processing of the filter chain
     * @throws ServletException
     *     if any error occurs during Keycloak authentication or processing of the filter chain
     */
    protected void processBearerAuthentication(final ServletContext context, final HttpServletRequest req, final HttpServletResponse res,
            final FilterChain chain, final Boolean performTokenExchange, final OIDCServletHttpFacade facade)
            throws IOException, ServletException
    {
        if (Boolean.TRUE.equals(performTokenExchange))
        {
            LOGGER.warn(
                    "Authentication was attempted using Bearer token - this cannot be supported using token exchange for accessing the primary backend endpoint {}",
                    this.primaryEndpoint);
            LOGGER.warn("Continueing with filter chain processing without handling the Bearer token");

            this.continueFilterChain(context, req, res, chain);
        }
        else
        {
            final BearerTokenRequestAuthenticator authenticator = new BearerTokenRequestAuthenticator(this.keycloakDeployment);
            final AuthOutcome authOutcome = authenticator.authenticate(facade);

            if (authOutcome == AuthOutcome.AUTHENTICATED)
            {
                final AccessToken token = authenticator.getToken();
                final RefreshableAccessTokenHolder tokenHolder = new RefreshableAccessTokenHolder(token, token,
                        authenticator.getTokenString(), null);
                this.onKeycloakAuthenticationSuccess(context, req, res, chain, facade, tokenHolder);
            }
            else if (authOutcome == AuthOutcome.FAILED)
            {
                LOGGER.warn("Bearer token authentication failed - issueing failure challenge with details");
                // not using regular onKeycloakAuthenticationFailure handling since that only applies to proper OIDC filter authentication,
                // with the potential of redirecting to the IdP authentication UI
                req.getSession().invalidate();

                authenticator.getChallenge().challenge(facade);
            }
            else
            {
                LOGGER.warn(
                        "Unexpected authentication outcome {} on Bearer authentication with guaranteed token presence - continueing with filter chain processing",
                        authOutcome);

                this.continueFilterChain(context, req, res, chain);
            }
        }
    }

    /**
     * Processes the regular OIDC filter authentication on a request.
     *
     * @param context
     *     the servlet context
     * @param req
     *     the servlet request
     * @param res
     *     the servlet response
     * @param chain
     *     the filter chain
     * @param bodyBufferLimit
     *     the configured size limit to apply to any HTTP POST/PUT body buffering that may need to be applied to process the
     *     authentication via an intermediary redirect
     * @param facade
     *     the Keycloak HTTP facade
     * @throws IOException
     *     if any error occurs during Keycloak authentication or processing of the filter chain
     * @throws ServletException
     *     if any error occurs during Keycloak authentication or processing of the filter chain
     */
    protected void processFilterAuthentication(final ServletContext context, final HttpServletRequest req, final HttpServletResponse res,
            final FilterChain chain, final Integer bodyBufferLimit, final OIDCServletHttpFacade facade) throws IOException, ServletException
    {
        final OIDCFilterSessionStore tokenStore = new OIDCFilterSessionStore(req, facade,
                bodyBufferLimit != null ? bodyBufferLimit.intValue() : DEFAULT_BODY_BUFFER_LIMIT, this.keycloakDeployment,
                this.sessionIdMapper);

        // use 8443 as default SSL redirect based on Tomcat default server.xml configuration
        final FilterRequestAuthenticator authenticator = new FilterRequestAuthenticator(this.keycloakDeployment, tokenStore, facade, req,
                this.keycloakDeployment.getConfidentialPort());
        final AuthOutcome authOutcome = authenticator.authenticate();

        if (authOutcome == AuthOutcome.AUTHENTICATED)
        {
            this.onKeycloakAuthenticationSuccess(context, req, res, chain, facade, tokenStore);
        }
        // send SSO challenge if SSO is enforced or user previously used Keycloak
        // node: explicit logout resets relevant cookie for previous Keycloak use
        else if (authOutcome == AuthOutcome.NOT_ATTEMPTED && (this.forceSso || this.hasKeycloakCookie(req)))
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
            boolean continueFilterChain = true;
            if (authOutcome == AuthOutcome.NOT_ATTEMPTED)
            {
                LOGGER.debug("No authentication took place");

                if (this.isBackendRequiringBasicOrKeycloakAuthentication(req, req.getSession()))
                {
                    // any pages / URLs requiring no authentication have already been handled in checkForSkipCondition
                    continueFilterChain = false;
                    this.redirectToLoginPage(req, res, null);
                }

                if (continueFilterChain)
                {
                    LOGGER.debug("Continueing with filter chain processing");
                    if (this.loginFormEnhancementEnabled)
                    {
                        this.prepareLoginFormEnhancement(context, req, res, authenticator);
                    }
                }
            }
            else
            {
                LOGGER.warn("Unexpected authentication outcome {} - continueing with filter chain processing", authOutcome);
            }

            if (continueFilterChain)
            {
                this.continueFilterChain(context, req, res, chain);
            }
        }

    }

    /**
     * Sets up the necessary state to enhance the login form customisation to provide an action to perform a Keycloak login via a redirect.
     *
     * @param context
     *     the servlet context
     * @param req
     *     the HTTP servlet request being processed
     * @param res
     *     the HTTP servlet response being processed
     * @param authenticator
     *     the authenticator holding the challenge for a login redirect
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
            cookie.setHttpOnly(true);
            cookie.setSecure(req.isSecure());
            return cookie;
        }).forEach(res::addCookie);

        setRedirectFromCaptureFacade(req, captureFacade);
    }

    /**
     * Sets up the necessary state to enhance the login form customisation to provide an action to perform a Keycloak login via a redirect.
     *
     * @param context
     *     the servlet context
     * @param req
     *     the HTTP servlet request being processed
     * @param res
     *     the HTTP servlet response being processed
     */
    protected void prepareLoginFormEnhancement(final ServletContext context, final HttpServletRequest req, final HttpServletResponse res)
    {
        final KeycloakAuthenticationConfigElement keycloakAuthConfig = (KeycloakAuthenticationConfigElement) this.configService
                .getConfig(KeycloakConfigConstants.KEYCLOAK_CONFIG_SECTION_NAME).getConfigElement(KeycloakAuthenticationConfigElement.NAME);

        final Integer bodyBufferLimit = keycloakAuthConfig.getBodyBufferLimit();

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

                // but use the alfRedirectUrl if present in request
                final String alfRedirectUrl = req.getParameter(ALF_REDIRECT_URL);
                if (alfRedirectUrl != null && !alfRedirectUrl.isBlank())
                {
                    LOGGER.debug("Found {} query parameter with value {}", ALF_REDIRECT_URL, alfRedirectUrl);
                    return ALF_REDIRECT_URL + "=" + alfRedirectUrl;
                }
                return "";
            }

        };

        final ResponseHeaderCookieCaptureServletHttpFacade captureFacade = new ResponseHeaderCookieCaptureServletHttpFacade(wrappedReq);

        final OIDCFilterSessionStore tokenStore = new OIDCFilterSessionStore(req, captureFacade,
                bodyBufferLimit != null ? bodyBufferLimit.intValue() : DEFAULT_BODY_BUFFER_LIMIT, this.keycloakDeployment, null);

        final int sslPort = this.determineLikelySslPort(req);
        final OAuthRequestAuthenticator authenticator = new OAuthRequestAuthenticator(null, captureFacade, this.keycloakDeployment, sslPort,
                tokenStore);

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
            cookie.setHttpOnly(true);
            cookie.setSecure(req.isSecure());
            return cookie;
        }).forEach(res::addCookie);

        setRedirectFromCaptureFacade(req, captureFacade);
    }

    private static void setRedirectFromCaptureFacade(final HttpServletRequest req,
            final ResponseHeaderCookieCaptureServletHttpFacade captureFacade)
    {
        final List<String> redirects = captureFacade.getHeaders().get("Location");
        if (redirects != null && !redirects.isEmpty())
        {
            final String redirectPath = redirects.get(0);
            LOGIN_REDIRECT_URL.set(redirectPath);
        }
    }

    /**
     * Processes a successful authentication via Keycloak.
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
        final Object keycloakAccount = session != null ? session.getAttribute(KEYCLOAK_ACCOUNT_SESSION_KEY) : null;
        if (keycloakAccount instanceof OidcKeycloakAccount)
        {
            final KeycloakSecurityContext keycloakSecurityContext = ((OidcKeycloakAccount) keycloakAccount).getKeycloakSecurityContext();
            final AccessToken accessToken = keycloakSecurityContext.getToken();
            final String userId = accessToken.getPreferredUsername();
            LOGGER.debug("User {} successfully authenticated via Keycloak", userId);

            session.setAttribute(UserFactory.SESSION_ATTRIBUTE_EXTERNAL_AUTH, Boolean.TRUE);
            session.setAttribute(UserFactory.SESSION_ATTRIBUTE_KEY_USER_ID, userId);

            this.handleAlfrescoResourceAccessToken(session);
        }

        final String alfRedirectUrl = req.getParameter(ALF_REDIRECT_URL);

        if (facade.isEnded())
        {
            LOGGER.debug("Authenticator already handled response");

            if (alfRedirectUrl != null && !alfRedirectUrl.isBlank())
            {
                LOGGER.debug("Found {} query parameter - redirecting to {}", ALF_REDIRECT_URL, alfRedirectUrl);
                // this may override any redirect set by the authenticator
                res.sendRedirect(alfRedirectUrl);
            }

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

        this.completeRequestContext(req);

        LOGGER.debug("Continueing with filter chain processing");
        final HttpServletRequestWrapper requestWrapper = tokenStore.buildWrapper();
        this.continueFilterChain(context, requestWrapper, res, chain);
    }

    /**
     * Processes a successful authentication via Keycloak.
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
     * @param tokenHolder
     *     the holder for access token taken from the successful authentication
     * @throws IOException
     *     if any error occurs during Keycloak authentication or processing of the filter chain
     * @throws ServletException
     *     if any error occurs during Keycloak authentication or processing of the filter chain
     */
    protected void onKeycloakAuthenticationSuccess(final ServletContext context, final HttpServletRequest req,
            final HttpServletResponse res, final FilterChain chain, final OIDCServletHttpFacade facade,
            final RefreshableAccessTokenHolder tokenHolder) throws IOException, ServletException
    {
        final HttpSession session = req.getSession();

        session.setAttribute(ACCESS_TOKEN_SESSION_KEY, tokenHolder);

        final String userId = tokenHolder.getAccessToken().getPreferredUsername();
        LOGGER.debug("User {} successfully authenticated via Keycloak", userId);

        session.setAttribute(UserFactory.SESSION_ATTRIBUTE_EXTERNAL_AUTH, Boolean.TRUE);
        session.setAttribute(UserFactory.SESSION_ATTRIBUTE_KEY_USER_ID, userId);

        final String alfRedirectUrl = req.getParameter(ALF_REDIRECT_URL);

        if (facade.isEnded())
        {
            LOGGER.debug("Authenticator already handled response");

            if (alfRedirectUrl != null && !alfRedirectUrl.isBlank())
            {
                LOGGER.debug("Found {} query parameter - redirecting to {}", ALF_REDIRECT_URL, alfRedirectUrl);
                // this may override any redirect set by the authenticator
                res.sendRedirect(alfRedirectUrl);
            }

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
        this.continueFilterChain(context, req, res, chain);
    }

    protected void ensureKeycloakCookieSet(final HttpServletRequest req, final HttpServletResponse res)
    {
        final boolean hasKeycloakCookie = this.hasKeycloakCookie(req);

        if (!hasKeycloakCookie && this.rememberSso)
        {
            final Cookie keycloakCookie = new Cookie(KEYCLOAK_AUTHENTICATED_COOKIE, "true");
            keycloakCookie.setPath(req.getServletContext().getContextPath());
            keycloakCookie.setMaxAge(-1);
            keycloakCookie.setHttpOnly(true);
            keycloakCookie.setSecure(req.isSecure());
            res.addCookie(keycloakCookie);
        }
    }

    protected boolean hasKeycloakCookie(final HttpServletRequest req)
    {
        final Cookie[] cookies = req.getCookies();
        boolean hasKeycloakCookie = false;
        if (cookies != null && this.rememberSso)
        {
            for (final Cookie cookie : cookies)
            {
                hasKeycloakCookie = hasKeycloakCookie
                        || (KEYCLOAK_AUTHENTICATED_COOKIE.equalsIgnoreCase(cookie.getName()) && Boolean.parseBoolean(cookie.getValue()));
            }
        }
        return hasKeycloakCookie;
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
     * @param chain
     *     the filter chain
     * @throws IOException
     *     if any error occurs during processing of the filter chain
     * @throws ServletException
     *     if any error occurs during processing of the filter chain
     */
    protected void onKeycloakAuthenticationFailure(final ServletContext context, final HttpServletRequest req,
            final HttpServletResponse res, final FilterChain chain) throws IOException, ServletException
    {
        final Object authError = req.getAttribute(AuthenticationError.class.getName());
        LOGGER.warn("Keycloak authentication failed due to {}",
                authError != null ? authError : "<missing AuthenticationError details in request context>");
        LOGGER.debug("Resetting session and state cookie before continueing with filter chain");

        try
        {
            req.getSession().invalidate();
        }
        catch (final IllegalStateException ignore)
        {
            // Keycloak authenticator may have already invalidated it - no way to check and avoid exception
        }

        this.resetStateCookies(context, req, res);

        // need to check for no auth page in this case since it may be that a pro-active authentication failed but isn't actually required
        // to succeed to access the target
        final String servletPath = req.getServletPath();
        if (PAGE_SERVLET_PATH.equals(servletPath))
        {
            if (this.isNoAuthPage(req))
            {
                this.continueFilterChain(context, req, res, chain);
            }
            else
            {
                this.redirectToLoginPage(req, res, authError);
            }
        }
        else
        {
            this.redirectToLoginPage(req, res, authError);
        }
    }

    protected void redirectToLoginPage(final HttpServletRequest req, final HttpServletResponse res, final Object authError)
            throws IOException
    {
        LOGGER.debug("Redirecting to login page");

        final HttpSession session = req.getSession();
        session.setAttribute(REDIRECT_URI, req.getRequestURI());
        String queryString = req.getQueryString();
        if (queryString != null)
        {
            // strip OAuth state / code params from URL query
            final String paramNamesStr = OAuth2Constants.CODE + '|' + OAuth2Constants.STATE + '|' + OAuth2Constants.SESSION_STATE;
            final String matchStr = "(?:(?:\\?|&)(?:" + paramNamesStr + ")=[^$&]*)";

            queryString = queryString.replaceAll(matchStr, "");
            if (!queryString.isEmpty() && queryString.startsWith("&"))
            {
                queryString = '?' + queryString.substring(1);
            }
            session.setAttribute(REDIRECT_QUERY, queryString);
        }

        if (PAGE_SERVLET_PATH.equals(req.getServletPath()))
        {
            String error;
            if (authError instanceof OIDCAuthenticationError)
            {
                error = ((OIDCAuthenticationError) authError).getDescription();
            }
            else if (authError instanceof AuthenticationError)
            {
                error = authError.toString();
            }
            else
            {
                error = req.getParameter(ERROR_PARAMETER);
            }

            final String redirectUrl = req.getContextPath() + "/page?pt=login"
                    + (error == null ? "" : "&" + ERROR_PARAMETER + "=" + URLEncoder.encode(error));
            res.sendRedirect(redirectUrl);
        }
        else
        {
            res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            res.flushBuffer();
        }
    }

    /**
     * Completes the request context in the current thread by populating missing data, foremost any user details for the authenticated user.
     *
     * @param req
     *     the servlet request
     * @throws ServletException
     *     if an error occurs populating the request context
     */
    protected void completeRequestContext(final HttpServletRequest req) throws ServletException
    {
        try
        {
            RequestContextUtil.populateRequestContext(ThreadLocalRequestContext.getRequestContext(), req);
        }
        catch (final Exception ex)
        {
            LOGGER.error("Error calling populateRequestContext", ex);
            throw new ServletException(ex);
        }
    }

    /**
     * Continues processing the filter chain, either directly or by delegating to the facaded default SSO filter.
     *
     * @param context
     *     the servlet context
     * @param request
     *     the current request
     * @param response
     *     the response to the current request
     * @param chain
     *     the filter chain
     * @throws IOException
     *     if any exception is propagated by a filter in the chain or the actual request processing
     * @throws ServletException
     *     if any exception is propagated by a filter in the chain or the actual request processing
     */
    protected void continueFilterChain(final ServletContext context, final ServletRequest request, final ServletResponse response,
            final FilterChain chain) throws IOException, ServletException
    {
        final HttpSession session = ((HttpServletRequest) request).getSession(false);
        final Object keycloakAccount = session != null ? session.getAttribute(KEYCLOAK_ACCOUNT_SESSION_KEY) : null;

        // no point in forwarding to default SSO filter if already authenticated
        if (this.defaultSsoFilter != null && keycloakAccount == null && !this.ignoreDefaultFilter)
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
     *     the servlet request to check for potential conditions to skip
     * @param res
     *     the servlet response on which potential updates of cookies / response headers need to be set
     * @return {@code true} if processing of the {@link #doFilter(ServletContext, ServletRequest, ServletResponse, FilterChain) filter
     * operation} must be skipped, {@code false} otherwise
     * @throws ServletException
     *     if any error occurs during inspection of the request
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
                && AuthenticationUtil.isAuthenticated(req))
        {
            if (currentSession.getAttribute(KEYCLOAK_ACCOUNT_SESSION_KEY) != null
                    && !this.sessionIdMapper.hasSession(currentSession.getId()))
            {
                LOGGER.debug("Session {} for Keycloak-authenticated user {} was invalidated by back-channel logout", currentSession.getId(),
                        AuthenticationUtil.getUserId(req));
                currentSession.invalidate();
                currentSession = req.getSession(false);
            }
            else if (currentSession.getAttribute(ACCESS_TOKEN_SESSION_KEY) != null)
            {
                final RefreshableAccessTokenHolder accessToken = (RefreshableAccessTokenHolder) currentSession
                        .getAttribute(ACCESS_TOKEN_SESSION_KEY);
                if (!accessToken.isActive())
                {
                    LOGGER.debug("Access token in session from previous Bearer authorization for {} has expired - invalidating session",
                            AuthenticationUtil.getUserId(req));

                    currentSession.invalidate();
                    currentSession = req.getSession(false);
                }
            }
        }

        if (!this.externalAuthEnabled || !this.filterEnabled)
        {
            LOGGER.debug("Skipping processKeycloakAuthenticationAndActions as filter and/or external authentication are not enabled");
            skip = true;
        }
        else if (this.keycloakDeployment == null)
        {
            LOGGER.debug("Skipping processKeycloakAuthenticationAndActions as Keycloak adapter was not properly initialised");
            skip = true;
        }
        else if (servletRequestUri.matches(KEYCLOAK_ACTION_URL_PATTERN))
        {
            LOGGER.debug("Explicitly not skipping processKeycloakAuthenticationAndActions as Keycloak action URL is being called");
        }
        else if (req.getParameter("state") != null && req.getParameter("code") != null && this.hasStateCookie(req))
        {
            LOGGER.debug(
                    "Explicitly not skipping processKeycloakAuthenticationAndActions as state and code query parameters of OAuth2 redirect as well as state cookie are present");
        }
        else if (authHeader != null && authHeader.toLowerCase(Locale.ENGLISH).startsWith("bearer "))
        {
            LOGGER.debug(
                    "Explicitly not skipping processKeycloakAuthenticationAndActions as Bearer authorization header is present and Bearer authentication is not disallowed");
        }
        else if (authHeader != null && authHeader.toLowerCase(Locale.ENGLISH).startsWith("basic "))
        {
            LOGGER.debug("Explicitly not skipping processKeycloakAuthenticationAndActions as Basic authorization header is present");
        }
        else if (authHeader != null)
        {
            LOGGER.debug("Skipping processKeycloakAuthenticationAndActions as non-OIDC / non-Basic authorization header is present");
            skip = true;
        }
        else if (currentSession != null && AuthenticationUtil.isAuthenticated(req))
        {
            final KeycloakAccount keycloakAccount = (KeycloakAccount) currentSession.getAttribute(KEYCLOAK_ACCOUNT_SESSION_KEY);
            if (keycloakAccount != null)
            {
                skip = this.validateAndRefreshKeycloakAuthentication(req, res, AuthenticationUtil.getUserId(req), keycloakAccount);
            }
            else
            {
                /*
                 * Note: We could validate session with a custom call to /touch but we leave that to any remaining SSO filters. We patch
                 * remoteClient to submit a custom HTTP header to backend to avoid 302 redirects to Keycloak which other SSO filters cannot
                 * handle, and this also avoids any issues with (public) Keycloak auth server URL being unknown, e.g. in a Docker scenario
                 */
                LOGGER.debug(
                        "Skipping processKeycloakAuthenticationAndActions as non-Keycloak-authenticated session is already established");
                skip = true;
            }
        }
        else if (proxyMatcher.matches())
        {
            final String endpoint = proxyMatcher.group(1);
            final String noauth = proxyMatcher.group(2);
            if (noauth != null && !noauth.trim().isEmpty())
            {
                LOGGER.debug("Skipping processKeycloakAuthenticationAndActions as proxy servlet to noauth endpoint {} is being called",
                        endpoint);
                skip = true;
            }
            else if (!endpoint.equals(this.primaryEndpoint)
                    && (this.secondaryEndpoints == null || !this.secondaryEndpoints.contains(endpoint)))
            {
                LOGGER.debug(
                        "Skipping processKeycloakAuthenticationAndActions on proxy servlet call as endpoint {} has not been configured as a primary / secondary endpoint to handle",
                        endpoint);
                skip = true;
            }
            else
            {
                LOGGER.debug(
                        "Explicitely not skipping processKeycloakAuthenticationAndActions on proxy servlet call to endpoint {} which is expected to serve web scripts requiring authentication",
                        endpoint);
            }
        }
        else if (PAGE_SERVLET_PATH.equals(servletPath) && (LOGIN_PATH_INFORMATION.equals(pathInfo)
                || (pathInfo == null && LOGIN_PAGE_TYPE_PARAMETER_VALUE.equals(req.getParameter(PAGE_TYPE_PARAMETER_NAME)))))
        {
            LOGGER.debug("Skipping processKeycloakAuthenticationAndActions as login page was explicitly requested");
            skip = true;
        }
        else if (this.isNoAuthPage(req))
        {
            LOGGER.debug("Skipping processKeycloakAuthenticationAndActions as requested page does not require authentication");
            skip = true;
        }

        return skip;
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
     * @param keycloakAccount
     *     the Keycloak account object
     * @return {@code true} if processing of the {@link #doFilter(ServletContext, ServletRequest, ServletResponse, FilterChain) filter
     * operation} can be skipped as the account represents a valid and still active authentication, {@code false} otherwise
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
            LOGGER.debug("Skipping processKeycloakAuthenticationAndActions as Keycloak-authentication session is still valid");
            this.ensureKeycloakCookieSet(req, res);
            this.handleAlfrescoResourceAccessToken(currentSession);
            skip = true;
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
     *     the servlet request for which to check the authentication requirement of the target page
     * @return {@code true} if the requested page does not require user authentication,
     * {@code false} otherwise (incl. failure to resolve the request to a target page)
     * @throws ServletException
     *     if any error occurs during inspection of the request
     */
    protected boolean isNoAuthPage(final HttpServletRequest req) throws ServletException
    {
        final String pathInfo = req.getPathInfo();

        final RequestContext context = ThreadLocalRequestContext.getRequestContext();
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
     *     the request for which to check the type of page
     * @return {@code true} if the requested page is a login page,
     * {@code false} otherwise (incl. failure to resolve the request to a target page)
     * @throws ServletException
     *     if any error occurs during inspection of the request
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
            final RequestContext context = ThreadLocalRequestContext.getRequestContext();
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
     *     the request to check
     * @return {@code true} if the request is a request for logout,
     * {@code false} otherwise
     * @throws ServletException
     *     if any error occurs during inspection of the request
     */
    protected boolean isLogoutRequest(final HttpServletRequest req) throws ServletException
    {
        final String servletPath = req.getServletPath();
        final String pathInfo = req.getPathInfo();
        final boolean isLogoutRequest = (PAGE_SERVLET_PATH.equals(servletPath) && LOGOUT_PATH_INFORMATION.equals(pathInfo))
                || LOGOUT_SERVICE_PATH.equals(servletPath);
        return isLogoutRequest;
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
     * Checks if the backend requires HTTP Basic or Keycloak authentication for the current request context, which may include an externally
     * authenticated user.
     *
     * @param req
     *     the request to check
     * @param session
     *     the active session managing any persistent access token state
     * @return {@code true} if the backend requires HTTP Basic or Keycloak authentication, {@code false} otherwise
     */
    protected boolean isBackendRequiringBasicOrKeycloakAuthentication(final HttpServletRequest req, final HttpSession session)
    {
        LOGGER.debug("Checking if backend requires authentication");

        String userId = AuthenticationUtil.getUserId(req);
        if (userId == null)
        {
            userId = req.getRemoteUser();
            if (userId != null)
            {
                LOGGER.debug("Considering externally authenticated user {}", userId);
                session.setAttribute(UserFactory.SESSION_ATTRIBUTE_EXTERNAL_AUTH, Boolean.TRUE);
            }
        }

        boolean requiresAuth = false;
        try
        {
            final Connector conn = this.connectorService.getConnector(this.primaryEndpoint, userId, session);

            ConnectorContext ctx;
            if (req.getHeader(HEADER_ACCEPT_LANGUAGE) != null)
            {
                ctx = new ConnectorContext(null, Collections.singletonMap(HEADER_ACCEPT_LANGUAGE, req.getHeader(HEADER_ACCEPT_LANGUAGE)));
            }
            else
            {
                ctx = new ConnectorContext();
            }

            final Response remoteRes = conn.call("/touch", ctx);
            switch (remoteRes.getStatus().getCode())
            {
                case Status.STATUS_UNAUTHORIZED:
                    final String authenticate = remoteRes.getStatus().getHeaders().get(HEADER_WWWAUTHENTICATE);
                    requiresAuth = authenticate.equals("Basic") || authenticate.startsWith("Basic ");
                    if (requiresAuth)
                    {
                        LOGGER.debug("Backend requires HTTP Basic authentication");
                    }
                    break;
                case Status.STATUS_FOUND:
                    final String redirectTarget = remoteRes.getStatus().getHeaders().get("Location");
                    final String authServerBaseUrl = this.keycloakDeployment.getAuthServerBaseUrl();
                    requiresAuth = redirectTarget.startsWith(authServerBaseUrl);
                    if (requiresAuth)
                    {
                        LOGGER.debug("Backend requires Keycloak authentication");
                    }
                    break;
                default: // no special handling for most status codes
            }

            if (!requiresAuth)
            {
                LOGGER.debug("Backend does not require HTTP Basic or Keycloak authentication");
            }
        }
        catch (final ConnectorServiceException csex)
        {
            LOGGER.error(
                    "Could not determine if backend requires HTTP Basic or Keycloak authentication due to technical error - going to assume that it does",
                    csex);
            requiresAuth = true;
        }

        return requiresAuth;
    }

    /**
     * Checks, initialises and/or refreshes the access token for accessing the Alfresco backend based on configuration and current session
     * state / validity of any existing token.
     *
     * @param session
     *     the active session managing any persistent access token state
     */
    protected void handleAlfrescoResourceAccessToken(final HttpSession session)
    {
        final KeycloakAuthenticationConfigElement keycloakAuthConfig = (KeycloakAuthenticationConfigElement) this.configService
                .getConfig(KeycloakConfigConstants.KEYCLOAK_CONFIG_SECTION_NAME).getConfigElement(KeycloakAuthenticationConfigElement.NAME);
        if (keycloakAuthConfig != null && Boolean.TRUE.equals(keycloakAuthConfig.getPerformTokenExchange()))
        {
            final String alfrescoResourceName = keycloakAuthConfig.getAlfrescoResourceName();
            if (!EqualsHelper.nullSafeEquals(alfrescoResourceName, this.keycloakDeployment.getResourceName())
                    && alfrescoResourceName != null)
            {
                final Object backendAccessTokenCandidate = session.getAttribute(BACKEND_ACCESS_TOKEN_SESSION_KEY);
                RefreshableAccessTokenHolder token;
                if (!(backendAccessTokenCandidate instanceof RefreshableAccessTokenHolder))
                {
                    LOGGER.debug("Session does not yet contain an access token for the Alfresco backend resource {}", alfrescoResourceName);
                    token = null;
                }
                else
                {
                    token = (RefreshableAccessTokenHolder) backendAccessTokenCandidate;
                }

                // not really feasible to synchronise / lock concurrent refresh on token, especially given that we cannot lock across
                // potentially multiple Share instances
                // not a big problem - apart from wasted CPU cycles / latency - since each concurrently refreshed token is valid
                // independently
                if (token == null || !token.isActive()
                        || (token.canRefresh() && token.shouldRefresh(this.keycloakDeployment.getTokenMinimumTimeToLive())))
                {
                    AccessTokenResponse response;
                    try
                    {
                        // Note: we tried to simply just refresh with the refresh the already exchanged token for the target resource
                        // but audience typically is not correct in the resulting token
                        LOGGER.debug("Retrieving / refreshing access token for Alfresco backend resource {}", alfrescoResourceName);
                        response = this.getAccessToken(alfrescoResourceName, session);
                    }
                    catch (final IOException ioex)
                    {
                        LOGGER.error("Error retrieving / refreshing access token for Alfresco backend", ioex);
                        throw new AlfrescoRuntimeException("Error retrieving / refreshing access token for Alfresco backend", ioex);
                    }

                    final String tokenString = response.getToken();
                    try
                    {
                        // cannot use simple AdapterTokenVerifier.verifyTokens as it checks for wrong audience
                        // we also do not care about any IDToken retrieved (implicitly) with token exchange
                        final TokenVerifier<AccessToken> tokenVerifier = AdapterTokenVerifier.createVerifier(tokenString,
                                this.keycloakDeployment, true, AccessToken.class);
                        tokenVerifier.audience(alfrescoResourceName);
                        tokenVerifier.issuedFor(this.keycloakDeployment.getResourceName());

                        final AccessToken accessToken = tokenVerifier.verify().getToken();

                        if ((accessToken.getExp() - this.keycloakDeployment.getTokenMinimumTimeToLive()) <= Time.currentTime())
                        {
                            throw new AlfrescoRuntimeException(
                                    "Failed to retrieve / refresh the access token for the Alfresco backend with a longer time-to-live than the minimum");
                        }

                        token = new RefreshableAccessTokenHolder(response, new VerifiedTokens(accessToken, null));
                        session.setAttribute(BACKEND_ACCESS_TOKEN_SESSION_KEY, token);
                        LOGGER.debug("Successfully retrieved / refresh access token for Alfresco backend");
                    }
                    catch (final VerificationException vex)
                    {
                        LOGGER.error("Verification of access token for Alfresco backend failed in retry", vex);
                        throw new AlfrescoRuntimeException("Keycloak token exchange for access to backend yielded invalid access token",
                                vex);
                    }
                }
            }
            else if (alfrescoResourceName == null)
            {
                LOGGER.warn(
                        "Encountered configuration error: alfresco-resource-name has not been set, which is required for performing token exchange");
            }
            else
            {
                LOGGER.warn(
                        "Encountered configuration error: alfresco-resource-name is set to the same value as Share's adapter resource, which is unsuitable for performing token exchange");
            }
        }
        else
        {
            LOGGER.debug("Use of token exchange has not been enabled - calls to Alfresco backend will reuse the global access token");
        }
    }

    /**
     * Obtains an access token for the Alfresco backend by exchanging the current user access token in the session for an access token to
     * that backend resource.
     *
     * @param alfrescoResourceName
     *     the name of the Alfresco backend resource within the Keycloak realm
     * @param session
     *     the active session managing any persistent access token state
     * @return the response to obtaining the access token for the Alfresco backend
     * @throws IOException
     *     if any error occurs calling Keycloak to exchange the access token
     */
    protected AccessTokenResponse getAccessToken(final String alfrescoResourceName, final HttpSession session) throws IOException
    {
        AccessTokenResponse tokenResponse = null;
        final HttpClient client = this.keycloakDeployment.getClient();

        final HttpPost post = new HttpPost(KeycloakUriBuilder.fromUri(this.keycloakDeployment.getAuthServerBaseUrl())
                .path(ServiceUrlConstants.TOKEN_PATH).build(this.keycloakDeployment.getRealm()));
        final List<NameValuePair> formParams = new LinkedList<>();

        formParams.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, OAuth2Constants.TOKEN_EXCHANGE_GRANT_TYPE));
        formParams.add(new BasicNameValuePair(OAuth2Constants.AUDIENCE, alfrescoResourceName));
        formParams.add(new BasicNameValuePair(OAuth2Constants.REQUESTED_TOKEN_TYPE, OAuth2Constants.REFRESH_TOKEN_TYPE));

        final OidcKeycloakAccount keycloakAccount = (OidcKeycloakAccount) session.getAttribute(KEYCLOAK_ACCOUNT_SESSION_KEY);
        final RefreshableAccessTokenHolder accessToken = (RefreshableAccessTokenHolder) session.getAttribute(ACCESS_TOKEN_SESSION_KEY);
        if (keycloakAccount != null)
        {
            final String tokenString = keycloakAccount.getKeycloakSecurityContext().getTokenString();
            formParams.add(new BasicNameValuePair(OAuth2Constants.SUBJECT_TOKEN, tokenString));
        }
        else if (accessToken != null && accessToken.isActive())
        {
            formParams.add(new BasicNameValuePair(OAuth2Constants.SUBJECT_TOKEN, accessToken.getToken()));
        }
        else
        {
            throw new IllegalStateException(
                    "Either an active security context or access token should be present in the session, or previous validations have caught their non-existence and prevented this operation form being called");
        }
        
        final List<Header> headers = new LinkedList<>();

        ClientCredentialsProviderUtils.setClientCredentials(this.keycloakDeployment.getAdapterConfig(),
                this.keycloakDeployment.getClientAuthenticator(), new NameValueMapAdapter<>(headers, BasicHeader.class),
                new NameValueMapAdapter<>(formParams, BasicNameValuePair.class));

        for (final Header header : headers)
        {
            post.addHeader(header);
        }
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
            throw new AlfrescoRuntimeException("Failed to retrieve access token due to HTTP error " + status + ": " + statusReason);
        }
        if (entity == null)
        {
            throw new AlfrescoRuntimeException("Response to access token request did not contain a response body");
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

    protected void configureForcedRouteIfNecessary(final HttpClient client, final String forcedRoute)
    {
        final HttpHost forcedRouteHost = HttpHost.create(forcedRoute);
        final HttpParams params = client.getParams();
        final InetAddress local = ConnRouteParams.getLocalAddress(params);
        final HttpHost defaultProxy = ConnRouteParams.getDefaultProxy(params);
        final boolean secure = forcedRouteHost.getSchemeName().equalsIgnoreCase("https");

        HttpRoute route;
        if (defaultProxy == null)
        {
            route = new HttpRoute(forcedRouteHost, local, secure);
        }
        else
        {
            route = new HttpRoute(forcedRouteHost, local, defaultProxy, secure);
        }
        params.setParameter(ConnRoutePNames.FORCED_ROUTE, route);
    }

    protected HttpRoute createRoute(final ExtendedAdapterConfig adapterConfig, final HttpHost routeHost)
            throws UnknownHostException, MalformedURLException
    {
        final boolean secure = "https".equalsIgnoreCase(routeHost.getSchemeName());

        if (adapterConfig.getProxyUrl() != null)
        {
            // useful in parsing the URL for just what is needed for HttpHost
            final URL proxyUrl = new URL(adapterConfig.getProxyUrl());
            final HttpHost proxyHost = new HttpHost(proxyUrl.getHost(), proxyUrl.getPort(), proxyUrl.getProtocol());
            return new HttpRoute(routeHost, InetAddress.getLocalHost(), proxyHost, secure);
        }
        else
        {
            return new HttpRoute(routeHost, InetAddress.getLocalHost(), secure);
        }
    }

    protected HttpRoute createForcedRoute(final ExtendedAdapterConfig adapterConfig) throws UnknownHostException, MalformedURLException
    {
        // useful in parsing the URL for just what is needed for HttpHost
        final URL forcedRouteUrl = new URL(adapterConfig.getForcedRouteUrl());
        final HttpHost forcedRouteHost = new HttpHost(forcedRouteUrl.getHost(), forcedRouteUrl.getPort(), forcedRouteUrl.getProtocol());
        return this.createRoute(adapterConfig, forcedRouteHost);
    }

    protected HttpRoutePlanner createForcedRoutePlanner(final ExtendedAdapterConfig adapterConfig) throws MalformedURLException
    {
        final URL authServerUrl = new URL(adapterConfig.getAuthServerUrl());
        final HttpHost authServerHost = new HttpHost(authServerUrl.getHost(), authServerUrl.getPort(), authServerUrl.getProtocol());

        return (target, request, context) -> {
            try
            {
                if (authServerHost.equals(target))
                {
                    final HttpRoute route = KeycloakAuthenticationFilter.this.createForcedRoute(adapterConfig);
                    LOGGER.trace("Rerouting to forced route: {}", route);
                    return route;
                }
                else
                {
                    return KeycloakAuthenticationFilter.this.createRoute(adapterConfig, target);
                }
            }
            catch (final IOException ie)
            {
                throw new HttpException(ie.getMessage(), ie);
            }
        };
    }
}
