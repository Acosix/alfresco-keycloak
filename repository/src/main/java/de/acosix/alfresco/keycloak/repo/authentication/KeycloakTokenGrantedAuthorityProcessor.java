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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.alfresco.repo.security.authentication.AuthenticationUtil;
import org.alfresco.service.cmr.security.AuthorityService;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

import de.acosix.alfresco.keycloak.repo.authority.GrantedAuthorityAwareAuthorityServiceImpl;
import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;

/**
 * This token processor maps authorities found in a Keycloak access token to {@link GrantedAuthority granted authorities} of the
 * authenticated user. Such mapping does not
 * make the authenticated user a permanent / persisted member of any group represented by an authority, and as such operations like
 * {@link AuthorityService#getContainingAuthorities(org.alfresco.service.cmr.security.AuthorityType, String, boolean)
 * getContainingAuthorities} will not return any of the mapped authorities if the user is not a member based on Alfresco's internal
 * authority data. A {@link GrantedAuthorityAwareAuthorityServiceImpl granted-authority-aware AuthorityService} provided by this module
 * adapts the {@link AuthorityService#getAuthoritiesForUser(String) getAuthoritiesForUser} operation in such a way that the result includes
 * any authorities for the authenticated users specified via granted authorities. This ensures authorities are properly included in any
 * permission / access checking performed by Alfresco.
 *
 * @author Axel Faust
 */
public class KeycloakTokenGrantedAuthorityProcessor implements TokenProcessor, InitializingBean, ApplicationContextAware
{

    private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakTokenGrantedAuthorityProcessor.class);

    private static final String NAME = "GrantedAuthorityProcessor";

    protected ApplicationContext applicationContext;

    protected boolean enabled;

    protected Collection<AuthorityExtractor> authorityExtractors;

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public String getName()
    {
        return NAME;
    }

    /**
     * @param enabled
     *     the enabled to set
     */
    public void setEnabled(final boolean enabled)
    {
        this.enabled = enabled;
    }

    /**
     *
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
    public void afterPropertiesSet() throws BeansException
    {
        this.authorityExtractors = Collections
                .unmodifiableList(new ArrayList<>(this.applicationContext.getBeansOfType(AuthorityExtractor.class, false, true).values()));
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void handleUserTokens(final AccessToken accessToken, final IDToken idToken, final boolean freshLogin)
    {
        if (this.enabled)
        {
            LOGGER.debug("Mapping Keycloak access token to user authorities");

            final Set<String> mappedAuthorities = new HashSet<>();
            this.authorityExtractors.stream().map(extractor -> extractor.extractAuthorities(accessToken))
                    .forEach(mappedAuthorities::addAll);

            LOGGER.debug("Mapped user authorities from access token: {}", mappedAuthorities);

            if (!mappedAuthorities.isEmpty())
            {
                final Authentication currentAuthentication = AuthenticationUtil.getFullAuthentication();
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
    }
}
