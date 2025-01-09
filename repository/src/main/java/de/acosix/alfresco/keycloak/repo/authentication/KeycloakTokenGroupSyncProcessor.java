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
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.alfresco.repo.security.authentication.AuthenticationUtil;
import org.alfresco.repo.transaction.AlfrescoTransactionSupport;
import org.alfresco.repo.transaction.AlfrescoTransactionSupport.TxnReadState;
import org.alfresco.service.cmr.repository.DuplicateChildNodeNameException;
import org.alfresco.service.cmr.security.AuthenticationService;
import org.alfresco.service.cmr.security.AuthorityService;
import org.alfresco.service.cmr.security.AuthorityType;
import org.alfresco.service.cmr.security.PermissionService;
import org.alfresco.service.transaction.TransactionService;
import org.alfresco.util.PropertyCheck;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

import de.acosix.alfresco.keycloak.repo.util.AlfrescoCompatibilityUtil;

/**
 * This token processor handles group authorities found in a Keylcoak access token, optionally creating any groups not already existing in
 * Alfresco and/or synchronising the group membership of the current user with the set of groups specified in the token.
 *
 * @author Brian Long
 */
public class KeycloakTokenGroupSyncProcessor implements TokenProcessor, InitializingBean, ApplicationContextAware
{

    private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakTokenGroupSyncProcessor.class);

    private static final String NAME = "GroupSyncProcessor";

    protected ApplicationContext applicationContext;

    protected boolean createMissingGroupsOnLogin;

    protected boolean syncGroupMembershipOnLogin;

    protected TransactionService transactionService;

    protected AuthorityService authorityService;
    
    protected AuthenticationService authenticationService;

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
     *
     * {@inheritDoc}
     */
    @Override
    public void setApplicationContext(final ApplicationContext applicationContext)
    {
        this.applicationContext = applicationContext;
    }

    /**
     * @param createMissingGroupsOnLogin
     *     the createMissingGroupsOnLogin to set
     */
    public void setCreateMissingGroupsOnLogin(final boolean createMissingGroupsOnLogin)
    {
        this.createMissingGroupsOnLogin = createMissingGroupsOnLogin;
    }

    /**
     * @param syncGroupMembershipOnLogin
     *     the syncAuthorityMembershipOnLogin to set
     */
    public void setSyncGroupMembershipOnLogin(final boolean syncGroupMembershipOnLogin)
    {
        this.syncGroupMembershipOnLogin = syncGroupMembershipOnLogin;
    }

    /**
     * @param transactionService
     *     the transactionService to set
     */
    public void setTransactionService(final TransactionService transactionService)
    {
        this.transactionService = transactionService;
    }

    /**
     * @param authorityService
     *     the authorityService to set
     */
    public void setAuthorityService(final AuthorityService authorityService)
    {
        this.authorityService = authorityService;
    }
    
    /**
     * @param authenticationService
     *     the authenticationService to set
     */
    public void setAuthenticationService(AuthenticationService authenticationService)
    {
		this.authenticationService = authenticationService;
	}

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet() throws BeansException
    {
        PropertyCheck.mandatory(this, "transactionService", this.transactionService);
        PropertyCheck.mandatory(this, "authorityService", this.authorityService);
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
        if (freshLogin && (this.createMissingGroupsOnLogin || this.syncGroupMembershipOnLogin))
        {
            final Collection<String> groups = this.extractGroups(accessToken);

            final boolean requiresNew = AlfrescoTransactionSupport.getTransactionReadState() == TxnReadState.TXN_READ_ONLY;

            if (this.createMissingGroupsOnLogin)
            {
                AuthenticationUtil.runAsSystem(() -> this.transactionService.getRetryingTransactionHelper().doInTransaction(() -> {
                    this.syncGroups(groups);
                    return null;
                }, false, requiresNew));
            }

            if (this.syncGroupMembershipOnLogin)
            {
                AuthenticationUtil.runAsSystem(() -> this.transactionService.getRetryingTransactionHelper().doInTransaction(() -> {
                    boolean changed = this.syncGroupMemberships(accessToken.getPreferredUsername(), groups);
                    if (changed) {
                    	String ticket = this.authenticationService.getCurrentTicket();
                    	if (ticket != null) {
                    		LOGGER.debug("Invalidating Alfresco ticket as group membership changed: {}", ticket);
                    		this.authenticationService.invalidateTicket(ticket);
                    	}
                    }
                    return null;
                }, false, requiresNew));
            }
        }
    }

    /**
     * Extracts groups from the provided access token.
     *
     * @param accessToken
     *     the Keycloak access token for the authenticated user
     * @return the (mutable) collection of extracted group authority names
     */
    protected Collection<String> extractGroups(final AccessToken accessToken)
    {
        LOGGER.debug("Mapping Keycloak access token to user group authorities");

        final Set<String> groups = new HashSet<>();
        this.authorityExtractors.stream().map(extractor -> extractor.extractAuthorities(accessToken)).forEach(groups::addAll);
        groups.removeIf(a -> AuthorityType.getAuthorityType(a) != AuthorityType.GROUP);
        // in case some extractor mapped this pseudo-group
        groups.remove(PermissionService.ALL_AUTHORITIES);

        LOGGER.debug("Mapped user group authorities from access token: {}", groups);

        return groups;
    }

    /**
     * Synchronises the groups of the current user, but not the membership, as Alfresco user groups.
     *
     * @param groups
     *     the names of the user's groups extracted from the Keycloak access token
     */
    protected void syncGroups(final Collection<String> groups)
    {
        LOGGER.debug("Synchronizing user groups {}", groups);

        for (final String group : groups)
        {
            if (!this.authorityService.authorityExists(group))
            {
                LOGGER.debug("Creating group {}", group);
                final String groupShortName = this.authorityService.getShortName(group);

                try
                {
                    this.authorityService.createAuthority(AuthorityType.GROUP, groupShortName);
                }
                catch (final DuplicateChildNodeNameException dcnne)
                {
                    LOGGER.debug("Group {} already created; race condition?", groupShortName);
                }
            }
        }
    }

    /**
     * Synchronises the membership of the current user in Alfresco user groups.
     *
     * @param groups
     *     the Alfresco group authorities as determined from the Keycloak access token for the current user
     * @return true if group membership changed
     */
    protected boolean syncGroupMemberships(String username, final Collection<String> groups)
    {
        final String maskedUsername = AlfrescoCompatibilityUtil.maskUsername(username);
        boolean changed = false;

        LOGGER.debug("Synchronising group membership for user {} and token extracted groups {}", maskedUsername, groups);

        final Set<String> existingUnprocessedGroups = this.authorityService.getContainingAuthorities(AuthorityType.GROUP, username, true);

        LOGGER.debug("User {} is currently in the groups {}", maskedUsername, existingUnprocessedGroups);

        for (final String group : groups)
        {
            // !remove(group) ensures we only add if not already a member
            if (!existingUnprocessedGroups.remove(group) && this.authorityService.authorityExists(group))
            {
                LOGGER.debug("Adding user {} to group {}", maskedUsername, group);
                this.authorityService.addAuthority(group, username);
                changed = true;
            }
        }

        for (final String group : existingUnprocessedGroups)
        {
            LOGGER.debug("Removing user {} from group {}", maskedUsername, group);
            this.authorityService.removeAuthority(group, username);
            changed = true;
        }
        
        return changed;
    }
}