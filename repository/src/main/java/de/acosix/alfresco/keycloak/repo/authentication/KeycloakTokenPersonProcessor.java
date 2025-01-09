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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.alfresco.model.ContentModel;
import org.alfresco.repo.security.authentication.AuthenticationUtil;
import org.alfresco.repo.transaction.AlfrescoTransactionSupport;
import org.alfresco.repo.transaction.AlfrescoTransactionSupport.TxnReadState;
import org.alfresco.service.cmr.repository.NodeRef;
import org.alfresco.service.cmr.repository.NodeService;
import org.alfresco.service.cmr.security.PersonService;
import org.alfresco.service.namespace.QName;
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
 * This token processor maps profile data from the token of an authenticated user into the {@link ContentModel#TYPE_PERSON person
 * properties} for that user upon login.
 *
 * @author Axel Faust
 */
public class KeycloakTokenPersonProcessor implements TokenProcessor, InitializingBean, ApplicationContextAware
{

    private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakTokenPersonProcessor.class);

    private static final String NAME = "PersonProcessor";

    protected ApplicationContext applicationContext;

    protected boolean enabled;

    protected TransactionService transactionService;

    protected NodeService nodeService;

    protected PersonService personService;

    protected Collection<UserProcessor> userProcessors;

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public String getName()
    {
        return NAME;
    }

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
     * @param transactionService
     *     the transactionService to set
     */
    public void setTransactionService(final TransactionService transactionService)
    {
        this.transactionService = transactionService;
    }

    /**
     * @param nodeService
     *     the nodeService to set
     */
    public void setNodeService(final NodeService nodeService)
    {
        this.nodeService = nodeService;
    }

    /**
     * @param personService
     *     the personService to set
     */
    public void setPersonService(final PersonService personService)
    {
        this.personService = personService;
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet() throws BeansException
    {
        PropertyCheck.mandatory(this, "transactionService", this.transactionService);
        PropertyCheck.mandatory(this, "nodeService", this.nodeService);
        PropertyCheck.mandatory(this, "personService", this.personService);

        this.userProcessors = Collections
                .unmodifiableList(new ArrayList<>(this.applicationContext.getBeansOfType(UserProcessor.class, false, true).values()));
    }

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void handleUserTokens(final AccessToken accessToken, final IDToken idToken, final boolean freshLogin)
    {
        if (freshLogin && this.enabled)
        {
            final boolean requiresNew = AlfrescoTransactionSupport.getTransactionReadState() == TxnReadState.TXN_READ_ONLY;
            this.transactionService.getRetryingTransactionHelper().doInTransaction(() -> {
                this.updatePerson(accessToken, idToken);
                return null;
            }, false, requiresNew);
            
            AuthenticationUtil.setFullyAuthenticatedUser(accessToken.getPreferredUsername());
        }
    }

    /**
     * Updates the person for the current user with data mapped from the Keycloak tokens.
     *
     * @param accessToken
     *     the access token
     * @param idToken
     *     the ID token
     */
    protected void updatePerson(final AccessToken accessToken, final IDToken idToken)
    {
        final String username = accessToken.getPreferredUsername();

        LOGGER.debug("Mapping person property updates for user {}", AlfrescoCompatibilityUtil.maskUsername(username));

        final NodeRef person = this.personService.getPerson(username);

        final Map<QName, Serializable> updates = new HashMap<>();
        this.userProcessors.forEach(processor -> processor.mapUser(accessToken, idToken != null ? idToken : accessToken, updates));

        LOGGER.debug("Determined property updates for person node of user {}", AlfrescoCompatibilityUtil.maskUsername(username));

        final Set<QName> propertiesToRemove = updates.keySet().stream().filter(k -> updates.get(k) == null).collect(Collectors.toSet());
        updates.keySet().removeAll(propertiesToRemove);

        final Map<QName, Serializable> currentProperties = this.nodeService.getProperties(person);

        propertiesToRemove.retainAll(currentProperties.keySet());
        if (!propertiesToRemove.isEmpty())
        {
            // there is no bulk-remove, so we need to use setProperties to achieve a single update event
            final Map<QName, Serializable> newProperties = new HashMap<>(currentProperties);
            newProperties.putAll(updates);
            newProperties.keySet().removeAll(propertiesToRemove);
            this.nodeService.setProperties(person, newProperties);
        }
        else if (!updates.isEmpty())
        {
            this.nodeService.addProperties(person, updates);
        }
    }

}