package de.acosix.alfresco.keycloak.repo.authentication;

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

import org.alfresco.repo.security.authentication.AbstractAuthenticationComponent;
import org.alfresco.repo.transaction.AlfrescoTransactionSupport;
import org.alfresco.repo.transaction.AlfrescoTransactionSupport.TxnReadState;
import org.alfresco.service.cmr.repository.NodeRef;
import org.alfresco.service.cmr.repository.NodeService;
import org.alfresco.service.namespace.QName;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

import de.acosix.alfresco.keycloak.repo.util.AlfrescoCompatibilityUtil;
import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;

public class KeycloakTokenAuthorityMapper implements TokenProcessor, InitializingBean, ApplicationContextAware {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakTokenAuthorityMapper.class);
    
    private static final String NAME = "AuthorityMapper";

    protected ApplicationContext applicationContext;

    protected boolean enabled;
    
    protected boolean mapPersonPropertiesOnLogin;

    protected Collection<AuthorityExtractor> authorityExtractors;

    protected Collection<UserProcessor> userProcessors;
    
    @Override
    public String getName() {
    	return NAME;
    }
    
    public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

    /**
     * @param mapPersonPropertiesOnLogin
     *     the mapPersonPropertiesOnLogin to set
     */
    public void setMapPersonPropertiesOnLogin(final boolean mapPersonPropertiesOnLogin) {
        this.mapPersonPropertiesOnLogin = mapPersonPropertiesOnLogin;
    }
    
    @Override
    public void setApplicationContext(ApplicationContext applicationContext) {
    	this.applicationContext = applicationContext;
    }
    
    @Override
    public void afterPropertiesSet() throws BeansException {
        this.authorityExtractors = Collections
                .unmodifiableList(new ArrayList<>(this.applicationContext.getBeansOfType(AuthorityExtractor.class, false, true).values()));
        this.userProcessors = Collections
                .unmodifiableList(new ArrayList<>(this.applicationContext.getBeansOfType(UserProcessor.class, false, true).values()));
    }
	
	@Override
	public void handleUserTokens(AbstractAuthenticationComponent authComponent, AccessToken accessToken,
			IDToken idToken, boolean freshLogin) {
		if (!this.enabled)
			return;
		
        LOGGER.debug("Mapping Keycloak access token to user authorities");

        final Set<String> mappedAuthorities = new HashSet<>();
        this.authorityExtractors.stream().map(extractor -> extractor.extractAuthorities(accessToken))
                .forEach(mappedAuthorities::addAll);

        LOGGER.debug("Mapped user authorities from access token: {}", mappedAuthorities);

        if (!mappedAuthorities.isEmpty())
        {
            final Authentication currentAuthentication = authComponent.getCurrentAuthentication();
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
        
        if (freshLogin && this.mapPersonPropertiesOnLogin)
        {
            final boolean requiresNew = AlfrescoTransactionSupport.getTransactionReadState() == TxnReadState.TXN_READ_ONLY;
            authComponent.getTransactionService().getRetryingTransactionHelper().doInTransaction(() -> {
                this.updatePerson(authComponent, accessToken, idToken);
                return null;
            }, false, requiresNew);
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
    protected void updatePerson(AbstractAuthenticationComponent authComponent,
    		final AccessToken accessToken, final IDToken idToken)
    {
        final String userName = authComponent.getCurrentUserName();

        LOGGER.debug("Mapping person property updates for user {}", AlfrescoCompatibilityUtil.maskUsername(userName));

        final NodeRef person = authComponent.getPersonService().getPerson(userName);

        final Map<QName, Serializable> updates = new HashMap<>();
        this.userProcessors.forEach(processor -> processor.mapUser(accessToken, idToken != null ? idToken : accessToken, updates));

        LOGGER.debug("Determined property updates for person node of user {}", AlfrescoCompatibilityUtil.maskUsername(userName));

        final Set<QName> propertiesToRemove = updates.keySet().stream().filter(k -> updates.get(k) == null).collect(Collectors.toSet());
        updates.keySet().removeAll(propertiesToRemove);

        final NodeService nodeService = authComponent.getNodeService();
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

}
