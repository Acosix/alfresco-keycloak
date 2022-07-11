package de.acosix.alfresco.keycloak.repo.authentication;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.alfresco.repo.security.authentication.AbstractAuthenticationComponent;
import org.alfresco.repo.security.authentication.AuthenticationUtil;
import org.alfresco.repo.security.authentication.AuthenticationUtil.RunAsWork;
import org.alfresco.repo.transaction.AlfrescoTransactionSupport;
import org.alfresco.repo.transaction.AlfrescoTransactionSupport.TxnReadState;
import org.alfresco.service.cmr.repository.DuplicateChildNodeNameException;
import org.alfresco.service.cmr.security.AuthorityService;
import org.alfresco.service.cmr.security.AuthorityType;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.acosix.alfresco.keycloak.repo.util.AlfrescoCompatibilityUtil;
import net.sf.acegisecurity.GrantedAuthority;

public class KeycloakTokenAuthoritySync implements TokenProcessor {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakTokenAuthoritySync.class);

    private static final String NAME = "AuthoritySync";
    
    protected boolean enabled;
    
    protected boolean syncAuthorityMembershipOnLogin;
    
    protected AuthorityService authorityService;
    
    public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

    /**
     * @param syncAuthorityMembershipOnLogin
     *            the syncAuthorityMembershipOnLogin to set
     */
    public void setSyncAuthorityMembershipOnLogin(final boolean syncAuthorityMembershipOnLogin) {
        this.syncAuthorityMembershipOnLogin = syncAuthorityMembershipOnLogin;
    }
    
    public void setAuthorityService(AuthorityService authorityService) {
		this.authorityService = authorityService;
	}
    
    @Override
    public String getName() {
    	return NAME;
    }
    
    @Override
    public int getPriority() {
    	return 16;
    }
	
	@Override
	public void handleUserTokens(AbstractAuthenticationComponent authComponent, AccessToken accessToken,
			IDToken idToken, boolean freshLogin) {
		if (!this.enabled)
			return;
		
		if (freshLogin) {
	        boolean requiresNew = AlfrescoTransactionSupport.getTransactionReadState() == TxnReadState.TXN_READ_ONLY;
	        authComponent.getTransactionService().getRetryingTransactionHelper().doInTransaction(() -> {
	    		GrantedAuthority[] authorities = authComponent.getCurrentAuthentication().getAuthorities();
	    		this.syncAuthorities(Arrays.asList(authorities), accessToken, idToken);
	            return null;
	        }, false, requiresNew);
	
	    	if (this.syncAuthorityMembershipOnLogin)
	    	{
	            authComponent.getTransactionService().getRetryingTransactionHelper().doInTransaction(() -> {
	                String userName = authComponent.getCurrentUserName();
	        		GrantedAuthority[] authorities = authComponent.getCurrentAuthentication().getAuthorities();
	        		this.syncAuthorityMemberships(userName, Arrays.asList(authorities), accessToken, idToken);
	                return null;
	            }, false, requiresNew);
	    	}
		}
	}
    
    /**
     * Synchronizes the groups of the current user, but not the membership, as Alfresco user groups.
     * @param authorities
     *            the Alfresco authorities to persist as user groups
     * @param accessToken
     *            the access token
     * @param idToken
     *            the ID token
     */
    protected void syncAuthorities(final Collection<GrantedAuthority> authorities, final AccessToken accessToken, final IDToken idToken)
    {
        LOGGER.debug("Synchronizing user groups {}", authorities);

		AuthenticationUtil.runAsSystem(new RunAsLoggableWork<Void>() {
			@Override
			public Void doLoggedWork() {
		        for (GrantedAuthority authority : authorities)
		        {
		        	String authorityId = authority.getAuthority();
		
		        	if (AuthorityType.GROUP.equals(AuthorityType.getAuthorityType(authorityId)))
		        	{
		        		// we only persist groups (not roles) in Alfresco
		            	
	            		// if it didn't exist, then we need to associate the user to the group
	            		if (!authorityService.authorityExists(authorityId))
	            		{
	                		// group does not yet exist; create one
	            			
	                		if (LOGGER.isDebugEnabled())
	                			LOGGER.debug("Creating authority {}", authorityId);

	                		String authorityShortName = authorityService.getShortName(authorityId);
	                		authorityShortName = normalizeAuthority(authorityShortName);

	                		if (LOGGER.isDebugEnabled())
	                			LOGGER.debug("Creating group {}", authorityShortName);
	                		
	                		try {
	                			authorityService.createAuthority(AuthorityType.GROUP, authorityShortName);
	                		} catch (DuplicateChildNodeNameException dcnne) {
	                			LOGGER.debug("Group {} already created; race condition?", authorityShortName);
	                		}
	            		}
		        	}
		        }
		        
		        return null;
			}
		});
    }
    
    /**
     * Synchronizes the membership of the current user with the authority, as an Alfresco user group.
     * @param authorities
     *            the Alfresco authorities to persist as user groups
     * @param accessToken
     *            the access token
     * @param idToken
     *            the ID token
     */
    protected void syncAuthorityMemberships(String userName, final Collection<GrantedAuthority> authorities, final AccessToken accessToken, final IDToken idToken)
    {
		if (LOGGER.isDebugEnabled())
			LOGGER.debug("Synchronizing user group membership for user {}", AlfrescoCompatibilityUtil.maskUsername(userName));

		String userAuthorityId = this.authorityService.getName(AuthorityType.USER, userName);
        Set<String> persistedAuthorityIds = new HashSet<>(this.authorityService.getAuthoritiesForUser(userName));

		if (LOGGER.isDebugEnabled())
			LOGGER.debug("Current authorities for user {}: {}", AlfrescoCompatibilityUtil.maskUsername(userName), persistedAuthorityIds);

		AuthenticationUtil.runAsSystem(new RunAsLoggableWork<Void>() {
			@Override
			public Void doLoggedWork() throws Exception {
		        for (GrantedAuthority authority : authorities)
		        {
		        	String authorityId = authority.getAuthority();
            		LOGGER.trace("Inspecting authority '{}' to grant membership", authorityId);
		
		        	if (AuthorityType.GROUP.equals(AuthorityType.getAuthorityType(authorityId)))
		        	{
		        		// we only persist groups in Alfresco
		
		            	// remove if it exists; any remaining GROUP authorities will be unlinked from user later in this method
		            	persistedAuthorityIds.remove(authorityId);
		            	// we cannot assume persistedAuthorityIds has only registered groups; it includes authorities from keycloak
		            	
		            	authorityId = normalizeAuthority(authorityId);
	            		
	            		if (LOGGER.isDebugEnabled())
	            			LOGGER.debug("Adding user {} to group {}", AlfrescoCompatibilityUtil.maskUsername(userName), authorityId);
	            		
	            		try {
		            		// add the user to the existing group
		                    authorityService.addAuthority(authorityId, userAuthorityId);
	            		} catch (DuplicateChildNodeNameException dcnne) {
	            			if (LOGGER.isTraceEnabled())
	            				LOGGER.trace("User {} is already a member of group {}", AlfrescoCompatibilityUtil.maskUsername(userName), authorityId);
	            		}
		        	}
		        }

		        if (LOGGER.isDebugEnabled())
		        	LOGGER.debug("Removing user {} from authorities: {}", AlfrescoCompatibilityUtil.maskUsername(userName), persistedAuthorityIds);
		        
		        // revoke user from groups
		        for (String persistedAuthorityId : persistedAuthorityIds)
		        {
            		LOGGER.trace("Inspecting authority '{}' to revoke membership", persistedAuthorityId);
            		
		        	if (AuthorityType.GROUP.equals(AuthorityType.getAuthorityType(persistedAuthorityId)))
		        	{
		        		// disassociate persisted groups only
		        		persistedAuthorityId = normalizeAuthority(persistedAuthorityId);
		        		
		        		if (LOGGER.isDebugEnabled())
		        			LOGGER.debug("Removing user {} from group {}", AlfrescoCompatibilityUtil.maskUsername(userName), persistedAuthorityId);
		        		
		            	authorityService.removeAuthority(persistedAuthorityId, userAuthorityId);
		        	}
		        }
		        
		        return null;
			}
		});
    }
    
    private String normalizeAuthority(String authorityIdOrShortName) {
    	// in case we need to filter out special characters
    	return authorityIdOrShortName;
    }
    
    
    
    private interface RunAsLoggableWork<T> extends RunAsWork<T> {
    	
    	default T doWork() throws Exception {
    		long time = System.currentTimeMillis();
			LOGGER.trace("doWork()");
			
			T result;
    		try {
    			result = this.doLoggedWork();
    		} catch (Exception e) {
    			LOGGER.error("An unhandled exception occurred", e);
    			throw e;
    		} catch (Throwable t) {
    			LOGGER.error("An unhandled error occurred", t);
    			throw t;
    		}

			LOGGER.trace("doWork(): completed in {} ms", System.currentTimeMillis() - time);
			
			return result;
    	}
    	
    	T doLoggedWork() throws Exception;
    	
    }

}
