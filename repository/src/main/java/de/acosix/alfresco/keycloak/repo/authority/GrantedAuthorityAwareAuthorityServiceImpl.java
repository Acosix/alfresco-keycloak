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
package de.acosix.alfresco.keycloak.repo.authority;

import java.util.Set;

import org.alfresco.repo.security.authentication.AuthenticationUtil;
import org.alfresco.repo.security.authority.AuthorityServiceImpl;
import org.alfresco.service.cmr.security.AuthorityService;
import org.alfresco.service.cmr.security.PermissionService;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.GrantedAuthority;

/**
 * This specialisation of the Alfresco default authority service includes the current user's {@link GrantedAuthority granted authorities} in
 * the set of authorities. This is necessary to ensure that operations such as {@link AuthorityService#isAdminAuthority(String) admin
 * checks} work correctly, where as permission checks performed by the {@link PermissionService permission service} already take granted
 * authorities into account.
 *
 * @author Axel Faust
 */
public class GrantedAuthorityAwareAuthorityServiceImpl extends AuthorityServiceImpl
{

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public Set<String> getAuthoritiesForUser(final String currentUserName)
    {
        final Set<String> authoritiesForUser = super.getAuthoritiesForUser(currentUserName);

        final String runAsUser = AuthenticationUtil.getRunAsUser();
        final String fullUser = AuthenticationUtil.getFullyAuthenticatedUser();

        final Authentication runAsAuthentication = AuthenticationUtil.getRunAsAuthentication();
        final Authentication fullAuthentication = AuthenticationUtil.getFullAuthentication();

        if (runAsAuthentication != null && currentUserName.equals(runAsUser))
        {
            for (final GrantedAuthority authority : runAsAuthentication.getAuthorities())
            {
                authoritiesForUser.add(authority.getAuthority());
            }
        }
        else if (fullAuthentication != null && currentUserName.equals(fullUser))
        {
            for (final GrantedAuthority authority : fullAuthentication.getAuthorities())
            {
                authoritiesForUser.add(authority.getAuthority());
            }
        }

        return authoritiesForUser;
    }

}
