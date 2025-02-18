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
package de.acosix.alfresco.keycloak.repo.web.scripts;

import java.text.Collator;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import org.alfresco.util.PropertyCheck;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.extensions.surf.util.I18NUtil;
import org.springframework.extensions.webscripts.Cache;
import org.springframework.extensions.webscripts.DeclarativeWebScript;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.WebScriptException;
import org.springframework.extensions.webscripts.WebScriptRequest;

import de.acosix.alfresco.keycloak.repo.roles.Role;
import de.acosix.alfresco.keycloak.repo.roles.RoleService;

/**
 * This web script controller performs the role query, sort and pagination logic for the {@code roles.get} web script before passing roles
 * on to the FreeMarker response template.
 *
 * @author Axel Faust
 */
public class RolesGet extends DeclarativeWebScript implements InitializingBean
{

    protected RoleService roleService;

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet()
    {
        PropertyCheck.mandatory(this, "roleService", this.roleService);
    }

    /**
     * @param roleService
     *            the roleService to set
     */
    public void setRoleService(final RoleService roleService)
    {
        this.roleService = roleService;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected Map<String, Object> executeImpl(final WebScriptRequest req, final Status status, final Cache cache)
    {
        Map<String, Object> model = super.executeImpl(req, status, cache);
        if (model == null)
        {
            model = new HashMap<>();
        }

        final String shortNameFilterParam = req.getParameter("shortNameFilter");
        final String skipCountParam = req.getParameter("skipCount");
        final String maxItemsParam = req.getParameter("maxItems");
        final String sortByParam = req.getParameter("sortBy");
        final String dirParam = req.getParameter("dir");

        int skipCount = 0;
        int maxItems = -1;

        if (skipCountParam != null)
        {
            if (!skipCountParam.matches("^\\d+$"))
            {
                throw new WebScriptException(Status.STATUS_BAD_REQUEST, "The skipCount parameter must be a non-negative integer");
            }
            skipCount = Integer.parseInt(skipCountParam);
        }

        if (maxItemsParam != null)
        {
            if (!maxItemsParam.matches("^\\d+$"))
            {
                throw new WebScriptException(Status.STATUS_BAD_REQUEST, "The maxItems parameter must be a non-negative integer");
            }
            maxItems = Integer.parseInt(maxItemsParam);
        }

        final List<Role> roles = shortNameFilterParam != null && !shortNameFilterParam.trim().isEmpty()
                ? this.roleService.findRoles(shortNameFilterParam)
                : this.roleService.listRoles();

        if (roles.isEmpty())
        {
            final boolean sortDescending = "desc".equalsIgnoreCase(dirParam);
            final Function<Role, String> sortFieldProvider;

            if (sortByParam == null || sortByParam.trim().isEmpty())
            {
                sortFieldProvider = (r) -> {
                    return r.getName();
                };
            }
            else
            {
                switch (sortByParam.trim())
                {
                    case "authorityName":
                        sortFieldProvider = (r) -> {
                            return r.getName();
                        };
                        break;
                    case "keycloakName":
                        sortFieldProvider = (r) -> {
                            return r.getKeycloakName();
                        };
                        break;
                    case "description":
                        sortFieldProvider = (r) -> {
                            String desc = r.getDescription();
                            if (desc == null)
                            {
                                desc = "";
                            }
                            return desc;
                        };
                        break;
                    default:
                        throw new WebScriptException(Status.STATUS_BAD_REQUEST, "Unsupported sortBy parameter value");
                }
            }

            final Collator coll = Collator.getInstance(I18NUtil.getLocale());

            Collections.sort(roles, (r1, r2) -> {
                int result = coll.compare(sortFieldProvider.apply(r1), sortFieldProvider.apply(r2));
                if (sortDescending)
                {
                    result *= -1;
                }
                return result;
            });
        }

        final Map<String, Object> paging = new HashMap<>();
        paging.put("maxItems", Integer.valueOf(maxItems));
        paging.put("skipCount", Integer.valueOf(skipCount));
        paging.put("totalItems", Integer.valueOf(roles.size()));
        model.put("paging", paging);

        if (skipCount > 0 || maxItems != -1)
        {
            final List<Role> rolesSubList;
            if (skipCount >= roles.size())
            {
                rolesSubList = Collections.emptyList();
            }
            else
            {
                rolesSubList = maxItems != -1 ? roles.subList(skipCount, Math.min(maxItems + skipCount, roles.size()))
                        : roles.subList(skipCount, roles.size());
            }
            model.put("roles", rolesSubList);
        }
        else
        {
            model.put("roles", roles);
        }

        return model;
    }
}
