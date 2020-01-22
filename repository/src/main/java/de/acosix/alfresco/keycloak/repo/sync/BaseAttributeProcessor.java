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
package de.acosix.alfresco.keycloak.repo.sync;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.alfresco.repo.security.sync.NodeDescription;
import org.alfresco.service.namespace.NamespaceService;
import org.alfresco.service.namespace.QName;
import org.alfresco.util.PropertyCheck;
import org.springframework.beans.factory.InitializingBean;

/**
 * This class provides common configuration properties and logic for mapping processor handling Keycloak authority attributes.
 *
 * @author Axel Faust
 */
public abstract class BaseAttributeProcessor implements InitializingBean
{

    protected NamespaceService namespaceService;

    protected Map<String, String> attributePropertyMappings;

    protected Map<String, QName> attributePropertyQNameMappings;

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet()
    {
        PropertyCheck.mandatory(this, "namespaceService", this.namespaceService);

        if (this.attributePropertyMappings != null && !this.attributePropertyMappings.isEmpty())
        {
            this.attributePropertyQNameMappings = new HashMap<>();
            this.attributePropertyMappings
                    .forEach((k, v) -> this.attributePropertyQNameMappings.put(k, QName.resolveToQName(this.namespaceService, v)));
        }
    }

    /**
     * @param namespaceService
     *            the namespaceService to set
     */
    public void setNamespaceService(final NamespaceService namespaceService)
    {
        this.namespaceService = namespaceService;
    }

    /**
     * @param attributePropertyMappings
     *            the attributePropertyMappings to set
     */
    public void setAttributePropertyMappings(final Map<String, String> attributePropertyMappings)
    {
        this.attributePropertyMappings = attributePropertyMappings;
    }

    /**
     * Performs the general attribute to property mapping. This operation will not handle any value type conversions, relying instead on the
     * underlying data types and registered type converters in Alfresco to handle conversion in the persistence layer. Any attribute which
     * is only associated with a single value will be unwrapped from a list to the singular value, while all other attributes will be kept
     * as-is. THis operation also does not perform any checks whether a configured target property actually supports a multi-valued
     * property, again leaving that kind of processing to the Alfresco default functionality of integrity checking.
     *
     * @param attributes
     *            the list of attributes
     * @param nodeDescription
     *            the node description to enhance
     */
    protected void map(final Map<String, List<String>> attributes, final NodeDescription nodeDescription)
    {
        if (this.attributePropertyQNameMappings != null && attributes != null)
        {
            attributes.keySet().stream().filter(this.attributePropertyQNameMappings::containsKey)
                    .forEach(k -> this.mapAttribute(k, attributes, nodeDescription));
        }
    }

    /**
     * Maps an individual attribute to the correlating node property of the node description.
     *
     * @param attribute
     *            the name of the attribute to map
     * @param attributes
     *            the list of attributes
     * @param nodeDescription
     *            the node description to enhance
     */
    protected void mapAttribute(final String attribute, final Map<String, List<String>> attributes, final NodeDescription nodeDescription)
    {
        final QName propertyQName = this.attributePropertyQNameMappings.get(attribute);
        final List<String> values = attributes.get(attribute);
        if (values != null)
        {
            Serializable value;
            if (values.size() == 1)
            {
                value = values.get(0);
            }
            else
            {
                value = new ArrayList<>(values);
            }
            nodeDescription.getProperties().put(propertyQName, value);
        }
    }
}
