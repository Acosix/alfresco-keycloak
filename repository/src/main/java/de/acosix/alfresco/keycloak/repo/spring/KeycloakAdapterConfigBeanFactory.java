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
package de.acosix.alfresco.keycloak.repo.spring;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.alfresco.error.AlfrescoRuntimeException;
import org.alfresco.util.PropertyCheck;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.config.PlaceholderConfigurerSupport;
import org.springframework.util.PropertyPlaceholderHelper;

/**
 * @author Axel Faust
 */
public class KeycloakAdapterConfigBeanFactory implements FactoryBean<ExtendedAdapterConfig>, InitializingBean
{

    private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakAdapterConfigBeanFactory.class);

    private static final Map<String, Method> SETTER_BY_CONFIG_NAME;

    private static final Map<String, Class<?>> VALUE_TYPE_BY_CONFIG_NAME;

    private static final List<String> CONFIG_NAMES;

    static
    {
        final Map<String, Method> setterByConfigName = new HashMap<>();
        final Map<String, Class<?>> valueTypeByConfigName = new HashMap<>();
        final List<String> configNames = new ArrayList<>();

        final Set<Class<?>> supportedValueTypes = new HashSet<>(Arrays.asList(String.class, Map.class));
        final Map<Class<?>, Class<?>> primitiveWrapperTypeMap = new HashMap<>();
        final Class<?>[] wrapperTypes = { Integer.class, Long.class, Boolean.class, Short.class, Byte.class, Character.class, Float.class,
                Double.class };
        final Class<?>[] primitiveTypes = { int.class, long.class, boolean.class, short.class, byte.class, char.class, float.class,
                double.class };
        for (int i = 0; i < primitiveTypes.length; i++)
        {
            supportedValueTypes.add(primitiveTypes[i]);
            supportedValueTypes.add(wrapperTypes[i]);
            primitiveWrapperTypeMap.put(primitiveTypes[i], wrapperTypes[i]);
        }

        Class<?> cls = ExtendedAdapterConfig.class;
        while (cls != null && !Object.class.equals(cls))
        {
            final Field[] fields = cls.getDeclaredFields();
            for (final Field field : fields)
            {
                final JsonProperty annotation = field.getAnnotation(JsonProperty.class);
                if (annotation != null)
                {
                    final String configName = annotation.value();

                    final String fieldName = field.getName();
                    final StringBuilder setterNameBuilder = new StringBuilder(3 + fieldName.length());
                    setterNameBuilder.append("set");
                    setterNameBuilder.append(fieldName.substring(0, 1).toUpperCase(Locale.ENGLISH));
                    setterNameBuilder.append(fieldName.substring(1));
                    final String setterName = setterNameBuilder.toString();

                    Class<?> valueType = field.getType();
                    try
                    {
                        final Method setter = cls.getDeclaredMethod(setterName, valueType);

                        if (valueType.isPrimitive())
                        {
                            valueType = primitiveWrapperTypeMap.get(valueType);
                        }

                        if (supportedValueTypes.contains(valueType))
                        {
                            setterByConfigName.put(configName, setter);
                            valueTypeByConfigName.put(configName, valueType);
                            configNames.add(configName);
                        }
                    }
                    catch (final NoSuchMethodException nsme)
                    {
                        LOGGER.warn("Cannot support Keycloak adapter config field {} as no appropriate setter {} could be found in {}",
                                fieldName, setterName, cls);
                    }
                }
            }

            cls = cls.getSuperclass();
        }

        SETTER_BY_CONFIG_NAME = Collections.unmodifiableMap(setterByConfigName);
        VALUE_TYPE_BY_CONFIG_NAME = Collections.unmodifiableMap(valueTypeByConfigName);
        CONFIG_NAMES = Collections.unmodifiableList(configNames);
    }

    protected Properties propertiesSource;

    protected String configPropertyPrefix;

    protected String placeholderPrefix = PlaceholderConfigurerSupport.DEFAULT_PLACEHOLDER_PREFIX;

    protected String placeholderSuffix = PlaceholderConfigurerSupport.DEFAULT_PLACEHOLDER_SUFFIX;

    protected String valueSeparator = PlaceholderConfigurerSupport.DEFAULT_VALUE_SEPARATOR;

    protected PropertyPlaceholderHelper placeholderHelper;

    /**
     *
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet()
    {
        PropertyCheck.mandatory(this, "propertiesSource", this.propertiesSource);
        PropertyCheck.mandatory(this, "propertyPrefix", this.configPropertyPrefix);

        this.placeholderHelper = new PropertyPlaceholderHelper(this.placeholderPrefix, this.placeholderSuffix, this.valueSeparator, true);
    }

    /**
     * @param propertiesSource
     *     the propertiesSource to set
     */
    public void setPropertiesSource(final Properties propertiesSource)
    {
        this.propertiesSource = propertiesSource;
    }

    /**
     * @param configPropertyPrefix
     *     the configPropertyPrefix to set
     */
    public void setConfigPropertyPrefix(final String configPropertyPrefix)
    {
        this.configPropertyPrefix = configPropertyPrefix;
    }

    /**
     * @param placeholderPrefix
     *     the placeholderPrefix to set
     */
    public void setPlaceholderPrefix(final String placeholderPrefix)
    {
        this.placeholderPrefix = placeholderPrefix;
    }

    /**
     * @param placeholderSuffix
     *     the placeholderSuffix to set
     */
    public void setPlaceholderSuffix(final String placeholderSuffix)
    {
        this.placeholderSuffix = placeholderSuffix;
    }

    /**
     * @param valueSeparator
     *     the valueSeparator to set
     */
    public void setValueSeparator(final String valueSeparator)
    {
        this.valueSeparator = valueSeparator;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedAdapterConfig getObject() throws Exception
    {
        final ExtendedAdapterConfig adapterConfig = new ExtendedAdapterConfig();

        CONFIG_NAMES.forEach(configFieldName -> {
            final Class<?> valueType = VALUE_TYPE_BY_CONFIG_NAME.get(configFieldName);

            Object value;
            if (Map.class.isAssignableFrom(valueType))
            {
                value = this.loadConfigMap(configFieldName);
            }
            else
            {
                value = this.loadConfigValue(configFieldName, valueType);
            }

            if (value != null)
            {
                LOGGER.debug("Loaded {} as value of adapter config field {}", value, configFieldName);
                try
                {
                    final Method setter = SETTER_BY_CONFIG_NAME.get(configFieldName);
                    setter.invoke(adapterConfig, value);
                }
                catch (final IllegalAccessException | InvocationTargetException ex)
                {
                    throw new AlfrescoRuntimeException("Error building adapter configuration", ex);
                }
            }
            else
            {
                LOGGER.trace("No value specified for adapter config field {}", configFieldName);
            }
        });

        PropertyCheck.mandatory(adapterConfig, "auth-server-url", adapterConfig.getAuthServerUrl());
        PropertyCheck.mandatory(adapterConfig, "realm", adapterConfig.getRealm());
        PropertyCheck.mandatory(adapterConfig, "resource", adapterConfig.getResource());

        return adapterConfig;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Class<?> getObjectType()
    {
        return ExtendedAdapterConfig.class;
    }

    protected Object loadConfigValue(final String configFieldName, final Class<?> valueType)
    {
        Object effectiveValue;

        final String propertyName = this.configPropertyPrefix + "." + configFieldName;
        String value = this.propertiesSource.getProperty(propertyName);
        if (value != null)
        {
            value = this.placeholderHelper.replacePlaceholders(value, this.propertiesSource);
        }

        if (value != null && !value.trim().isEmpty())
        {
            final String trimmedValue = value.trim();
            if (Number.class.isAssignableFrom(valueType))
            {
                try
                {
                    effectiveValue = valueType.getMethod("valueOf", String.class).invoke(null, trimmedValue);
                }
                catch (final NoSuchMethodException | IllegalAccessException | InvocationTargetException ex)
                {
                    LOGGER.error(
                            "Number-based value type {} does not provide a publicly accessible, static valueOf to handle conversion of value {}",
                            valueType, trimmedValue);
                    throw new AlfrescoRuntimeException("Failed to convert configuration value " + trimmedValue, ex);
                }
            }
            else if (Boolean.class.equals(valueType))
            {
                effectiveValue = Boolean.valueOf(trimmedValue);
            }
            else if (Character.class.equals(valueType))
            {
                if (trimmedValue.length() > 1)
                {
                    throw new IllegalStateException("Value " + trimmedValue + " has more than one character");
                }
                effectiveValue = Character.valueOf(trimmedValue.charAt(0));
            }
            else if (String.class.equals(valueType))
            {
                effectiveValue = trimmedValue;
            }
            else
            {
                throw new UnsupportedOperationException("Unsupported value type " + valueType);
            }
        }
        else
        {
            effectiveValue = null;
        }

        return effectiveValue;
    }

    protected Map<String, Object> loadConfigMap(final String configFieldName)
    {
        final Map<String, Object> configMap = new HashMap<>();
        final String propertyPrefix = this.configPropertyPrefix + "." + configFieldName + ".";
        this.propertiesSource.stringPropertyNames().stream().filter(p -> p.startsWith(propertyPrefix)).forEach(propertyName -> {
            final String propertyConfigSuffix = propertyName.substring(propertyPrefix.length());
            String value = this.propertiesSource.getProperty(propertyName);
            value = this.placeholderHelper.replacePlaceholders(value, this.propertiesSource);

            LOGGER.debug("Resolved value {} for map key {} of config field {}", value, propertyConfigSuffix, configFieldName);
            if (value != null && !value.trim().isEmpty())
            {
                configMap.put(propertyConfigSuffix, value.trim());
            }
        });

        return configMap.isEmpty() ? null : configMap;
    }
}