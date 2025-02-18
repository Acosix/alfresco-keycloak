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
package de.acosix.alfresco.keycloak.share.config;

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
import java.util.Set;

import org.alfresco.error.AlfrescoRuntimeException;
import org.alfresco.util.EqualsHelper;
import org.alfresco.util.ParameterCheck;
import org.alfresco.util.PropertyCheck;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.extensions.config.ConfigElement;

import de.acosix.alfresco.utility.share.config.BaseCustomConfigElement;

/**
 * @author Axel Faust
 */
public class KeycloakAdapterConfigElement extends BaseCustomConfigElement
{

    public static final String NAME = KeycloakConfigConstants.KEYCLOAK_ADAPTER_CONFIG_NAME;

    private static final Logger LOGGER = LoggerFactory.getLogger(KeycloakAdapterConfigElement.class);

    private static final long serialVersionUID = -7211927327179092723L;

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

    protected final Map<String, Object> configValueByField = new HashMap<>();

    protected final Set<String> markedAsUnset = new HashSet<>();

    /**
     * Creates a new instance of this class.
     */
    public KeycloakAdapterConfigElement()
    {
        super(NAME);
    }

    /**
     * Checks if a specific field is supported by this config element.
     *
     * @param fieldName
     *            the name of the field to check
     * @return {@code true} if the field is supported, {@code false} otherwise
     */
    public boolean isFieldSupported(final String fieldName)
    {
        ParameterCheck.mandatoryString("fieldName", fieldName);
        return CONFIG_NAMES.contains(fieldName);
    }

    /**
     * Retrieves the expected type of value for a specific field. This operation will never return a class object for primitive types,
     * instead replacing those with the class object for the corresponding wrapper type.
     *
     * @param fieldName
     *            the name of the field for which to retrieve the type of value
     * @return the type of value for the field
     */
    public Class<?> getFieldValueType(final String fieldName)
    {
        if (!this.isFieldSupported(fieldName))
        {
            throw new IllegalArgumentException(fieldName + " is not a supported field");
        }
        return VALUE_TYPE_BY_CONFIG_NAME.get(fieldName);
    }

    /**
     * Retrieves the configured value for a specific field. Default values inherent in the {@link ExtendedAdapterConfig Keycloak classes}
     * are not
     * considered by this operation.
     *
     * @param fieldName
     *     the name of the field for which to retrieve the value
     * @return the currently configured value for the field, or {@code null} if no value has been configured
     */
    public Object getFieldValue(final String fieldName)
    {
        return this.configValueByField.get(fieldName);
    }

    /**
     * Sets the configured value for a specific field.
     *
     * @param fieldName
     *            the name of the field for which to set the value
     * @param value
     *            the value of the field to set
     * @throws IllegalArgumentException
     *             if the field is {@link #isFieldSupported(String) not supported} or the type of value does not match the required type
     */
    public void setFieldValue(final String fieldName, final Object value)
    {
        if (!this.isFieldSupported(fieldName))
        {
            throw new IllegalArgumentException(fieldName + " is not a supported field");
        }
        ParameterCheck.mandatory("value", value);
        final Class<?> valueType = VALUE_TYPE_BY_CONFIG_NAME.get(fieldName);
        if (!valueType.isInstance(value))
        {
            throw new IllegalArgumentException("Value is not an instance of " + valueType);
        }
        this.configValueByField.put(fieldName, value);
        this.markedAsUnset.remove(fieldName);
    }

    /**
     * Removes the configured value for a specific field.
     *
     * @param fieldName
     *            the name of the field for which to set the value
     * @param markAsUnset
     *            {@code true} if the field should be marked as explicitly unset for the purpose of {@link #combine(ConfigElement) merging
     *            with other config elements}, {@code false} otherwise
     * @throws IllegalArgumentException
     *             if the field is {@link #isFieldSupported(String) not supported}
     */
    public void removeFieldValue(final String fieldName, final boolean markAsUnset)
    {
        if (!this.isFieldSupported(fieldName))
        {
            throw new IllegalArgumentException(fieldName + " is not a supported field");
        }
        this.configValueByField.remove(fieldName);
        if (markAsUnset)
        {
            this.markedAsUnset.add(fieldName);
        }
    }

    /**
     * Retrieves the explicit {@code unset} flag of a field that may have been set via {@link #removeFieldValue(String, boolean) value
     * removal}.
     *
     * @param fieldName
     *            the name of the field for which to retrieve the flag
     * @return the value of the flag
     */
    public boolean isFieldMarkedAsUnset(final String fieldName)
    {
        if (!this.isFieldSupported(fieldName))
        {
            throw new IllegalArgumentException(fieldName + " is not a supported field");
        }
        return this.markedAsUnset.contains(fieldName);
    }

    /**
     * Builds an instance of a Keycloak adapter configuration based on the configured values managed by this config element.
     *
     * @return the adapter configuration instance
     */
    public ExtendedAdapterConfig buildAdapterConfiguration()
    {
        final ExtendedAdapterConfig adapterConfig = new ExtendedAdapterConfig();

        try
        {
            for (final String configName : CONFIG_NAMES)
            {
                final Object value = this.configValueByField.get(configName);
                if (value != null)
                {
                    final Method setter = SETTER_BY_CONFIG_NAME.get(configName);
                    setter.invoke(adapterConfig, value);
                }
            }
        }
        catch (final IllegalAccessException | InvocationTargetException ex)
        {
            throw new AlfrescoRuntimeException("Error building adapter configuration", ex);
        }

        PropertyCheck.mandatory(adapterConfig, "auth-server-url", adapterConfig.getAuthServerUrl());
        PropertyCheck.mandatory(adapterConfig, "realm", adapterConfig.getRealm());
        PropertyCheck.mandatory(adapterConfig, "resource", adapterConfig.getResource());

        return adapterConfig;
    }

    /**
     * {@inheritDoc}
     */
    @SuppressWarnings({ "rawtypes", "unchecked" })
    @Override
    public ConfigElement combine(final ConfigElement configElement)
    {
        if (!(configElement instanceof KeycloakAdapterConfigElement))
        {
            throw new IllegalArgumentException("Cannot combine with " + configElement);
        }

        final KeycloakAdapterConfigElement combined = new KeycloakAdapterConfigElement();
        final KeycloakAdapterConfigElement otherConfigElement = (KeycloakAdapterConfigElement) configElement;

        for (final String configName : CONFIG_NAMES)
        {
            final Object thisValue = this.getFieldValue(configName);
            final Object otherValue = otherConfigElement.getFieldValue(configName);

            if (otherValue != null)
            {
                Object valueToSet = otherValue;
                if (thisValue instanceof Map<?, ?> && otherValue instanceof Map<?, ?>)
                {
                    valueToSet = new HashMap<>((Map<?, ?>) thisValue);
                    ((Map) valueToSet).putAll((Map) otherValue);
                }
                else if (otherValue instanceof Map<?, ?>)
                {
                    valueToSet = new HashMap<>((Map<?, ?>) otherValue);
                }
                combined.setFieldValue(configName, valueToSet);
            }
            else if (otherConfigElement.isFieldMarkedAsUnset(configName) || this.isFieldMarkedAsUnset(configName))
            {
                combined.removeFieldValue(configName, true);
            }
            else if (thisValue != null)
            {
                combined.setFieldValue(configName, thisValue instanceof Map<?, ?> ? new HashMap<>((Map<?, ?>) thisValue) : thisValue);
            }
        }

        return combined;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        final StringBuilder builder = new StringBuilder();
        builder.append("KeycloakAdapterConfigElement [");
        builder.append("configValueByField=");
        builder.append(this.configValueByField);
        builder.append(",markedAsUnset=");
        builder.append(this.markedAsUnset);
        builder.append("]");
        return builder.toString();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode()
    {
        final int prime = 31;
        int result = super.hashCode();

        // use class-consistent order for actual config values
        for (final String configName : CONFIG_NAMES)
        {
            final Object value = this.configValueByField.get(configName);
            final int valueHash = value == null ? (this.markedAsUnset.contains(configName) ? -1 : 0) : value.hashCode();
            result = prime * result + valueHash;
        }

        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(final Object obj)
    {
        if (this == obj)
        {
            return true;
        }
        if (!super.equals(obj))
        {
            return false;
        }
        if (!(obj instanceof KeycloakAdapterConfigElement))
        {
            return false;
        }
        final KeycloakAdapterConfigElement other = (KeycloakAdapterConfigElement) obj;
        if (!EqualsHelper.nullSafeEquals(this.configValueByField, other.configValueByField))
        {
            return false;
        }
        if (!EqualsHelper.nullSafeEquals(this.markedAsUnset, other.markedAsUnset))
        {
            return false;
        }
        return true;
    }

}
