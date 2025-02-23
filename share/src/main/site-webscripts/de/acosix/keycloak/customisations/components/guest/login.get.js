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

function main()
{
    var keycloakRedirectUrl, keycloakRedirectUriModel, parameters, idx, parameter, parameterModel;

    // redirect URL is already pre-constructed for a simple <a> redirect
    // we want to support a form-based redirect for UI consistency, so need to deconstruct and even decode (parts of) URL
    keycloakRedirectUrl = Packages.de.acosix.alfresco.keycloak.share.web.KeycloakAuthenticationFilter.getLoginRedirectUrl();
    if (keycloakRedirectUrl !== null)
    {
        // make sure it is a JS string, not Java string
        keycloakRedirectUrl = String(keycloakRedirectUrl);
        keycloakRedirectUriModel = {
            baseUrl : keycloakRedirectUrl.substring(0, keycloakRedirectUrl.indexOf('?')),
            parameters : []
        };
        parameters = keycloakRedirectUrl.substring(keycloakRedirectUrl.indexOf('?') + 1).split(/&/);
        for (idx = 0; idx < parameters.length; idx++)
        {
            parameter = parameters[idx];
            if (parameter !== '' && parameter.indexOf('=') !== -1)
            {
                parameterModel = {
                    name : parameter.substring(0, parameter.indexOf('=')),
                    value : null
                };
                if (parameterModel.name === 'redirect_uri')
                {
                    parameterModel.value = decodeURIComponent(parameter.substring(parameter.indexOf('=') + 1));
                    if (parameterModel.value.indexOf('?') !== -1)
                    {
                        if (parameterModel.value.indexOf('?alfRedirectUrl=') !== -1)
                        {
                            if (parameterModel.value.indexOf('&') !== -1)
                            {
                                parameterModel.value = parameterModel.value.substring(0, parameterModel.value.indexOf('&'));
                            }
                        }
                        else
                        {
                            parameterModel.value = parameterModel.value.substring(0, parameterModel.value.indexOf('?'));
                        }
                    }
                }
                else
                {
                    parameterModel.value = parameter.substring(parameter.indexOf('=') + 1);
                }
                keycloakRedirectUriModel.parameters.push(parameterModel);
            }
        }

        model.keycloakRedirectUriModel = keycloakRedirectUriModel;
    }
}

main();
