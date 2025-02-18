<#-- 
 Copyright 2019 - 2025 Acosix GmbH

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 -->
 <#function showRedirectForm>
    <#local showRedirect = false />
    <#local authConfig = config.scoped['Keycloak']['keycloak-auth-config'] />
    <#if authConfig?? && authConfig.enhanceLoginForm??>
        <#local showRedirect = authConfig.enhanceLoginForm />
    </#if>
    <#return showRedirect />
</#function>

<#if keycloakRedirectUriModel?? && showRedirectForm()>
    <@markup id="oidc-redirect-button" target="form" action="after">
        <#assign el = args.htmlid?html>
        <#-- reuse CSS for consistent look&feel -->
        <form action="${keycloakRedirectUriModel.baseUrl}" method="get" class="form-fields login">
            <#list keycloakRedirectUriModel.parameters as parameter>
                <input type="hidden" name="${parameter.name?html}" value="${parameter.value?html}" />
            </#list>
            <div class="form-field">
                <#-- YUI style button without extra client-side JS code -->
                <span class="yui-button yui-submit-button">
                    <span class="first-child">
                        <button type="submit" tabindex="0" id="${el}-oidcRedirect">${msg('button.oidc-sso')?html}</button>
                    </span>
                </span>
            </div>
        </form>
    </@markup>
</#if>