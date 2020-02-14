<#compress><#escape x as jsonUtils.encodeJSONString(x)>{
    "data": [<#list roles as role>{
        "authorityType": "ROLE",
        "shortName": "${role.name?substring(5)}",
        "fullName": "${role.name}",
        "displayName": "${role.description!role.keycloakName}"
    }<#if role_has_next>,</#if></#list>],
    "paging" : {
        "maxItems": ${paging.maxItems?c},
        "skipCount": ${paging.skipCount?c},
        "totalItems": ${paging.totalItems?c},
        "totalItemsRangeEnd": ${paging.totalItems?c},
        "confidence": "exact"
    }
}</#escape></#compress>