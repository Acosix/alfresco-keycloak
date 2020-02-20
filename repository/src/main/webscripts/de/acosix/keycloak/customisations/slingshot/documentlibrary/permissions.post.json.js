/* global keycloakRoles: false */
function main()
{
    var nodeRef, node, permissions, idx, permissionObj, add, authority, permission, keycloakRolesHash, keycloakRolesArr, jdx;

    nodeRef = url.templateArgs.store_type + '://' + url.templateArgs.store_id + '/' + url.templateArgs.id;
    // normally not a fan of Alfresco utils object, but needed here for consistency with base script (there via parse-args.lib.js import)
    node = utils.resolveNodeReference(nodeRef);

    permissions = json.getJSONArray('permissions');
    for (idx = 0; idx < permissions.length(); idx++)
    {
        permissionObj = permissions.getJSONObject(idx);
        add = !permissionObj.has('remove') || !permissionObj.getBoolean('remove');

        authority = permissionObj.getString('authority');
        permission = permissionObj.getString('role');

        if (/^ROLE_.+$/.test(authority))
        {
            // lazy init
            if (!keycloakRolesHash)
            {
                keycloakRolesArr = keycloakRoles.listRoles();
                keycloakRolesHash = {};
                for (jdx = 0; jdx < keycloakRolesArr.length; jdx++)
                {
                    keycloakRolesHash[keycloakRolesArr[jdx].name] = true;
                }
            }

            // only process if role mapped from Keycloak
            if (keycloakRolesHash.hasOwnProperty(authority))
            {
                if (add)
                {
                    node.setPermission(permission, authority);
                }
                else
                {
                    node.removePermission(permission, authority);
                }
            }
        }
    }
}

main();
