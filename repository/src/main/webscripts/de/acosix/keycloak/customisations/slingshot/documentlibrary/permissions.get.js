/* global keycloakRoles: false */

var keycloakRolesHash;

function process(permissions)
{
    var idx, permissionObj, authority, keycloakRolesArr, jdx, role;

    for (idx = 0; idx < permissions.length; idx++)
    {
        permissionObj = permissions[idx];
        authority = permissionObj.authority.name;

        if (authority && /^ROLE_.+$/.test(authority))
        {
            // lazy init
            if (!keycloakRolesHash)
            {
                keycloakRolesArr = keycloakRoles.listRoles();
                keycloakRolesHash = {};
                for (jdx = 0; jdx < keycloakRolesArr.length; jdx++)
                {
                    keycloakRolesHash[keycloakRolesArr[jdx].name] = keycloakRolesArr[jdx];
                }
            }

            // only process if role mapped from Keycloak
            if (keycloakRolesHash.hasOwnProperty(authority))
            {
                role = keycloakRolesHash[authority];
                if (role)
                {
                    // enhance permissionObj.authority to at least add displayName
                    // may/will still look like a user in UI which only differentiates groups / users
                    permissionObj.authority = {
                        name : authority,
                        fullName : authority,
                        shortName : authority.substring(5),
                        displayName : role.description || role.keycloakName
                    };
                }
            }
        }
    }
}

function main()
{
    var permissions = model.data;

    process(permissions.direct);
    process(permissions.inherited);

    model.data = permissions;
}

main();
