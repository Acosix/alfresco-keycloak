var userMenu, otherMenuGroup, logoutItem;

if (model.jsonModel && model.jsonModel.widgets
        && Packages.de.acosix.alfresco.keycloak.share.web.KeycloakAuthenticationFilter.isAuthenticatedByKeycloak())
{
    // default Share does not show logout action for externally authenticated users
    // but with Keycloak we can actually support it, so add it (if missing and user menu has not been removed)

    userMenu = widgetUtils.findObject(model.jsonModel.widgets, 'id', 'HEADER_USER_MENU');
    if (userMenu)
    {
        otherMenuGroup = widgetUtils.findObject(model.jsonModel.widgets, 'id', 'HEADER_USER_MENU_OTHER_GROUP');
        if (!otherMenuGroup)
        {
            otherMenuGroup = {
                id : 'HEADER_USER_MENU_OTHER_GROUP',
                name : 'alfresco/menus/AlfMenuGroup',
                config : {
                    label : 'group.other.label',
                    widgets : [],
                    additionalCssClasses : 'alf-menu-group-no-label'
                }
            };
            userMenu.config.widgets.push(otherMenuGroup);
        }

        logoutItem = widgetUtils.findObject(model.jsonModel.widgets, 'id', 'HEADER_USER_MENU_LOGOUT');
        if (!logoutItem)
        {
            otherMenuGroup.config.widgets.push({
                id : 'HEADER_USER_MENU_LOGOUT',
                name : 'alfresco/header/AlfMenuItem',
                config : {
                    id : 'HEADER_USER_MENU_LOGOUT',
                    label : 'logout.label',
                    iconClass : 'alf-user-logout-icon',
                    publishTopic : 'ALF_DOLOGOUT'
                }
            });
        }
    }
}
