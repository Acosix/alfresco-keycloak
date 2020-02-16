(function()
{
    var Dom = YAHOO.util.Dom;
    
    if (Alfresco.component.ManagePermissions)
    {
        Alfresco.component.ManagePermissions.prototype.fnRenderCellAuthorityIcon = function Acosix_Keycloak_ManagePermissions_fnRenderCellAuthorityIcon()
        {
            return function Acosix_Keycloak_ManagePermissions_renderCellAuthorityIcon(elCell, oRecord, oColumn)
            {
                var authority, isGroupLike, iconUrl;

                Dom.setStyle(elCell, 'width', oColumn.width + 'px');
                Dom.setStyle(elCell.parentNode, 'width', oColumn.width + 'px');

                authority = oRecord.getData('authority');
                // main modification - treat ROLE just like a group, because any number of users can belong to a role
                isGroupLike = /^(GROUP|ROLE)_.*/.test(authority.name);
                // end main modification
                iconUrl = Alfresco.constants.URL_RESCONTEXT + 'components/images/' + (isGroupLike ? 'group' : 'no-user-photo') + '-64.png';

                if (authority.avatar && authority.avatar.length !== 0)
                {
                    iconUrl = Alfresco.constants.PROXY_URI + authority.avatar + '?c=queue&ph=true';
                }
                else if (authority.iconUrl)
                {
                    // As passed-back from the Authority Finder component
                    iconUrl = authority.iconUrl;
                }
                elCell.innerHTML = '<img class="icon32" src="' + iconUrl + '" alt="icon" />';
            };
        };
    }
}());
