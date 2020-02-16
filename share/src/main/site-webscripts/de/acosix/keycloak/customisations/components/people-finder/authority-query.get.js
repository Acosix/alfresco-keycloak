function main()
{
    var requestedAuthorityType, filter, maxResults, url, response, responseObj, authorities, idx;

    requestedAuthorityType = args.authorityType ? String(args.authorityType).toLowerCase() : 'all';
    filter = args.filter ? String(args.filter) : null;
    maxResults = args.maxResults ? parseInt(String(args.maxResults)) : 0;

    if (requestedAuthorityType === 'all')
    {
        url = '/acosix/api/keycloak/roles';
        if (maxResults > 0)
        {
            url += '?maxItems=' + maxResults;
        }
        if (filter)
        {
            url += url.indexOf('?') === -1 ? '?' : '&';
            url += 'shortNameFilter=' + encodeURIComponent(filter);
        }
        response = remote.call(url);
        if (response.status.code === 200)
        {
            responseObj = JSON.parse(response.text);
            authorities = model.authorities;

            for (idx = 0; idx < responseObj.data.length; idx++)
            {
                // UI likely cannot handle authorityType ROLE, which would be semantically correct
                authorities.push({
                    authorityType : 'GROUP',
                    shortName : responseObj.data[idx].shortName,
                    fullName : responseObj.data[idx].fullName,
                    displayName : responseObj.data[idx].displayName,
                    description : responseObj.data[idx].fullName,
                    metadata : {}
                });
            }

            model.authorities = authorities;
        }
    }
}

main();
