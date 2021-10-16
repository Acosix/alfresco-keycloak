package de.acosix.alfresco.keycloak.repo.sync;

import java.util.List;
import java.util.Map;

import org.alfresco.model.ContentModel;
import org.alfresco.repo.security.sync.NodeDescription;
import org.alfresco.service.cmr.security.AuthorityType;
import org.alfresco.util.PropertyMap;
import org.keycloak.representations.idm.GroupRepresentation;

/**
 * This group synchronisation mapping processor maps the default Alfresco authority container properties from a Keycloak group
 * using custom attribute as group ID and name.
 * If custom attribute is not provided, default Keycloak's group ID and Name is used. 
 *
 * @author howkymike
 */
public class AttributeGroupProcessor implements GroupProcessor{

	protected String attributeName;
	protected boolean enabled;

    /**
     * @param enabled
     * the enabled to set
     */
    public void setEnabled(final boolean enabled)
    {
        this.enabled = enabled;
    }
    
    /**
     * @param attributeName
     * the attributeName to set
     */
    public void setAttributeName(String attributeName) 
    {
		this.attributeName = attributeName;
	}

	
	@Override
	public void mapGroup(GroupRepresentation group, NodeDescription groupNode) 
	{
        if (this.enabled)
        {
            String authorityName = group.getId(), displayName = group.getName();
            
            if(attributeName != null && !attributeName.isEmpty()) 
            {
            	Map<String, List<String>> groupAttributes =  group.getAttributes();
            	if(groupAttributes != null) 
            	{
            		List<String> attributeNameValList = groupAttributes.get(attributeName);
            		if(attributeNameValList != null && !attributeNameValList.isEmpty()) 
            		{
            			String attributeNameVal = attributeNameValList.get(0);
            			if(attributeNameVal != null && !attributeNameVal.isEmpty()) 
            			{
            				authorityName = displayName = attributeNameVal;
            			}
            		}
            	}
            }
            
            final PropertyMap properties = groupNode.getProperties();
            properties.put(ContentModel.PROP_AUTHORITY_NAME, AuthorityType.GROUP.getPrefixString() + authorityName);
            properties.put(ContentModel.PROP_AUTHORITY_DISPLAY_NAME, displayName);
        }
	}

}
