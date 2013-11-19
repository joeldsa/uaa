package org.cloudfoundry.identity.uaa.user;

import java.util.Date;
import java.util.List;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;

import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.filter.AndFilter;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class LdapUaaUserDatabase implements UaaUserDatabase {

	private LdapTemplate ldapTemplate = null;
	private String[] searchAttributes = {"objectguid","cn","mail","userPrincipalName","gn","sn"};

	public LdapUaaUserDatabase(LdapTemplate ldapTemplate) {
		this.ldapTemplate = ldapTemplate;
	}

	@SuppressWarnings("unchecked")
	@Override
	public UaaUser retrieveUserByName(String username) throws UsernameNotFoundException {
		AndFilter filter = new AndFilter();
		filter.and(new EqualsFilter("userPrincipalName", username));

		List<UaaUser> results = ldapTemplate.search(
			     "", filter.encode(), SearchControls.SUBTREE_SCOPE,
			     searchAttributes,
			     new UaaUserAttributesMapper());

		if (null != results && results.size() > 0) {
			return results.get(0);
		} else {
			return null;
		}
	}

	public class UaaUserAttributesMapper implements AttributesMapper {
		@Override
		public UaaUser mapFromAttributes(Attributes attrs) throws NamingException {
			String id = getAttributeValue(attrs, "objectguid");
			String username = getAttributeValue(attrs, "cn");
			String email = getAttributeValue(attrs, "mail");
			if (null == email) {
				email = getAttributeValue(attrs, "userPrincipalName");
			}
			String givenName = getAttributeValue(attrs, "gn");
			String familyName = getAttributeValue(attrs, "sn");

			return new UaaUser(id, username, null, email, UaaAuthority.USER_AUTHORITIES, givenName, familyName, new Date(),
					new Date());
		}

		private String getAttributeValue(Attributes attrs, String attributeName) throws NamingException {
			Attribute attribute = attrs.get(attributeName);
			if(null != attribute) {
				return (String) attribute.get();
			} else {
				return null;
			}
		}
	}
}
