/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.saml2;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.util.StringUtils;
import org.opensaml.saml2.common.SAML2Helper;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Subject;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.XSString;

/**
 * @author AritraChatterjee
 * 
 */
public class Saml2Realm extends AuthorizingRealm {

	/*
	 * Each IdP might have a separate key to indicate remember me authentication
	 */
	private String rememberMeAttributeName = "REMEMBER_ME";

	/*
	 * This is the URL of the identity provider
	 */
	private String identityProviderUrlPrefix;

	/*
	 * The service provider consumer URL
	 */
	private String serviceProviderConsumerUrl;

	/*
	 * Default roles to be applied to authenticated user
	 */
	private String defaultRoles;

	/*
	 * Default permissions to be applied to authenticated user
	 */
	private String defaultPermissions;

	/*
	 * Names of attributes containing roles
	 */
	private String roleAttributeNames;

	/*
	 * Names of attributes containing permissions
	 */
	private String permissionAttributeNames;

	public Saml2Realm() {
		setAuthenticationTokenClass(Saml2Token.class);
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(
			AuthenticationToken token) throws AuthenticationException {
		Saml2Token saml2Token = (Saml2Token) token;
		if (token == null) {
			return null;
		}

		String saml2TokenString = (String) saml2Token.getCredentials();
		if (!StringUtils.hasText(saml2TokenString)) {
			return null;
		}

		try {
			Response response = TokenToSaml2Response
					.convertToken(saml2TokenString);

			/*
			 * TODO This is just to keep things simple, assume one assertion per
			 * response.
			 */
			Assertion assertion = response.getAssertions().get(0);

			Subject subject = assertion.getSubject();
			String nameId = subject.getNameID().getValue();

			saml2Token.setNameId(nameId);

			/*
			 * Fail authentication in case there has been a timeout
			 */
			if (!SAML2Helper.isValid(response)) {
				return null;
			}

			/*
			 * TODO Again, keeping things simple, assuming one attribute
			 * statement per assertion
			 */
			List<Attribute> principals = assertion.getAttributeStatements()
					.get(0).getAttributes();

			PrincipalCollection principalCollection = new SimplePrincipalCollection(
					principals, getName());
			return new SimpleAuthenticationInfo(principalCollection,
					saml2TokenString);
		} catch (Saml2TokenValidationException e) {
			throw new Saml2AuthenticationException(e);
		}
	}

	@SuppressWarnings("unchecked")
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(
			PrincipalCollection principals) {
		/*
		 * Retrieve user information
		 */
		SimplePrincipalCollection principalCollection = (SimplePrincipalCollection) principals;
		List<Attribute> listPrincipals = principalCollection.asList();

		Map<String, List<XMLObject>> attributes = new HashMap<String, List<XMLObject>>();
		for (Attribute attribute : listPrincipals) {
			attributes.put(attribute.getName(), attribute.getAttributeValues());
		}

		/*
		 * create simple authorization info
		 */
		SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();

		/*
		 * Add default roles
		 */
		addRoles(simpleAuthorizationInfo, split(defaultRoles));

		/*
		 * Add default permissions
		 */
		addPermissions(simpleAuthorizationInfo, split(defaultPermissions));

		/*
		 * Get roles from attributes
		 */
		List<String> attributeNames = split(roleAttributeNames);

		for (String attributeName : attributeNames) {
			List<XMLObject> xmlValues = attributes.get(attributeName);
			addRoles(simpleAuthorizationInfo,
					getStringValuesFromXMLObjects(xmlValues));
		}

		/*
		 * Get permissions from attributes
		 */
		attributeNames = split(permissionAttributeNames);
		for (String attributeName : attributeNames) {
			List<XMLObject> xmlValues = attributes.get(attributeName);
			addPermissions(simpleAuthorizationInfo,
					getStringValuesFromXMLObjects(xmlValues));
		}
		return simpleAuthorizationInfo;
	}

	/**
	 * Gets the XML values from a list of XML objects as String values
	 * 
	 * @param xmlObjs
	 *            XML object list
	 * @return XML values as String list
	 */
	protected static List<String> getStringValuesFromXMLObjects(
			List<XMLObject> xmlObjs) {
		List<String> strings = new ArrayList<String>();
		for (XMLObject xmlObj : xmlObjs) {
			if (xmlObj instanceof XSString) {
				strings.add(((XSString) xmlObj).getValue());
			} else if (xmlObj instanceof XSAny) {
				strings.add(((XSAny) xmlObj).getTextContent());
			}
		}
		return strings;
	}

	/**
	 * Splits a string into a list of non-empty and trimmed strings, delimited
	 * with commas
	 * 
	 * @param s
	 *            the input string
	 * @return the list of not empty and trimmed strings
	 */
	private List<String> split(String s) {
		List<String> list = new ArrayList<String>();
		String[] elements = StringUtils.split(s, ',');
		if (elements != null && elements.length > 0) {
			for (String element : elements) {
				if (StringUtils.hasText(element)) {
					list.add(element.trim());
				}
			}
		}
		return list;
	}

	/**
	 * Add roles to the simple authorization info.
	 * 
	 * @param simpleAuthorizationInfo
	 * @param roles
	 *            the list of roles to add
	 */
	protected void addRoles(SimpleAuthorizationInfo simpleAuthorizationInfo,
			List<String> roles) {
		for (String role : roles) {
			simpleAuthorizationInfo.addRole(role);
		}
	}

	/**
	 * Add permissions to the simple authorization info.
	 * 
	 * @param simpleAuthorizationInfo
	 * @param permissions
	 *            the list of permissions to add
	 */
	protected void addPermissions(
			SimpleAuthorizationInfo simpleAuthorizationInfo,
			List<String> permissions) {
		for (String permission : permissions) {
			simpleAuthorizationInfo.addStringPermission(permission);
		}
	}

	public String getRememberMeAttributeName() {
		return rememberMeAttributeName;
	}

	public void setRememberMeAttributeName(String rememberMeAttributeName) {
		this.rememberMeAttributeName = rememberMeAttributeName;
	}

	public String getIdentityProviderUrlPrefix() {
		return identityProviderUrlPrefix;
	}

	public void setIdentityProviderUrlPrefix(String identityProviderUrlPrefix) {
		this.identityProviderUrlPrefix = identityProviderUrlPrefix;
	}

	public String getServiceProviderConsumerUrl() {
		return serviceProviderConsumerUrl;
	}

	public void setServiceProviderConsumerUrl(String serviceProviderConsumerUrl) {
		this.serviceProviderConsumerUrl = serviceProviderConsumerUrl;
	}

	public String getDefaultRoles() {
		return defaultRoles;
	}

	public void setDefaultRoles(String defaultRoles) {
		this.defaultRoles = defaultRoles;
	}

	public String getDefaultPermissions() {
		return defaultPermissions;
	}

	public void setDefaultPermissions(String defaultPermissions) {
		this.defaultPermissions = defaultPermissions;
	}

	public String getRoleAttributeNames() {
		return roleAttributeNames;
	}

	public void setRoleAttributeNames(String roleAttributeNames) {
		this.roleAttributeNames = roleAttributeNames;
	}

	public String getPermissionAttributeNames() {
		return permissionAttributeNames;
	}

	public void setPermissionAttributeNames(String permissionAttributeNames) {
		this.permissionAttributeNames = permissionAttributeNames;
	}

}
