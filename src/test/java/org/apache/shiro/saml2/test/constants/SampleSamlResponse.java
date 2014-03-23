/*
 * Copyright (c) 2014 Fair Isaac Corporation (FIC). 
 * 181 Metro Drive, Suite 700, San Jose, CA 95110, U.S.A. 
 * All rights reserved.
 * 
 * This software is the confidential and proprietary information of FIC. 
 * (\"Confidential Information\").  You shall not disclose such Confidential 
 * Information and shall use it only in accordance with the terms of the 
 * license agreement you entered into with FIC.
 */
package org.apache.shiro.saml2.test.constants;

/**
 * @author AritraChatterjee
 * 
 */
public class SampleSamlResponse {

	//@formatter:off
	public static final String SAMPLE_SAML_RESPONSE = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" "
			+ "ID=\"identifier_2\" InResponseTo=\"identifier_1\" Version=\"2.0\" IssueInstant=\"2004-12-05T09:22:05\" Destination=\"https://sp.example.com/SAML2/SSO/POST\"> "
			+ "<saml:Issuer>https://idp.example.org/SAML2</saml:Issuer>"
			+ "<samlp:Status><samlp:StatusCode  Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>"
			+ "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"identifier_3\" Version=\"2.0\" IssueInstant=\"2004-12-05T09:22:05\">"
			+ "<saml:Issuer>https://idp.example.org/SAML2</saml:Issuer>"
			+ "<!-- a POSTed assertion MUST be signed --><!--ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"></ds:Signature-->"
			+ "<saml:Subject>"
			+ "<saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\">shiro-saml2</saml:NameID>"
			+ "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">"
			+ "<saml:SubjectConfirmationData InResponseTo=\"identifier_1\" Recipient=\"https://sp.example.com/SAML2/SSO/POST\" NotOnOrAfter=\"2004-12-05T09:27:05\"/>"
			+ "</saml:SubjectConfirmation>"
			+ "</saml:Subject>"
			+ "<saml:Conditions NotBefore=\"2004-12-05T09:17:05\" NotOnOrAfter=\"2004-12-05T09:27:05\">"
			+ "<saml:AudienceRestriction>"
			+ "<saml:Audience>https://sp.example.com/SAML2</saml:Audience>"
			+ "</saml:AudienceRestriction>"
			+ "</saml:Conditions>"
			+ "<saml:AuthnStatement AuthnInstant=\"2004-12-05T09:22:00\" SessionIndex=\"identifier_3\">"
			+ "<saml:AuthnContext>"
			+ "<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>"
			+ "</saml:AuthnContext>"
			+ "</saml:AuthnStatement>"
			+ "</saml:Assertion>"
			+ "</samlp:Response>";
	//@formatter:on
}
