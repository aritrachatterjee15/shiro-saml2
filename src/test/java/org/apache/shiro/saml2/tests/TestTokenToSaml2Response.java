/*
 * Copyright (c) 2014 Fair Isaac Corporation (FIC). 
 * 181 Metro Drive, Suite 700, San Jose, CA 95110, U.S.A. 
 * All rights reserved.
 * 
 * This software is the confidential and proprietary information of FIC. 
 * ("Confidential Information").  You shall not disclose such Confidential 
 * Information and shall use it only in accordance with the terms of the 
 * license agreement you entered into with FIC.
 */
package org.apache.shiro.saml2.tests;

import org.apache.shiro.saml2.Saml2TokenValidationException;
import org.apache.shiro.saml2.TokenToSaml2Response;
import org.apache.shiro.saml2.test.constants.SampleSamlResponse;
import org.junit.Assert;
import org.junit.Test;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.util.Base64;

/**
 * @author AritraChatterjee
 * 
 */
public class TestTokenToSaml2Response {

	/**
	 * Test that the SAML2 response parser is working as expected
	 * 
	 * @throws Saml2TokenValidationException
	 * @throws ConfigurationException
	 */
	@Test
	public void testConvertToken() throws Saml2TokenValidationException,
			ConfigurationException {
		Response response = TokenToSaml2Response
				.convertToken(Base64
						.encodeBytes(SampleSamlResponse.SAMPLE_SAML_RESPONSE
								.getBytes()));
		Assert.assertEquals("shiro-saml2", response.getAssertions().get(0)
				.getSubject().getNameID().getValue());

	}
}
