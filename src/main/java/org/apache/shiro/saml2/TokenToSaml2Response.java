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

import java.io.ByteArrayInputStream;
import java.io.IOException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

/**
 * @author AritraChatterjee
 * 
 */
public final class TokenToSaml2Response {

	private TokenToSaml2Response() {
		// Disabling initialization
	}

	public static Response convertToken(String token)
			throws Saml2TokenValidationException {
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			throw new Saml2TokenValidationException(
					"OpenSAML bootstrap configuration failed.", e);
		}

		ByteArrayInputStream inputStream = new ByteArrayInputStream(
				token.getBytes());

		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder docBuilder;

		try {
			docBuilder = documentBuilderFactory.newDocumentBuilder();
		} catch (ParserConfigurationException e) {
			throw new Saml2TokenValidationException(e);
		}

		Document document;
		try {
			document = docBuilder.parse(inputStream);
		} catch (SAXException e) {
			throw new Saml2TokenValidationException(e);
		} catch (IOException e) {
			throw new Saml2TokenValidationException(e);
		}
		Element element = document.getDocumentElement();

		UnmarshallerFactory unmarshallerFactory = Configuration
				.getUnmarshallerFactory();
		Unmarshaller unmarshaller = unmarshallerFactory
				.getUnmarshaller(element);
		XMLObject responseXmlObj;

		try {
			responseXmlObj = unmarshaller.unmarshall(element);
		} catch (UnmarshallingException e) {
			throw new Saml2TokenValidationException(e);
		}

		return (Response) responseXmlObj;
	}
}
