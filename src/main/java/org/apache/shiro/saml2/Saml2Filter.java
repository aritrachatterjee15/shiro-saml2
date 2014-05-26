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

import java.io.IOException;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Saml2Filter extends AuthenticatingFilter {

	private static final Logger LOGGER = LoggerFactory
			.getLogger(Saml2Filter.class);

	/*
	 * The name of the parameter in the request containing the SAML token as
	 * indicated in the SAML 2.0 Bindings Specification
	 */
	private static final String SAML_PARAMETER = "SAMLResponse";

	/*
	 * The URL where the application is redirected if the service provider
	 * ticket validation failed
	 */
	private String failureUrl;

	/**
	 * The token created for this authentication is a Saml2Token containing the
	 * SAML2 response received on the Service Provider Consumer URL configured
	 * with the Identity Provider (on which the filter must be configured).
	 * 
	 * @param request
	 *            the incoming request
	 * @param response
	 *            the outgoing response
	 * @throws Exception
	 *             if there is an error processing the request.
	 */
	@Override
	protected AuthenticationToken createToken(ServletRequest request,
			ServletResponse response) throws Exception {
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		String samlResponse = httpRequest.getParameter(SAML_PARAMETER);
		return new Saml2Token(samlResponse);
	}

	/**
	 * Execute login by creating
	 * {@link #createToken(javax.servlet.ServletRequest, javax.servlet.ServletResponse)
	 * token} and logging subject with this token.
	 * 
	 * @param request
	 *            the incoming request
	 * @param response
	 *            the outgoing response
	 * @throws Exception
	 *             if there is an error processing the request.
	 */
	@Override
	protected boolean onAccessDenied(ServletRequest request,
			ServletResponse response) throws Exception {
		return executeLogin(request, response);
	}

	/**
	 * Returns <code>false</code> to always force authentication (user is never
	 * considered authenticated by this filter).
	 * 
	 * @param request
	 *            the incoming request
	 * @param response
	 *            the outgoing response
	 * @param mappedValue
	 *            the filter-specific configuration value mapped to this filter
	 *            in the URL rules mappings.
	 * @return <code>false</code>
	 */
	@Override
	protected boolean isAccessAllowed(ServletRequest request,
			ServletResponse response, Object mappedValue) {
		return false;
	}

	/**
	 * If login has failed, redirect user to the Identity Provider error page
	 * except if the user is already authenticated, in which case redirect to
	 * the default success URL.
	 * 
	 * @param token
	 *            the token representing the current authentication
	 * @param ae
	 *            the current authentication exception
	 * @param request
	 *            the incoming request
	 * @param response
	 *            the outgoing response
	 */
	@Override
	protected boolean onLoginFailure(AuthenticationToken token,
			AuthenticationException ae, ServletRequest request,
			ServletResponse response) {

		Subject subject = getSubject(request, response);
		if (subject.isAuthenticated() || subject.isRemembered()) {
			try {
				issueSuccessRedirect(request, response);
			} catch (Exception e) {
				LOGGER.error("Cannot redirect to the default success url", e);
			}
		} else {
			try {
				WebUtils.issueRedirect(request, response, failureUrl);
			} catch (IOException e) {
				LOGGER.error("Cannot redirect to failure url : {}", failureUrl,
						e);
			}
		}
		return false;
	}

	public void setFailureUrl(String failureUrl) {
		this.failureUrl = failureUrl;
	}
}
