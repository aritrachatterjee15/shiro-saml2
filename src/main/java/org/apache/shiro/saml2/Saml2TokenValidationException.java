/**
 * 
 */
package org.apache.shiro.saml2;

/**
 * @author tae
 * 
 */
public class Saml2TokenValidationException extends Exception {

	private static final long serialVersionUID = 2546850717853364959L;

	public Saml2TokenValidationException() {
		super();
	}

	public Saml2TokenValidationException(String message, Throwable cause,
			boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

	public Saml2TokenValidationException(String message, Throwable cause) {
		super(message, cause);
	}

	public Saml2TokenValidationException(String message) {
		super(message);
	}

	public Saml2TokenValidationException(Throwable cause) {
		super(cause);
	}

}
