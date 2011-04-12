/*
 * Copyright (c) 2006, Chuck Mortimore - xmldap.org
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the names xmldap, xmldap.org, xmldap.com nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE REGENTS AND CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.xmldap.rp.servlet;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.xmldap.exceptions.InfoCardProcessingException;
import org.xmldap.exceptions.KeyStoreException;
import org.xmldap.rp.Token;
import org.xmldap.util.KeystoreUtil;
import org.xmldap.util.PropertiesManager;
import org.xmldap.util.XSDDateTime;


public class RelyingPartyServlet extends HttpServlet {

    private PrivateKey privateKey = null;
    private X509Certificate cert = null;

    public void init(ServletConfig config) throws ServletException {

        super.init(config);

        try {
            
            PropertiesManager properties = new PropertiesManager(PropertiesManager.RELYING_PARTY, config.getServletContext());
            String keystorePath = properties.getProperty("keystore");
            System.out.println("keystore: " + keystorePath);
            String keystorePassword = properties.getProperty("keystore-password");
            System.out.println("keystore-password: " + keystorePassword);
            String key = properties.getProperty("key");
            System.out.println("key: " + key);
            String keyPassword = properties.getProperty("key-password");
            System.out.println("key-password: " + keyPassword);

            KeystoreUtil keystore = new KeystoreUtil(keystorePath, keystorePassword);
            privateKey = keystore.getPrivateKey(key,keyPassword);
            if (privateKey == null) {
            	throw new ServletException("the private key is null. alias=" + key);
            }
            cert = keystore.getCertificate(key);
            if (cert == null) {
            	throw new ServletException("the cert is null. alias=" + key);
            }

        } catch (IOException e) {
            throw new ServletException(e);
        } catch (KeyStoreException e) {
            throw new ServletException(e);
        }

    }


    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String AcceptHeaderValue = request.getHeader("Accept");
		if ((AcceptHeaderValue != null) && (AcceptHeaderValue.indexOf("application/xhtml+xml") >= 0)) {
			response.setContentType("application/xhtml+xml");
		}
        PrintWriter out = response.getWriter();
    	out.println("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">");

        out.println("<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\"><head><title>Sample Relying Party</title><style>BODY {color:#000;font-family: verdana, arial, sans-serif;}</style></head>\n" +
                "<body>\n" +
                "<b>Your certificate:</b><br/><br/>" +
                "<textarea cols=\"80\" rows=\"20\">" + escapeHtmlEntities(cert.toString()) + "</textarea>\n" +
                "</body>\n" +
                "</html>");
        out.close();
        return;

    }


    private static String escapeHtmlEntities(String html) {
		StringBuffer result = new StringBuffer();
		for (int i = 0; i < html.length(); i++) {
			char ch = html.charAt(i);
			if (ch == '<') {
				result.append("&lt;");
			} else if (ch == '>') {
				result.append("&gt;");
			} else if (ch == '\"') {
				result.append("&quot;");
			} else if (ch == '\'') {
				result.append("&#039;");
			} else if (ch == '&') {
				result.append("&amp;");
			} else {
				result.append(ch);
			}
		}
		return result.toString();
	}

    public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String AcceptHeaderValue = request.getHeader("Accept");
		if ((AcceptHeaderValue != null) && (AcceptHeaderValue.indexOf("application/xhtml+xml") >= 0)) {
			response.setContentType("application/xhtml+xml");
		}
        PrintWriter out = response.getWriter();
        	out.println("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">");

            out.println("<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\"><head><title>Sample Relying Party</title><style type=\"text/css\">BODY {color:#000;font-family: verdana, arial, sans-serif;}</style></head><body>");

            String encryptedXML = request.getParameter("xmlToken");
            if ((encryptedXML == null) || (encryptedXML.equals(""))) {
                out.println("Sorry - you did not POST a security token.  Something went wrong with your selector</body></html>");
                out.close();
                return;
            }

            out.println("<h2>Here's what you posted:</h2>");
            out.println("<p><textarea rows='10' cols='150' readonly='readonly'>" + escapeHtmlEntities(encryptedXML) + "</textarea></p>");

            try {

	            Token token = new Token(encryptedXML, privateKey);
	
	            if (token.isEncrypted()) {
		            out.println("<h2>And here's the decrypted token:</h2>");
		            out.println("<p><textarea rows='10' cols='150' readonly='readonly'>" + escapeHtmlEntities(token.getDecryptedToken()) + "</textarea></p>");
	            } else {
		            out.println("<h2>The token is not encrypted!</h2>");
	            }
	            
	            try {
	            	out.println("<h2>Valid Signature: " + token.isSignatureValid() + "</h2>");
	            } catch (InfoCardProcessingException e) {
	            	out.println("<h2>INVALID Signature</h2>");
	            	
	            }
	            boolean conditionsValid = token.isConditionsValid();
	            if (conditionsValid) {
	            	out.println("<h2>Valid Conditions: " +  conditionsValid + "</h2>");
	            } else {
	            	XSDDateTime dt = new XSDDateTime();
	            	out.println("<h2>Valid Conditions: " +  conditionsValid + "</h2>&nbsp;Time on Server:&nbsp;" + dt.getDateTime());
	            }
	            out.println("<h2>Confirmation method: " + escapeHtmlEntities(token.getConfirmationMethod()) + "</h2>");
	            if (token.getAudience() != null) {
	                out.println("<h2>Audience is restricted to: " + escapeHtmlEntities(token.getAudience()) + "</h2>");
	            } else {
	                out.println("<h2>Audience is NOT restricted</h2>");
	            }
	            try {
	            	X509Certificate cert = token.getCertificateOrNull();
	            	if (cert != null) {
	            		out.println("<h2>Valid Certificate: " + token.isCertificateValid() + "</h2>");
	            	} else {
	            		out.println("<h2>No Certificate in Token</h2>");
	            	}
	
	            } catch (InfoCardProcessingException e) {
	
	               out.println("<h2>Valid Certificate: " + e.getMessage() + "</h2>");
	
	            }
	            Map claims = token.getClaims();
	            out.println("<h2>You provided the following claims:</h2>");
	            Set keys = claims.keySet();
	            Iterator keyIter = keys.iterator();
	            while (keyIter.hasNext()){
	                String name = (String) keyIter.next();
	                String value = (String) claims.get(name);
	                out.println("<p>" + escapeHtmlEntities(name) + ": " + escapeHtmlEntities(value) + "</p>");
	            }
	            
	            String userAgent = request.getHeader("user-agent");
	            if ((userAgent != null) && !"".equals(userAgent)) {
	            	out.println("<h2>Your user agent is</h2>");
	            	out.println("<p>" + escapeHtmlEntities(userAgent) + "</p>");
	            }
	    		String cardSelectorName = request.getHeader("X-ID-Selector");
	            if (cardSelectorName != null) {
	            	out.println("<p style=\"font-size:xx-small\">Your ID selector is: " + escapeHtmlEntities(cardSelectorName) + "</p>");
	            }

	            out.println("</body></html>");
        } catch (InfoCardProcessingException e) {
            e.printStackTrace();
            out.println("<h2>An error occured:</h2>");
            out.println("<p><textarea rows='10' cols='150'>");
            e.printStackTrace(out);
            out.println("</textarea></p>");
        } finally {
            out.close();
        }

    }
}
