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
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY
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


package org.xmldap.sts.servlet;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.URISyntaxException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.xmldap.exceptions.KeyStoreException;
import org.xmldap.exceptions.SerializationException;
import org.xmldap.infocard.InfoCard;
import org.xmldap.infocard.TokenServiceReference;
import org.xmldap.infocard.UserCredential;
import org.xmldap.infocard.policy.SupportedClaim;
import org.xmldap.infocard.policy.SupportedClaimTypeList;
import org.xmldap.infocard.policy.SupportedToken;
import org.xmldap.infocard.policy.SupportedTokenList;
import org.xmldap.sts.db.CardStorage;
import org.xmldap.sts.db.DbSupportedClaim;
import org.xmldap.sts.db.ManagedCard;
import org.xmldap.sts.db.SupportedClaims;
import org.xmldap.sts.db.impl.CardStorageEmbeddedDBImpl;
import org.xmldap.util.Base64;
import org.xmldap.util.KeystoreUtil;
import org.xmldap.util.PropertiesManager;
import org.xmldap.ws.WSConstants;


public class CardServlet extends HttpServlet {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	protected static CardStorage storage = null;
    protected String base64ImageFile = null;

    protected X509Certificate[] certChain = null;
    protected PrivateKey privateKey = null;
    protected String domainname = null;
    protected String issuerName = null;
    protected String servletPath = null;

    protected SupportedClaims supportedClaimsImpl = null;


    public void init(ServletConfig config) throws ServletException {

		super.init(config);

		try {
			PropertiesManager properties = new PropertiesManager(
					PropertiesManager.SECURITY_TOKEN_SERVICE, config
							.getServletContext());
			String keystorePath = properties.getProperty("keystore");
			String keystorePassword = properties
					.getProperty("keystore.password");
			String key = properties.getProperty("key.name");
			String keyPassword = properties.getProperty("key.password");
			String imageFilePathString = properties.getProperty("image.file");
			String supportedClaimsClass = properties
					.getProperty("supportedClaimsClass");
			supportedClaimsImpl = SupportedClaims
					.getInstance(supportedClaimsClass);
			storage = new CardStorageEmbeddedDBImpl(supportedClaimsImpl);

			KeystoreUtil keystore = new KeystoreUtil(keystorePath,
					keystorePassword);
			privateKey = keystore.getPrivateKey(key, keyPassword);
			if (privateKey == null) {
				throw new ServletException("privateKey is null");
			}
			certChain = keystore.getCertificateChain(key);
			if (certChain == null) {
				throw new ServletException("certChain is null");
			}
			if (certChain.length == 0) {
				throw new ServletException("certChain.length is zero");
			}
			domainname = properties.getProperty("domain");
			if (domainname == null) {
				throw new ServletException("domainname is null");
			}
			servletPath = properties.getProperty("servletPath");
			if (servletPath == null) {
				throw new ServletException("servletPath is null");
			}
			issuerName = properties.getProperty("issuerName");
			if (issuerName == null) {
				issuerName = "https://" + domainname + servletPath;
			}

			{
				java.io.InputStream fis = getServletContext()
						.getResourceAsStream(imageFilePathString);
				base64ImageFile = getImageFileEncodedAsBase64(fis);
			}

		} catch (IOException e) {
			throw new ServletException(e);
		} catch (KeyStoreException e) {
			throw new ServletException(e);
		} catch (InstantiationException e) {
			throw new ServletException(e);
		} catch (IllegalAccessException e) {
			throw new ServletException(e);
		} catch (ClassNotFoundException e) {
			throw new ServletException(e);
		}

	}


    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        HttpSession session = request.getSession(true);
        String username = getUsername(session);
        if (username == null) {
            dispatchUnauthenticatedRequest(request, response); // no username means invalid state . . .
            return;
        }

        String cardId = extractCardIdFromRequest(request);


        System.out.println(cardId);
        ManagedCard managedCard = storage.getCard(cardId);
        if (managedCard == null) {
            /* log */
        	System.out.println("CardServlet: could not find card:" + cardId);
            return;
        }
        String userCredentialType = (String)session.getAttribute("UserCredential");
        if (userCredentialType == null) {
        	userCredentialType = UserCredential.USERNAME;
        	System.out.println("Warn: UserCredentialType is null. Using default: " + UserCredential.USERNAME);
        }
        
        UserCredential usercredential = null;
        if (UserCredential.USERNAME.equals(userCredentialType)) {
        	usercredential = new UserCredential(UserCredential.USERNAME, username);
        } else {
        	response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "only username password credentials are currently supported");
        	return;
        }
        String tokenServiceEndpoint = "https://" + domainname + "/" + servletPath + "/" + "tokenservice";
        String mexEndpoint = "https://" + domainname + "/" + servletPath + "/" + "mex" + "/" + userCredentialType;

    //  x509Certificate2.appendChild("MIIEQTCCA6qgAwIBAgICAQQwDQYJKoZIhvcNAQEFBQAwgbsxJDAiBgNVBAcTG1ZhbGlDZXJ0IFZhbGlkYXRpb24gTmV0d29yazEXMBUGA1UEChMOVmFsaUNlcnQsIEluYy4xNTAzBgNVBAsTLFZhbGlDZXJ0IENsYXNzIDIgUG9saWN5IFZhbGlkYXRpb24gQXV0aG9yaXR5MSEwHwYDVQQDExhodHRwOi8vd3d3LnZhbGljZXJ0LmNvbS8xIDAeBgkqhkiG9w0BCQEWEWluZm9AdmFsaWNlcnQuY29tMB4XDTA0MDExNDIxMDUyMVoXDTI0MDEwOTIxMDUyMVowgewxCzAJBgNVBAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMSUwIwYDVQQKExxTdGFyZmllbGQgVGVjaG5vbG9naWVzLCBJbmMuMTAwLgYDVQQLEydodHRwOi8vd3d3LnN0YXJmaWVsZHRlY2guY29tL3JlcG9zaXRvcnkxMTAvBgNVBAMTKFN0YXJmaWVsZCBTZWN1cmUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxKjAoBgkqhkiG9w0BCQEWG3ByYWN0aWNlc0BzdGFyZmllbGR0ZWNoLmNvbTCBnTANBgkqhkiG9w0BAQEFAAOBiwAwgYcCgYEA2xFDa9zRaXhZSehudBQIdBFsfrcqqCLYQjx6z59QskaupmcaIyK+D7M0+6yskKpbKMJw9raKgCrgm5xS4JGocqAW4cROfREJs5651POyUMRtSAi9vCqXDG2jimo8ms9KNNwe3upaJsChooKpSvuGIhKQOrKC1JKRn6lFn8Ok2/sCAQOjggEhMIIBHTAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIBBjBKBgNVHR8EQzBBMD+gPaA7hjlodHRwOi8vY2VydGlmaWNhdGVzLnN0YXJmaWVsZHRlY2guY29tL3JlcG9zaXRvcnkvcm9vdC5jcmwwTwYDVR0gBEgwRjBEBgtghkgBhvhFAQcXAzA1MDMGCCsGAQUFBwIBFidodHRwOi8vd3d3LnN0YXJmaWVsZHRlY2guY29tL3JlcG9zaXRvcnkwOQYIKwYBBQUHAQEELTArMCkGCCsGAQUFBzABhh1odHRwOi8vb2NzcC5zdGFyZmllbGR0ZWNoLmNvbTAdBgNVHQ4EFgQUrFXet+oT6/yYaOJTYB7xJT6M7ucwCQYDVR0jBAIwADANBgkqhkiG9w0BAQUFAAOBgQB+HJi+rQONJYXufJCIIiv+J/RCsux/tfxyaAWkfZHvKNF9IDk7eQg3aBhS1Y8D0olPHhHR6aV0S/xfZ2WEcYR4WbfWydfXkzXmE6uUPI6TQImMwNfy5wdS0XCPmIzroG3RNlOQoI8WMB7ew79/RqWVKvnI3jvbd/TyMrEzYaIwNQ==");
    //  x509Certificate3.appendChild("MIIC5zCCAlACAQEwDQYJKoZIhvcNAQEFBQAwgbsxJDAiBgNVBAcTG1ZhbGlDZXJ0IFZhbGlkYXRpb24gTmV0d29yazEXMBUGA1UEChMOVmFsaUNlcnQsIEluYy4xNTAzBgNVBAsTLFZhbGlDZXJ0IENsYXNzIDIgUG9saWN5IFZhbGlkYXRpb24gQXV0aG9yaXR5MSEwHwYDVQQDExhodHRwOi8vd3d3LnZhbGljZXJ0LmNvbS8xIDAeBgkqhkiG9w0BCQEWEWluZm9AdmFsaWNlcnQuY29tMB4XDTk5MDYyNjAwMTk1NFoXDTE5MDYyNjAwMTk1NFowgbsxJDAiBgNVBAcTG1ZhbGlDZXJ0IFZhbGlkYXRpb24gTmV0d29yazEXMBUGA1UEChMOVmFsaUNlcnQsIEluYy4xNTAzBgNVBAsTLFZhbGlDZXJ0IENsYXNzIDIgUG9saWN5IFZhbGlkYXRpb24gQXV0aG9yaXR5MSEwHwYDVQQDExhodHRwOi8vd3d3LnZhbGljZXJ0LmNvbS8xIDAeBgkqhkiG9w0BCQEWEWluZm9AdmFsaWNlcnQuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDOOnHK5avIWZJV16vYdA757tn2VUdZZUcOBVXc65g2PFxTXdMwzzjsvUGJ7SVCCSRrCl6zfN1SLUzm1NZ9WlmpZdRJEy0kTRxQb7XBhVQ7/nHk01xC+YDgkRoKWzk2Z/M/VXwbP7RfZHM047QSv4dk+NoS/zcnwbNDu+97bi5p9wIDAQABMA0GCSqGSIb3DQEBBQUAA4GBADt/UG9vUJSZSWI4OB9L+KXIPqeCgfYrx+jFzug6EILLGACOTb2oWH+heQC1u+mNr0HZDzTuIYEZoDJJKPTEjlbVUjP9UNV+mWwD5MlM/Mtsq2azSiGM5bUMMj4QssxsodyamEwCW/POuZ6lcg5Ktz885hZo+L7tdEy8W9ViH0Pd");

        InfoCard card = new InfoCard(certChain, privateKey);
        card.setCardId("https://" + domainname + "/" + servletPath + "/" + "card/" + managedCard.getCardId(), 1);
        card.setCardName(managedCard.getCardName());
        card.setIssuer(issuerName);

        if (managedCard.getRequireAppliesTo()) {
        	// optional
        	card.setRequireAppliesTo();  // optional = false
        }
        if (managedCard.getRequireStrongRecipientIdentity()) {
        	// optional
        	card.setRequireStrongRecipientIdentity(true);
        }
        
        {
	        String frontImageStr = managedCard.getCardfrontimage();
	        if (frontImageStr != null) {
	        	// String value = "data:" + contentType + ";base64," + Base64.encodeBytesNoBreaks(buffer);
	        	if (frontImageStr.startsWith("data:")) {
	        		frontImageStr = frontImageStr.substring(5);
	        		int i = frontImageStr.indexOf(';');
	        		if (i < 1) {
	        			System.err.println("CardServlet: wrong format ; cardId = " + cardId + " frontImageString = " + frontImageStr);
	        		} else {
	        			String contentType = frontImageStr.substring(0, i);
	        			String base64 = frontImageStr.substring(i+1);
	        			card.setBase64BinaryCardImage(base64, contentType, "front");
	        		}
	        	} else {
	        		System.err.println("CardServlet: wrong format for cardId = " + cardId + " frontImageString = " + frontImageStr);
	        	}
	        } else {
	        	System.out.println("CardServlet: front image is not set. cardId = " + cardId);
	            // set card logo/image if available . . . 
	            if (base64ImageFile != null) {
	                card.setBase64BinaryCardImage(base64ImageFile, "image/png", "front"); // FIXME hardcoded mimeType
	            }
	        }
        }
        {
	        String backImageStr = managedCard.getCardbackimage();
	        if (backImageStr != null) {
	        	// String value = "data:" + contentType + ";base64," + Base64.encodeBytesNoBreaks(buffer);
	        	if (backImageStr.startsWith("data:")) {
	        		backImageStr = backImageStr.substring(5);
	        		int i = backImageStr.indexOf(';');
	        		if (i < 1) {
	        			System.err.println("CardServlet: wrong format ; cardId = " + cardId + " backImageStr = " + backImageStr);
	        		} else {
	        			String contentType = backImageStr.substring(0, i);
	        			String base64 = backImageStr.substring(i+1);
	        			card.setBase64BinaryCardImage(base64, contentType, "back");
	        		}
	        	} else {
	        		System.err.println("CardServlet: wrong format for cardId = " + cardId + " backImageStr = " + backImageStr);
	        	}
	        } else {
	        	System.out.println("CardServlet: back image is not set. cardId = " + cardId);
	
	        }
        }        

        {
        	String frontHtml = managedCard.getFrontHtml();
        	if (frontHtml != null) {
        		card.setFrontHtml(frontHtml);
        	} else {
        		System.out.println("CardServlet: front html is not set. cardId = " + cardId);
        	}
        }
        {
        	String backHtml = managedCard.getBackHtml();
        	if (backHtml != null) {
        		card.setBackHtml(backHtml);
        	} else {
        		System.out.println("CardServlet: back html is not set. cardId = " + cardId);
        	}
        }
//		The next line made no sense since the dates are in the database and 
//        are in the card already
//        XSDDateTime issued = new XSDDateTime();
//        XSDDateTime expires = new XSDDateTime(525600);
//
//        card.setTimeIssued(issued.getDateTime());
//        card.setTimeExpires(expires.getDateTime());
        card.setTimeIssued(managedCard.getTimeIssued());
        String timeexpired = managedCard.getTimeExpires();
        if (timeexpired != null) {
        	card.setTimeExpires(timeexpired);
        }
        
        {
	        TokenServiceReference tsr = getTokenServiceReference(tokenServiceEndpoint, mexEndpoint, certChain[0], usercredential);
	        List<TokenServiceReference> list = new ArrayList<TokenServiceReference>();
	        list.add(tsr);
	        card.setTokenServiceReference(list);
        }
        
        {
	        SupportedToken token = new SupportedToken(WSConstants.SAML11_NAMESPACE);
	        List<SupportedToken> list = new ArrayList<SupportedToken>();
	        SupportedTokenList tokenList = new SupportedTokenList(list);
	        tokenList.addSupportedToken(token);
	        card.setTokenList(tokenList);
        }
        SupportedClaimTypeList claimList = getSupportedClaimList(managedCard);
        card.setClaimList(claimList);

        try {
			card.setPrivacyPolicy(getPrivacyPolicyReference(domainname), 1);
		} catch (URISyntaxException e) {
			throw new ServletException(e);
		}


        PrintWriter out = response.getWriter();
        response.setContentType("application/x-informationcard; charset=utf-8");

        try {
            out.println(card.toXML());
        } catch (SerializationException e) {
            throw new ServletException(e);
        }

        out.flush();
        out.close();
        return;


    }

    protected String getPrivacyPolicyReference(String domainname) {
        return "https://" + domainname + "/" + servletPath + "/PrivacyPolicy.xml";
    }

    protected TokenServiceReference getTokenServiceReference(String tokenServiceEndpoint, String mexEndpoint, X509Certificate cert, UserCredential usercredential) {
    	TokenServiceReference tsr = new TokenServiceReference(tokenServiceEndpoint, mexEndpoint, cert, usercredential);
        return tsr;
    }

    protected SupportedClaimTypeList getSupportedClaimList(ManagedCard managedCard) {
    	List<DbSupportedClaim> supportedClaims = supportedClaimsImpl.dbSupportedClaims();
        SupportedClaim supportedClaim = new SupportedClaim("PPID", org.xmldap.infocard.Constants.IC_NS_PRIVATEPERSONALIDENTIFIER, "your personal private identitfier");
        ArrayList<SupportedClaim> cl = new ArrayList<SupportedClaim>();
        cl.add(supportedClaim);
    	for (DbSupportedClaim claim : supportedClaims) {
    		String value = managedCard.getClaim(claim.uri);
    		if ((value != null) && !("".equals(value))) {
	    		// TODO: support description. Axel
	    		supportedClaim = new SupportedClaim(claim.displayTags[0].displayTag, claim.uri, "A Description");
	    		cl.add(supportedClaim);
    		}
    	}
        SupportedClaimTypeList claimList = new SupportedClaimTypeList(cl);
//        SupportedClaimList claimList = new SupportedClaimList();
//        SupportedClaim given = new SupportedClaim("GivenName", org.xmldap.infocard.Constants.IC_NS_GIVENNAME);
//        SupportedClaim sur = new SupportedClaim("Surname", org.xmldap.infocard.Constants.IC_NS_SURNAME);
//        SupportedClaim email = new SupportedClaim("EmailAddress", org.xmldap.infocard.Constants.IC_NS_EMAILADDRESS);
//        SupportedClaim ppid = new SupportedClaim("PPID", org.xmldap.infocard.Constants.IC_NS_PRIVATEPERSONALIDENTIFIER);
//        claimList.addSupportedClaim(given);
//        claimList.addSupportedClaim(sur);
//        claimList.addSupportedClaim(email);
//        claimList.addSupportedClaim(ppid);
        return claimList;
    }

    protected void dispatchUnauthenticatedRequest(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        RequestDispatcher dispatcher = request.getRequestDispatcher("/cardmanager/");
        dispatcher.forward(request, response);
    }

    protected String getUsername(HttpSession session) {
        String username = (String) session.getAttribute("username");
        return username;
    }

    /**
     * Get the card identifier from the GET request URL (i.e. http://sts.xmldap.org/card/<b>MY-CARD-IDENTIFIER</b>.crd
     *
     * @param request
     * @return a card identifier that can be used to retrieve the actual card object from the card store
     */
    protected static String extractCardIdFromRequest(HttpServletRequest request) {
        String url = request.getRequestURL().toString();
        return extractCardIdFromUrl(url);
    }

    /**
     * Get the card identifier from the GET request URL (i.e. http://sts.xmldap.org/card/<b>MY-CARD-IDENTIFIER</b>.crd
     *
     * @param url
     * @return a card identifier that can be used to retrieve the actual card object from the card store
     */

    protected static String extractCardIdFromUrl(String url) {
        int index = url.lastIndexOf("/");
        index++;
        String cardID = url.substring(index, url.length() - 4);
        return cardID;
    }

    /**
     * Gets the file referenced by path and returns it's data as a Base64 string.
     * @param imageFilePathString path to the file
     * @return Base64 encoded image data (usaully a PNG)
     */
    protected String getImageFileEncodedAsBase64(String imageFilePathString) {
        String encodedFile;
        encodedFile = Base64.encodeFromFile(imageFilePathString);
        return encodedFile;
    }
    protected String getImageFileEncodedAsBase64(InputStream ins) {
        String encodedFile;
        encodedFile = Base64.encodeFromInputStream(ins, 0);
        return encodedFile;
    }
}
