/*
 * Copyright (c) 2008 Axel Nennker http://ignisvulpis.blogspot.com/
 * 
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

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URISyntaxException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.logging.Logger;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import nu.xom.Builder;
import nu.xom.Document;
import nu.xom.Element;
import nu.xom.Elements;
import nu.xom.Nodes;
import nu.xom.XPathContext;

import org.xmldap.exceptions.CryptoException;
import org.xmldap.exceptions.KeyStoreException;
import org.xmldap.exceptions.SerializationException;
import org.xmldap.infocard.Constants;
import org.xmldap.infocard.InfoCard;
import org.xmldap.infocard.TokenServiceReference;
import org.xmldap.infocard.UserCredential;
import org.xmldap.infocard.policy.SupportedClaim;
import org.xmldap.infocard.policy.SupportedClaimTypeList;
import org.xmldap.infocard.policy.SupportedToken;
import org.xmldap.infocard.policy.SupportedTokenList;
import org.xmldap.sts.db.CardStorage;
import org.xmldap.sts.db.SupportedClaims;
import org.xmldap.sts.db.impl.CardStorageEmbeddedDBImpl;
import org.xmldap.util.KeystoreUtil;
import org.xmldap.util.PropertiesManager;
import org.xmldap.util.XSDDateTime;

public class ProxySTS  extends HttpServlet {

	static Logger log = Logger.getLogger("org.xmldap.sts.servlet.proxySTS");

    RSAPrivateKey key = null;
    X509Certificate cert = null;
    String domain = null;
    private String servletPath = null;
    private X509Certificate[] certChain = null;

    CardStorage storage = null;
    SupportedClaims supportedClaimsImpl = null;

    String pathToSslCert = null;
//    String issuer = "CN=VeriSign Class 3 Code Signing 2004 CA,OU=Terms of use at https://www.verisign.com/rpa (c)04,OU=VeriSign Trust Network,O=VeriSign\\, Inc.,C=US";
    String issuer = null;

    public void init(ServletConfig config) throws ServletException {

        super.init(config);

        try {

            PropertiesManager properties = new PropertiesManager(PropertiesManager.SECURITY_TOKEN_SERVICE, config.getServletContext());
            String keystorePath = properties.getProperty("keystore");
            if (keystorePath == null) {
            	throw new ServletException("keystorePath is null");
            }
            String keystorePassword = properties.getProperty("keystore.password");
            if (keystorePassword == null) {
            	throw new ServletException("keystorePassword is null");
            }
            String keyname = properties.getProperty("key.name");
            if (keyname == null) {
            	throw new ServletException("cert is null");
            }
            String keypassword = properties.getProperty("key.password");
            if (keypassword == null) {
            	throw new ServletException("keypassword is null");
            }
            domain = properties.getProperty("domain");
            if (domain == null) {
            	throw new ServletException("domainname is null");
            }
            servletPath = properties.getProperty("servletPath");
            if (servletPath == null) {
            	throw new ServletException("servletPath is null");
            }

            String supportedClaimsClass = properties.getProperty("supportedClaimsClass");
            supportedClaimsImpl = SupportedClaims.getInstance(supportedClaimsClass);
            storage = new CardStorageEmbeddedDBImpl(supportedClaimsImpl);
            
            KeystoreUtil keystore = new KeystoreUtil(keystorePath, keystorePassword);
            cert = keystore.getCertificate(keyname);

            key = (RSAPrivateKey) keystore.getPrivateKey(keyname,keypassword);

            certChain = keystore.getCertificateChain(keyname);
            if (certChain == null) {
            	throw new ServletException("certChain is null");
            }
            if (certChain.length == 0) {
            	throw new ServletException("certChain.length is zero");
            }

            pathToSslCert = properties.getProperty("pathToSslCert");
            if (pathToSslCert == null) {
            	throw new ServletException("pathToSslCert is null");
            }

            issuer = properties.getProperty("issuer");
            if (issuer == null) {
            	throw new ServletException("issuer is null");
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

        storage.startup();

    }

//  <register><cardId>1873F8A0-503B-2618-C2B2-90D662198B51</cardId><cert>MIIE1jCCA76
//  gAwIBAgIQG5t/GM10hgvEMeYewFYfOzANBgkqhkiG9w0BAQUFADCBtDELMAkGA1UEBhMCVVMxFzAVBgN
//  VBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTswOQYDVQQ
//  LEzJUZXJtcyBvZiB1c2UgYXQgaHR0cHM6Ly93d3cudmVyaXNpZ24uY29tL3JwYSAoYykwNDEuMCwGA1U
//  EAxMlVmVyaVNpZ24gQ2xhc3MgMyBDb2RlIFNpZ25pbmcgMjAwNCBDQTAeFw0wNzAzMTYwMDAwMDBaFw0
//  wODAzMTUyMzU5NTlaMIGnMQswCQYDVQQGEwJERTEPMA0GA1UECBMGQmVybGluMQ8wDQYDVQQHEwZCZXJ
//  saW4xKzApBgNVBAoUIlQtU3lzdGVtcyBFbnRlcnByaXNlIFNlcnZpY2VzIEdtYkgxHDAaBgNVBAsUE1N
//  5c3RlbXMgSW50ZWdyYXRpb24xKzApBgNVBAMUIlQtU3lzdGVtcyBFbnRlcnByaXNlIFNlcnZpY2VzIEd
//  tYkgwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAK0FJv9g3xIFUFYMSZ7wfrX3N+X4UHlrWVDsdKQ
//  3DJ2tXdnY9OaocSMp4lb5UqjPZxQvHUo5ogJs8jgSB2yp5OWH6DCYfIR6rxxuKI5evNhOwX3nuoyd5L/
//  S2NmPHLig384XdPKjFBSjZUbOpWvofHMwcRvs380LdUe2K99hnuEHAgMBAAGjggFxMIIBbTAJBgNVHRM
//  EAjAAMA4GA1UdDwEB/wQEAwIHgDBABgNVHR8EOTA3MDWgM6Axhi9odHRwOi8vQ1NDMy0yMDA0LWNybC5
//  2ZXJpc2lnbi5jb20vQ1NDMy0yMDA0LmNybDBEBgNVHSAEPTA7MDkGC2CGSAGG+EUBBxcDMCowKAYIKwY
//  BBQUHAgEWHGh0dHBzOi8vd3d3LnZlcmlzaWduLmNvbS9ycGEwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCs
//  GAQUFBwMDMHUGCCsGAQUFBwEBBGkwZzAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AudmVyaXNpZ24uY29
//  tMD8GCCsGAQUFBzAChjNodHRwOi8vQ1NDMy0yMDA0LWFpYS52ZXJpc2lnbi5jb20vQ1NDMy0yMDA0LWF
//  pYS5jZXIwHwYDVR0jBBgwFoAUCPVR6Pv+PT1kNnxoz1t4qN+5xTcwEQYJYIZIAYb4QgEBBAQDAgQQMA0
//  GCSqGSIb3DQEBBQUAA4IBAQBGd+ZCppyQvEPvedj7FMl/nwUa/alEsr8XdOP1MzaueUsZeUAykg1uGow
//  9Cey4pbw7NNTg1C8nKHvf652gSixMJjsESpfXqbkSRnPNZl/bu4zm8yWcg1G89ZaxndKqLdr+ww5jmHC
//  sQyRh6Nurj6bTZNtXGdo2VMFpUWqZbCZjD0PsQa4ObZuyoIC4UTy2oTl3paKJhsaoBZLD/P2v6X6+R34
//  GU/dz0QaT1ChlrwMrWJXYCLb4eL1YSIu44r7u5yKhLZBCWFGgDpZjh8tWJihOrq93tWE+yoO9c4eabNT
//  8d3T4stxUo82pN140om64bgVU6Y8A6ZhrLJ5C/Fzqfdf+</cert></register>
  
    private void handlePoll(Element root, HttpServletRequest request, HttpServletResponse response) throws IOException {
    	ServletContext serletContext = request.getSession().getServletContext();
    	String rst = (String)serletContext.getAttribute("rst");
    	if (rst != null) {
	        response.setContentType("application/soap+xml; charset=\"utf-8\"");
	        response.setContentLength(rst.length());
	        PrintWriter out = response.getWriter();
	        out.println(rst);
	        out.flush();
	        out.close();
    	}
    }
    
    private void handleLopp(Element root, HttpServletRequest request, HttpServletResponse response) throws IOException {
    	ServletContext serletContext = request.getSession().getServletContext();
    	Elements kids = root.getChildElements();
    	if (kids.size() == 1) {
    		serletContext.setAttribute("token", kids.get(0).toXML());
    	}
    }
    
    private void handleRegister(Element root, HttpServletRequest request, HttpServletResponse response) throws IOException {
    		Element certElement = root.getFirstChildElement("cert");
    		String b64EncodedX509Certificate = certElement.getValue();
    		try {
				X509Certificate portableSTScert = org.xmldap.crypto.CryptoUtils.X509fromB64(b64EncodedX509Certificate);
//				try {
//					portableSTScert.checkValidity();
//				} catch (CertificateExpiredException e) {
//					response.sendError(javax.servlet.http.HttpServletResponse.SC_NOT_ACCEPTABLE, e.getMessage());
//					e.printStackTrace();
//				} catch (CertificateNotYetValidException e) {
//					response.sendError(javax.servlet.http.HttpServletResponse.SC_NOT_ACCEPTABLE, e.getMessage());
//					e.printStackTrace();
//				}
				javax.security.auth.x500.X500Principal issuerPrincipal = portableSTScert.getIssuerX500Principal();
				System.out.println("issuer principal: " + issuerPrincipal.getName());
				if (issuer.equals(issuerPrincipal.getName())) {
					javax.security.auth.x500.X500Principal subjectPrincipal = portableSTScert.getSubjectX500Principal();
					System.out.println("register subject principal: " + subjectPrincipal.getName());
					request.getSession(true).getServletContext().setAttribute(subjectPrincipal.getName(), b64EncodedX509Certificate);
				} else {
					System.out.println("wrong issuer principal: " + issuerPrincipal.getName());
					System.out.println("expec issuer principal: " + issuer);
					response.sendError(javax.servlet.http.HttpServletResponse.SC_NOT_ACCEPTABLE, "wrong issuer");
				}
			} catch (CryptoException e) {
				response.sendError(javax.servlet.http.HttpServletResponse.SC_NOT_ACCEPTABLE, e.getMessage());
				e.printStackTrace();
			}
    }

    private void handleUnregister(Element root, HttpServletRequest request, HttpServletResponse response) throws IOException {
		Element certElement = root.getFirstChildElement("cert");
		String b64EncodedX509Certificate = certElement.getValue();
		try {
			X509Certificate portableSTScert = org.xmldap.crypto.CryptoUtils.X509fromB64(b64EncodedX509Certificate);
			javax.security.auth.x500.X500Principal issuerPrincipal = portableSTScert.getIssuerX500Principal();
			System.out.println("issuer principal: " + issuerPrincipal.getName());
			if (issuer.equals(issuerPrincipal.getName())) {
				javax.security.auth.x500.X500Principal subjectPrincipal = portableSTScert.getSubjectX500Principal();
				System.out.println("unregister subject principal: " + subjectPrincipal.getName());
				request.getSession(true).getServletContext().setAttribute(subjectPrincipal.getName(), null);
			} else {
				response.sendError(javax.servlet.http.HttpServletResponse.SC_NOT_ACCEPTABLE, "wrong issuer");
			}
		} catch (CryptoException e) {
			response.sendError(javax.servlet.http.HttpServletResponse.SC_NOT_ACCEPTABLE, e.getMessage());
			e.printStackTrace();
		}
    }

    protected void getCard(HttpServletResponse response) throws ServletException {
    	InfoCard card = new InfoCard(certChain, key);
    	String cardId = "0";
        card.setCardId("https://" + domain + "/" + servletPath + "/" + "proxySTS/" + cardId, 1);
        card.setCardName(domain);

        String tokenServiceEndpoint = "https://" + domain + "/" + servletPath + "/" + "proxySTS";
        String mexEndpoint = "https://" + domain + "/" + servletPath + "/" + "mex" + "/" + "proxySTS";
        card.setIssuer(tokenServiceEndpoint);
        XSDDateTime issued = new XSDDateTime();
        card.setTimeIssued(issued.getDateTime());
        String username = "username";
        UserCredential usercredential = new UserCredential(UserCredential.USERNAME, username);
        TokenServiceReference tsr = new TokenServiceReference(tokenServiceEndpoint, mexEndpoint, certChain[0], usercredential);
        ArrayList<TokenServiceReference> tsrl = new ArrayList<TokenServiceReference>();
        tsrl.add(tsr);
        card.setTokenServiceReference(tsrl);
        
        {
	        SupportedToken token = new SupportedToken(org.xmldap.ws.WSConstants.SAML11_NAMESPACE);
	        ArrayList<SupportedToken> stl = new ArrayList<SupportedToken>();
	        stl.add(token);
	        SupportedTokenList tokenList = new SupportedTokenList(stl);
	        tokenList.addSupportedToken(token);
	        card.setTokenList(tokenList);
        }
        
        {
	        ArrayList<SupportedClaim> cl = new ArrayList<SupportedClaim>();
	        cl.add(new SupportedClaim(Constants.IC_GIVENNAME, Constants.IC_NS_GIVENNAME, "Your givenname"));
	        cl.add(new SupportedClaim(Constants.IC_SURNAME, Constants.IC_NS_SURNAME, "Your surname"));
	        cl.add(new SupportedClaim(Constants.IC_EMAILADDRESS, Constants.IC_NS_EMAILADDRESS, "Your email address"));
	        cl.add(new SupportedClaim(Constants.IC_PRIVATEPERSONALIDENTIFIER, Constants.IC_NS_PRIVATEPERSONALIDENTIFIER, "RP PPID"));
	        SupportedClaimTypeList claimList = new SupportedClaimTypeList(cl);
	        card.setClaimList(claimList);
        }
        
        try {
			card.setPrivacyPolicy("https://" + domain + "/" + servletPath + "/PrivacyPolicy.xml", 1);
		} catch (URISyntaxException e) {
			throw new ServletException("internal error in proxySTS", e);
		}

		try {
			PrintWriter out = response.getWriter();
	        String cardStr = card.toXML();
	        response.setContentType("application/x-informationcard");
	        response.setContentLength(cardStr.length());
			out.print(cardStr);
		} catch (java.io.IOException e) {
			throw new ServletException(e);
		} catch (SerializationException e) {
			throw new ServletException(e);
		} 

    }
    
    protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
    	getCard(response);

	}

	private void getCert(HttpServletResponse response)
			throws FileNotFoundException, ServletException, IOException {
		response.setContentType("application/x-x509-ca-cert");
System.out.println("proxySTS doGET reading " + pathToSslCert);
		java.io.InputStream fis = new FileInputStream(pathToSslCert);
		// java.io.FileInputStream fis = new
		// java.io.FileInputStream(privaceStatement);
//		java.io.BufferedReader ins = new java.io.BufferedReader(
//				new java.io.InputStreamReader(fis));
		try {
			PrintWriter out = response.getWriter();
			while (true) {
				int c = fis.read();
				if (c != -1) {
					out.write(c);
				} else {
					break;
				}
			}
		} catch (EOFException eof) {
			// nothing
		} catch (java.io.IOException e) {
			throw new ServletException(e);
		} finally {
			fis.close();
//			ins.close();
		}
	}

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException {
    	try {
	    	HttpSession session = request.getSession();
	    	session.getServletContext().log("proxySTS Servlet got a request");
	    	
	    	log.finest("proxySTS got a request");
	        int contentLen = request.getContentLength();
	
	        String requestXML = null;
	        if (contentLen > 0) {
	
	            DataInputStream inStream = new DataInputStream(request.getInputStream());
	            byte[] buf = new byte[contentLen];
	            inStream.readFully(buf);
	            requestXML = new String(buf);
	
	            System.out.println("proxySTS Request:\n" + requestXML);
	
	        } else {
	        	Utils.soapFault(request, response, "soap:Client", "empty request", "");
	        	return;
	        }
	
	        //let's make a doc
	        Builder parser = new Builder();
	        Document req = null;
	        try {
	            req = parser.build(requestXML, "");
	        } catch (nu.xom.ParsingException e) {
	            e.printStackTrace();
	            Utils.soapFault(request, response, "soap:Client", "nu.xom.ParsingException", e.getMessage());
	            return;
	        } catch (IOException e) {
	            e.printStackTrace();
	            Utils.soapFault(request, response, "soap:Server", "IOException", e.getMessage());
	            return;
	        }
	
	        XPathContext context = Utils.buildRSTcontext();
	
	        log.finest("We have a doc");
	        {
	        	Nodes rsts = req.query("//wst:RequestSecurityToken",context);
	        	if (rsts.size() > 0) {
	        		Element rst = (Element) rsts.get(0);
	                log.finest("proxySTS RST: " + rst.toXML());
	                ServletContext serletContext = request.getSession().getServletContext();
	                serletContext.setAttribute("rst", rst.toXML());
	                serletContext.setAttribute("token", null);
					int count = 0;
					try {
						while (count++ < 5) {
			                try {
								Thread.sleep(5000);
							} catch (InterruptedException e) {
								e.printStackTrace();
								Utils.soapFault(request, response, "soap:Server", "InterruptedException", e.getMessage());
								return;
							}
							String token = (String)serletContext.getAttribute("token");
							if (token != null) {
						        response.setContentType("application/soap+xml");
						        response.setContentLength(token.length());
						        log.finest("proxySTS Response:\n " + token);
						        PrintWriter out = response.getWriter();
						        out.println(token);
						        out.flush();
						        out.close();
						        return;
							}
						}
						Utils.soapFault(request, response, "soap:Server", "timeout", "");
					} finally {
		                serletContext.setAttribute("rst", null);
		                serletContext.setAttribute("token", null);
					}
	        	} else {
	                Element root = req.getRootElement();
	                if ("register".equals(root.getLocalName())) {
	                	handleRegister(root, request, response);
	                } else if ("unregister".equals(root.getLocalName())) {
	                	handleUnregister(root, request, response);
	                } else if ("poll".equals(root.getLocalName())) {
	                	handlePoll(root, request, response);
	                } else if ("llop".equals(root.getLocalName())) {
	                	handleLopp(root, request, response);
	                } else {
	                	Utils.soapFault(request, response, "soap:Client", "The root element must be 'register' or 'unregister' or 'poll' not " + root.getLocalName(), "");
	                }
	        	}
	        }
    	} catch (IOException e) {
    		try {
				Utils.soapFault(request, response, "soap:Server", "IOException", e.getMessage());
			} catch (IOException e1) {
				throw new ServletException(e);
			}
    	}

    }








}
