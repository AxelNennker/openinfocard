package org.xmldap.sts.servlet;

/*
 * Copyright (c) 2007, Axel Nennker - http://axel.nennker.de/
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
 *     * The names of the contributors may NOT be used to endorse or promote products
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
 * 
 */

import java.io.DataInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.Locale;
import java.util.logging.Logger;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import nu.xom.Builder;
import nu.xom.Document;
import nu.xom.Element;
import nu.xom.Nodes;
import nu.xom.XPathContext;

import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.xmldap.exceptions.CryptoException;
import org.xmldap.exceptions.KeyStoreException;
import org.xmldap.exceptions.ParsingException;
import org.xmldap.exceptions.TokenIssuanceException;
import org.xmldap.sts.db.CardStorage;
import org.xmldap.sts.db.ManagedCard;
import org.xmldap.sts.db.SupportedClaims;
import org.xmldap.sts.db.impl.CardStorageEmbeddedDBImpl;
import org.xmldap.util.Bag;
import org.xmldap.util.CertsAndKeys;
import org.xmldap.util.KeystoreUtil;
import org.xmldap.util.PropertiesManager;
import org.xmldap.ws.WSConstants;

public class MetaSTSServlet  extends HttpServlet {

	static Logger log = Logger.getLogger("org.xmldap.sts.servlet.MetaSTSServlet");

    String domain = null;
    private String servletPath = null;

    CardStorage storage = null;
    SupportedClaims supportedClaimsImpl = null;
    KeystoreUtil keystore = null;
    
    X509Certificate caCert = null;
    RSAPrivateKey caPrivateKey = null;
    
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
            
            keystore = new KeystoreUtil(keystorePath, keystorePassword);
            
            caCert = keystore.getCertificate("caCert");
            caPrivateKey = (RSAPrivateKey)keystore.getPrivateKey("caPrivateKey", keypassword);
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


    private Bag parseToken(Element tokenXML) throws ParsingException{

        Bag tokenElements = new Bag();

        XPathContext context = new XPathContext();
        context.addNamespace("s",WSConstants.SOAP12_NAMESPACE);
        context.addNamespace("a", WSConstants.WSA_NAMESPACE_05_08);
        context.addNamespace("wst", "http://schemas.xmlsoap.org/ws/2005/02/trust");
        context.addNamespace("wsid","http://schemas.microsoft.com/ws/2005/05/identity");
        context.addNamespace("o","http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
        context.addNamespace("u","http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");

        Nodes uns = tokenXML.query("//o:Username",context);
        Element un = (Element) uns.get(0);
        String userName = un.getValue();
        log.finest("username: " + userName);
        tokenElements.put("username", userName);


        Nodes pws = tokenXML.query("//o:Password",context);
        Element pw = (Element) pws.get(0);
        String password = pw.getValue();
        tokenElements.put("password", password);

        return tokenElements;

    }



    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

    	HttpSession session = request.getSession();
    	session.getServletContext().log("MetaSTS Servlet got a request");
    	System.out.println("Boink"); System.out.flush();
    	
    	log.finest("MetaSTS got a request");
        int contentLen = request.getContentLength();

        String requestXML = null;
        if (contentLen > 0) {

            DataInputStream inStream = new DataInputStream(request.getInputStream());
            byte[] buf = new byte[contentLen];
            inStream.readFully(buf);
            requestXML = new String(buf);

            log.finest("STS Request:");
            log.finest(requestXML);

        }

        //let's make a doc
        Builder parser = new Builder();
        Document req = null;
        try {
            req = parser.build(requestXML, "");
        } catch (nu.xom.ParsingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        XPathContext context = buildRSTcontext();

        log.finest("We have a doc");

        Bag tokenElements = parseToken(req, context);
        boolean isUser = authenticate(tokenElements);
        
        //TODO = SOAPFaulr
        if (!isUser) {
        	response.sendError(HttpServletResponse .SC_UNAUTHORIZED);
        	return;
        }


        String requestURL = request.getRequestURL().toString();
        String servletPath = request.getServletPath();
        int i = requestURL.indexOf(servletPath);
        String prefix = requestURL.substring(0, i);
        Bag requestElements = null;
        try {
            Nodes rsts = req.query("//wst:RequestSecurityToken",context);
            Element rst = (Element) rsts.get(0);
            log.finest("RST: " + rst.toXML());
            requestElements = Utils.parseRequest(rst, prefix);
        } catch (ParsingException e) {
        	response.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
            e.printStackTrace();
            //TODO - SOAP Fault
        }

        ManagedCard card = storage.getCard((String)requestElements.get("cardId"));
        if (card == null ) throw new IOException("Unable to read card: " + (String)requestElements.get("cardId"));

        log.finest("STS Issuing Managed Card " + (String)requestElements.get("cardId") + " for " + card.getClaim(org.xmldap.infocard.Constants.IC_NS_EMAILADDRESS));

        String username = (String) tokenElements.get("username");
        X509Certificate cert = null;
        RSAPrivateKey key = null;
       	String password = (String) tokenElements.get("password");
        try {
        	cert = keystore.getCertificate(username);
           	key = (RSAPrivateKey) keystore.getPrivateKey(username,password);

        } catch (KeyStoreException e) {
        	KeyPair kp;
			try {
				kp = CertsAndKeys.generateKeyPair();
			} catch (NoSuchAlgorithmException e1) {
				response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e1.getMessage());
				e1.printStackTrace();
				return;
			} catch (NoSuchProviderException e1) {
				response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e1.getMessage());
				e1.printStackTrace();
				return;
			}
        	String issuer = caCert.getSubjectDN().getName();
        	try {
        		RSAPublicKey certificatePublicKey = (RSAPublicKey)kp.getPublic();
				cert = org.xmldap.util.CertsAndKeys.generateClientCertificate(
						BouncyCastleProvider.PROVIDER_NAME,
						certificatePublicKey, caPrivateKey, 
						new X509Name("CN="+issuer), new X509Name("CN="+username), null,
						(Date)null, null, null);
				keystore.storeCert(username,cert,kp.getPrivate(),password);
			} catch (InvalidKeyException e1) {
				response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e1.getMessage());
				e1.printStackTrace();
				return;
			} catch (CertificateEncodingException e1) {
				response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e1.getMessage());
				e1.printStackTrace();
				return;
			} catch (SecurityException e1) {
				response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e1.getMessage());
				e1.printStackTrace();
				return;
			} catch (SignatureException e1) {
				response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e1.getMessage());
				e1.printStackTrace();
				return;
			} catch (IllegalStateException e1) {
				response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e1.getMessage());
				e1.printStackTrace();
				return;
			} catch (NoSuchProviderException e1) {
				response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e1.getMessage());
				e1.printStackTrace();
				return;
			} catch (NoSuchAlgorithmException e1) {
				response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e1.getMessage());
				e1.printStackTrace();
				return;
			} catch (TokenIssuanceException e1) {
				response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e1.getMessage());
				e1.printStackTrace();
				return;
			} catch (KeyStoreException e1) {
				response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e1.getMessage());
				e1.printStackTrace();
				return;
			}
        	key = (RSAPrivateKey)kp.getPrivate();
        	try {
				keystore.storeCert(username, cert, key, password);
			} catch (KeyStoreException e1) {
				response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e1.getMessage());
				e1.printStackTrace();
				return;
			}
        }

        String relyingPartyURL = null;
        String relyingPartyCertB64 = null;
        try {
			Bag appliesToBag = Utils.parseAppliesTo(req, context);
			relyingPartyURL = (String) appliesToBag.get("relyingPartyURL");
			relyingPartyCertB64 = (String) appliesToBag.get("relyingPartyCertB64");
		} catch (ParsingException e) {
        	response.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
            e.printStackTrace();
            //TODO - SOAP Fault
            return;
		}

        Locale clientLocale = request.getLocale();
        String cardIssuer = "https://" + domain + servletPath;
        String stsResponse = "";
		try {
			stsResponse = Utils.issue(
					card, requestElements, clientLocale, cert, key, cardIssuer, 
					supportedClaimsImpl, 
					relyingPartyURL, relyingPartyCertB64,
					"SHA1withRSA");
		} catch (CryptoException e) {
			//TODO - SOAP Fault
			throw new ServletException(e);
		} catch (TokenIssuanceException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

        response.setContentType("application/soap+xml; charset=\"utf-8\"");
        response.setContentLength(stsResponse.length());
        log.finest("STS Response:\n " + stsResponse);
        PrintWriter out = response.getWriter();
        out.println(stsResponse);
        out.flush();
        out.close();

    }


	/**
	 * @param req
	 * @param context
	 * @return
	 */
	private Bag parseToken(Document req, XPathContext context) {
		Nodes tokenElm = req.query("//o:UsernameToken",context);
        Element token = (Element) tokenElm.get(0);
        log.finest("Token:" + token.toXML());


        Bag tokenElements = null;
        try {
            tokenElements = parseToken(token);
        } catch (ParsingException e) {
            e.printStackTrace();
            //TODO - SOAP Fault
        }
		return tokenElements;
	}


	/**
	 * @return
	 */
	private XPathContext buildRSTcontext() {
		XPathContext context = new XPathContext();
        context.addNamespace("s",WSConstants.SOAP12_NAMESPACE);
        context.addNamespace("a", WSConstants.WSA_NAMESPACE_05_08);
        context.addNamespace("o","http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
        context.addNamespace("u","http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
        context.addNamespace("wst", "http://schemas.xmlsoap.org/ws/2005/02/trust");
		return context;
	}


    private boolean authenticate(Bag tokenElements) {
        String username = (String) tokenElements.get("username");
        String password = (String) tokenElements.get("password");
        return authenticate(username, password);
    }

    protected boolean authenticate(String username, String password) {
        boolean isUser = storage.authenticate(username,password);
        System.out.println("STS Authenticated: " + username  + ":" + isUser );
        return isUser;
    }





}
