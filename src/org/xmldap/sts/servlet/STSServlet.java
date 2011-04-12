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

import java.io.DataInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
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

import org.xmldap.exceptions.CryptoException;
import org.xmldap.exceptions.KeyStoreException;
import org.xmldap.exceptions.ParsingException;
import org.xmldap.exceptions.TokenIssuanceException;
import org.xmldap.sts.db.CardStorage;
import org.xmldap.sts.db.ManagedCard;
import org.xmldap.sts.db.SupportedClaims;
import org.xmldap.sts.db.impl.CardStorageEmbeddedDBImpl;
import org.xmldap.util.Bag;
import org.xmldap.util.KeystoreUtil;
import org.xmldap.util.PropertiesManager;

public class STSServlet  extends HttpServlet {

	static Logger log = Logger.getLogger("org.xmldap.sts.servlet.STSServlet");

    RSAPrivateKey key = null;
    X509Certificate cert = null;
    String domain = null;
    String issuerName = null;
    private String servletPath = null;

    CardStorage storage = null;
    SupportedClaims supportedClaimsImpl = null;

    String messageDigestAlgorithm = null;
    
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
            issuerName = properties.getProperty("issuerName");
            if (issuerName == null) {
            	issuerName = "https://" + domain + servletPath;
            }
            messageDigestAlgorithm = properties.getProperty("messageDigestAlgorithm");
            if (messageDigestAlgorithm == null) {
            	messageDigestAlgorithm = "SHA1";
            }
            
            String supportedClaimsClass = properties.getProperty("supportedClaimsClass");
            if (supportedClaimsClass == null) {
            	throw new ServletException("supportedClaimsClass is null");
            }
            supportedClaimsImpl = SupportedClaims.getInstance(supportedClaimsClass);
            if (supportedClaimsImpl == null) {
            	throw new ServletException("supportedClaimsImpl is null");
            }
            storage = new CardStorageEmbeddedDBImpl(supportedClaimsImpl);
            if (supportedClaimsClass == null) {
            	throw new ServletException("storage is null");
            }
            
            KeystoreUtil keystore = new KeystoreUtil(keystorePath, keystorePassword);
            cert = keystore.getCertificate(keyname);

            key = (RSAPrivateKey) keystore.getPrivateKey(keyname,keypassword);


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


    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

    	HttpSession session = request.getSession();
    	session.getServletContext().log("STS Servlet got a request");
    	System.out.println("Boink"); System.out.flush();
    	
    	log.finest("STS got a request");
        int contentLen = request.getContentLength();

        String requestXML = null;
        if (contentLen > 0) {

            DataInputStream inStream = new DataInputStream(request.getInputStream());
            byte[] buf = new byte[contentLen];
            inStream.readFully(buf);
            requestXML = new String(buf);

            System.out.println("STS Request:\n" + requestXML);

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

        XPathContext context = Utils.buildRSTcontext();

        log.finest("We have a doc");

        boolean isUser = false;
		try {
			isUser = Utils.authenticate(storage, req, context);
		} catch (ParsingException e) {
			log.fine("authentication failed");
			response.sendError(HttpServletResponse.SC_BAD_REQUEST, "authentication failed\n\n" + e.getMessage());
			return;
		}
        
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
            return;
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
		
        ManagedCard card = storage.getCard((String)requestElements.get("cardId"));
        if (card == null ) throw new IOException("Unable to read card: " + (String)requestElements.get("cardId"));

        System.out.println("STS Issuing Managed Card " + (String)requestElements.get("cardId") + " for " + card.getClaim(org.xmldap.infocard.Constants.IC_NS_EMAILADDRESS));

        Locale clientLocale = request.getLocale();
        String stsResponse = "";
		try {
			stsResponse = Utils.issue(
					card, requestElements, clientLocale, cert, key, 
					issuerName, supportedClaimsImpl, 
					relyingPartyURL, relyingPartyCertB64,
					messageDigestAlgorithm);
		} catch (CryptoException e) {
			response.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
            e.printStackTrace();
            //TODO - SOAP Fault
            return;
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








}
