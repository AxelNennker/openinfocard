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
import java.security.interfaces.RSAPrivateKey;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.sourceforge.lightcrypto.SafeObject;
import nu.xom.Attribute;
import nu.xom.Builder;
import nu.xom.Document;
import nu.xom.Element;
import nu.xom.Nodes;
import nu.xom.ParsingException;
import nu.xom.XPathContext;

import org.xmldap.crypto.CryptoUtils;
import org.xmldap.exceptions.KeyStoreException;
import org.xmldap.util.Bag;
import org.xmldap.util.KeystoreUtil;
import org.xmldap.util.PropertiesManager;
import org.xmldap.ws.WSConstants;


public class STSWithSym  extends HttpServlet {


    RSAPrivateKey key;


    public void init(ServletConfig config) throws ServletException {

        super.init(config);

        try {

            PropertiesManager properties = new PropertiesManager(PropertiesManager.SECURITY_TOKEN_SERVICE, config.getServletContext());
            String keystorePath = properties.getProperty("keystore");
            String keystorePassword = properties.getProperty("keystore-password");
            String keyname = properties.getProperty("key-name");
            String keypassword = properties.getProperty("key-password");

            KeystoreUtil keystore = new KeystoreUtil(keystorePath, keystorePassword);
            key = (RSAPrivateKey) keystore.getPrivateKey(keyname,keypassword);



        } catch (IOException e) {
            throw new ServletException(e);
        } catch (KeyStoreException e) {
            throw new ServletException(e);
        }

    }






    private Bag parseToken(String tokenXML) throws ParsingException{

        Bag tokenElements = new Bag();

        //let's make a doc
        Builder parser = new Builder();
        Document req = null;
        try {
            req = parser.build(tokenXML, "");
        } catch (ParsingException e) {
            e.printStackTrace();
            throw new ParsingException("Issue parsing request", e);

        } catch (IOException e) {
            e.printStackTrace();
            throw new ParsingException("Issue parsing request", e);
        }


        XPathContext context = new XPathContext();
        context.addNamespace("s",WSConstants.SOAP12_NAMESPACE);
        context.addNamespace("a", WSConstants.WSA_NAMESPACE_05_08);
        context.addNamespace("wst", "http://schemas.xmlsoap.org/ws/2005/02/trust");
        context.addNamespace("wsid","http://schemas.microsoft.com/ws/2005/05/identity");
        context.addNamespace("o","http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
        context.addNamespace("u","http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");

        Nodes uns = req.query("//o:Username",context);
        Element un = (Element) uns.get(0);
        String userName = un.getValue();
        System.out.println("userName: " + userName);
        tokenElements.put("userName", userName);


        Nodes pws = req.query("//o:Password",context);
        Element pw = (Element) pws.get(0);
        String password = pw.getValue();
        System.out.println("password: " + password);
        tokenElements.put("password", password);

        return tokenElements;

    }


    /*
    <wst:RequestSecurityToken Context="ProcessRequestSecurityToken" xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust">
    <wsid:InformationCardReference xmlns:wsid="http://schemas.xmlsoap.org/ws/2005/05/identity">
        <wsid:CardId>https://xmldap.org/sts/card/2E55ECBE-1423-38AE-DA05-0B27F44907F8</wsid:CardId>
        <wsid:CardVersion>1</wsid:CardVersion>
    </wsid:InformationCardReference>
    <wst:Claims>
        <wsid:ClaimType Uri="http://schemas.microsoft.com/ws/2005/05/identity/claims/givenname"
                        xmlns:wsid="http://schemas.xmlsoap.org/ws/2005/05/identity"/>
        <wsid:ClaimType Uri="http://schemas.microsoft.com/ws/2005/05/identity/claims/surname"
                        xmlns:wsid="http://schemas.xmlsoap.org/ws/2005/05/identity"/>
        <wsid:ClaimType Uri="http://schemas.microsoft.com/ws/2005/05/identity/claims/emailaddress"
                        xmlns:wsid="http://schemas.xmlsoap.org/ws/2005/05/identity"/>
    </wst:Claims>
    <wst:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</wst:KeyType>
    <wst:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</wst:TokenType>
    <wsid:RequestDisplayToken xml:lang="en" xmlns:wsid="http://schemas.xmlsoap.org/ws/2005/05/identity"/>
</wst:RequestSecurityToken>

    */

    private Bag parseRequest(String requestXML) throws ParsingException{

        //let's make a doc
        Builder parser = new Builder();
        Document req = null;
        try {
            req = parser.build(requestXML, "");
        } catch (ParsingException e) {
            e.printStackTrace();
            throw new ParsingException("Issue parsing request", e);

        } catch (IOException e) {
            e.printStackTrace();
            throw new ParsingException("Issue parsing request", e);
        }

        Bag requestElements = new Bag();


        XPathContext context = new XPathContext();
        context.addNamespace("s",WSConstants.SOAP12_NAMESPACE);
        context.addNamespace("a", WSConstants.WSA_NAMESPACE_05_08);
        context.addNamespace("wst", "http://schemas.xmlsoap.org/ws/2005/02/trust");
        context.addNamespace("wsid","http://schemas.xmlsoap.org/ws/2005/05/identity");
        context.addNamespace("o","http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
        context.addNamespace("u","http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");

        Nodes cids = req.query("//wsid:CardId",context);
        Element cid = (Element) cids.get(0);
        String cardId = cid.getValue();
        System.out.println("cardId: " + cardId);
        requestElements.put("cardId", cardId);


        Nodes cvs = req.query("//wsid:CardVersion",context);
        Element cv = (Element) cvs.get(0);
        String cardVersion = cv.getValue();
        System.out.println("CardVersion: " + cardVersion);
        requestElements.put("cardVersion", cardVersion);


        Nodes claims = req.query("//wsid:ClaimType",context);
        for (int i = 0; i < claims.size(); i++ ) {

            Element claimElm = (Element)claims.get(i);
            Attribute uri = claimElm.getAttribute("Uri");
            String claim = uri.getValue();
            System.out.println(claim);
            requestElements.put("claim", claim);

        }

        Nodes kts = req.query("//wst:KeyType",context);
        Element kt = (Element) kts.get(0);
        String keyType = kt.getValue();
        System.out.println("keyType: " + keyType);
        requestElements.put("keyType", keyType);

        Nodes tts = req.query("//wst:TokenType",context);
        Element tt = (Element) tts.get(0);
        String tokenType = tt.getValue();
        System.out.println("tokenType: " + tokenType);
        requestElements.put("tokenType", tokenType);

        return requestElements;


    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        System.out.println("STS got a request");
        int contentLen = request.getContentLength();

        String requestXML = null;
        if (contentLen > 0) {

            DataInputStream inStream = new DataInputStream(request.getInputStream());
            byte[] buf = new byte[contentLen];
            inStream.readFully(buf);
            requestXML = new String(buf);

            System.out.println("STS Request:");
            System.out.println(requestXML);

        }

        //let's make a doc
        Builder parser = new Builder();
        Document req = null;
        try {
            req = parser.build(requestXML, "");
        } catch (ParsingException e) {
            e.printStackTrace();

        } catch (IOException e) {
            e.printStackTrace();
        }



        System.out.println("We have a doc");

        XPathContext context = new XPathContext();
        context.addNamespace("s",WSConstants.SOAP12_NAMESPACE);
        context.addNamespace("e","http://www.w3.org/2001/04/xmlenc#");
        context.addNamespace("a", WSConstants.WSA_NAMESPACE_05_08);
        context.addNamespace("o","http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
        context.addNamespace("u","http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
        context.addNamespace("c","http://schemas.xmlsoap.org/ws/2005/02/sc");

        Nodes keyCipher = req.query("//e:EncryptedKey/e:CipherData/e:CipherValue",context);
        Element keyElm = (Element) keyCipher.get(0);
        String cipherKey = keyElm.getValue();
        System.out.println("We have a key ciphervalue");


        Nodes bodCipher = req.query("//s:Body//e:CipherValue",context);
        Element bod = (Element) bodCipher.get(0);
        String cipherText = bod.getValue();
        System.out.println("We have a body ciphervalue");


        Nodes tokenCipher = req.query("//s:Header/o:Security/e:EncryptedData/e:CipherData/e:CipherValue",context);
        Element tok = (Element) tokenCipher.get(0);
        String tokenCipherText = tok.getValue();
        System.out.println("We have a token");


        Nodes ids = req.query("//a:MessageID",context);
        Element id = (Element) ids.get(0);
        String messageId = id.getValue();
        System.out.println("ID: " + messageId);




        byte[] clearTextKey = null;
        try {
            clearTextKey = CryptoUtils.decryptRSAOAEP(cipherKey, key);
        } catch (org.xmldap.exceptions.CryptoException e) {
            e.printStackTrace();
        }


        SafeObject keyBytes = new SafeObject();
        try {
            keyBytes.setText(clearTextKey);
        } catch (Exception e) {
            e.printStackTrace();
        }


         StringBuffer clearTextBuffer = new StringBuffer(cipherText);

         StringBuffer rst = null;
         try {
             rst = CryptoUtils.decryptAESCBC(clearTextBuffer, keyBytes);
         } catch (org.xmldap.exceptions.CryptoException e) {
             e.printStackTrace();
         }

         System.out.println(rst);


         StringBuffer tokenBuffer = new StringBuffer(tokenCipherText);
         StringBuffer token = null;
         try {
             token = CryptoUtils.decryptAESCBC(tokenBuffer, keyBytes);
         } catch (org.xmldap.exceptions.CryptoException e) {
             e.printStackTrace();
         }

         System.out.println(token);



        Bag requestElements = null;
        try {
            requestElements = parseRequest(rst.toString());
        } catch (ParsingException e) {
            e.printStackTrace();
            //TODO - SOAP Fault
        }


        Bag tokenElements = null;
        try {
            tokenElements = parseToken(token.toString());
        } catch (ParsingException e) {
            e.printStackTrace();
            //TODO - SOAP Fault
        }


        //TODO - authenticate!


        String stsResponse = issue(messageId, requestElements);

        response.setContentType("application/soap+xml; charset=\"utf-8\"");
        response.setContentLength(stsResponse.length());
        System.out.println("STS Response:\n " + stsResponse);
        PrintWriter out = response.getWriter();
        out.println(stsResponse);
        out.flush();
        out.close();

    }

    private String issue(String messageId, Bag requestElements) throws IOException {

    /*  OLD TEST ISSUE
	String issuePath = _su.getIssueFilePathString();

    if (issuePath == null) {
	    issuePath = "/home/cmort/issue.xml";
	}
        InputStream in = new FileInputStream(issuePath);

        StringBuffer issueBuff = new StringBuffer();
        DataInputStream ins = new DataInputStream(in);

        while (in.available() !=0) {
            issueBuff.append(ins.readLine());
        }

        in.close();
        ins.close();

        MessageFormat issueResponse = new MessageFormat(issueBuff.toString());

        XSDDateTime now = new XSDDateTime();
        XSDDateTime later = new XSDDateTime(10);   //one week -what's up with window's time???
        String[] args = {messageId, now.getDateTime(), later.getDateTime()};

        return issueResponse.format(args);


    } */


        Element envelope = new Element(WSConstants.SOAP_PREFIX + ":Envelope", WSConstants.SOAP12_NAMESPACE);
        envelope.addNamespaceDeclaration(WSConstants.WSA_PREFIX, WSConstants.WSA_NAMESPACE_05_08);
        envelope.addNamespaceDeclaration(WSConstants.WSU_PREFIX, WSConstants.WSU_NAMESPACE);
        envelope.addNamespaceDeclaration(WSConstants.WSSE_PREFIX, WSConstants.WSSE_NAMESPACE_OASIS_10);
        envelope.addNamespaceDeclaration(WSConstants.TRUST_PREFIX, WSConstants.TRUST_NAMESPACE_05_02);
        envelope.addNamespaceDeclaration("ic", "http://schemas.xmlsoap.org/ws/2005/05/identity");

        Element header = new Element(WSConstants.SOAP_PREFIX + ":Header", WSConstants.SOAP12_NAMESPACE);
        Element body = new Element(WSConstants.SOAP_PREFIX + ":Body", WSConstants.SOAP12_NAMESPACE);


        envelope.appendChild(header);
        envelope.appendChild(body);



        //Build headers

        Element action = new Element(WSConstants.WSA_PREFIX + ":Action", WSConstants.WSA_NAMESPACE_05_08);
        Attribute id1 = new Attribute("wsu:Id", WSConstants.WSU_NAMESPACE, "_1");
        action.addAttribute(id1);
        action.appendChild("http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Issue");
        header.appendChild(action);

        Element relatesTo = new Element(WSConstants.WSA_PREFIX + ":RelatesTo", WSConstants.WSA_NAMESPACE_05_08);
        Attribute id2 = new Attribute("wsu:Id", WSConstants.WSU_NAMESPACE, "_2");
        relatesTo.addAttribute(id2);
        relatesTo.appendChild(messageId);
        header.appendChild(relatesTo);

        Element to = new Element(WSConstants.WSA_PREFIX + ":To", WSConstants.WSA_NAMESPACE_05_08);
        Attribute id3 = new Attribute("wsu:Id", WSConstants.WSU_NAMESPACE, "_3");
        to.addAttribute(id3);
        to.appendChild("http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous");
        header.appendChild(to);

        Element security = new Element(WSConstants.WSSE_PREFIX + ":Security", WSConstants.WSSE_NAMESPACE_OASIS_10);
        //Attribute id3 = new Attribute("wsu:Id", WSConstants.WSU_NAMESPACE, "_3");
        //to.addAttribute(id3);
        header.appendChild(security);


        //Build body
        Element rstr = new Element(WSConstants.TRUST_PREFIX + ":RequestSecurityTokenResponse", WSConstants.TRUST_NAMESPACE_05_02);
        Element tokenType = new Element(WSConstants.TRUST_PREFIX + ":TokenType", WSConstants.TRUST_NAMESPACE_05_02);
        tokenType.appendChild("urn:oasis:names:tc:SAML:1.0:assertion");
        rstr.appendChild(tokenType);
        Element rst = new Element(WSConstants.TRUST_PREFIX + ":RequestedSecurityToken", WSConstants.TRUST_NAMESPACE_05_02);
        Element assertion = new Element(WSConstants.SAML_PREFIX + ":Assertion", WSConstants.SAML11_NAMESPACE);

        rst.appendChild(assertion);
        rstr.appendChild(rst);

        body.appendChild(rstr);

        return envelope.toXML();
    }


}
