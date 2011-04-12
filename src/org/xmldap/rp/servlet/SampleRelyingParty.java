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

public class SampleRelyingParty extends HttpServlet {

    private PrivateKey privateKey = null;

    public void init(ServletConfig config) throws ServletException {

        try {

            //Get the private key used for decryption - must correspond to the server's SSL cert
            KeystoreUtil keystore = new KeystoreUtil("xmldap.jks", "storepassword");
            privateKey = keystore.getPrivateKey("certalias", "keypassword");

        } catch (KeyStoreException e) {
            throw new ServletException("Error accessing PrivateKey", e);
        }

    }


    public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {


        try {

            //Get the encrypted token from the request
            String encryptedXML = request.getParameter("xmlToken");
            if ((encryptedXML == null) || (encryptedXML.equals(""))) throw new ServletException("No token provided");

            //Decryt the token
            Token token = new Token(encryptedXML, privateKey);

            //Check the token's validity
            if ((token.isSignatureValid()) && (token.isConditionsValid()) && (token.isCertificateValid())) {

                //Print out the provided claims
                PrintWriter out = response.getWriter();
                Map claims = token.getClaims();
                out.println("<h2>You provided the following claims:</h2>");
                Set keys = claims.keySet();
                Iterator keyIter = keys.iterator();
                while (keyIter.hasNext()) {
                    String name = (String) keyIter.next();
                    String value = (String) claims.get(name);
                    out.println(name + ": " + value + "<br>");
                }
                out.close();

            }

        } catch (InfoCardProcessingException e) {
            throw new ServletException(e);
        }

    }


}
