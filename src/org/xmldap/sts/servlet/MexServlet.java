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

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import nu.xom.Builder;
import nu.xom.Document;
import nu.xom.Element;
import nu.xom.Nodes;
import nu.xom.ParsingException;
import nu.xom.XPathContext;

import org.xmldap.exceptions.KeyStoreException;
import org.xmldap.infocard.UserCredential;
import org.xmldap.util.Base64;
import org.xmldap.util.KeystoreUtil;
import org.xmldap.util.PropertiesManager;
import org.xmldap.ws.WSConstants;


public class MexServlet extends HttpServlet {

	private final static String soap_prefix = "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:a=\"http://www.w3.org/2005/08/addressing\"><s:Header><a:Action s:mustUnderstand=\"1\">http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse</a:Action><a:RelatesTo>{0}</a:RelatesTo></s:Header><s:Body>";
	private final static String soap_postfix = "</s:Body></s:Envelope>";

    private String cert = null;

    public void init(ServletConfig config) throws ServletException {

        super.init(config);

        try {

            PropertiesManager properties = new PropertiesManager(PropertiesManager.SECURITY_TOKEN_SERVICE, config.getServletContext());
            String keystorePath = properties.getProperty("keystore");
            System.out.println("keystore: " + keystorePath);
            String keystorePassword = properties.getProperty("keystore.password");
            System.out.println("keystore.password: " + keystorePassword);
            String key = properties.getProperty("key.name");
            System.out.println("key.name: " + key);

            KeystoreUtil keystore = new KeystoreUtil(keystorePath, keystorePassword);
            X509Certificate certificate = keystore.getCertificate(key);
            cert = Base64.encodeBytesNoBreaks(certificate.getEncoded());

        } catch (IOException e) {
            throw new ServletException(e);
        } catch (KeyStoreException e) {
            throw new ServletException(e);
        } catch (CertificateEncodingException e) {
            throw new ServletException(e);
        }

    }

    protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

    	String url = request.getRequestURL().toString();
    	
		System.out.println("MEX got a GET request: " + url);
		ServletContext application = getServletConfig().getServletContext();
		
		String filename = null;
		if (url.indexOf("symmetric-binding") > 0) { // this is experimental and works only for my environment. Axel
			filename = "WEB-INF/mex-pwd-symmetric-binding-get.xml";
		} else if (url.endsWith("proxySTS")) {
			filename = "WEB-INF/mex-proxy-get.xml";
		} else if (url.endsWith(UserCredential.USERNAME) || url.endsWith("/mex")) {
			filename = "WEB-INF/mex-pwd-get.xml";
		} else if (url.endsWith(UserCredential.SELF_ISSUED)) {
			filename = "WEB-INF/mex-self-get.xml";
		} else if (url.endsWith(UserCredential.X509)) {
			filename = "WEB-INF/mex-x509-get.xml";
		} else if (url.endsWith(UserCredential.KERB)) {
			filename = "WEB-INF/mex-kerb-get.xml";
		} else {
			response.sendError(HttpServletResponse.SC_NOT_FOUND, "no mex data is associated with this url " + url);
			return;
		}
		
		StringBuffer mexBuff = new StringBuffer();
		{
			System.out.println("MEX reading file " + filename);
			InputStream in = application.getResourceAsStream(filename);
	        if (in == null) {
	            in = application.getResourceAsStream('/' + filename); // second try
	            if (in == null) {
					System.err.println("MexServlet: Get: Error reading resource " + filename);
					response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error reading resource " + filename);
					return;
	            }
            }
	
			BufferedReader ins = new BufferedReader(new InputStreamReader(in));
			char[] cbuf = new char[2048];
			try {
				while (true) {
					int c = ins.read(cbuf, 0, cbuf.length);
					if (c != -1) {
						mexBuff.append(cbuf, 0, c);
					} else {
						break;
					}
				}
	
	//			while (in.available() != 0) {
	//				mexBuff.append(ins.readLine());
	//			}
	
			} catch (IOException e) {
				throw new ServletException(e);
			} finally {
				in.close();
				ins.close();
			}
		}
		
		String[] args = { cert };
		MessageFormat mexResponse = new MessageFormat(mexBuff.toString());

		String resp = mexResponse.format(args);
		response.setContentLength(resp.length());
        response.setContentType("application/soap+xml; charset=utf-8");

		PrintWriter out = response.getWriter();
		out.println(resp);
		out.flush();
		out.close();
		System.out.println("MEX replied");
		System.out.println(resp);

	}

 protected void doPost(HttpServletRequest request, HttpServletResponse
 response) throws ServletException, IOException {

        System.out.println("MEX got a POST request: " + request.getRequestURL());
    	String url = request.getRequestURL().toString();

        int contentLen = request.getContentLength();
        DataInputStream inStream = new DataInputStream(request.getInputStream());
        byte[] buf = new byte[contentLen];
        inStream.readFully(buf);
        String mexRequest = new String(buf);

        //let's make a doc
        Builder parser = new Builder();
        Document mex = null;
        try {
            mex = parser.build(mexRequest, "");
        } catch (ParsingException e) {
            throw new ServletException(e);
        } catch (IOException e) {
            throw new ServletException(e);
        }


        XPathContext context = new XPathContext();
        context.addNamespace("s", WSConstants.SOAP12_NAMESPACE);
        context.addNamespace("a", "http://www.w3.org/2005/08/addressing");


        Nodes messageIDs = mex.query("//a:MessageID", context);
        Element messageID = (Element) messageIDs.get(0);


        String[] args = {messageID.getValue(), cert};

		String filename = null;
		if (url.endsWith(UserCredential.USERNAME) || url.endsWith("/mex")) {
			filename = "WEB-INF/mex-pwd-post.xml";
		} else if (url.endsWith("proxySTS")) {
			filename = "WEB-INF/mex-proxy-post.xml";
		} else if (url.endsWith(UserCredential.SELF_ISSUED)) {
			filename = "WEB-INF/mex-self-post.xml";
		} else if (url.endsWith(UserCredential.X509)) {
			filename = "WEB-INF/mex-x509-post.xml";
		} else if (url.endsWith(UserCredential.KERB)) {
			filename = "WEB-INF/mex-kerb-post.xml";
		} else {
			response.sendError(HttpServletResponse.SC_NOT_FOUND, "no mex data is associated with this url " + url);
			return;
		}
		System.out.println("MEX reading file " + filename);

        ServletContext application = getServletConfig().getServletContext();
        InputStream in = application.getResourceAsStream(filename);
        if (in == null) {
            in = application.getResourceAsStream('/' + filename); // second try
            if (in == null) {
				System.err.println("MexServlet: Post: Error reading resource " + filename);
				response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "error reading resource " + filename);
				return;
            }
        }


        StringBuffer mexBuff = new StringBuffer();
        BufferedReader ins = new BufferedReader(new InputStreamReader(in));
        try {
            System.out.println("MEX reading file");
            char[] cbuf = new char[2048];
			while (true) {
				int c = ins.read(cbuf, 0, cbuf.length);
				if (c != -1) {
					mexBuff.append(cbuf, 0, c);
				} else {
					break;
				}
			}
            
//            while (in.available() !=0) {
//                mexBuff.append(ins.readLine());
//            }

            in.close();
            ins.close();

        } catch (IOException e) {
            throw new ServletException(e);
        }

        MessageFormat mexResponse = new MessageFormat(mexBuff.toString());

        String resp = mexResponse.format(args);
        response.setContentLength(resp.length());
        response.setContentType("application/soap+xml; charset=utf-8");

        PrintWriter out = response.getWriter();
        out.println(resp);
        out.flush();
        out.close();
        System.out.println("MEX replied");
        System.out.println(resp);


    }

}
