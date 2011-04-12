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

package org.xmldap.transport;

import java.io.InputStreamReader;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.StringRequestEntity;
import org.apache.commons.httpclient.protocol.Protocol;
import org.xmldap.exceptions.SerializationException;
import org.xmldap.ws.soap.Message;

import com.sun.slamd.example.BlindTrustSocketFactory;

public class HTTPTransport implements SOAPTransport {


    private HttpClient httpClient;
    private String endpoint;

    public HTTPTransport(String endpoint) throws TransportException {

        init(endpoint, false);

    }

    public HTTPTransport(String endpoint, boolean useBlindTrust) throws TransportException {

        init(endpoint, useBlindTrust);

    }

    public void init(String endpoint, boolean useBlindTrust) throws TransportException {

        this.endpoint = endpoint;

        if (useBlindTrust) {

            BlindTrustSocketFactory blindTrust;
            try {
                blindTrust = new BlindTrustSocketFactory();
            } catch (Exception e) {
                throw new TransportException("Error establishing blind trust", e);
            }

            Protocol.registerProtocol("https", new Protocol("https", blindTrust, 443));

        }

        httpClient = new HttpClient();

    }


    public void send(Message messageImpl) throws TransportException {

        try {
            send(messageImpl.toXML());
        } catch (SerializationException e) {
            throw new TransportException(e);
        }

    }


    public void send(String message) throws TransportException {

        PostMethod post = new PostMethod(endpoint);

        post.setRequestEntity(new StringRequestEntity(message));
        post.setRequestHeader("Content-type", "text/xml; charset=utf-8");
        //TODO - support SOAPAction
        post.setRequestHeader("SOAPAction", "\"\"");


        try {
            int statusCode = 0;
            statusCode = httpClient.executeMethod(post);

            StringBuffer responseBuffer = new StringBuffer();
            InputStreamReader stream = new InputStreamReader(post.getResponseBodyAsStream(), "UTF-8");

            int l;
            char[] buffer = new char[1024];
            while ((l = stream.read(buffer)) != -1) {
                responseBuffer.append(buffer);
            }


            String responseXML = responseBuffer.toString();

            if (statusCode == 200) {

                System.out.println("RESPONSE\n" + responseXML);

            } else {

                System.out.println("FAULT\n" + responseXML);
            }


        } catch (Exception e) {

            throw new TransportException("Error connecting to service: " + e.toString(), e);

        } finally {
            post.releaseConnection();
        }

    }

    public void sendAsyncPoll(Message messageImpl) throws TransportException {
        //To change body of implemented methods use File | Settings | File Templates.
    }

    public void sendAsyncCallback(Message messageImpl) throws TransportException {
        //To change body of implemented methods use File | Settings | File Templates.
    }

}
