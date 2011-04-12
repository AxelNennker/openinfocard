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
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.StringRequestEntity;
import org.apache.commons.httpclient.protocol.Protocol;

import com.sun.slamd.example.BlindTrustSocketFactory;

public class HTTPClient {


    private HttpClient httpClient;

    public HTTPClient() {

        init();

    }

    private void init() {

        BlindTrustSocketFactory blindTrust = null;
        try {
            blindTrust = new BlindTrustSocketFactory();
        } catch (Exception e) {

            //TODO - something

        }

        Protocol.registerProtocol("https", new Protocol("https", blindTrust, 443));

        httpClient = new HttpClient();

    }


    public String get(String url) {

        GetMethod get = new GetMethod(url);

        String response = "";

        try {
            int statusCode = 0;
            statusCode = httpClient.executeMethod(get);

            StringBuffer responseBuffer = new StringBuffer();
            InputStreamReader stream = new InputStreamReader(get.getResponseBodyAsStream(), "UTF-8");

            int l;
            char[] buffer = new char[1024];
            while ((l = stream.read(buffer)) != -1) {
                responseBuffer.append(buffer);
            }

            response = responseBuffer.toString();

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        } finally {
            get.releaseConnection();
        }

        return response;


    }


    public String post(String url, String message) {

        StringBuffer responseBuffer = new StringBuffer();
        PostMethod post = new PostMethod(url);
        post.setRequestEntity(new StringRequestEntity(message));
        post.setRequestHeader("Content-type", "application/x-www-form-urlencoded;");

        try {
            int statusCode = 0;
            statusCode = httpClient.executeMethod(post);

            InputStreamReader stream = new InputStreamReader(post.getResponseBodyAsStream(), "UTF-8");

            int l;
            char[] buffer = new char[1024];
            while ((l = stream.read(buffer)) != -1) {
                responseBuffer.append(buffer);
            }


        } catch (Exception e) {

            return e.getMessage();

        } finally {
            post.releaseConnection();
        }

        return responseBuffer.toString();
    }

}
