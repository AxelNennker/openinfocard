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

package org.xmldap.ws.soap.impl;

import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import nu.xom.Builder;
import nu.xom.Document;
import nu.xom.Element;
import nu.xom.ParsingException;

import org.xmldap.exceptions.MessageException;
import org.xmldap.exceptions.SerializationException;
import org.xmldap.ws.WSConstants;
import org.xmldap.ws.soap.Message;
import org.xmldap.xml.Serializable;


public class MessageImpl implements Message {


    private Vector headers = new Vector();
    private Element body;
    private String soapNamespace = WSConstants.SOAP12_NAMESPACE;


    public MessageImpl() {
    }

    public MessageImpl(String body) throws MessageException {

        setBody(body);

    }

    public MessageImpl(Element body) {
        this.body = body;
    }

    public void setSoapNamespace(String soapNamespace) {
        this.soapNamespace = soapNamespace;
    }

    public void addHeader(Serializable header) {

        headers.add(header);

    }

    public void addHeader(String header) throws MessageException {

        Element headerElement = createFragment(header);
        headers.add(headerElement);

    }

    public void addHeaders(List headerList) {

        Iterator listIter = headerList.iterator();
        while (listIter.hasNext()) {

            Element thisHeader = (Element) listIter.next();
            headers.add(thisHeader);

        }

    }

    public void setBody(Element body) {

        this.body = body;

    }


    public void setBody(String xml) throws MessageException {

        this.body = createFragment(xml);

    }


    private Element createFragment(String xml) throws MessageException {

        Element fragment = null;
        Builder parser = new Builder();
        Document bodyDoc = null;
        try {
            bodyDoc = parser.build(xml, "");
            fragment = new Element(bodyDoc.getRootElement());
            fragment.detach();
        } catch (ParsingException e) {
            throw new MessageException("Unable to parse XML fragment", e);
        } catch (IOException e) {
            throw new MessageException("Unable to parse XML fragment", e);
        }
        return fragment;
    }


    public Element serialize() throws SerializationException {

        //TODO - find something better than this to do here.
        if (body == null) return null;

        if (body.getParent() != null) body.detach();

        //Create the envelope
        Element soapEnvelope = new Element(WSConstants.SOAP_PREFIX + ":Envelope", soapNamespace);

        //Add the headers
        if (!headers.isEmpty()) {
            Element headerElement = new Element(WSConstants.SOAP_PREFIX + ":Header", soapNamespace);
            Iterator headerIter = headers.iterator();
            while (headerIter.hasNext()) {
                Serializable thisHeader = (Serializable) headerIter.next();
                Element thisHeaderElement = thisHeader.serialize();
                headerElement.appendChild(thisHeaderElement);
            }
            soapEnvelope.appendChild(headerElement);
        }

        //Add the body
        Element bodyElement = new Element(WSConstants.SOAP_PREFIX + ":Body", soapNamespace);
        bodyElement.appendChild(body);
        soapEnvelope.appendChild(bodyElement);

        return soapEnvelope;

    }

    public String toXML() throws SerializationException {

        Element message = serialize();
        return message.toXML();

    }


}
