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

package org.xmldap.ws.soap.headers.addressing.impl;

import nu.xom.Element;

import org.xmldap.exceptions.SerializationException;
import org.xmldap.ws.WSConstants;
import org.xmldap.xml.Serializable;

/**
 * Created by IntelliJ IDEA.
 * User: cmort
 * Date: Mar 16, 2006
 * Time: 5:24:49 PM
 * To change this template use File | Settings | File Templates.
 */
public class RelatesToHeader implements Serializable {


    private String relatesTo = null;

    public RelatesToHeader(String relatesTo) {
        this.relatesTo = relatesTo;
    }

    public String getRelatesTo() {
        return relatesTo;
    }

    public void setRelatesTo(String relatesTo) {
        this.relatesTo = relatesTo;
    }


    public String toXML() throws SerializationException {

        String xml = null;
        Element element = serialize();
        if (element != null) xml = element.toXML();
        return xml;

    }

    public Element serialize() throws SerializationException {

        Element serialized = null;
        if (relatesTo != null) {
            serialized = new Element(WSConstants.WSA_PREFIX + ":RelatesTo", WSConstants.WSA_NAMESPACE_04_08);
            serialized.appendChild(relatesTo);

        }
        return serialized;
    }
}
