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

package org.xmldap.xmldsig;

import nu.xom.Attribute;
import nu.xom.Element;

import org.xmldap.exceptions.SerializationException;
import org.xmldap.ws.WSConstants;
import org.xmldap.xml.Serializable;

/**
 * Created by IntelliJ IDEA.
 * User: cmort
 * Date: Mar 21, 2006
 * Time: 11:28:00 AM
 * To change this template use File | Settings | File Templates.
 */
public class Signature implements Serializable {

    SignedInfo signedInfo = null;
    SignatureValue signatureValue = null;
    KeyInfo keyInfo = null;
    String Id = null;

    public Signature(SignedInfo signedInfo, SignatureValue signatureValue, KeyInfo keyInfo) {
        this.signedInfo = signedInfo;
        this.signatureValue = signatureValue;
        this.keyInfo = keyInfo;
    }

    public Signature(SignedInfo signedInfo, SignatureValue signatureValue, KeyInfo keyInfo, String Id) {
        this.signedInfo = signedInfo;
        this.signatureValue = signatureValue;
        this.keyInfo = keyInfo;
        this.Id = Id;
    }

    private Element getSignature() throws SerializationException {


        Element signature = new Element("dsig:Signature", "http://www.w3.org/2000/09/xmldsig#");
        if (Id != null) {
        	Attribute wsuId = new Attribute(WSConstants.WSU_PREFIX + ":Id", WSConstants.WSU_NAMESPACE, Id);
        	signature.addAttribute(wsuId);
        }
        try {
            signature.appendChild(signedInfo.serialize());
        } catch (SerializationException e) {
            e.printStackTrace();
            throw e;
        }
        try {
            signature.appendChild(signatureValue.serialize());
        } catch (SerializationException e) {
            e.printStackTrace();
            throw e;
        }
        try {
            signature.appendChild(keyInfo.serialize());
        } catch (SerializationException e) {
            e.printStackTrace();
            throw e;
        }
        return signature;


    }

    public String toXML() throws SerializationException {
        Element sigElm = getSignature();
        return sigElm.toXML();
    }

    public Element serialize() throws SerializationException {
        return getSignature();
    }
}
