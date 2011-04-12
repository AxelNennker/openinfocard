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

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import nu.xom.Element;

import org.xmldap.exceptions.SerializationException;
import org.xmldap.util.Base64;

public class SimpleKeyInfo implements KeyInfo {

    private X509Certificate[] certChain;

    public SimpleKeyInfo(X509Certificate cert) {
    	certChain = new X509Certificate[]{cert};
    }

    public SimpleKeyInfo(X509Certificate[] certChain) {
    	if (certChain == null) {
    		throw new IllegalArgumentException("SimpleKeyInfo: certCain == null");
    	}
    	if (certChain.length == 0) {
    		throw new IllegalArgumentException("SimpleKeyInfo: certCain.size() == 0");
    	}
    	this.certChain = certChain;
    }

    private Element getKeyInfo() throws SerializationException {

        //TODO - extract constants!
        Element keyInfo = new Element("dsig:KeyInfo", "http://www.w3.org/2000/09/xmldsig#");

        Element x509Data = new Element("dsig:X509Data", "http://www.w3.org/2000/09/xmldsig#");

        for (int i=0; i<certChain.length; i++) {
        	X509Certificate cert = certChain[i];
        	Element x509Certificate = new Element("dsig:X509Certificate", "http://www.w3.org/2000/09/xmldsig#");

	        try {
	            x509Certificate.appendChild(Base64.encodeBytesNoBreaks(cert.getEncoded()));
	        } catch (CertificateEncodingException e) {
	            throw new SerializationException("Error getting Cert for keyinfo", e);
	        }

	        x509Data.appendChild(x509Certificate);
        }
        keyInfo.appendChild(x509Data);
        return keyInfo;


    }

    public String toXML() throws SerializationException {
        Element keyInfo = serialize();
        return keyInfo.toXML();
    }

    public Element serialize() throws SerializationException {
        return getKeyInfo();
    }
}
