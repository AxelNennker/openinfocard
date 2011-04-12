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

package org.xmldap.saml;

import nu.xom.Element;

import org.xmldap.exceptions.KeyStoreException;
import org.xmldap.exceptions.SerializationException;
import org.xmldap.util.KeystoreUtil;
import org.xmldap.ws.WSConstants;
import org.xmldap.xml.Serializable;
import org.xmldap.xmldsig.AsymmetricKeyInfo;
import org.xmldap.xmldsig.KeyInfo;


public class Subject implements Serializable {

	public static String HOLDER_OF_KEY = "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key";
	public static String BEARER = "urn:oasis:names:tc:SAML:1.0:cm:bearer";
	
    private String confirmationMethod = null;
    private KeyInfo keyInfo = null;

    public Subject(KeyInfo keyInfo, String confirmationMethod) {
        this.keyInfo = keyInfo;
        this.confirmationMethod = confirmationMethod;
    }

    public Subject(String confirmationMethod) {
        this.keyInfo = null;
        this.confirmationMethod = confirmationMethod;
    }

    private Element getSubject() throws SerializationException {

        Element subject = new Element(WSConstants.SAML_PREFIX + ":Subject", WSConstants.SAML11_NAMESPACE);
        Element subjectConfirmation = new Element(WSConstants.SAML_PREFIX + ":SubjectConfirmation", WSConstants.SAML11_NAMESPACE);
        Element confirmationMethodElm = new Element(WSConstants.SAML_PREFIX + ":ConfirmationMethod", WSConstants.SAML11_NAMESPACE);
        confirmationMethodElm.appendChild(confirmationMethod);
        subjectConfirmation.appendChild(confirmationMethodElm);
        if (keyInfo != null) {
        	subjectConfirmation.appendChild(keyInfo.serialize());
        }
        subject.appendChild(subjectConfirmation);
        return subject;

    }

    public String toXML() throws SerializationException {

        Element subject = serialize();
        return subject.toXML();
    }

    public Element serialize() throws SerializationException {

        return getSubject();

    }

    public static void main(String[] args) throws KeyStoreException {

        //Get my keystore
        KeystoreUtil keystore = null;
        keystore = new KeystoreUtil("/Users/cmort/build/infocard/conf/xmldap.jks", "storepassword");


        AsymmetricKeyInfo keyInfo = null;
		keyInfo = new AsymmetricKeyInfo(keystore.getCertificate("xmldap"));

        Subject subject = new Subject(keyInfo, Subject.HOLDER_OF_KEY);
        try {
            System.out.println(subject.toXML());
        } catch (SerializationException e) {
            e.printStackTrace();
        }


    }
}
