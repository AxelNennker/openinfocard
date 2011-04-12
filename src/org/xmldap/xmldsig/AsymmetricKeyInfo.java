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

import java.math.BigInteger;
import java.security.Principal;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import nu.xom.Element;

import org.xmldap.exceptions.SerializationException;
import org.xmldap.util.Base64;
import org.xmldap.ws.WSConstants;


public class AsymmetricKeyInfo implements KeyInfo {


    //private KeystoreUtil keystoreUtil = null;
    X509Certificate cert = null;

    public AsymmetricKeyInfo(X509Certificate cert) {
        this.cert = cert;
    }

    private Element getKeyInfo() throws SerializationException {

        Element keyInfo = new Element("dsig:KeyInfo", WSConstants.DSIG_NAMESPACE);
        Element keyName = new Element("dsig:KeyName", WSConstants.DSIG_NAMESPACE);
        Element keyValue = new Element("dsig:KeyValue", WSConstants.DSIG_NAMESPACE);

        //TODO - based on key
        Element rsaKeyValue = new Element("dsig:RSAKeyValue", WSConstants.DSIG_NAMESPACE);
        Element modulus = new Element("dsig:Modulus", WSConstants.DSIG_NAMESPACE);
        Element exponent = new Element("dsig:Exponent", WSConstants.DSIG_NAMESPACE);
        Element x509Data = new Element("dsig:X509Data", WSConstants.DSIG_NAMESPACE);
        Element x509Certificate = new Element("dsig:X509Certificate", WSConstants.DSIG_NAMESPACE);


        try {
            //Populate the cert element
            x509Certificate.appendChild(Base64.encodeBytesNoBreaks(cert.getEncoded()));

            //populate the name element
            Principal dn = cert.getSubjectDN();
            keyName.appendChild("Public Key for " + dn.toString());

            //populate modulus
            RSAPublicKey key = (RSAPublicKey) cert.getPublicKey();
            BigInteger mod = key.getModulus();
            byte[] modArray = mod.toByteArray();
            modulus.appendChild(Base64.encodeBytesNoBreaks(modArray));
            rsaKeyValue.appendChild(modulus);

            //populate exponent
            BigInteger exp = key.getPublicExponent();
            byte[] expArray = exp.toByteArray();
            exponent.appendChild(Base64.encodeBytesNoBreaks(expArray));
            rsaKeyValue.appendChild(exponent);

        } catch (ClassCastException e) {

            throw new SerializationException("Only RSA Public Keys are supported at this time", e);

         } catch (CertificateEncodingException e) {
            throw new SerializationException(e);
        }

        // build the KeyInfoElement
        keyValue.appendChild(rsaKeyValue);
        x509Data.appendChild(x509Certificate);
        keyInfo.appendChild(keyName);
        keyInfo.appendChild(keyValue);
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
