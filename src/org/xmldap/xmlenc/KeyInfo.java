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

package org.xmldap.xmlenc;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import nu.xom.Attribute;
import nu.xom.Element;

import org.xmldap.crypto.CryptoUtils;
import org.xmldap.exceptions.KeyStoreException;
import org.xmldap.exceptions.SerializationException;
import org.xmldap.util.KeystoreUtil;
import org.xmldap.ws.WSConstants;
import org.xmldap.xml.Serializable;

/**
 * <AsymmetricKeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
 * <e:EncryptedKey xmlns:e="http://www.w3.org/2001/04/xmlenc#">
 * <e:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p">
 * <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
 * </e:EncryptionMethod>
 * <AsymmetricKeyInfo>
 * <o:SecurityTokenReference xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
 * <o:KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-soap-mes sage-security-1.1#ThumbprintSHA1" EncodingType="http://docs.oasis-open.org/ws s/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">
 * +PYbznDaB/dlhjIfqCQ458E72wA=
 * </o:KeyIdentifier>
 * </o:SecurityTokenReference>
 * </AsymmetricKeyInfo>
 * <e:CipherData>
 * <e:CipherValue> Eq9UhAJ8C9K5l4Mr3qmgX0XnyL1ChKs2PqMj0Sk6snw/IRNtXqLzmgbj2Vd3vFA4Vx1hileSTyqc1 kAsskqpqBc4bMHT61w1f0NxU10HDor0DlNVcVDm/AfLcyLqEP+oh05B+5ntVIJzL8Ro3typF0eoSm 3S6UnINOHIjHaVWyg= </e:CipherValue>
 * </e:CipherData>
 * </e:EncryptedKey>
 * </AsymmetricKeyInfo>
 */

public class KeyInfo implements Serializable {

    private X509Certificate cert = null;
    //TODO - Make this random!
    private byte[] secretKey;

    public KeyInfo(X509Certificate cert, byte[] secretKey) {
        this.cert = cert;
        this.secretKey = secretKey;

    }

    public String toXML() throws SerializationException {

        Element keyInfo = serialize();
        return keyInfo.toXML();

    }

    public Element serialize() throws SerializationException {

       Element keyInfo = new Element(WSConstants.DSIG_PREFIX + ":KeyInfo", WSConstants.DSIG_NAMESPACE);

        Element encryptedKey = new Element(WSConstants.ENC_PREFIX + ":EncryptedKey", WSConstants.ENC_NAMESPACE);
        Element encryptionMethod = new Element(WSConstants.ENC_PREFIX + ":EncryptionMethod", WSConstants.ENC_NAMESPACE);
        Attribute encMethAlg = new Attribute("Algorithm", "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p");
        encryptionMethod.addAttribute(encMethAlg);
        Element digestMethod = new Element(WSConstants.DSIG_PREFIX + ":DigestMethod", WSConstants.DSIG_NAMESPACE);
        Attribute digMethAlg = new Attribute("Algorithm", "http://www.w3.org/2000/09/xmldsig#sha1");
        digestMethod.addAttribute(digMethAlg);
        encryptionMethod.appendChild(digestMethod);
        encryptedKey.appendChild(encryptionMethod);


        Element subKeyInfo = new Element(WSConstants.DSIG_PREFIX + ":KeyInfo", WSConstants.DSIG_NAMESPACE);
        Element securityTokenReference = new Element(WSConstants.WSSE_PREFIX + ":SecurityTokenReference", WSConstants.WSSE_NAMESPACE_OASIS_10);
        Element keyIdentifier = new Element(WSConstants.WSSE_PREFIX + ":KeyIdentifier", WSConstants.WSSE_NAMESPACE_OASIS_10);
        Attribute valueType = new Attribute("ValueType", "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1");
        Attribute encodingType = new Attribute("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
        keyIdentifier.addAttribute(valueType);
        keyIdentifier.addAttribute(encodingType);
//        PublicKey key = cert.getPublicKey();

        String fingerPrint = "";
        try {
//            fingerPrint = CryptoUtils.digest(key.getEncoded());
        	fingerPrint = CryptoUtils.digest(cert.getEncoded(), "SHA");
        } catch (org.xmldap.exceptions.CryptoException e) {
            throw new SerializationException(e);
        } catch (CertificateEncodingException e) {
        	throw new SerializationException(e);
		}

        keyIdentifier.appendChild(fingerPrint);
        securityTokenReference.appendChild(keyIdentifier);
        subKeyInfo.appendChild(securityTokenReference);
        encryptedKey.appendChild(subKeyInfo);

        Element cipherData = new Element(WSConstants.ENC_PREFIX + ":CipherData", WSConstants.ENC_NAMESPACE);
        Element cipherValue = new Element(WSConstants.ENC_PREFIX + ":CipherValue", WSConstants.ENC_NAMESPACE);

        try {
        	RSAPublicKey rsaPublicKey = (RSAPublicKey)cert.getPublicKey();
            String cipherText = CryptoUtils.rsaoaepEncrypt(secretKey, rsaPublicKey);
            cipherValue.appendChild(cipherText);
        } catch (org.xmldap.exceptions.CryptoException e) {
            throw new SerializationException(e);
        }
        cipherData.appendChild(cipherValue);
        encryptedKey.appendChild(cipherData);

        keyInfo.appendChild(encryptedKey);
        return keyInfo;


    }


    public static void main(String[] args) {

    	KeyInfo keyInfo = null;
        try {
        	KeystoreUtil keystore = null;
            keystore = new KeystoreUtil("/Users/cmort/build/infocard/conf/xmldap.jks", "storepassword");
            keyInfo = new KeyInfo(keystore.getCertificate("identityblog"), "test".getBytes());
        } catch (KeyStoreException e) {
            e.printStackTrace();
            return;
        }

        try {
            System.out.println(keyInfo.toXML());
        } catch (SerializationException e) {
            e.printStackTrace();
        }
    }
}
