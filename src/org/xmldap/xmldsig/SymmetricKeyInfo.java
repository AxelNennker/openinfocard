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
 *     * Neither the name of the University of California, Berkeley nor the
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
import org.xmldap.crypto.CryptoUtils;
import org.xmldap.exceptions.KeyStoreException;
import org.xmldap.exceptions.SerializationException;
import org.xmldap.util.KeystoreUtil;
import org.xmldap.ws.WSConstants;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * Created by IntelliJ IDEA.
 * User: cmort
 * Date: Mar 26, 2006
 * Time: 3:19:12 PM
 * To change this template use File | Settings | File Templates.
 */
public class SymmetricKeyInfo implements KeyInfo {

    private byte[] secretKey;
    private X509Certificate cert;
    private KeystoreUtil keystore;
    private String alias;

    public SymmetricKeyInfo(X509Certificate cert, byte[] secretKey) {
        this.secretKey = secretKey;
        this.cert = cert;
    }

    public SymmetricKeyInfo(KeystoreUtil keystore, String alias, byte[] secretKey) {
        this.keystore = keystore;
        this.alias = alias;
        this.secretKey = secretKey;
    }

    public byte[] getSecretKey() {
        return secretKey;
    }


    public Element getEmphemeralSymmetricKeyInfo() throws SerializationException {

        try {

            if ((cert == null) && (alias != null)) cert = keystore.getCertificate(alias);

        } catch (org.xmldap.exceptions.KeyStoreException e) {

            throw new SerializationException("Error accessing keystore", e);

        }

        if (cert == null) throw new SerializationException("Could not load cert with alias: " + alias);


        Element keyInfo = new Element(WSConstants.DSIG_PREFIX + ":KeyInfo", WSConstants.DSIG_NAMESPACE);

        Element encryptedKey = new Element(WSConstants.ENC_PREFIX + ":EncryptedKey", WSConstants.ENC_NAMESPACE);
        Element encryptionMethod = new Element(WSConstants.ENC_PREFIX + ":EncryptionMethod", WSConstants.ENC_NAMESPACE);
        Attribute encMethAlg = new Attribute("Algorithm", "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p");
        encryptionMethod.addAttribute(encMethAlg);
        encryptedKey.appendChild(encryptionMethod);

        Element subKeyInfo = new Element(WSConstants.DSIG_PREFIX + ":KeyInfo", WSConstants.DSIG_NAMESPACE);
        Element x509Data = new Element(WSConstants.DSIG_PREFIX + ":X509Data", WSConstants.DSIG_NAMESPACE);
        Element keyIdentifier = new Element(WSConstants.WSSE_PREFIX + ":KeyIdentifier", WSConstants.WSSE_NAMESPACE_OASIS_10);
        Attribute valueType = new Attribute("ValueType", "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1");
        Attribute encodingType = new Attribute("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
        keyIdentifier.addAttribute(valueType);
        keyIdentifier.addAttribute(encodingType);
        PublicKey key = cert.getPublicKey();

        System.out.println(cert.toString());

        String fingerPrint = "";
        try {
            fingerPrint = CryptoUtils.digest(key.getEncoded());

        } catch (org.xmldap.exceptions.CryptoException e) {
            e.printStackTrace();
        }

        keyIdentifier.appendChild(fingerPrint);
        x509Data.appendChild(keyIdentifier);

        subKeyInfo.appendChild(x509Data);
        encryptedKey.appendChild(subKeyInfo);

        Element cipherData = new Element(WSConstants.ENC_PREFIX + ":CipherData", WSConstants.ENC_NAMESPACE);
        Element cipherValue = new Element(WSConstants.ENC_PREFIX + ":CipherValue", WSConstants.ENC_NAMESPACE);

        try {
            String cipherText = CryptoUtils.rsaoaepEncrypt(secretKey, cert);
            cipherValue.appendChild(cipherText);
        } catch (org.xmldap.exceptions.CryptoException e) {
            e.printStackTrace();
        }
        cipherData.appendChild(cipherValue);
        encryptedKey.appendChild(cipherData);

        keyInfo.appendChild(encryptedKey);
        return keyInfo;

    }


    public String toXML() throws SerializationException {

        Element keyInfo = serialize();
        return keyInfo.toXML();

    }

    public Element serialize() throws SerializationException {

        return getEmphemeralSymmetricKeyInfo();


    }


    public static void main(String[] args) {


        KeystoreUtil keystore = null;
        try {
            keystore = new KeystoreUtil("/Users/cmort/build/infocard/conf/xmldap.jks", "storepassword");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        SymmetricKeyInfo keyInfo = null;
        try {
            keyInfo = new SymmetricKeyInfo(keystore, "xmldap", CryptoUtils.genKey(128));
        } catch (org.xmldap.exceptions.CryptoException e) {
            e.printStackTrace();
        }


        try {
            System.out.println(keyInfo.toXML());
        } catch (SerializationException e) {
            e.printStackTrace();
        }
    }
}
