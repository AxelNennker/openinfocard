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

import java.security.cert.X509Certificate;

import nu.xom.Attribute;
import nu.xom.Element;

import org.xmldap.crypto.CryptoUtils;
import org.xmldap.exceptions.KeyStoreException;
import org.xmldap.exceptions.SerializationException;
import org.xmldap.util.KeystoreUtil;
import org.xmldap.ws.WSConstants;
import org.xmldap.xml.Serializable;

/*
  <enc:EncryptedData Type="http://www.w3.org/2001/04/xmlenc#Element" xmlns:enc= "http://www.w3.org/2001/04/xmlenc#">

    <enc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc" />

    <AsymmetricKeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <e:EncryptedKey xmlns:e="http://www.w3.org/2001/04/xmlenc#">
            <e:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p">
                <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
            </e:EncryptionMethod>
            <AsymmetricKeyInfo>
                <o:SecurityTokenReference xmlns:o="http://docs.oasis-open.org/wss/2004/01/oas is-200401-wss-wssecurity-secext-1.0.xsd">
                    <o:KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-soap-mes sage-security-1.1#ThumbprintSHA1" EncodingType="http://docs.oasis-open.org/ws s/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">
                        +PYbznDaB/dlhjIfqCQ458E72wA=
                    </o:KeyIdentifier>
                </o:SecurityTokenReference>
            </AsymmetricKeyInfo>
            <e:CipherData>
                <e:CipherValue> Eq9UhAJ8C9K5l4Mr3qmgX0XnyL1ChKs2PqMj0Sk6snw/IRNtXqLzmgbj2Vd3vFA4Vx1hileSTyqc1 kAsskqpqBc4bMHT61w1f0NxU10HDor0DlNVcVDm/AfLcyLqEP+oh05B+5ntVIJzL8Ro3typF0eoSm 3S6UnINOHIjHaVWyg= </e:CipherValue>
            </e:CipherData>
        </e:EncryptedKey>
    </AsymmetricKeyInfo>

    <enc:CipherData>
        <enc:CipherValue> ...= </enc:CipherValue>
    </enc:CipherData>

</enc:EncryptedData>

/enc:EncryptedData/dsig:KeyInfo/enc:EncryptedKey/enc:CipherData
/enc:EncryptedData/enc:CipherData/enc:CipherValue

*/


public class EncryptedData implements Serializable {

    private String METHOD = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
    //private String METHOD = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";

    //TODO - Make this random!
    private byte[] secretKey;
    private KeyInfo keyInfo;
    private String data;

    public EncryptedData(X509Certificate certForEncryption) {

        //TODO - remove code copy
        try {
            secretKey = CryptoUtils.genKey(256);
        } catch (org.xmldap.exceptions.CryptoException e) {
            e.printStackTrace();
        }

        keyInfo = new KeyInfo(certForEncryption, secretKey);

    }

    public void setData(String data) {
        this.data = data;
    }

    public String toXML() throws SerializationException {

        Element encryptedMethod = serialize();
        return encryptedMethod.toXML();

    }


    public Element serialize() throws SerializationException {

        Element encryptedData = new Element(WSConstants.ENC_PREFIX + ":EncryptedData", WSConstants.ENC_NAMESPACE);
        Attribute type = new Attribute("Type", "http://www.w3.org/2001/04/xmlenc#Element");
        encryptedData.addAttribute(type);

        Element encryptionMethod = new Element(WSConstants.ENC_PREFIX + ":EncryptionMethod", WSConstants.ENC_NAMESPACE);
        Attribute encAlg = new Attribute("Algorithm", METHOD);
        encryptionMethod.addAttribute(encAlg);
        encryptedData.appendChild(encryptionMethod);

        encryptedData.appendChild(keyInfo.serialize());


        Element cipherData = new Element(WSConstants.ENC_PREFIX + ":CipherData", WSConstants.ENC_NAMESPACE);
        Element cipherValue = new Element(WSConstants.ENC_PREFIX + ":CipherValue", WSConstants.ENC_NAMESPACE);

        String cipherText = null;
        try {
          cipherText = CryptoUtils.encryptAESCBC(data, secretKey);
        } catch (org.xmldap.exceptions.CryptoException e) {
            e.printStackTrace();
        }
        cipherValue.appendChild(cipherText);
        cipherData.appendChild(cipherValue);
        encryptedData.appendChild(cipherData);

        return encryptedData;

    }

    public static void main(String[] args) {

    	EncryptedData encrypted = null;
        try {
            KeystoreUtil keystore = new KeystoreUtil("/Users/cmort/build/infocard/conf/xmldap.jks", "storepassword");
            encrypted = new EncryptedData(keystore.getCertificate("identityblog"));
        } catch (KeyStoreException e) {
            e.printStackTrace();
            return;
        }

        encrypted.setData("Encrypt Me123456");

        try {
            System.out.println(encrypted.toXML());
        } catch (SerializationException e) {
            e.printStackTrace();
        }


    }


}
