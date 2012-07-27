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

package org.xmldap.rp;

import java.io.IOException;
import java.security.PrivateKey;

import nu.xom.Document;
import nu.xom.Element;
import nu.xom.Nodes;
import nu.xom.ParsingException;
import nu.xom.XPathContext;

import org.xmldap.crypto.CryptoUtils;
import org.xmldap.exceptions.CryptoException;
import org.xmldap.ws.WSConstants;
import org.xmldap.xml.XmlUtils;


public class DecryptUtil {

	Document xml = null;
//	PrivateKey key = null;
	
    static XPathContext context = null;


	public DecryptUtil(String encryptedXML) throws CryptoException {
		if (context == null) {
			context = new XPathContext();
		    context.addNamespace("enc", WSConstants.ENC_NAMESPACE);
		    context.addNamespace("dsig", WSConstants.DSIG_NAMESPACE);
		    context.addNamespace("wsse", WSConstants.WSSE_NAMESPACE_OASIS_10);
		}
		
        try {
            xml = XmlUtils.parse(encryptedXML);
        } catch (ParsingException e) {
            System.err.println("ERROR encrypted xml: " + encryptedXML);
//            System.err.println("ERROR PrivateKey: " + key.toString());

            throw new CryptoException("Error buidling a XOM Document out of encrypted token", e);
        } catch (IOException e) {
            System.err.println("ERROR encrypted xml: " + encryptedXML);
//            System.err.println("ERROR PrivateKey: " + key.toString());

            throw new CryptoException("Error buidling a XOM Document out of encrypted token", e);
        }
//		this.key = key;
	}
	
	public String decryptToken(PrivateKey key) throws CryptoException {
		return decryptToken( xml, key);
	}
	
	public boolean isEncrypted() {
		Nodes keys = xml.query("/enc:EncryptedData", context);
		return (keys.size() > 0);
	}
	
    private static String decryptToken(Document xml, PrivateKey key) throws CryptoException {

        String keyCipherText = getOneElement(xml, context, "/enc:EncryptedData/dsig:KeyInfo/enc:EncryptedKey/enc:CipherData/enc:CipherValue");

        String dataCipherText = getOneElement(xml, context, "/enc:EncryptedData/enc:CipherData/enc:CipherValue");

        byte[] clearTextKey = null;
        try {
            clearTextKey = CryptoUtils.decryptRSAOAEP(keyCipherText, key);
//            System.out.println("Key Length: " + clearTextKey.length);
        } catch (org.xmldap.exceptions.CryptoException e) {
            throw new CryptoException("Error using RSA to decrypt the AES Encryption Key", e);
        }
        
        try {
            byte[] cleartextBytes = CryptoUtils.decryptAESCBC(dataCipherText, clearTextKey);
            return new String(cleartextBytes);
        } catch (org.xmldap.exceptions.CryptoException e) {
            System.out.println("dataCipherText: " + dataCipherText);
            throw new CryptoException("Error performing AES decryption of token", e);
        }
    }

	/**
	 * @param xml
	 * @param context
	 * @param keyCipherText
	 * @return
	 * @throws CryptoException
	 */
	private static String getOneElement(Document xml, XPathContext context, String query) throws CryptoException {
		String value = null;
		Nodes keys = xml.query(query, context);
        if (keys.size() == 1) {
        	Element cipherValue = (Element) keys.get(0);
        	value = cipherValue.getValue();
        } else {
        	if (keys.size() < 1) {
        		throw new CryptoException("could not find '" + query + "' in assertion");
        	} else {
        		throw new CryptoException("found too many values (" + keys.size() + ") of '" + query + "' in assertion");
        	}
        }
		return value;
	}


}
