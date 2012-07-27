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

package org.xmldap.infocard.roaming;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

import nu.xom.Builder;
import nu.xom.Document;
import nu.xom.Element;
import nu.xom.Nodes;
import nu.xom.ParsingException;
import nu.xom.XPathContext;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESLightEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.xmldap.crypto.CryptoUtils;
import org.xmldap.crypto.EncryptedStoreKeys;
import org.xmldap.exceptions.CryptoException;
import org.xmldap.exceptions.SerializationException;
import org.xmldap.util.Base64;
import org.xmldap.util.XmlFileUtil;
import org.xmldap.ws.WSConstants;
import org.xmldap.xml.Canonicalizable;
import org.xmldap.xml.XmlUtils;


public class EncryptedStore {

    private static byte[] bom = {(byte)0xEF, (byte)0xBB, (byte)0xBF};

    String roamingStoreString = null;
    String encryptedStoreString = null;
    byte[] salt = null;
    
    public String getRoamingStoreString() {
    	return roamingStoreString;
    }
    
    public String getEncryptedStoreString() {
    	return encryptedStoreString;
    }
    
//    public EncryptedStore(String encryptedStoreString, String password) throws CryptoException, ParsingException{
//
//        int index = encryptedStoreString.indexOf("<?xml");
//        String data = encryptedStoreString.substring(index);
//
//        Builder parser = new Builder();
//        Document encryptedStore = null;
//        try {
//            encryptedStore = parser.build(data, "");
//        } catch (IOException e) {
//            e.printStackTrace();
//            throw new ParsingException("Error parsing", e);
//        }
//
//        roamingStore = decryptStore(encryptedStore, password);
//
//    }

    public String getParsedRoamingStore() {
        //let's make a doc
        Builder parser = new Builder();
        Document roamingStore = null;
        try {
            roamingStore = parser.build(roamingStoreString, "");
        } catch (ParsingException e) {
            e.printStackTrace();

        } catch (IOException e) {
            e.printStackTrace();
        }

        return roamingStore.toXML();
    }
    
    public EncryptedStore(byte[] bytes, String password) throws CryptoException, ParsingException{
    	String encoding = XmlFileUtil.getEncoding(bytes);
    	int offset = XmlFileUtil.getBomLength(bytes);
    	roamingStoreString = decryptStore(encoding, bytes, offset, password);
    }
    
    public EncryptedStore(InputStream encryptedStoreStream, String password) throws CryptoException, ParsingException{
    	String encoding = null;
    	try {
			encoding = XmlFileUtil.getEncoding(encryptedStoreStream);
		} catch (IOException e) {
			throw new CryptoException(e);
		}
    	roamingStoreString = decryptStore(encoding, encryptedStoreStream, password);
    }


    public EncryptedStore(String encoding, InputStream encryptedStoreStream, String password) throws CryptoException, ParsingException{
    	roamingStoreString = decryptStore(encoding, encryptedStoreStream, password);
    }


    private String decryptStore(String encoding, byte[] bytes, int offset, String password) throws CryptoException, ParsingException{
        Document encryptedStore = null;
        try {
        	ByteArrayInputStream bais = new ByteArrayInputStream(bytes, offset, bytes.length);
            encryptedStore = XmlFileUtil.readXml(encoding, bais);
        } catch (IOException e) {
            throw new ParsingException("Error parsing EncryptedStore", e);
        }

        return decryptStore(encryptedStore, password);
    }


    private String decryptStore(String encoding, InputStream encryptedStoreStream, String password) throws CryptoException, ParsingException{

        Document encryptedStore = null;
        try {
            encryptedStore = XmlFileUtil.readXml(encoding, encryptedStoreStream);
        } catch (IOException e) {
            throw new ParsingException("Error parsing EncryptedStore", e);
        }

        return decryptStore(encryptedStore, password);
    }

    private static String decryptStore(Document encryptedStore, String password) throws CryptoException, ParsingException{



        XPathContext context = new XPathContext();
        context.addNamespace("id","http://schemas.xmlsoap.org/ws/2005/05/identity");
        context.addNamespace("enc","http://www.w3.org/2001/04/xmlenc#");

        Nodes saltNodes = encryptedStore.query("//id:StoreSalt",context);
        Element saltElm = (Element) saltNodes.get(0);

        Nodes cipherValueNodes = encryptedStore.query("//enc:CipherValue",context);
        Element cipherValueElm = (Element) cipherValueNodes.get(0);


        return decrypt(cipherValueElm.getValue(), password, saltElm.getValue());


    }


    private static String decrypt(String cipherText, String password, String salt) throws CryptoException{


        EncryptedStoreKeys keys = new EncryptedStoreKeys(password,Base64.decode(salt));

        byte[] cipherBytes = Base64.decode(cipherText);
        byte[] iv = new byte[16];
        byte[] integrityCode = new byte[32];
        byte[] data = new byte[cipherBytes.length - iv.length - integrityCode.length];
        byte[] ivPlusData = new byte[cipherBytes.length  - integrityCode.length];

        //Copy IV
        System.arraycopy(cipherBytes, 0, iv, 0, 16);

        //Copy integrityCode
        System.arraycopy(cipherBytes, 16, integrityCode, 0, 32);

        //Copy data
        System.arraycopy(cipherBytes, 48, data, 0, data.length);

        //Copy iv and data
        System.arraycopy(iv, 0, ivPlusData, 0, 16);
        System.arraycopy(data, 0, ivPlusData, 16, data.length);


        byte[] clearText = CryptoUtils.decryptAESCBC(Base64.encodeBytesNoBreaks(ivPlusData), keys.getEncryptionKey());

        byte[] hashedIntegrityCode;
        try {
        	hashedIntegrityCode = getHashedIntegrityCode(iv, keys.getIntegrityKey(),  clearText);
        } catch (NoSuchAlgorithmException e) {
        	throw new CryptoException("NoSuchAlgorithmException while Parsing Roaming Store", e);
        } catch (UnsupportedEncodingException e) {
        	throw new CryptoException("UnsupportedEncodingException while Error Parsing Roaming Store", e);
		}
        boolean valid = Arrays.equals(integrityCode, hashedIntegrityCode);
        if (!valid) {
            throw new CryptoException("The cardstore did not pass the integrity check - it may have been tampered with");
        }

        //get rid of the byte order mark
        int start = 0;
        while (start < clearText.length && clearText[start] != '<') start++;
        return new String(clearText, start, clearText.length-start);

    }

    public void toStream(OutputStream output) throws IOException {
        Element encryptedStore = new Element("EncryptedStore", WSConstants.INFOCARD_NAMESPACE);
        Element storeSalt = new Element("StoreSalt", WSConstants.INFOCARD_NAMESPACE);

        storeSalt.appendChild(Base64.encodeBytesNoBreaks(salt));
        encryptedStore.appendChild(storeSalt);
        Element encryptedData = new Element("EncryptedData", WSConstants.ENC_NAMESPACE);
        Element cipherData = new Element("CipherData", WSConstants.ENC_NAMESPACE);
        Element cipherValue = new Element("CipherValue", WSConstants.ENC_NAMESPACE);

        encryptedStore.appendChild(encryptedData);
        encryptedData.appendChild(cipherData);
        cipherData.appendChild(cipherValue);
        cipherValue.appendChild(getEncryptedStoreString());

        try {
            output.write(bom);
            output.write("<?xml version=\"1.0\" encoding=\"utf-8\"?>".getBytes("UTF8"));
            byte[] bytes = XmlUtils.canonicalize(encryptedStore, Canonicalizable.EXCLUSIVE_CANONICAL_XML);
            output.write(bytes);
//            output.write(encryptedStore.toXML().getBytes("UTF8"));

        } catch (IOException e) {
            e.printStackTrace();
            throw e;
        }

    }

    public EncryptedStore(RoamingStore roamingStore, String password) throws CryptoException{
        Random rand = new Random();
        byte[] salt = new byte[16];
        rand.nextBytes(salt);
        byte[] iv = new byte[16];
        rand.nextBytes(iv);
    	init(roamingStore, password, salt, iv);
    }

    public EncryptedStore(RoamingStore roamingStore, String password, byte[] salt, byte[] iv) throws CryptoException{
    	init(roamingStore, password, salt, iv);
    }

    void init(RoamingStore roamingStore, String password, byte[] salt, byte[] iv) throws CryptoException{

    	this.salt = salt;
        EncryptedStoreKeys keys = new EncryptedStoreKeys(password,salt);

        try {
        	roamingStoreString = roamingStore.toXML();
        } catch (SerializationException e) {
            throw new CryptoException("Error getting RoamingStore XML", e);
        }
        byte[] integrityCode;
        try {
        	integrityCode= getHashedIntegrityCode(iv, keys.getIntegrityKey(),roamingStoreString.getBytes());
        } catch (NoSuchAlgorithmException e) {
        	throw new CryptoException("NoSuchAlgorithmException while getting getHashedIntegrityCode", e);
        } catch (UnsupportedEncodingException e) {
        	throw new CryptoException("UnsupportedEncodingException while getting getHashedIntegrityCode", e);
		}

        ByteArrayOutputStream dataBytes = new ByteArrayOutputStream();
        try {
            dataBytes.write(bom);
            dataBytes.write(roamingStoreString.getBytes("UTF8"));
        } catch (IOException e) {
        	throw new CryptoException("IOException while writing to ByteArrayOutputStream", e);
        }


        //encrypt
        AESLightEngine aes = new AESLightEngine();
        CBCBlockCipher cbc = new CBCBlockCipher(aes);
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(cbc);
        KeyParameter key = new KeyParameter(keys.getEncryptionKey());
        ParametersWithIV paramWithIV = new ParametersWithIV(key, iv);
        byte inputBuffer[] = new byte[16];
        byte outputBuffer[] = new byte[16];
        int bytesProcessed = 0;
        cipher.init(true, paramWithIV);
        int bytesRead = 0;
        ByteArrayInputStream inputStream = new ByteArrayInputStream(dataBytes.toByteArray());
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
			while((bytesRead = inputStream.read(inputBuffer)) > 0)  {
				int outsize = cipher.getUpdateOutputSize(bytesRead);
				if (outputBuffer.length < outsize) {
					outputBuffer = new byte[outputBuffer.length * 2];
				}
			    bytesProcessed = cipher.processBytes(inputBuffer, 0, bytesRead, outputBuffer, 0);
			    if(bytesProcessed > 0)  outputStream.write(outputBuffer, 0, bytesProcessed);
			}
		} catch (DataLengthException e) {
			throw new CryptoException(e);
		} catch (IllegalStateException e) {
			throw new CryptoException(e);
		} catch (IOException e) {
			throw new CryptoException(e);
		}
        try {
        	int outsize = cipher.getOutputSize(0);
			if (outputBuffer.length < outsize) {
				outputBuffer = new byte[outsize];
			}
			bytesProcessed = cipher.doFinal(outputBuffer, 0);
		} catch (DataLengthException e) {
			throw new CryptoException(e);
		} catch (IllegalStateException e) {
			throw new CryptoException(e);
		} catch (InvalidCipherTextException e) {
			throw new CryptoException(e);
		}

	    if(bytesProcessed > 0) outputStream.write(outputBuffer, 0, bytesProcessed);
        byte[] cipherText = outputStream.toByteArray();


        //append iv + integrityCode + cipherText
        byte[] blob = new byte[ 48 + cipherText.length];
        System.arraycopy(iv, 0, blob, 0, 16);
        System.arraycopy(integrityCode, 0, blob, 16, 32);
        System.arraycopy(cipherText, 0, blob, 48, cipherText.length);

        //Base64 encode and return
        encryptedStoreString = Base64.encodeBytesNoBreaks(blob);
    }




    private static byte[] getHashedIntegrityCode(byte[] iv, byte[] integrityKey,  byte[] clearBytes) throws UnsupportedEncodingException, NoSuchAlgorithmException {

        byte[] lastBlock = new byte[16];
        System.arraycopy(clearBytes,clearBytes.length - 16 ,lastBlock, 0, 16);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        byte[] integrityCheck = new byte[64];
        System.arraycopy(iv, 0, integrityCheck, 0, 16);
        System.arraycopy(integrityKey, 0, integrityCheck, 16, 32);
        System.arraycopy(lastBlock, 0, integrityCheck, 48, 16);
        digest.update(integrityCheck);
        return digest.digest();

    }


//    public static void main(String[] args) {
//
//        String  password = "password";
//
//        EncryptedStore encryptedStore = null;
//        try {
//            InputStream stream =  new FileInputStream("/Users/cmort/Desktop/Infocard/CardBackups/backup.crds");
//            encryptedStore = new EncryptedStore(stream, password);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//        System.out.println(encryptedStore.getParsedRoamingStore());
//
//        RoamingStore store = new RoamingStore();
//
//
//        //Get my keystore
//        KeystoreUtil keystore = null;
//        try {
//            keystore = new KeystoreUtil("/Users/cmort/xmldap_files/xmldap_org.jks", "password");
//        } catch (KeyStoreException e) {
//            e.printStackTrace();
//        }
//
//        X509Certificate cert = null;
//        try {
//            cert = keystore.getCertificate("tomcat");
//        } catch (KeyStoreException e) {
//            e.printStackTrace();
//        }
//
//
//        InfoCard card = new InfoCard(); // no cert -> unsigned
//        card.setCardId("https://xmldap.org/cards/123456");
//        card.setCardName("Custom card");
//        card.setCardVersion(1);
//        card.setIssuerName("xmldap.org");
//        card.setIssuer("http://xmldap.org/");
//        XSDDateTime issued = new XSDDateTime();
//        XSDDateTime expires = new XSDDateTime(525600);
//
//        card.setTimeIssued(issued.getDateTime());
//        card.setTimeExpires(expires.getDateTime());
//
//        TokenServiceReference tsr = new TokenServiceReference("http://xmldap.org/sts/tokenservice", "https://xmldap.org/sts/mex", cert);
//        tsr.setAuthType(TokenServiceReference.USERNAME, "cmort");
//        card.setTokenServiceReference(tsr);
//
//
//        SupportedTokenList tokenList = new SupportedTokenList();
//        SupportedToken token = new SupportedToken(SupportedToken.SAML11);
//        tokenList.addSupportedToken(token);
//        card.setTokenList(tokenList);
//
//        SupportedClaimList claimList = new SupportedClaimList();
//        SupportedClaim given = new SupportedClaim("GivenName", Constants.IC_NAMESPACE_PREFIX + "givenname", "Your given name.");
//        SupportedClaim sur = new SupportedClaim("Surname", Constants.IC_NAMESPACE_PREFIX + "surname", "Your surname.");
//        SupportedClaim email = new SupportedClaim("EmailAddress", Constants.IC_NAMESPACE_PREFIX + "emailaddress", "Your Email-Address");
//        claimList.addSupportedClaim(given);
//        claimList.addSupportedClaim(sur);
//        claimList.addSupportedClaim(email);
//        card.setClaimList(claimList);
//
//        card.setPrivacyPolicy("https://xmldap.org/PrivacyPolicy.xml");
//
//        RoamingInformationCard ric = new RoamingInformationCard(card);
//        store.addRoamingInformationCard(ric);
//        FileOutputStream fos = null;
//        try {
//            fos = new FileOutputStream("/Users/cmort/Desktop/Infocard/CardBackups/ManualBackup.crds");
//            encryptedStore = new EncryptedStore(store, password);
//            encryptedStore.toStream(fos);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//
//
//        EncryptedStore encryptedStore1 = null;
//        try {
//            InputStream stream =  new FileInputStream("/Users/cmort/Desktop/Infocard/CardBackups/ManualBackup.crds");
//            encryptedStore1 = new EncryptedStore(stream, password);
//        } catch (FileNotFoundException e) {
//            e.printStackTrace();
//        } catch (ParsingException e) {
//            e.printStackTrace();
//        } catch (CryptoException e) {
//            e.printStackTrace();
//        }
//        System.out.println(encryptedStore1.getParsedRoamingStore());
//
//    }

}
