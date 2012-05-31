/*
 * Copyright (c) 2006, Axel Nennker - http://axel.nennker.de/
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
 *     * The names of the contributors may NOT be used to endorse or promote products
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
 * 
 */
package org.xmldap.asn1;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;

import junit.framework.TestCase;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.xmldap.util.CertsAndKeys;

public class LogotypeTest extends TestCase {

//	DER Sequence
//    Tagged [1]
//        Tagged [0]
//            DER Sequence
//                DER Sequence
//                    DER Sequence
//                        IA5String(image/gif) 
//                        DER Sequence
//                            DER Sequence
//                                DER Sequence
//                                    ObjectIdentifier(1.3.14.3.2.26)
//                                DER Octet String[20] 
//                        DER Sequence
//                            IA5String(http://logo.verisign.com/vslogo.gif) 

	private static final byte[] verisign_logotypeExtension = { (byte) 0x30,
			(byte) 0x5f, (byte) 0xa1, (byte) 0x5d, (byte) 0xa0, (byte) 0x5b,
			(byte) 0x30, (byte) 0x59, (byte) 0x30, (byte) 0x57, (byte) 0x30,
			(byte) 0x55, (byte) 0x16, (byte) 0x09, (byte) 0x69, (byte) 0x6d,
			(byte) 0x61, (byte) 0x67, (byte) 0x65, (byte) 0x2f, (byte) 0x67,
			(byte) 0x69, (byte) 0x66, (byte) 0x30, (byte) 0x21, (byte) 0x30,
			(byte) 0x1f, (byte) 0x30, (byte) 0x07, (byte) 0x06, (byte) 0x05,
			(byte) 0x2b, (byte) 0x0e, (byte) 0x03, (byte) 0x02, (byte) 0x1a,
			(byte) 0x04, (byte) 0x14, (byte) 0x8f, (byte) 0xe5, (byte) 0xd3,
			(byte) 0x1a, (byte) 0x86, (byte) 0xac, (byte) 0x8d, (byte) 0x8e,
			(byte) 0x6b, (byte) 0xc3, (byte) 0xcf, (byte) 0x80, (byte) 0x6a,
			(byte) 0xd4, (byte) 0x48, (byte) 0x18, (byte) 0x2c, (byte) 0x7b,
			(byte) 0x19, (byte) 0x2e, (byte) 0x30, (byte) 0x25, (byte) 0x16,
			(byte) 0x23, (byte) 0x68, (byte) 0x74, (byte) 0x74, (byte) 0x70,
			(byte) 0x3a, (byte) 0x2f, (byte) 0x2f, (byte) 0x6c, (byte) 0x6f,
			(byte) 0x67, (byte) 0x6f, (byte) 0x2e, (byte) 0x76, (byte) 0x65,
			(byte) 0x72, (byte) 0x69, (byte) 0x73, (byte) 0x69, (byte) 0x67,
			(byte) 0x6e, (byte) 0x2e, (byte) 0x63, (byte) 0x6f, (byte) 0x6d,
			(byte) 0x2f, (byte) 0x76, (byte) 0x73, (byte) 0x6c, (byte) 0x6f,
			(byte) 0x67, (byte) 0x6f, (byte) 0x2e, (byte) 0x67, (byte) 0x69,
			(byte) 0x66 };

	public void setUp() throws Exception {
		super.setUp();
	}
	
	public void testLogotypeCert()  throws Exception {
		Provider provider = new BouncyCastleProvider();
		if (null == Security.getProvider(provider.getName())) {
			Security.addProvider(provider);
		}
		KeyPair kp = CertsAndKeys.generateKeyPair(provider);
		KeyPair caKeyPair = CertsAndKeys.generateKeyPair(provider);
		X509Name issuer = new X509Name(
				"CN=w4de3esy0069028.gdc-bln01.t-systems.com, OU=SSC ENPS, O=T-Systems, L=Berlin, ST=Berln, C=DE");
		X509Name subject = issuer;
		X509Certificate caCert = CertsAndKeys.generateCaCertificate(provider, "caCert", kp, issuer);
		X509Certificate cert = CertsAndKeys.generateSSLServerCertificate(
				provider, "SSL server cert",
				caKeyPair, caCert, kp,
				issuer, subject);
		byte[] fromExtensionValue = cert.getExtensionValue(Logotype.id_pe_logotype.getId());
		ASN1Encodable extVal = X509ExtensionUtil.fromExtensionValue(fromExtensionValue);
		Logotype logotype = Logotype.getInstance((ASN1Sequence)extVal);
		LogotypeInfo[] communityLogos = logotype.getCommunityLogos();
		assertNull(communityLogos);
		LogotypeInfo issuerLogo = logotype.getIssuerLogo();
		assertNotNull(issuerLogo);
		LogotypeInfo subjectLogo = logotype.getSubjectLogo();
		assertNull(subjectLogo);
		LogotypeInfo[] otherLogos = logotype.getOtherLogos();
		assertNull(otherLogos);
		
		assertEquals(0, issuerLogo.getTagNo());
		assertTrue((issuerLogo.getTagNo() == LogotypeInfo.direct) || (issuerLogo.getTagNo() == LogotypeInfo.indirect));
		if (issuerLogo.getTagNo() == LogotypeInfo.direct) {
			LogotypeData direct = issuerLogo.getLogotypeData();
			assertNotNull(direct);
			LogotypeDetails[] images = direct.getImages();
			assertEquals(1, images.length);
			LogotypeDetails logotypeDetails = images[0];
			String mediaType = logotypeDetails.getMediaType();
			assertEquals("image/jpg", mediaType);
			DigestInfo[] dis = logotypeDetails.getLogotypeHash();
			assertEquals(1, dis.length);
			DigestInfo di = dis[0];
			AlgorithmIdentifier algId = di.getAlgorithmId();
			assertEquals("1.3.14.3.2.26", algId.getObjectId().getId());
			byte[] digest = di.getDigest();
			byte[] expected = { -106, -38, 90, -10, 15, 80, -15, -124, -124, 58, 63, 44, 45, -102, 91, -13, -114, -95, -48, -44};
			assertEquals(expected.length , digest.length);
			for (int i=0; i<digest.length; i++) {
				assertEquals(expected[i], digest[i]);
			}
			String[] uris = logotypeDetails.getLogotypeURI();
			assertEquals(1, uris.length);
			String uri = uris[0];
			assertEquals("http://static.flickr.com/10/buddyicons/18119196@N00.jpg?1115549486", uri);
		} else if (issuerLogo.getTagNo() == LogotypeInfo.indirect) {
			LogotypeReference indirect = issuerLogo.getLogotypeReference();
//			LogotypeReference indirect = LogotypeReference.getInstance((ASN1TaggedObject)issuerLogo.toASN1Primitive(), false);
			assertNotNull(indirect);
		}

	}
	
	public void testTOILogotypeExtensionCreation()  throws Exception {
		Logotype logotype = composeToi();
		ASN1Primitive obj = logotype.toASN1Primitive();
//        String str = ASN1Dump.dumpAsString(obj);
//        assertEquals("", str);
		byte[] seq = obj.getEncoded();
		verifyToi(seq);
	}

	/**
	 * @return
	 */
	private Logotype composeToi() {
		String mediaType = "image/gif";
		AlgorithmIdentifier  algId = new AlgorithmIdentifier("1.3.14.3.2.26");
		byte[] digest = { -113, -27, -45, 26, -122, -84, -115, -114, 107, -61, -49, -128, 106, -44, 72, 24, 44, 123, 25, 46};
		DigestInfo digestInfo = new DigestInfo(algId, digest);
		DigestInfo[] logotypeHash = { digestInfo };
		String[] logotypeURI = { "http://logo.verisign.com/vslogo.gif" };
		LogotypeDetails imageDetails = new LogotypeDetails( mediaType, logotypeHash, logotypeURI );
//		LogotypeImageInfo imageInfo = null;
//		LogotypeImage image = new LogotypeImage(imageDetails, imageInfo);
//		LogotypeImage[] images = { image };
		LogotypeDetails[] images = { imageDetails };
		LogotypeAudio[] audio = null;
		LogotypeData direct = new LogotypeData(images, audio);
		LogotypeInfo[] communityLogos = null;
		LogotypeInfo issuerLogo = new LogotypeInfo(direct);
		LogotypeInfo subjectLogo = null;
		OtherLogotypeInfo[] otherLogos = null;
		Logotype logotype = new Logotype(communityLogos, issuerLogo, subjectLogo, otherLogos);
		return logotype;
	}
	
	public void testTOILogotypeExtensionGetInstance()  throws Exception {
		verifyToi(verisign_logotypeExtension);
	}

//	public void testTOILogotypeExtensionDump()  throws Exception {
//        ByteArrayInputStream   stream = new ByteArrayInputStream(verisign_logotypeExtension);
//        ASN1InputStream        aStream = new ASN1InputStream(stream);
//        
//        ASN1Sequence root = (ASN1Sequence)aStream.readObject();
//        String str = ASN1Dump.dumpAsString(root);
//        assertEquals("", str);
//	}

	/**
	 * @param root
	 */
	private void verifyToi(byte[] logotypeBytes)   throws Exception {
		Logotype logotype = Logotype.getInstance(logotypeBytes);
		LogotypeInfo[] communityLogos = logotype.getCommunityLogos();
		assertNull(communityLogos);
		LogotypeInfo issuerLogo = logotype.getIssuerLogo();
		assertNotNull(issuerLogo);
		LogotypeInfo subjectLogo = logotype.getSubjectLogo();
		assertNull(subjectLogo);
		LogotypeInfo[] otherLogos = logotype.getOtherLogos();
		assertNull(otherLogos);
		
		assertEquals(0, issuerLogo.getTagNo());
		assertTrue((issuerLogo.getTagNo() == LogotypeInfo.direct) || (issuerLogo.getTagNo() == LogotypeInfo.indirect));
		if (issuerLogo.getTagNo() == LogotypeInfo.direct) {
			LogotypeData direct = issuerLogo.getLogotypeData();
			assertNotNull(direct);
			LogotypeDetails[] images = direct.getImages();
			assertEquals(1, images.length);
			LogotypeDetails logotypeDetails = images[0];
			String mediaType = logotypeDetails.getMediaType();
			assertEquals("image/gif", mediaType);
			DigestInfo[] dis = logotypeDetails.getLogotypeHash();
			assertEquals(1, dis.length);
			DigestInfo di = dis[0];
			AlgorithmIdentifier algId = di.getAlgorithmId();
			assertEquals("1.3.14.3.2.26", algId.getObjectId().getId());
			byte[] digest = di.getDigest();
			byte[] expected = { -113, -27, -45, 26, -122, -84, -115, -114, 107, -61, -49, -128, 106, -44, 72, 24, 44, 123, 25, 46};
			assertEquals(expected.length , digest.length);
			for (int i=0; i<digest.length; i++) {
				assertEquals(expected[i], digest[i]);
			}
			String[] uris = logotypeDetails.getLogotypeURI();
			assertEquals(1, uris.length);
			String uri = uris[0];
			assertEquals("http://logo.verisign.com/vslogo.gif", uri);
		} else if (issuerLogo.getTagNo() == LogotypeInfo.indirect) {
			LogotypeReference indirect = issuerLogo.getLogotypeReference();
//			LogotypeReference indirect = LogotypeReference.getInstance((ASN1TaggedObject)issuerLogo.toASN1Primitive(), false);
			assertNotNull(indirect);
		}
	}
	
	public void testTOILogotypeExtension()  throws Exception {
        ByteArrayInputStream   stream = new ByteArrayInputStream(verisign_logotypeExtension);
        ASN1InputStream        aStream = new ASN1InputStream(stream);
        
        ASN1Sequence root = (ASN1Sequence)aStream.readObject();
        assertEquals(1, root.size());
       	DERTaggedObject taggedObject = (DERTaggedObject)root.getObjectAt(0);
       	assertEquals(1,taggedObject.getTagNo()); // tag=1 issuerLogo
       	DERTaggedObject issuerLogo = (DERTaggedObject)taggedObject.getObject();
       	assertEquals(0,issuerLogo.getTagNo()); // tag=0 direct
       	DERSequence direct = (DERSequence)issuerLogo.getObject();
       	assertEquals(1, direct.size());
       	DERSequence logotypeData = (DERSequence)direct.getObjectAt(0);
       	assertEquals(1, logotypeData.size());
       	DERSequence imageDetails = (DERSequence)logotypeData.getObjectAt(0);
       	assertEquals(3,imageDetails.size());
       	DERIA5String mediaType = (DERIA5String)imageDetails.getObjectAt(0);
       	assertEquals("image/gif", mediaType.getString());
       	DERSequence logotypeHash = (DERSequence)imageDetails.getObjectAt(1);
       	assertEquals(1,logotypeHash.size());
       	DERSequence logotypeURISequence = (DERSequence)imageDetails.getObjectAt(2);
       	assertEquals(1,logotypeURISequence.size());
       	DERSequence hashAlgAndValue = (DERSequence)logotypeHash.getObjectAt(0);
       	assertEquals(2, hashAlgAndValue.size());
       	DERIA5String logotypeURI = (DERIA5String)logotypeURISequence.getObjectAt(0);
       	assertEquals("http://logo.verisign.com/vslogo.gif", logotypeURI.getString());
       	DERSequence hashAlgSequence = (DERSequence)hashAlgAndValue.getObjectAt(0);
       	assertEquals(1, hashAlgSequence.size());
       	DERObjectIdentifier o = (DERObjectIdentifier)hashAlgSequence.getObjectAt(0);
       	// http://asn1.elibel.tm.fr/cgi-bin/oid/display?oid=1.3.14.3.2.26&action=display
       	assertEquals("1.3.14.3.2.26", o.getId()); // sha-1
       	DEROctetString hashValue = (DEROctetString)hashAlgAndValue.getObjectAt(1);
       	byte[] digest = hashValue.getOctets();
		byte[] expected = { -113, -27, -45, 26, -122, -84, -115, -114, 107, -61, -49, -128, 106, -44, 72, 24, 44, 123, 25, 46};
		assertEquals(expected.length , digest.length);
		for (int i=0; i<digest.length; i++) {
			assertEquals(expected[i], digest[i]);
		}

//        Logotype lt = (Logotype)obj;
        
//        assertEquals(null, lt);

	}

}
