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
package org.xmldap.tools;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;
import org.xmldap.exceptions.TokenIssuanceException;
import org.xmldap.util.CertsAndKeys;

public class GenerateSSLServerCertificate {

	/**
	 * @param args
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 * @throws TokenIssuanceException 
	 * @throws KeyStoreException 
	 * @throws IOException 
	 * @throws FileNotFoundException 
	 * @throws CertificateException 
	 * @throws SignatureException 
	 * @throws SecurityException 
	 * @throws InvalidKeyException 
	 */
	public static void main(String[] args) throws NoSuchAlgorithmException,
			NoSuchProviderException, KeyStoreException, CertificateException,
			FileNotFoundException, IOException, InvalidKeyException,
			SecurityException, SignatureException {

		String storePassword = "changeit";
		String sslServerCertNickname = "tomcat";
		String keyPassword = "changeit";
		String caCertNickname = "caCert";
		
		Provider provider = new BouncyCastleProvider();
		if (Security.getProvider("BC") == null) {
			Security.addProvider(provider);
		}

		String issuerStr = "CN=xmldap Class 3 Extended Validation SSL CA, O=xmldap, L=San Francisco, ST=California, C=US";
		X509Name issuer = new X509Name(issuerStr);

		KeyPair caKeyPair = CertsAndKeys.generateKeyPair(provider);
		{
			PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier) caKeyPair
					.getPrivate();
			bagAttr.setBagAttribute(
					PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
					new DERBMPString(caCertNickname));
			bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
					new SubjectKeyIdentifierStructure(caKeyPair.getPublic()));
		}
		X509Certificate caCert = CertsAndKeys.generateCaCertificate(provider,
				"xmldap Class 3 Extended Validation SSL CA", caKeyPair, issuer);

		KeyPair kp = CertsAndKeys.generateKeyPair(provider);
		{
			PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier) kp
					.getPrivate();
			bagAttr.setBagAttribute(
					PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
					new DERBMPString(sslServerCertNickname));
			bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
					new SubjectKeyIdentifierStructure(kp.getPublic()));
		}

		String domain = "w4de3esy0069028.gdc-bln01.t-systems.com";

		String jurisdictionOfIncorporationCountryNameOidStr = "1.3.6.1.4.1.311.60.2.1.3"; // DE
		String jurisdictionOfIncorporationStateOrProvinceNameOidStr = "1.3.6.1.4.1.311.60.2.1.2"; // Hessen
		String jurisdictionOfIncorporationLocalityNameOidStr = "1.3.6.1.4.1.311.60.2.1.1"; // Frankfurt

//        Subject: serialNumber=2871352/1.3.6.1.4.1.311.60.2.1.3=US/1.3.6.1.4.1.31
//        1.60.2.1.2=Delaware, C=US/postalCode=95125, ST=California, L=San Jose/streetAddr
//        ess=2145 Hamilton Ave, O=eBay Inc., OU=Site_Operations, CN=signin.ebay.com
		X509Name subject = new X509Name(
				  "CN=" + domain
				+ ",OU=PD"
				+ ",O=T-Systems" 
				+ ",L=Berlin" 
				+ ",street=Goslarer Ufer 35" 
				+ ",ST=Berlin" 
				+ ",postalCode=10589" 
				+ ",C=DE"
				+ "," + jurisdictionOfIncorporationStateOrProvinceNameOidStr + "=Hessen" 
				+ "," + jurisdictionOfIncorporationCountryNameOidStr + "=DE"
				+ ",SN=Handelsregister Amtsgericht Frankfurt am Main HRB 55933"
				+ "," + jurisdictionOfIncorporationLocalityNameOidStr + "=Frankfurt am Main" 
				);
		//		X509Certificate cert = CertsAndKeys.generateSSLServerCertificate(
		//				null, null, 
		//				kp,
		//				issuer, issuer);
		X509Certificate cert = CertsAndKeys.generateSSLServerCertificate(provider,
				sslServerCertNickname,
				caKeyPair, caCert, kp, issuer, subject);
		try {
			cert.verify(caKeyPair.getPublic(), "BC");
			System.out.println("verified cert");
		} catch (Exception e) {
			System.out.println("could not verify cert");
		}

//		PKCS10CertificationRequest certRequest = CertsAndKeys.generateCertificateRequest(cert, kp.getPrivate());
		
//		CertsAndKeys.printCert(cert);
//		System.out.println(cert.toString());
		
		String keystorePath = "";
		String caCertPath = "";
		String serverCertPath = "";
		String caCertKeyPath = "";
		String serverCertKeyPath = "";
		String certRequestPath = "";
		
		String tmpdir = System.getProperty("java.io.tmpdir");
		if (tmpdir != null) {
			keystorePath = tmpdir + "keystore.jks";
			caCertPath = tmpdir + "caCert.der";
			caCertKeyPath = tmpdir + "caCert-key.der";
			serverCertPath = tmpdir + domain + ".der";
			serverCertKeyPath = tmpdir + domain + "-key.der";
			certRequestPath = tmpdir + domain + ".csr";
		} else {
			File[] roots = File.listRoots();
			keystorePath = roots[0].getPath() + "keystore.jks";
			caCertPath = roots[0].getPath() + "caCert.der";
			caCertKeyPath = roots[0].getPath() + "caCert-key.der";
			serverCertPath = roots[0].getPath() + domain + ".der";
			serverCertKeyPath = roots[0].getPath() + domain + "-key.der";
			certRequestPath = roots[0].getPath() + domain + ".csr";
		}

		KeyStore ks = KeyStore.getInstance("JKS");
		ks.load(null, storePassword.toCharArray());

//		Certificate[] caChain = { caCert };
//		ks.setKeyEntry(caCertNickname, caKeyPair.getPrivate(), keyPassword
//				.toCharArray(), caChain);
		ks.setCertificateEntry(caCertNickname, caCert);
		
		Certificate[] chain = { cert, caCert };
		ks.setKeyEntry(sslServerCertNickname, kp.getPrivate(), keyPassword
				.toCharArray(), chain);
		File file = new File(keystorePath);
		file.createNewFile();
		FileOutputStream fos = new java.io.FileOutputStream(file);
		ks.store(fos, storePassword.toCharArray());
		fos.close();

		System.out.println("saved keystore to: " + keystorePath);

//		file = new File(certRequestPath);
//		file.createNewFile();
//		fos = new java.io.FileOutputStream(file);
//		fos.write(certRequest.getEncoded());
//		fos.close();
//		System.out.println("saved certificate request to: " + certRequestPath);

		file = new File(caCertPath);
		file.createNewFile();
		fos = new java.io.FileOutputStream(file);
		fos.write(caCert.getEncoded());
		fos.close();
		System.out.println("saved caCert to: " + caCertPath);

		file = new File(caCertKeyPath);
		file.createNewFile();
		fos = new java.io.FileOutputStream(file);
		fos.write(caKeyPair.getPrivate().getEncoded());
		fos.close();
		System.out.println("saved caCert private key to: " + caCertKeyPath);

		file = new File(serverCertKeyPath);
		file.createNewFile();
		fos = new java.io.FileOutputStream(file);
		fos.write(kp.getPrivate().getEncoded());
		fos.close();
		System.out.println("saved server private key to: " + serverCertKeyPath);

		file = new File(serverCertPath);
		file.createNewFile();
		fos = new java.io.FileOutputStream(file);
		fos.write(cert.getEncoded());
		fos.close();
		System.out.println("saved server certificate to: " + serverCertPath);

//		String dump = ASN1Dump.dumpAsString(cert);
//		System.out.println("ASN1Dump:");
//		System.out.println(dump);

	}

}
