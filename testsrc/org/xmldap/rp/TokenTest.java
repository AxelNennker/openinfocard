package org.xmldap.rp;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.pkcs.RSAPrivateKeyStructure;
import org.xmldap.exceptions.CryptoException;
import org.xmldap.exceptions.InfoCardProcessingException;
import org.xmldap.infocard.SelfIssuedToken;
import org.xmldap.rp.Token;
import org.xmldap.util.Base64;
import org.xmldap.util.XmldapCertsAndKeys;
import org.xmldap.xmldsig.ValidatingBaseEnvelopedSignature;

import junit.framework.TestCase;

public class TokenTest extends TestCase {

	String selfIssuedTokenStr = null;
	RSAPrivateKey xmldapKey = null;
	
	protected void setUp() throws Exception {
		super.setUp();
		
		X509Certificate xmldapCert = XmldapCertsAndKeys.getXmldapCert();
		xmldapKey = XmldapCertsAndKeys.getXmldapPrivateKey();
		
		X509Certificate relyingPartyCert = xmldapCert;
		RSAPublicKey signingKey = (RSAPublicKey)xmldapCert.getPublicKey();
        String signingAlgorithm = "SHA1withRSA";
		SelfIssuedToken token = new SelfIssuedToken(signingKey, xmldapKey, signingAlgorithm);
	
		token.setPrivatePersonalIdentifier(Base64.encodeBytesNoBreaks("ppid".getBytes()));
		token.setValidityPeriod(-5, 10);
		token.setConfirmationMethodBEARER();
		
		selfIssuedTokenStr = token.toXML();
		// e.g.: 
		// <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" MajorVersion="1" MinorVersion="1" 
		// AssertionID="uuid-8A443583-6887-6A21-D5D8-811EEF95AE32" 
		// Issuer="http://schemas.xmlsoap.org/ws/2005/05/identity/issuer/self"  
		// IssueInstant="2007-09-13T09:05:03Z"> 
		// <saml:Conditions NotBefore="2007-09-13T09:00:02Z" NotOnOrAfter="2007-09-13T09:15:02Z" /> 
		// <saml:AttributeStatement><saml:Subject> 
		// <saml:SubjectConfirmation><saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod> 
		// </saml:SubjectConfirmation></saml:Subject> 
		// <saml:Attribute AttributeName="privatepersonalidentifier"  
		// AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/"> 
		// <saml:AttributeValue>cHBpZA==</saml:AttributeValue></saml:Attribute></saml:AttributeStatement> 
		// <dsig:Signature xmlns:dsig="http://www.w3.org/2000/09/xmldsig#"><dsig:SignedInfo> 
		// <dsig:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /> 
		// <dsig:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" /> 
		// <dsig:Reference URI="#uuid-8A443583-6887-6A21-D5D8-811EEF95AE32"><dsig:Transforms> 
		// <dsig:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" /> 
		// <dsig:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /></dsig:Transforms> 
		// <dsig:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" /> 
		// <dsig:DigestValue>mqNBJacR2OJcr2UTHf4oGU6xYg4=</dsig:DigestValue></dsig:Reference> 
		// </dsig:SignedInfo> 
		// <dsig:SignatureValue>xydYzGbfpdGPA0KIUCVn/UHsekDF67X/a7yAUxaae9T5XeGeiFXv4Mb/GGG41c4J 
		// Su7eA1/5Wcz4a0Wl/woArL7z812SFubyVeKqCDDXTOus38Me5CCHfKdAqVNQi2nTDPF4g4plc8JeZNpAF8ATA 
		// GaCPU8O4vwr6SfueFILMOBrOUc9DKzi8i0Bc7uJ1niODoUBgBn+OmGAdCX1lZgwGmXpid1WoiCzBkJ+luihF7 
		// GZ757Xys7CgH389eBO560fXMG9eHdDy4cw3x71ozq8XglcegJkxfLD5cNolsMIuj7ufxi/x6Wp0fkhRyC3V9O 
		// M2tbxH+kIKltMQQrN4OcLVw==</dsig:SignatureValue><dsig:KeyInfo><dsig:KeyValue> 
		// <dsig:RSAKeyValue><dsig:Modulus>ANMnkVA4xfpG0bLos9FOpNBjHAdFahy2cJ7FUwuXd/IShnG+5qF/z 
		// 1SdPWzRxTtpFFyodtXlBUEIbiT+IbYPZF1vCcBrcFa8Kz/4rBjrpPZgllgA/WSVKjnJvw8q4/tO6CQZSlRlj/ 
		// ebNK9VyT1kN+MrKV1SGTqaIJ2l+7Rd05WHscwZMPdVWBbRrg76YTfy6H/NlQIArNLZanPvE0Vd5QfD4ZyG2hT 
		// h3y7ZlJAUndGJ/kfZw8sKuL9QSrh4eOTc280NQUmPGz6LP5MXNmu0RxEcomod1+ToKll90yEKFAUKuPYFgm9J 
		// +vYm4tzRequLy/njteRIkcfAdcAtt6PCYjU=</dsig:Modulus><dsig:Exponent>AQAB</dsig:Exponent> 
		// </dsig:RSAKeyValue></dsig:KeyValue></dsig:KeyInfo></dsig:Signature></saml:Assertion>

	}

//	public void testAvocoToken() throws InfoCardProcessingException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
//		String header = "-----BEGIN RSA PRIVATE KEY-----";
//		String pem = "MIICXQIBAAKBgQDGfLfIl9O7QJaZThGzBrYb6d1WVrrHKfFu6SjSGy9xaGr/fOvV" +
//	"2VlLG3gq77rNkrgP0nnFSrZhW0iUEvHhQUpO7f0aoAe0PDvFglWzk835EOHUslVw" +
//	"9W41GOTCLoBuWjt1iOcrvrAnCs5WWync49wsS9ZwIVFziyP3g67iXCTzcwIDAQAB" +
//	"AoGADCRK9clb2WONEtm0uXfaogB/Wq25hT9qlndK2PdywoQ5r2FL5+wAy1hl1HKP" +
//	"wc2M1uLwMgJs/62e1fgGtdnRmsDOCVxd2Km/kLfXh0kT7arx0oqFM2SNpATxcm08" +
//	"Cr7s+1oCexLnlPjR3Oj4pIGABpYgrwJUPxw5ytIJaxWvFGkCQQDxIC7fyfIwR8fM" +
//	"f0RrhD1RvNZJ02vwRt3dTsTPulMYmDCi/0K3OD+KA1lsite3fQ525m+YF1SDSsSK" +
//	"dnRXgpStAkEA0rsxtjPbvilYXDtBVWu4oDTtRdmzLAo/406CyVHz/KBgvW6DmckC" +
//	"fRmMbYhBw4yj+++86VCBuO2hVAJFlyyMnwJAQPXiqvfE/6zW7wj6bdzaiELPmGQV" +
//	"GE5/RzgJXc1cxat6ru8GEkZdF9l/Jfbh1tUiKHY8akUex6BFAuiWv1y2oQJBAJSV" +
//	"OrLuk7TcMBowCZvyLSaAyv/iRMv7mhpqpBrQ9wicCDno70+ChIeyeOpOFZiM1J7x" +
//	"5bBYfG7o1kSGqYyy858CQQDHYVKbtLup4yWARBaONDPEjCl4KNzifAmK68Ztn8Ur" +
//	"PJeCM38EP1gEh1BhJdX6uBBJvA0s+r7EgxJ/7CUAW/Zk";
//		String footer = "-----END RSA PRIVATE KEY-----";
//
//		byte[] asn1bytes = Base64.decode(pem);
//		ByteArrayInputStream bais = new ByteArrayInputStream(asn1bytes);
//		ASN1InputStream asn1is = new ASN1InputStream(bais);
//		DERObject obj = asn1is.readObject();
//		RSAPrivateKeyStructure rsa = new
//			RSAPrivateKeyStructure((ASN1Sequence)obj);
//		
//		RSAPrivateKeySpec rsaKeyspeck = new RSAPrivateKeySpec(rsa.getModulus(), rsa.getPrivateExponent()); 
//
//		KeyFactory f = KeyFactory.getInstance("RSA");
//
//		RSAPrivateKey aPrivateKey = (RSAPrivateKey)f.generatePrivate(rsaKeyspeck);
//		
//		String encryptedAvocoToken = "<enc:EncryptedData xmlns:enc=\"http://www.w3.org/2001/04/xmlenc#\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\"><enc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\" /><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><enc:EncryptedKey><enc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\" /></enc:EncryptionMethod><ds:KeyInfo><wsse:SecurityTokenReference xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><wsse:KeyIdentifier ValueType=\"http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1\" EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">h4GY+C5IkUIgD6BUY3ujKUXWp6g=</wsse:KeyIdentifier></wsse:SecurityTokenReference></ds:KeyInfo><enc:CipherData><enc:CipherValue>jOUoECtLGnl28jjUCjt1rFQdRbhaPRT5RRnSNcgPY7adGu8xjrXuTo/W41w+1st7RJd+h7vJgSrzjDzznAc+dRlaeq0MY2u+wzLAKEe+rb99TEeR/4lDj3AFNEUjb/SoKHUUxMUKAK4rz1+SiORakzRIf/p/kPhkuF4Rq6GuhdE=</enc:CipherValue></enc:CipherData></enc:EncryptedKey></ds:KeyInfo><enc:CipherData><enc:CipherValue>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</enc:CipherValue></enc:CipherData></enc:EncryptedData>";
//		Token token = new Token(encryptedAvocoToken, aPrivateKey);
//		
//		String assertion = token.getDecryptedToken();
//		String expectedAssertion = "<saml:Assertion MajorVersion=\"1\" MinorVersion=\"1\" AssertionID=\"uuid-4b890b06b9681\" Issuer=\"https://www.secure2cardspace.com/ICAM/tokenservice.php\" IssueInstant=\"2010-02-27T12:07:34Z\" xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\"><saml:Conditions NotBefore=\"2010-02-27T12:07:34Z\" NotOnOrAfter=\"2010-02-27T13:07:34Z\" ><saml:AudienceRestrictionCondition><saml:Audience>https://localhost/loa1RP/</saml:Audience></saml:AudienceRestrictionCondition></saml:Conditions><saml:AttributeStatement><saml:Subject><saml:SubjectConfirmation><saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod></saml:SubjectConfirmation></saml:Subject><saml:Attribute AttributeName=\"privatepersonalidentifier\" AttributeNamespace=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims\"><saml:AttributeValue>5b5c45655a6eedf8d0cf9a91ee00eeb9e8a69ca0ae56d4b1aa9e18d3fe95c1d7</saml:AttributeValue></saml:Attribute><saml:Attribute AttributeName=\"imi_1.0_profile#assurancelevel1\" AttributeNamespace=\"http://idmanagement.gov/icam/2009/09\"><saml:AttributeValue>true</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><dsig:Signature xmlns:dsig=\"http://www.w3.org/2000/09/xmldsig#\"><dsig:SignedInfo><dsig:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" /><dsig:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\" /><dsig:Reference URI=\"#uuid-4b890b06b9681\"><dsig:Transforms><dsig:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" /><dsig:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" /></dsig:Transforms><dsig:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\" /><dsig:DigestValue>klj9nweioSfJ/l/XvBXxAA4vDAs=</dsig:DigestValue></dsig:Reference></dsig:SignedInfo><dsig:SignatureValue>GbWlZw3mZy4ot5GPdQYO5sWMwVunHs90jBWNeRZFgn7TQ+18pgMaIU+VsIuRkmdrJQ+x8vRikDlkM87vPKpbyYhkE7MtyG14NLvC/xzsh5gs7RzXyoDl2Ra6y0zUJMc57ZELCQey6h5iJKPQvBWhyGmpSxkr1PmJ8S/RTiaeXp0=</dsig:SignatureValue><dsig:KeyInfo><dsig:X509Data><dsig:X509Certificate>MIIDijCCAvOgAwIBAgIQHKV4syFVzVqiQo9sJY5ksjANBgkqhkiG9w0BAQUFADCBzjELMAkGA1UEBhMCWkExFTATBgNVBAgTDFdlc3Rlcm4gQ2FwZTESMBAGA1UEBxMJQ2FwZSBUb3duMR0wGwYDVQQKExRUaGF3dGUgQ29uc3VsdGluZyBjYzEoMCYGA1UECxMfQ2VydGlmaWNhdGlvbiBTZXJ2aWNlcyBEaXZpc2lvbjEhMB8GA1UEAxMYVGhhd3RlIFByZW1pdW0gU2VydmVyIENBMSgwJgYJKoZIhvcNAQkBFhlwcmVtaXVtLXNlcnZlckB0aGF3dGUuY29tMB4XDTA5MDczMTAwMDAwMFoXDTExMDgyMDIzNTk1OVowgY4xCzAJBgNVBAYTAkdCMQ8wDQYDVQQIEwZEb3JzZXQxEDAOBgNVBAcTB1N3YW5hZ2UxGTAXBgNVBAoTEEF2b2NvIFNlY3VyZSBMdGQxHjAcBgNVBAsTFUFkbWluaXN0cmF0aW9uIE9mZmljZTEhMB8GA1UEAxMYd3d3LnNlY3VyZTJjYXJkc3BhY2UuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDhRV36HcXgGP8/Gw3r4fGbBxMlr8DLEHYZeVaBlRBgt4v46n5St0JjdiDdcIrFM9rOJI0m9PKEG8iWVqON/GDoGDC4HI4jmA0zYdIwmr1wTWDIWrfI2xBQxtfYEj+mqTweAKZqhA6VTj3rcsMJuWn4c1NfOc/2XPvOUidKq452YwIDAQABo4GmMIGjMAwGA1UdEwEB/wQCMAAwQAYDVR0fBDkwNzA1oDOgMYYvaHR0cDovL2NybC50aGF3dGUuY29tL1RoYXd0ZVNlcnZlclByZW1pdW1DQS5jcmwwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcwAYYWaHR0cDovL29jc3AudGhhd3RlLmNvbTANBgkqhkiG9w0BAQUFAAOBgQAEcmUMxqPsUcFYPa9giziZj6cKk/AAoAx25sCjgsVddx6CPyW1u5JaRlxr0BUQ2QprN/0ZlnaliqFDaPu7VmLAXjfS5XRJ6Y2XWnSCGxMNkV99NlLU5MQLRiH9CueeHF8CFFOWIwVNu4LytyaNmQnv97eekMI34ZlUY4jsvNHEWQ==</dsig:X509Certificate></dsig:X509Data></dsig:KeyInfo></dsig:Signature></saml:Assertion>";
//		assertEquals(expectedAssertion, assertion);
//	}
	
	public void testGetClientDigest() throws InfoCardProcessingException, CryptoException {
		Token token = new Token(selfIssuedTokenStr, xmldapKey);
		String digest = token.getClientDigest();
		
		assertEquals("Di8/RScn6chI6xtbQhLXZQNJTiE=",digest);
	}
	
	public void testSelfIssuedToken() throws InfoCardProcessingException {
		Token token = new Token(selfIssuedTokenStr, xmldapKey);
		assertFalse(token.isEncrypted());
		
		assertTrue(token.isSignatureValid());
	}
	
	public void testSelfIssuedToken2() throws InfoCardProcessingException, CryptoException {
		String petitTokenStr = "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\" MajorVersion=\"1\" MinorVersion=\"1\" AssertionID=\"uuid-E94A4623-422A-D4ED-242A-C8893146A338\" Issuer=\"http://schemas.xmlsoap.org/ws/2005/05/identity/issuer/self\" IssueInstant=\"2008-04-02T17:07:15Z\"><saml:Conditions NotBefore=\"2008-04-02T17:02:15Z\" NotOnOrAfter=\"2008-04-02T17:17:15Z\"><saml:AudienceRestrictionCondition><saml:Audience>http://localhost:8080/relyingparty/</saml:Audience></saml:AudienceRestrictionCondition></saml:Conditions>" + 
			"<saml:AttributeStatement><saml:Subject><saml:SubjectConfirmation><saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod></saml:SubjectConfirmation></saml:Subject><saml:Attribute AttributeName=\"givenname\" AttributeNamespace=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims\"><saml:AttributeValue>Patrick</saml:AttributeValue></saml:Attribute><saml:Attribute AttributeName=\"surname\" AttributeNamespace=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims\"><saml:AttributeValue>Petit</saml:AttributeValue></saml:Attribute><saml:Attribute AttributeName=\"emailaddress\" AttributeNamespace=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims\"><saml:AttributeValue>Patrick.Michel.Petit@gmail.com</saml:AttributeValue></saml:Attribute><saml:Attribute AttributeName=\"privatepersonalidentifier\" AttributeNamespace=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims\"><saml:AttributeValue>cG9FbmlTV2dVblQ4dHVRRElqSVpWRU1GdE9JUEUrZS9EcnVMb1ZUdGRrST0=</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>" +
			"<dsig:Signature xmlns:dsig=\"http://www.w3.org/2000/09/xmldsig#\"><dsig:SignedInfo><dsig:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" /><dsig:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\" /><dsig:Reference URI=\"#uuid-E94A4623-422A-D4ED-242A-C8893146A338\"><dsig:Transforms><dsig:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" /><dsig:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" /></dsig:Transforms><dsig:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\" /><dsig:DigestValue>2ToPlLCRarT6Nda1hoY3kkVJSe0=</dsig:DigestValue></dsig:Reference></dsig:SignedInfo><dsig:SignatureValue>CRkt12uDe1kLxmdty6tugG4Yi3mcbefhVvNBggWKxLUFakTJ/7zz5L6BPmnrU+bs9+o7QhH8wYBt6KidtynbCtKY8SwlxMMc+8Qbu1r0uurS+UxGkN5p30QlomQ1BVjfKd5zmr3mKvNXZpVwqE9FG8343AfGGB3KpoRYAH9Ivk5BH1cF1EYaNNytF4WPmkdwkfXr5/kxyf526564XUFPrSmz86BTyksGZfD6D3UAHenps3IdfgpIzv1Y3wOLJADZdxHJxmBI7qZ31wIMAGUhkKUQGfmoe677ICkHBOPMyQszycIrR9FD87HzRKe6hhSc5h3DmQvuJ111KM7suSRwpA==</dsig:SignatureValue><dsig:KeyInfo><dsig:KeyValue><dsig:RSAKeyValue><dsig:Modulus>l6OIACU8lEN+m6XawDTJRHAZlaMSAcz0pgtxBoqtpxIdl1YjKJ4HyOz3rMlnOMk8n43Y5SLMu4p5G09Pr6gIz25FwOSctFtflvmGEHczScYvtEgjrybBE+nrWcrIORuqpgCJ1mbG0/GSFsClI70k5rgHtL7M9Zha3NyAQUUyUcbvpYrR04+BGkQwyrOP7g/l191laJizLtIuA/OJgjM5dhXt2hjMRUkDImQvW2L9U/UM5SvXp6ecVXkYnwVDtDDdjaV6p5jPY8HjJKtBGsvqCtYfjNWiCZL/Bw90/JMW7blqrAa42BviPl9/wIHpvRM4q2mYEZFL8mbwqRxSz9OYnQ==</dsig:Modulus><dsig:Exponent>AQAB</dsig:Exponent></dsig:RSAKeyValue></dsig:KeyValue></dsig:KeyInfo></dsig:Signature>" + 
			"</saml:Assertion>";
		//                               "http://www.w3.org/2000/09/xmldsig#"
		Token token = new Token(petitTokenStr, null);
		assertFalse(token.isEncrypted());
		
		assertTrue(token.isSignatureValid());

		String digest = token.getClientDigest();
		assertEquals("tAhEE404bgkTVqhLmqf0ZmNpsEE=",digest);
	}
	
	public void testSelfIssuedToken3() throws InfoCardProcessingException, CryptoException {
		String petitTokenStr = "<root><saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\" MajorVersion=\"1\" MinorVersion=\"1\" AssertionID=\"uuid-E94A4623-422A-D4ED-242A-C8893146A338\" Issuer=\"http://schemas.xmlsoap.org/ws/2005/05/identity/issuer/self\" IssueInstant=\"2008-04-02T17:07:15Z\"><saml:Conditions NotBefore=\"2008-04-02T17:02:15Z\" NotOnOrAfter=\"2008-04-02T17:17:15Z\"><saml:AudienceRestrictionCondition><saml:Audience>http://localhost:8080/relyingparty/</saml:Audience></saml:AudienceRestrictionCondition></saml:Conditions>" + 
			"<saml:AttributeStatement><saml:Subject><saml:SubjectConfirmation><saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod></saml:SubjectConfirmation></saml:Subject><saml:Attribute AttributeName=\"givenname\" AttributeNamespace=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims\"><saml:AttributeValue>Patrick</saml:AttributeValue></saml:Attribute><saml:Attribute AttributeName=\"surname\" AttributeNamespace=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims\"><saml:AttributeValue>Petit</saml:AttributeValue></saml:Attribute><saml:Attribute AttributeName=\"emailaddress\" AttributeNamespace=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims\"><saml:AttributeValue>Patrick.Michel.Petit@gmail.com</saml:AttributeValue></saml:Attribute><saml:Attribute AttributeName=\"privatepersonalidentifier\" AttributeNamespace=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims\"><saml:AttributeValue>cG9FbmlTV2dVblQ4dHVRRElqSVpWRU1GdE9JUEUrZS9EcnVMb1ZUdGRrST0=</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>" +
			"<dsig:Signature xmlns:dsig=\"http://www.w3.org/2000/09/xmldsig#\"><dsig:SignedInfo><dsig:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" /><dsig:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\" /><dsig:Reference URI=\"#uuid-E94A4623-422A-D4ED-242A-C8893146A338\"><dsig:Transforms><dsig:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" /><dsig:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" /></dsig:Transforms><dsig:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\" /><dsig:DigestValue>2ToPlLCRarT6Nda1hoY3kkVJSe0=</dsig:DigestValue></dsig:Reference></dsig:SignedInfo><dsig:SignatureValue>CRkt12uDe1kLxmdty6tugG4Yi3mcbefhVvNBggWKxLUFakTJ/7zz5L6BPmnrU+bs9+o7QhH8wYBt6KidtynbCtKY8SwlxMMc+8Qbu1r0uurS+UxGkN5p30QlomQ1BVjfKd5zmr3mKvNXZpVwqE9FG8343AfGGB3KpoRYAH9Ivk5BH1cF1EYaNNytF4WPmkdwkfXr5/kxyf526564XUFPrSmz86BTyksGZfD6D3UAHenps3IdfgpIzv1Y3wOLJADZdxHJxmBI7qZ31wIMAGUhkKUQGfmoe677ICkHBOPMyQszycIrR9FD87HzRKe6hhSc5h3DmQvuJ111KM7suSRwpA==</dsig:SignatureValue><dsig:KeyInfo><dsig:KeyValue><dsig:RSAKeyValue><dsig:Modulus>l6OIACU8lEN+m6XawDTJRHAZlaMSAcz0pgtxBoqtpxIdl1YjKJ4HyOz3rMlnOMk8n43Y5SLMu4p5G09Pr6gIz25FwOSctFtflvmGEHczScYvtEgjrybBE+nrWcrIORuqpgCJ1mbG0/GSFsClI70k5rgHtL7M9Zha3NyAQUUyUcbvpYrR04+BGkQwyrOP7g/l191laJizLtIuA/OJgjM5dhXt2hjMRUkDImQvW2L9U/UM5SvXp6ecVXkYnwVDtDDdjaV6p5jPY8HjJKtBGsvqCtYfjNWiCZL/Bw90/JMW7blqrAa42BviPl9/wIHpvRM4q2mYEZFL8mbwqRxSz9OYnQ==</dsig:Modulus><dsig:Exponent>AQAB</dsig:Exponent></dsig:RSAKeyValue></dsig:KeyValue></dsig:KeyInfo></dsig:Signature>" + 
			"</saml:Assertion></root>";
		//                               "http://www.w3.org/2000/09/xmldsig#"
		Token token = new Token(petitTokenStr, null);
		assertFalse(token.isEncrypted());
		
		boolean threw = false;
		try {
			boolean falsch = token.isSignatureValid();
		} catch (InfoCardProcessingException e) {
			threw = true;
		}
		assertTrue(threw);
		threw = false;
		try {
			String digest = token.getClientDigest();
			assertEquals("tAhEE404bgkTVqhLmqf0ZmNpsEE=",digest);
		} catch (CryptoException e) {
			threw = true;
		}
		assertTrue(threw);
	}
	
	public void testLength() {
		String sv = "xydYzGbfpdGPA0KIUCVn/UHsekDF67X/a7yAUxaae9T5XeGeiFXv4Mb/GGG41c4JSu7eA1/5Wcz4a0Wl/woArL7z812SFubyVeKqCDDXTOus38Me5CCHfKdAqVNQi2nTDPF4g4plc8JeZNpAF8ATAGaCPU8O4vwr6SfueFILMOBrOUc9DKzi8i0Bc7uJ1niODoUBgBn+OmGAdCX1lZgwGmXpid1WoiCzBkJ+luihF7GZ757Xys7CgH389eBO560fXMG9eHdDy4cw3x71ozq8XglcegJkxfLD5cNolsMIuj7ufxi/x6Wp0fkhRyC3V9OM2tbxH+kIKltMQQrN4OcLVw==";
		String mo = "ANMnkVA4xfpG0bLos9FOpNBjHAdFahy2cJ7FUwuXd/IShnG+5qF/z1SdPWzRxTtpFFyodtXlBUEIbiT+IbYPZF1vCcBrcFa8Kz/4rBjrpPZgllgA/WSVKjnJvw8q4/tO6CQZSlRlj/ebNK9VyT1kN+MrKV1SGTqaIJ2l+7Rd05WHscwZMPdVWBbRrg76YTfy6H/NlQIArNLZanPvE0Vd5QfD4ZyG2hTh3y7ZlJAUndGJ/kfZw8sKuL9QSrh4eOTc280NQUmPGz6LP5MXNmu0RxEcomod1+ToKll90yEKFAUKuPYFgm9J+vYm4tzRequLy/njteRIkcfAdcAtt6PCYjU=";
		assertEquals(sv.length(), mo.length());
		BigInteger modulus = new BigInteger(1, Base64.decode(mo));
		assertEquals(2048, modulus.bitLength());
		assertEquals(Base64.decode(sv).length+1, Base64.decode(mo).length);
	}
	
	public void testLengthA() throws CryptoException {
		String a = "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\" AssertionID=\"uuid-7B20C5C0-9B85-35D1-590A-D1B3093451CF\" Issuer=\"http://schemas.microsoft.com/ws/2005/05/identity/issuer/self\" IssueInstant=\"2007-08-30T15:10:47Z\" MajorVersion=\"1\" MinorVersion=\"1\"><saml:Conditions NotBefore=\"2007-08-30T15:05:47Z\" NotOnOrAfter=\"2007-08-30T15:20:47Z\"><saml:AudienceRestrictionCondition><saml:Audience>https://w4de3esy0069028.gdc-bln01.t-systems.com:8443/relyingparty/</saml:Audience></saml:AudienceRestrictionCondition></saml:Conditions><saml:AttributeStatement><saml:Subject><saml:SubjectConfirmation><saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod></saml:SubjectConfirmation></saml:Subject><saml:Attribute AttributeName=\"givenname\" AttributeNamespace=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname\"><saml:AttributeValue>Axel</saml:AttributeValue></saml:Attribute><saml:Attribute AttributeName=\"surname\" AttributeNamespace=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname\"><saml:AttributeValue>Nennker</saml:AttributeValue></saml:Attribute><saml:Attribute AttributeName=\"emailaddress\" AttributeNamespace=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress\"><saml:AttributeValue>axel@nennker.de</saml:AttributeValue></saml:Attribute><saml:Attribute AttributeName=\"privatepersonalidentifier\" AttributeNamespace=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier\"><saml:AttributeValue>bXRwZTJPZUhldWJKU1lydDMxWThodnB1cFpCRmd6MDVlaXViWWo3NzJaTT0=</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><dsig:Signature xmlns:dsig=\"http://www.w3.org/2000/09/xmldsig#\"><dsig:SignedInfo><dsig:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" /><dsig:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\" /><dsig:Reference URI=\"#uuid-7B20C5C0-9B85-35D1-590A-D1B3093451CF\"><dsig:Transforms><dsig:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" /><dsig:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" /></dsig:Transforms><dsig:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\" /><dsig:DigestValue>P834/zjB6jZbz80UPkCJQ+IGoqk=</dsig:DigestValue></dsig:Reference></dsig:SignedInfo><dsig:SignatureValue>lg/8RNBJ2JsSwkPY8G4VU+mS89NhPKn0psIIwdD9uiMVknLxQk3+79kP46CzLfpczy6Azjv17sXMgHJDr7XFchfKArhoAgaVc+ulkUpSOJNW8f5cVLMHvEmD2Qo5/VcYOgrVS72+d0rK8A42twUublm+8TjxGPp/oVSFxtTmg4E=</dsig:SignatureValue><dsig:KeyInfo><dsig:KeyValue><dsig:RSAKeyValue><dsig:Modulus>ALgc5OE4nyN5TfZS6wa5LT4rEfAMMuoOWknZoRv4T6wZcoEh31g2haNcbcqq+5PXeB+hSMwL4XBfKqs+JK5a4/WyTVfJ+Zedutq5t6S5Rq5v2jwVuFy5ZuWVAl5629slvcPtNGg3LeHvkz7fcgbxLreAIk5ojE4YQRRpffmGWH4j</dsig:Modulus><dsig:Exponent>AQAB</dsig:Exponent></dsig:RSAKeyValue></dsig:KeyValue></dsig:KeyInfo></dsig:Signature></saml:Assertion>";
		String sv = "lg/8RNBJ2JsSwkPY8G4VU+mS89NhPKn0psIIwdD9uiMVknLxQk3+79kP46CzLfpczy6Azjv17sXMgHJDr7XFchfKArhoAgaVc+ulkUpSOJNW8f5cVLMHvEmD2Qo5/VcYOgrVS72+d0rK8A42twUublm+8TjxGPp/oVSFxtTmg4E=";
		String mo = "ALgc5OE4nyN5TfZS6wa5LT4rEfAMMuoOWknZoRv4T6wZcoEh31g2haNcbcqq+5PXeB+hSMwL4XBfKqs+JK5a4/WyTVfJ+Zedutq5t6S5Rq5v2jwVuFy5ZuWVAl5629slvcPtNGg3LeHvkz7fcgbxLreAIk5ojE4YQRRpffmGWH4j";
		assertEquals(sv.length(), mo.length());
		BigInteger modulus = new BigInteger(1, Base64.decode(mo));
		assertEquals(1024, modulus.bitLength());
		
		assertTrue(ValidatingBaseEnvelopedSignature.validate(a));
		assertEquals(Base64.decode(sv).length+1, Base64.decode(mo).length);
	}
}
