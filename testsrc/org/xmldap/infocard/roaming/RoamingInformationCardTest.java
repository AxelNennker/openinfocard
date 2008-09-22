package org.xmldap.infocard.roaming;


import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;

import org.junit.Before;
import org.xmldap.exceptions.SerializationException;
import org.xmldap.infocard.InfoCard;
import org.xmldap.infocard.TokenServiceReference;
import org.xmldap.infocard.UserCredential;
import org.xmldap.infocard.policy.SupportedClaim;
import org.xmldap.infocard.policy.SupportedClaimTypeList;
import org.xmldap.infocard.policy.SupportedToken;
import org.xmldap.infocard.policy.SupportedTokenList;
import org.xmldap.util.XmldapCertsAndKeys;
import org.xmldap.ws.WSConstants;

public class RoamingInformationCardTest extends TestCase {
	InfoCard card; 
	RoamingInformationCard ric;
	
	@Before
	public void setUp() throws Exception {

		{
			card = new InfoCard();
			card.setCardId("card1", 1);
			card.setIssuer("issuer");
			card.setTimeIssued("2006-09-28T12:58:26Z");
			{
				String displayName = "displayName";
				String uri = "uri";
				String description = "description";
				SupportedClaim claim = new SupportedClaim(displayName, uri, description);
				ArrayList<SupportedClaim> cl = new ArrayList<SupportedClaim>();
				cl.add(claim);
				SupportedClaimTypeList claimList = new SupportedClaimTypeList(cl);
				card.setClaimList(claimList);
			}
			{
				SupportedToken token = new SupportedToken(WSConstants.SAML11_NAMESPACE); // default is SAML11
				List<SupportedToken> list = new ArrayList<SupportedToken>();
				list.add(token);
				SupportedTokenList tokenList = new SupportedTokenList(list);
				card.setTokenList(tokenList);
			}
			{
				X509Certificate cert = XmldapCertsAndKeys.getXmldapCert1();
				UserCredential usercredential = new UserCredential(UserCredential.USERNAME, "username");
				TokenServiceReference tsr = new TokenServiceReference("sts", "mex", cert, usercredential);
				List<TokenServiceReference> tokenServiceReference = new ArrayList<TokenServiceReference>();
				tokenServiceReference.add(tsr);
				card.setTokenServiceReference(tokenServiceReference);
			}
			card.setPrivacyPolicy("privacyPolicyUrl", 1);
		}
		{
			InformationCardMetaData informationCardMetaData = new InformationCardMetaData(card, card.getIssuer());
			informationCardMetaData.setHashSalt("hashsalt");
			String masterKeyBase64 ="masterkeybytes";
			InformationCardPrivateData informationCardPrivateData = new ManagedInformationCardPrivateData(masterKeyBase64);
			ric = new RoamingInformationCard(informationCardMetaData, informationCardPrivateData);
		}
	}

	public void testToXml() throws SerializationException {
		String expected = "<RoamingInformationCard xmlns=\"http://schemas.xmlsoap.org/ws/2005/05/identity\"><InformationCardMetaData xml:lang=\"en\"><ic:InformationCard xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:ic=\"http://schemas.xmlsoap.org/ws/2005/05/identity\" xmlns:mex=\"http://schemas.xmlsoap.org/ws/2004/09/mex\" xmlns:wsa=\"http://www.w3.org/2005/08/addressing\" xmlns:wsid=\"http://schemas.xmlsoap.org/ws/2006/02/addressingidentity\" xmlns:wst=\"http://schemas.xmlsoap.org/ws/2005/02/trust\" xml:lang=\"en-us\"><ic:InformationCardReference><ic:CardId>card1</ic:CardId><ic:CardVersion>1</ic:CardVersion></ic:InformationCardReference><ic:CardImage MimeType=\"image/png\">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</ic:CardImage><ic:Issuer>issuer</ic:Issuer><ic:TimeIssued>2006-09-28T12:58:26Z</ic:TimeIssued><ic:TokenServiceList><ic:TokenService><wsa:EndpointReference><wsa:Address>sts</wsa:Address><wsa:Metadata><mex:Metadata><mex:MetadataSection><mex:MetadataReference><wsa:Address>mex</wsa:Address></mex:MetadataReference></mex:MetadataSection></mex:Metadata></wsa:Metadata><wsid:Identity><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDkDCCAvmgAwIBAgIJAO+Fcd4yj0h/MA0GCSqGSIb3DQEBBQUAMIGNMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEPMA0GA1UEChMGeG1sZGFwMScwJQYDVQQLFB5DaHVjayBNb3J0aW1vcmUgJiBBeGVsIE5lbm5rZXIxFzAVBgNVBAMTDnd3dy54bWxkYXAub3JnMB4XDTA3MDgxODIxMTIzMVoXDTE3MDgxNTIxMTIzMVowgY0xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMQ8wDQYDVQQKEwZ4bWxkYXAxJzAlBgNVBAsUHkNodWNrIE1vcnRpbW9yZSAmIEF4ZWwgTmVubmtlcjEXMBUGA1UEAxMOd3d3LnhtbGRhcC5vcmcwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAOKUn6/QqTZj/BWoQVxNFI0Z2AXI1azws+RyuJek60NiawQrFAKk0Ph+/YnUiQAnzbsT+juZV08UpaPa2IE3g0+RFZtODlqoGGGakSOd9NNnDuNhsdtXJWgQq8paM9Sc4nUue31iq7LvmjSGSL5w84NglT48AcqVGr+/5vy8CfT/AgMBAAGjgfUwgfIwHQYDVR0OBBYEFGcwQKLQtW8/Dql5t70BfXX66dmaMIHCBgNVHSMEgbowgbeAFGcwQKLQtW8/Dql5t70BfXX66dmaoYGTpIGQMIGNMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEPMA0GA1UEChMGeG1sZGFwMScwJQYDVQQLFB5DaHVjayBNb3J0aW1vcmUgJiBBeGVsIE5lbm5rZXIxFzAVBgNVBAMTDnd3dy54bWxkYXAub3JnggkA74Vx3jKPSH8wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOBgQAYQisGgrg1xw0TTgIZcz3JXr+ZtwjeKqEewoxCxBz1uki7hJYHIznEZq4fzSMtcBMgbKmOTzFNV0Yr/tnJ9rrljRf8EXci62ffzj+Kkny7JtM6Ltxq0BJuF3jrXogdbsc5J3W9uJ7C2+uJTHG1mApbOdJGvLAGLCaNw5NpP7+ZXQ==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></wsid:Identity></wsa:EndpointReference><ic:UserCredential><ic:DisplayCredentialHint>Please enter your username and password.</ic:DisplayCredentialHint><ic:UsernamePasswordCredential><ic:Username>username</ic:Username></ic:UsernamePasswordCredential></ic:UserCredential></ic:TokenService></ic:TokenServiceList><ic:SupportedTokenTypeList><wst:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</wst:TokenType></ic:SupportedTokenTypeList><ic:SupportedClaimTypeList><ic:SupportedClaimType Uri=\"uri\"><ic:DisplayTag>displayName</ic:DisplayTag><ic:Description>description</ic:Description></ic:SupportedClaimType></ic:SupportedClaimTypeList><ic:PrivacyNotice Version=\"1\">privacyPolicyUrl</ic:PrivacyNotice><ic07:RequireStrongRecipientIdentity xmlns:ic07=\"http://schemas.xmlsoap.org/ws/2007/01/identity\" /></ic:InformationCard><IsSelfIssued>false</IsSelfIssued><HashSalt>hashsalt</HashSalt><TimeLastUpdated>2006-09-28T12:58:26Z</TimeLastUpdated><IssuerId /><IssuerName>issuer</IssuerName><BackgroundColor>16777215</BackgroundColor></InformationCardMetaData><InformationCardPrivateData><MasterKey>masterkeybytes</MasterKey></InformationCardPrivateData></RoamingInformationCard>";
		assertEquals(expected, ric.toXML());
	}
}
