package org.xmldap.xmldsig;

import java.security.InvalidParameterException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import nu.xom.Element;
import nu.xom.Elements;

import org.xmldap.crypto.CryptoUtils;
import org.xmldap.exceptions.CryptoException;
import org.xmldap.exceptions.ParsingException;
import org.xmldap.ws.WSConstants;

public class ParsedX509Data {
//  <dsig:X509Data>
//  <dsig:X509Certificate>MIIDjzCCAvigAwIBAgIG ... RPo71Qg6ApCinzllSDoga5zFbSS8pzX</dsig:X509Certificate>
// </dsig:X509Data>
	ArrayList<X509Certificate> certs = null;
	public ParsedX509Data(Element element) throws ParsingException {
		Elements kids = element.getChildElements("X509Certificate", WSConstants.DSIG_NAMESPACE);
		if (kids.size() > 0) {
			certs = new ArrayList<X509Certificate>(kids.size());
			for (int index=0; index<kids.size(); index++) {
				Element child = kids.get(index);
				String certificateB64 = child.getValue();
				try {
//					System.err.println("ParsedX509Data: index=" + index + "; cert=" + certificateB64);
					X509Certificate cert = CryptoUtils.X509fromB64(certificateB64);
//					cert.checkValidity();
					certs.add(cert);
				} catch (CryptoException e) {
					throw new ParsingException(e);
//				} catch (CertificateExpiredException e) {
//					throw new ParsingException(e);
//				} catch (CertificateNotYetValidException e) {
//					throw new ParsingException(e);
				}
			}
		} else {
			throw new InvalidParameterException("Expected child element 'X509Certificate'");
		}

	}
	public List<X509Certificate> getCertificates() {
		return certs;
	}
}
