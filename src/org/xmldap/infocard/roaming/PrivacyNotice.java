package org.xmldap.infocard.roaming;

import java.net.URI;
import java.net.URISyntaxException;

import nu.xom.Element;

import org.xmldap.exceptions.ParsingException;

public class PrivacyNotice {
	long version = -1;
	String uri = null;
	
	public PrivacyNotice(String uri, long version) throws URISyntaxException {
		setUri(uri);
		setVersion(version);
	}
	
	public PrivacyNotice(Element privacyNotice) throws ParsingException {
//		<ic:PrivacyNotice Version=�xs:unsignedInt�?> xs:anyURI </ic:PrivacyNotice>
		if ("PrivacyNotice".equals(privacyNotice.getLocalName())) {
			nu.xom.Attribute versionA = privacyNotice.getAttribute("Version");
			if (versionA != null) {
				try {
					version = Integer.valueOf(versionA.getValue()).longValue();
					if (version < 0) {
						throw new ParsingException("PrivacyNotice Version must be greater then zero: " + version);
					}
				}
				catch (NumberFormatException e) {
					throw new ParsingException( "PrivacyNotice Version is not a number: " + versionA.getValue(), e);
				}
			} // else optional
			
			uri = privacyNotice.getValue();
			try {
				URI u = new URI(uri);
				uri = u.toASCIIString();
			} catch (URISyntaxException e) {
				throw new ParsingException("PrivacyNotice uri is not a valid uri: " + uri, e);
			}
		} else {
			throw new ParsingException("Expected PrivacyNotice");
		}
	}
	public long getVersion() {
		return version;
	}
	public void setVersion(long version) {
		if (version < 0) {
			throw new IllegalArgumentException("PrivacyNotice version must be greater then zero");
		}
		this.version = version;
	}
	public String getUri() {
		return uri;
	}
	public void setUri(String uriASCIIString) throws URISyntaxException {
		this.uri = new URI(uriASCIIString).toASCIIString();
	}
}
