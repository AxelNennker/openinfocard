package org.xmldap.util;

import java.io.UnsupportedEncodingException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.SimpleTimeZone;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEREncodableVector;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x509.Attribute;

public class SubjectDirectoryAttributes implements ASN1Encodable {
	// http://asn1.elibel.tm.fr/cgi-bin/oid/display?oid=1.3.6.1.5.5.7.9&action=display
	// PKIX personal data gender
	public static final String genderOidStr = "1.3.6.1.5.5.7.9.4";

	// PKIX personal data dateOfBirth
	public static final String dateOfBirthOidStr = "1.3.6.1.5.5.7.9.1";

	public static final String streetAddressOidStr = "2.5.4.9";

	public static final String telephoneNumberOidStr = "2.5.4.20";
	
	// http://oid.elibel.tm.fr/0.9.2342.19200300.100.1.41
	public static final String mobileTelephoneNumberOidStr = "0.9.2342.19200300.100.1.41";

	// 2.5.4.20 - id-at-telephoneNumber
	// http://www.alvestrand.no/objectid/2.5.4.html

	// 1.3.6.1.3.x internet experimental

	ASN1Sequence seq;

	public SubjectDirectoryAttributes(Attribute attribute) {
		this.seq = new DERSequence(attribute);
	}

	public SubjectDirectoryAttributes(DEREncodableVector attributes) {
		this.seq = new DERSequence(attributes);
	}

	static public Attribute string2Attribute(DERObjectIdentifier oid,
			String value) throws UnsupportedEncodingException {
		if ((value != null) && !value.equals("")) {
			DERPrintableString genderValue = new DERPrintableString(value);
			ASN1Set valueSet = new DERSet(genderValue);
			Attribute attr = new Attribute(DERObjectIdentifier.getInstance(oid), valueSet);
			return attr;
		} else {
			return null;
		}
	}

	static public Attribute gender2Attribute(String value)
			throws UnsupportedEncodingException {
		// id-pda-gender AttributeType ::= { id-pda 3 }
		// Gender ::= PrintableString (SIZE(1))
		if (value.length() > 1) {
			value = value.substring(1, 1);
		}
		return string2Attribute(new DERObjectIdentifier(genderOidStr), value);
	}

	static public Attribute streetAddress2Attribute(String value)
			throws UnsupportedEncodingException {
		// DirectoryString ::= CHOICE {
		// teletexString TeletexString (SIZE (1..MAX)),
		// printableString PrintableString (SIZE (1..MAX)),
		// universalString UniversalString (SIZE (1..MAX)),
		// utf8String UTF8String (SIZE (1..MAX)),
		// bmpString BMPString (SIZE (1..MAX))  }
		return string2Attribute(new DERObjectIdentifier(streetAddressOidStr),
				value);
	}

	static public Attribute telephoneNumber2Attribute(String value)
			throws UnsupportedEncodingException {
		// telephoneNumber ATTRIBUTE ::= {
		// WITH SYNTAX PrintableString (SIZE (1..ub-telephone-number))
		// EQUALITY MATCHING RULE telephoneNumberMatch
		// SUBSTRINGS MATCHING RULE telephoneNumberSubstringsMatch
		// ID id-at-telephoneNumber	}
		return string2Attribute(new DERObjectIdentifier(telephoneNumberOidStr),
				value);
	}

	static public Attribute dateOfBirth2Attribute(Date date)
			throws UnsupportedEncodingException {
		// id-pda-dateOfBirth AttributeType ::= { id-pda 1 }
		// DateOfBirth ::= GeneralizedTime
        SimpleTimeZone      tz = new SimpleTimeZone(0, "Z");
        SimpleDateFormat    dateF = new SimpleDateFormat("yyyyMMddHHmmss");

        dateF.setTimeZone(tz);
        String  d = dateF.format(date) + "Z";
        DERGeneralizedTime time = new DERGeneralizedTime(d);
		ASN1Set valueSet = new DERSet(time);
		Attribute attr = new Attribute(new ASN1ObjectIdentifier(dateOfBirthOidStr), valueSet);
		return attr;
	}

	public SubjectDirectoryAttributes(String gender, Date dateOfBirth,
			String streetAddress, String telephoneNumber) {
		ASN1EncodableVector attributes = new ASN1EncodableVector();

		Attribute attr = null;
		try {
			attr = gender2Attribute(gender);
			if (attr != null) {
				attributes.add(attr);
			}
			attr = dateOfBirth2Attribute(dateOfBirth);
			if (attr != null) {
				attributes.add(attr);
			}
			attr = streetAddress2Attribute(streetAddress);
			if (attr != null) {
				attributes.add(attr);
			}
			attr = telephoneNumber2Attribute(telephoneNumber);
			if (attr != null) {
				attributes.add(attr);
			}
		} catch (UnsupportedEncodingException e) {
			// if UTF-8 is unsupported, then something is terribly wrong
			e.printStackTrace();
		}
		this.seq = new DERSequence(attributes);
	}

	public int size() {
		if (seq != null)
			return seq.size();
		return 0;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		return seq;
	}

}
