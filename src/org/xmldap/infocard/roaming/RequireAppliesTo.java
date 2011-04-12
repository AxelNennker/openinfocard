package org.xmldap.infocard.roaming;

import nu.xom.Attribute;
import nu.xom.Element;

import org.xmldap.exceptions.ParsingException;

public class RequireAppliesTo {
// <ic:RequireAppliesTo Optional=”xs:boolean” /> ?
	boolean optional = false;
	public RequireAppliesTo(Element requireAppliesTo) throws ParsingException {
		Attribute optionalA = requireAppliesTo.getAttribute("Optional");
		if (optionalA != null) {
			if ("true".equals(optionalA.getValue()) || "1".equals(optionalA.getValue())) {
				optional = true;
			} else if ("false".equals(optionalA.getValue()) || "0".equals(optionalA.getValue())) {
				optional = false;
			} else {
				throw new ParsingException("Value of attribute Optional must be one of true,1,false,0");
			}
		} else {
			optional = false;
		}
	}
	
	public RequireAppliesTo(boolean optional) {
		this.optional = optional;
	}
	
	public boolean getOptional() {
		return optional;
	}
}
