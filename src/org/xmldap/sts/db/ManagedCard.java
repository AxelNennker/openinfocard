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


package org.xmldap.sts.db;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.xmldap.util.RandomGUID;


public class ManagedCard {


    private String cardName;
    private String cardId;
    private String privatePersonalIdentifier;
    private int cardVersion = 1;
    private String timeIssued;
    private String timeExpires;
    boolean requireAppliesTo = false;
    boolean requireStrongRecipientIdentity = true;
    
    private String cardfrontimage = null;
	private String cardbackimage = null;
    private String icon = null;
    
	private String frontHtml = null;
	private String backHtml = null;
	
    private Map<String,Object> supportedClaims = new HashMap<String,Object>();

    public ManagedCard() {
        RandomGUID guid = new RandomGUID();
        cardId =  guid.toString();
        privatePersonalIdentifier =  guid.toString();
    }


    public ManagedCard(String cardId) {
        this.cardId =  cardId;
        privatePersonalIdentifier =  cardId;
    }

    public String getCardName() {
        return cardName;
    }

    public void setCardName(String cardName) {
        this.cardName = cardName;
    }

    public String getPrivatePersonalIdentifier() {
        return privatePersonalIdentifier;
    }

    public void setPrivatePersonalIdentifier(String privatePersonalIdentifier) {
        this.privatePersonalIdentifier = privatePersonalIdentifier;
    }

    public String getCardId() {
        return cardId;
    }

    public void setCardId(String cardId) {
        this.cardId = cardId;
    }

    public int getCardVersion() {
        return cardVersion;
    }

    public void setCardVersion(int cardVersion) {
        this.cardVersion = cardVersion;
    }

    public String getTimeIssued() {
        return timeIssued;
    }

    public void setTimeIssued(String timeIssued) {
    	if (timeIssued == null) throw new IllegalArgumentException("timeissued is required and must not be null");
    	if ("".equals(timeIssued)) throw new IllegalArgumentException("timeissued is required and must not be empty");
        this.timeIssued = timeIssued;
    }

    public String getTimeExpires() {
        return timeExpires;
    }

    public void setTimeExpires(String timeExpires) {
        this.timeExpires = timeExpires;
    }

    public String getClaim(String uri) {
    	return (String)supportedClaims.get(uri);
    }
    
    public void setClaim(String uri, String value) {
    	supportedClaims.put(uri, value);
    }
    
    public Set<String>getClaims() {
    	return supportedClaims.keySet();
    }


	public boolean getRequireAppliesTo() {
		return requireAppliesTo;
	}


	public void setRequireAppliesTo(boolean requireAppliesTo) {
		this.requireAppliesTo = requireAppliesTo;
	}


	public boolean getRequireStrongRecipientIdentity() {
		return requireStrongRecipientIdentity;
	}


	public void setRequireStrongRecipientIdentity(
			boolean requireStrongRecipientIdentity) {
		this.requireStrongRecipientIdentity = requireStrongRecipientIdentity;
	}
    
    public String getCardfrontimage() {
		return cardfrontimage;
	}


	public void setCardfrontimage(String cardfrontimage) {
		this.cardfrontimage = cardfrontimage;
	}


	public String getCardbackimage() {
		return cardbackimage;
	}


	public void setCardbackimage(String cardbackimage) {
		this.cardbackimage = cardbackimage;
	}


	public String getIcon() {
		return icon;
	}


	public void setIcon(String icon) {
		this.icon = icon;
	}


	public String getFrontHtml() {
		return frontHtml;
	}


	public void setFrontHtml(String frontHtml) {
		this.frontHtml = frontHtml;
	}


	public String getBackHtml() {
		return backHtml;
	}


	public void setBackHtml(String backHtml) {
		this.backHtml = backHtml;
	}

}
