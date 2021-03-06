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
 */package org.xmldap.asn1;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class LogotypeAudio implements ASN1Encodable {
//	LogotypeAudio ::= SEQUENCE {
//		   audioDetails    LogotypeDetails,
//		   audioInfo       LogotypeAudioInfo OPTIONAL }
	ASN1Sequence audioDetails = null;
	ASN1Sequence audioInfo = null;

	public static LogotypeAudio getInstance(ASN1Sequence obj) {
		if (obj.size() == 2) {
			ASN1Sequence audioDetails = ASN1Sequence.getInstance(obj.getObjectAt(0));
			ASN1Sequence audioInfo = ASN1Sequence.getInstance(obj.getObjectAt(1));
			return new LogotypeAudio(audioDetails, audioInfo);
		}
		throw new IllegalArgumentException("sequence must have length 2");
	}
	
	public LogotypeAudio(ASN1Sequence audioDetails, ASN1Sequence audioInfo) {
		this.audioDetails = audioDetails;
		this.audioInfo = audioInfo;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(audioDetails);
		v.add(audioInfo);
		return new DERSequence(v);
	}
}
