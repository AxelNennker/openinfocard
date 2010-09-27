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

//Implements Kevin's contract:
//IIdentitySelector.GetBrowserToken(data.issuer , data.recipientURL, data.requiredClaims ,data.optionalClaims , data.tokenType ,data.privacyPolicy, data.privacyPolicyVersion ,sslStatus.serverCert );

const Cu = Components.utils;
Cu.import("resource://gre/modules/XPCOMUtils.jsm");

const nsISupports = Components.interfaces.nsISupports;
const IIdentitySelector = Components.interfaces.IIdentitySelector;

const IIDENTITYSELECTOR_IID_STR = "ddd9bc02-c964-4bd5-b5bc-943e483c6c57";

const CONTRACT_ID = "@xmldap.org/identityselector;1";
const CLASS_ID = Components.ID("{72e894fd-0d6c-484d-abe8-5903b5f8bf3b}");
const CLASS_NAME = "The openinfocard identity selector";

const SELECTOR_CLASS_NAME = "OpeninfocardSelector";

const nsIX509Cert = Components.interfaces.nsIX509Cert;

const CATMAN_CONTRACTID = "@mozilla.org/categorymanager;1";
const nsICategoryManager = Components.interfaces.nsICategoryManager;

function Xmldapidentityselector() {
  this.wrappedJSObject = this;  
}

Xmldapidentityselector.prototype = {
    classDescription: CLASS_NAME,  
    classID:          CLASS_ID,  
    contractID:       CONTRACT_ID,  
    _xpcom_categories : [ {
      category : IIDENTITYSELECTOR_IID_STR,
      entry : CLASS_NAME,
      value : SELECTOR_CLASS_NAME + ':' + CONTRACT_ID,
      service : false
    } ],
    QueryInterface: XPCOMUtils.generateQI([IIdentitySelector]),
    
    GetBrowserToken: function (
     issuer , recipientURL, requiredClaims, optionalClaims , tokenType, 
     privacyPolicy, privacyPolicyVersion, serverCert, issuerPolicy, 
     extraParamsLenght, extraParams) {

    debug('issuer: ' + issuer);
    debug('recipientURL: ' + recipientURL);
    if (requiredClaims !== null) {
      requiredClaims = requiredClaims.replace(/\s+/g,' ');
    }
    debug('requiredClaims: ' + requiredClaims);
    if (optionalClaims !== null) {
      optionalClaims = optionalClaims.replace(/\s+/g,' ');
    }
    debug('optionalClaims: ' + optionalClaims);
    debug('tokenType: ' + tokenType);
    debug('privacyPolicy: ' + privacyPolicy);
    debug('privacyPolicyVersion: ' + privacyPolicyVersion);
    debug('serverCert: ' + serverCert);
    debug('issuerPolicy: ' + issuerPolicy);
    debug('extraParamsLenght: ' + extraParamsLenght);


    var callback;

    var policy = {};
    if (tokenType) {
      policy.tokenType = tokenType;
    }
    if (issuer) {
      policy.issuer = issuer;
    }
    if (requiredClaims) {
      policy.requiredClaims = requiredClaims;
    }
    if (optionalClaims) {
      policy.optionalClaims = optionalClaims;
    }
    if (privacyPolicy) {
      policy.privacyUrl = privacyPolicy;
    }
    if (privacyPolicyVersion) {
      policy.privacyVersion = privacyPolicyVersion;
    }
    if (issuerPolicy) {
      policy.issuerPolicy = issuerPolicy;
    }
    if (extraParamsLenght) {
      policy.extraParamsLenght = extraParamsLenght;
    }
    if (extraParams) {
      policy.extraParams = extraParams;
    }

    //get a handle on a window
    var wm = Components.classes["@mozilla.org/appshell/window-mediator;1"].getService(Components.interfaces.nsIWindowMediator);
    var win = wm.getMostRecentWindow("navigator:browser");

    var mwNode = win.document.getElementById("main-window");
    if (mwNode) {
      if (mwNode.style.backgroundImage) {
        policy.backgroundImage = mwNode.style.backgroundImage;
        debug('backgroundImage: ' + mwNode.style.backgroundImage);
      }
    }
    
    if (serverCert != null) {
      policy["cert"] = getDer(serverCert,win);
      policy["cn"] = serverCert.commonName;

      var chain = serverCert.getChain();
      debug('chain: ' + chain);
      debug('chainLength: ' + chain.length);
      debug('chain[0]: ' + chain.queryElementAt(0, nsIX509Cert));

      policy["chainLength"] = ""+chain.length;
      for (var i = 0; i < chain.length; ++i) {
        var currCert = chain.queryElementAt(i, nsIX509Cert);
        policy["certChain"+i] = getDer(currCert,win);
      }
//			debugObject("serverCert: ", serverCert, 0);
    }

        // win.document.URL is undefined
        // win.document.location.href is chrome://.../browser.xul
		policy["url"] = recipientURL; 

		if ("urn:oasis:names:tc:IC:1.0:managedcard" == tokenType) {
			var cardWiz = win.openDialog("chrome://infocard/content/cardWizard.xul","Card Wizard", "modal,chrome,resizable=yes,width=640,height=480",
                policy, function (callbackData) { callback = callbackData;});
			
		} else {
	        var cardManager = win.openDialog("chrome://infocard/content/cardManager.xul","InfoCard Selector", "modal,chrome,resizable,width=800,height=640,centerscreen", policy, function (callbackData) { callback = callbackData;});
	        var doc = win.document;
	        var event = doc.createEvent("Events");
	        event.initEvent("CloseIdentitySelector", true, true);
	        win.dispatchEvent(event);
	
	        debug('Token: ' + callback);
		}

        return callback;

    },

}


function getDer(cert,win){

    var length = {};
    var derArray = cert.getRawDER(length);
    var certBytes = '';
    for (var i = 0; i < derArray.length; i++) {
        certBytes = certBytes + String.fromCharCode(derArray[i]);
    }
    return win.btoa(certBytes);

}

/**
* XPCOMUtils.generateNSGetFactory was introduced in Mozilla 2 (Firefox 4).
* XPCOMUtils.generateNSGetModule is for Mozilla 1.9.2 (Firefox 3.6).
*/
if (XPCOMUtils.generateNSGetFactory) {
  var NSGetFactory = XPCOMUtils.generateNSGetFactory([Xmldapidentityselector]);
} else {
  var NSGetModule = XPCOMUtils.generateNSGetModule([Xmldapidentityselector]);
}


function debugObject(prefix, object, indent) {
	var msg = "";
	var count = 0;
	//if (indent > 3) return;
	var pre = "";
	for (var j=0; j<indent; j++) { pre += '\t'; }
	for (var i in object) {
		var value = object[i];
		if (typeof(value) == 'object') {
			//debugObject(prefix, value, indent+1);
			msg += pre + i + ' type=' + typeof(value) + ':' + value + '\n';
//			debug(prefix + pre + i + ' type=' + typeof(value) + ':' + value);
		} else if ((typeof(value) == 'string') || ((typeof(value) == 'boolean')) || ((typeof(value) == 'number'))) {
			msg += pre + ':' + i + '=' + value + '\n';
//			debug(prefix + pre + ':' + i + '=' + value);
		} else {
			msg += pre + i + ' type=' + typeof(value) + '\n'
//			debug(prefix + pre + i + ' type=' + typeof(value));
		}
	}
	debug(msg);
}

function debug(msg) {
  var debug = Components.classes["@mozilla.org/consoleservice;1"].getService(Components.interfaces.nsIConsoleService);
  debug.logStringMessage("XMLDAP: " + msg);
}