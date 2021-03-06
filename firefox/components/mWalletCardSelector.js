/*
 * Copyright (c) 2009, Axel Nennker
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

const Cc = Components.classes;
const Ci = Components.interfaces;
const Cr = Components.results;
const Cu = Components.utils;

Cu.import("resource://gre/modules/XPCOMUtils.jsm");

const nsISupports = Components.interfaces.nsISupports;
const IIdentitySelector = Components.interfaces.IIdentitySelector;

const CONTRACT_ID = "@openinfocard.org/cardstore-phone;1";
const CLASS_ID = Components.ID("{72e894fd-0d6c-484d-abe8-5903b5f8bf3c}");
const CLASS_NAME = "The phone card selector";

const SELECTOR_CLASS_NAME = "mWalletSelector";

const nsIX509Cert = Components.interfaces.nsIX509Cert;

const CATMAN_CONTRACTID = "@mozilla.org/categorymanager;1";
const nsICategoryManager = Components.interfaces.nsICategoryManager;

function debug(msg) {
    var cs = Components.classes["@mozilla.org/consoleservice;1"].getService(Components.interfaces.nsIConsoleService);
    cs.logStringMessage("WALLET: " + msg);
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
//      debug(prefix + pre + i + ' type=' + typeof(value) + ':' + value);
    } else if ((typeof(value) == 'string') || ((typeof(value) == 'boolean')) || ((typeof(value) == 'number'))) {
      msg += pre + ':' + i + '=' + value + '\n';
//      debug(prefix + pre + ':' + i + '=' + value);
    } else {
      msg += pre + i + ' type=' + typeof(value) + '\n';
//      debug(prefix + pre + i + ' type=' + typeof(value));
    }
  }
  debug(msg);
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

function mWalletIdentitySelector() {
  this.wrappedJSObject = this;  
}

mWalletIdentitySelector.prototype = {
  classDescription: CLASS_NAME,
  classID:          CLASS_ID,  
  contractID:       CONTRACT_ID,  
  _xpcom_categories: [{  
         category: "information-card-storage",
         entry: "@openinfocard.org/cardstore-phone;1",
         service: true  
  }],  
  // QueryInterface implementation
  QueryInterface: XPCOMUtils.generateQI([Ci.IInformationCardStore,
                                         Ci.nsISupports]),
  errorstring: "",
  errornumber: 0,

  /* returns true on success */
  login : function login(credentials) {
    return true;
  },
  
  logout : function logout() {
  },

  loggedIn : function loggedIn() {
    return true;
  },


  clearCardStore : function clearCardStore() {
  },

  // the informationCardXml is defined in ISIP 1.5
  addCard : function addCard(informationCardXml) {
  },
  removeCard : function removeCard(cardId) {
  },

  // the roamingStoreXml is defined in ISIP 1.5
  addCardsFromRoamingStore : function addCardsFromRoamingStore(roamingStoreXml) {
  },

  // the informationCardXml is defined in ISIP 1.5
  updateCard : function updateCard(informationCardXml, cardId) {
    // Fixme
  },

  getAllCardIds : function getAllCardIds(count, cardIds) {
    count = 0;
    cardIds = []; // FIXME
  },

  getCardCount : function getCardCount() {
    var count = 0; // FIXME
    return count;
  },

  //    nsISimpleEnumerator getInformationCards();
  getInformationCards : function getInformationCards() {
    return new CardEnumerator();
  },
  
  // returns an encrypted card store as defined in ISIP 1.5
  cardStoreExportAllCards : function cardStoreExportAllCards(password) {
    return null;
  },
  cardStoreExportCards : function cardStoreExportCards(password, count, cardIds) {
    return null;
  },

  // this may return null if this cardStore is not willing to reveal the mastersecret
  getMasterSecretForCard : function getMasterSecretForCard(cardId) {
    return null;
  },
  
  getRpIdentifier : function getRpIdentifier(cardId, relyingPartyCertificate) {
    return null;
  },
  
  getCardByPPID : function getCardByPPID(PPID, relyingPartyCertificate) {
    return null;
  },

  getCardStoreName : function getCardStoreName() {
    return "NFC Phone"; //this.mDB;
  },
  getCardStoreVersion : function getCardStoreVersion() {
    return "1.0";
  },

  GetBrowserToken: function (
     issuer , recipientURL, requiredClaims, optionalClaims , tokenType, 
     privacyPolicy, privacyPolicyVersion, serverCert, issuerPolicy, 
     extraParamsLenght, extraParams) {

        debug('issuer: ' + issuer);
        debug('recipientURL: ' + recipientURL);
        debug('requiredClaims: ' + requiredClaims);
        debug('optionalClaims: ' + optionalClaims);
        debug('tokenType: ' + tokenType);
        debug('privacyPolicy: ' + privacyPolicy);
        debug('privacyPolicyVersion: ' + privacyPolicyVersion);
        debug('serverCert: ' + serverCert);
        debug('issuerPolicy: ' + issuerPolicy);
        debug('extraParamsLenght: ' + extraParamsLenght);


        var callback;

        var policy = {};
        policy.tokenType = tokenType;
        policy.issuer = issuer;
        policy.requiredClaims = requiredClaims;
        policy.optionalClaims = optionalClaims;
        policy.privacyUrl = privacyPolicy;
        policy.privacyVersion = privacyPolicyVersion;
        policy.issuerPolicy = issuerPolicy;
        policy.extraParamsLenght = extraParamsLenght;
        policy.extraParams = extraParams;

        //get a handle on a window
        var wm = Components.classes["@mozilla.org/appshell/window-mediator;1"].getService(Components.interfaces.nsIWindowMediator);
        var win = wm.getMostRecentWindow("navigator:browser");

    if (serverCert !== null) {
          policy.cert = getDer(serverCert,win);
          policy.cn = serverCert.commonName;

        var chain = serverCert.getChain();
      debug('chain: ' + chain);
      debug('chainLength: ' + chain.length);
      debug('chain[0]: ' + chain.queryElementAt(0, nsIX509Cert));
      
      policy.chainLength = ""+chain.length;
      for (var i = 0; i < chain.length; ++i) {
        var currCert = chain.queryElementAt(i, nsIX509Cert);
        policy["certChain"+i] = getDer(currCert,win);
      }
      
//      debugObject("serverCert: ", serverCert, 0);
    }
    
        // win.document.URL is undefined
        // win.document.location.href is chrome://.../browser.xul
    policy.url = recipientURL; 

        var cardManager = win.openDialog("chrome://infocard/content/mWallet.xul","Phone Card Selector", "modal,chrome,resizable,width=800,height=640,centerscreen", policy, function (callbackData) { callback = callbackData;});
        var doc = win.document;
        var event = doc.createEvent("Events");
        event.initEvent("CloseIdentitySelector", true, true);
        win.dispatchEvent(event);
        
        debug('Token: ' + callback);

        return callback;

    }

};

function CardEnumerator() {
  this.index = 0;
  this.cardFile = null;
}

CardEnumerator.prototype.QueryInterface = function(iid) {
  if (iid.equals(Components.interfaces.nsISupports) ||
      iid.equals(Components.interfaces.nsISimpleEnumerator))
    return this;
  throw Components.results.NS_NOINTERFACE;
};

CardEnumerator.prototype.getNext = function() {
  return null;
};

CardEnumerator.prototype.hasMoreElements = function() {
  return false;
};

/**
* XPCOMUtils.generateNSGetFactory was introduced in Mozilla 2 (Firefox 4).
* XPCOMUtils.generateNSGetModule is for Mozilla 1.9.2 (Firefox 3.6).
*/
if (XPCOMUtils.generateNSGetFactory) {
  var NSGetFactory = XPCOMUtils.generateNSGetFactory([mWalletIdentitySelector]);
} else {
  var NSGetModule = XPCOMUtils.generateNSGetModule([mWalletIdentitySelector]);
}
