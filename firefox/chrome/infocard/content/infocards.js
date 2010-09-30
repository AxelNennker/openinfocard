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

var selectedCard;
var selectorDebugging = true;
var tokenIssuerInitialized = false;

var gOpenIdManager = null;

Components.utils.import("resource://infocard/CardstoreToolkit.jsm");
Components.utils.import("resource://infocard/OICCrypto.jsm");
Components.utils.import("resource://infocard/tokenissuer.jsm");
Components.utils.import("resource://infocard/IdentitySelectorDiag.jsm");
Components.utils.import("resource://infocard/cmDebug.jsm");
Components.utils.import("resource://infocard/InformationCardHelper.jsm");

function getPolicy(){
  var policy = null;
  if ((window.hasOwnProperty("arguments")) && (window.arguments !== undefined) && (window.arguments.length > 0)) {
      policy = window.arguments[0];
  }
  return policy;
}

//update the list of RPs to where a card has been sent
//this function is called from "ok" -> selectedCard is set
function updateRPIDs(policy) {
  var relyingPartyCertB64 = policy.cert;
  var rpIdentifier = computeRpIdentifier(relyingPartyCertB64);
  var count = 0;
  var xmllist = selectedCard.rpIds;
  for (var i=0; i<xmllist.length(); i++) {
    var rpId = xmllist[i].toString();
    count++;
    icDebug("updateRPIDs:" + selectedCard.name + " rpId:" + rpId + " rpIdentifier:" + rpIdentifier);
    if (rpId == rpIdentifier) {
      // this RP is already in list of RPs
      return false;
    }
  }
  selectedCard.rpIds[count] = rpIdentifier;
  return true;
}

//update the list of RPs to where a card has been sent
//this function is called from "ok" -> selectedCard is set
function updateRPPPID(policy) {
  var rpPPID = policy.rpPPID;
  icDebug("updateRPs rpPPID=" + rpPPID);
  var rpPPIdList = selectedCard.rpPPID;
  var count = 0;
  for (var j=0; j<rpPPIdList.length(); j++) {
    var aRpPPID = rpPPIdList[j].toString();
    count++;
    icDebug("updateRPs:" + selectedCard.name + " aRpPPID:" + aRpPPID + " rpPPID:" + rpPPID);
    if (aRpPPID == rpPPID) {
      // this rpPPID is already in list of rpPPID
      return false;
    }
  }
  selectedCard.rpPPID[count] = rpPPID;
  return true;
}

//update the list of RPs to where a card has been sent
//this function is called from "ok" -> selectedCard is set
function updateRPs(policy) {
  if (!policy) {
    policy = getPolicy();
  }
  var n1, n2;
  
  if (policy) {
    if (policy.hasOwnProperty("cert")) {
      n1 = updateRPIDs(policy);
    }
    if (policy.hasOwnProperty("rpPPID")) {
      n2 = updateRPPPID(policy);
    }
    if (n1 || n2) {
      updateCard(selectedCard); // save to disk
    }
  } // else nothing
}

function computeClientPseudonymPre20080829(policy){
  var url = policy.url; // RP url
  return OICCrypto.hex_sha1(url + selectedCard.id);
}

function getRandomBytes(howMany) {
    var i;
    var bytes = [];
    for (i=0; i<howMany; i++) {
      bytes[i] = Math.round(Math.random()*255);
    }
    return bytes;
}

//return binary value of hashsalt
function getHashSalt(card) {
  var hashSalt;
  if (card.hashsalt !== undefined) {
    hashSalt = window.atob(card.hashsalt);
  } else {
    hashSalt = "" + getRandomBytes(256);
    card.hashsalt = window.btoa(hashsalt);
    icDebug("card.hashsalt: " + card.hashsalt);
    storeCard(card);
    hashSalt = window.atob(card.hashsalt);
  }
  return hashSalt;
}

//return binary value of masterkey
function getMasterKey(card) {
  var masterkey;
  if (card.masterkey !==undefined) {
    masterkey = window.atob(card.masterkey);
  } else {
    masterkey = "" + getRandomBytes(256);
    card.masterkey = window.btoa(masterkey);
    icDebug("card.masterkey: " + card.masterkey);
    storeCard(card);
    masterkey = window.atob(card.masterkey);
  }
  return masterkey;
}

function certFromB64(certB64) {
  
}

function getCaCertForServerCert(cert)
{
   var i=1;
   var nextCertInChain;
   nextCertInChain = cert;
   var lastSubjectName="";
   while(true)
   {
     if(nextCertInChain === null)
     {
        return null;
     }
     if((nextCertInChain.type == nsIX509Cert.CA_CERT) ||
                                 (nextCertInChain.subjectName = lastSubjectName))
     {
        break;
     }

     lastSubjectName = nextCertInChain.subjectName;
     nextCertInChain = nextCertInChain.issuer;
   }

   return nextCertInChain;
}

function computeRpPpidSeed(policy) {
  var relyingPartyCertB64 = null;
  if (policy.hasOwnProperty("cert")) {
    relyingPartyCertB64 = policy.cert;
  }
    if (relyingPartyCertB64 !==null) {
    var cert = certFromB64(relyingPartyCertB64);
      if (isEV(relyingPartyCertB64)) {
      } else {
      }
    } else {
    }
}

// returns the base64 encoded value of ClientPseudonym
function computeClientPseudonymPost20080829(policy){
  var url = policy.url; // RP url
  var relyingPartyCertB64 = null;
  if (policy.hasOwnProperty("cert")) {
    relyingPartyCertB64 = policy.cert;
  }

  var rpPpidSeed = computeRpPpidSeed(policy);
  var hashSalt = getHashSalt(selectedCard);
  var masterkey = getMasterKey(selectedCard);
  var clientPseudonymPpidBytes = sha256(masterkey + rpPpidSeed + hashsalt);
  return window.btoa(clientPseudonymPpidBytes);
}

function finish(tokenToReturn) {

  icDebug("Token: " + tokenToReturn);
  if (tokenToReturn !==null) {
    window.arguments[1](tokenToReturn);
  }
  window.close();
}

function getXmldapHttpListener() {
  try {
    const CONTRACT_ID = "@xmldap/httplistener-service;1";
    icDebug("registerOpenIdListener start. href=" + CONTRACT_ID );
      var claszInstance = null;
      try {
        var clasz = Components.classes[CONTRACT_ID];
      if (clasz !== undefined) {
        icDebug("registerOpenIdListener start. href=" + clasz );
        claszInstance = clasz.createInstance();
        claszInstance = claszInstance.QueryInterface(Components.interfaces.nsIOpenIDListener);
      } else {
        icDebug("registerOpenIdListener the class " + CONTRACT_ID + " is not installed");
      }
      } catch(e1) {
      icDebug("registerOpenIdListener exception:"+e1 );
      }
      return claszInstance;
  } catch(e) {
    icDebug("registerOpenIdListener exception:"+e );
      Components.utils.reportError(e);
      throw e;
  }
}

function removeOpenIdListener(gOpenIdManager) {
  if (!gOpenIdManager) {
    icDebug("removeOpenIdListener !gOpenIdManager" );
    return;
  }
  try {
    icDebug("removeOpenIdListener start." );
      var claszInstance = getXmldapHttpListener();
      
      if (claszInstance !== null) {
        icDebug("removeOpenIdListener removeOpenidListener");
        claszInstance.removeOpenidListener(gOpenIdManager);
      } else {
        icDebug("removeOpenIdListener Could not unregister openid listener" );
      }
  } catch(e) {
    icDebug("removeOpenIdListener exception:"+e );
      Components.utils.reportError(e);
  }
}

function newFinalizeOpenId(logService, url, error) {
  if (logService) {
    logService.logStringMessage('new newFinalizeOpenId: url=' + url + "\nerror=" + error);
  } else {
    dump('new newFinalizeOpenId: url=' + url + "\nerror=" + error);
  }
    if (url !== null) {
      // first remove the listener so we will not be called again while we are destroyed
      // finish will close this window
      try {
        if (gOpenIdManager) {
          removeOpenIdListener(gOpenIdManager);
          gOpenIdManager = null;
        }
      } catch (e) {
        logService.logStringMessage("newFinalizeOpenId. Exception: " + e );
      }
      try {
        // FIXME updateRPs is not defined
        updateRPs();
      } catch (ee) {
        logService.logStringMessage("newFinalizeOpenId. exception: " + ee );
      }
      try {
        // FIXME finish is not defined
        finish(url);
      } catch (eee) {
        logService.logStringMessage("newFinalizeOpenId. exception= " + eee );
      }
    }
    if (error !== null) {
      logService.logStringMessage("newFinalizeOpenId. error=" + error );
      window.close();
    }
}

function finalizeOpenId(openid_nickname, openid_fullname, openid_email, verified_id, openidServer) {
    icDebug('finalizeOpenId: start');

    openidServer.stopServer();
    
    var tokenToReturn;
    var policy = getPolicy();

    policy.type = "selfAsserted";
    selectedCard.privatepersonalidentifier = OICCrypto.hex_sha1(selectedCard.cardName + selectedCard.version + selectedCard.id);

    var count = 0;
    var data = new XML("<selfasserted/>");

    selectedCard.supportedclaim[count] = "givenname";
    data.givenname = openid_nickname;
    count++;

    selectedCard.supportedclaim[count] = "surname";
    data.surname = openid_fullname;
    count++;

    selectedCard.supportedclaim[count] = "emailaddress";
    data.emailaddress = openid_email;
    count++;

    selectedCard.carddata.data = data;
    policy.card = selectedCard.toString();

    policy = processCard(policy,false);

    icDebug('2');

    finish(policy.tokenToReturn);
}

function getOpenIDAuthParameters(extraParams){
  try {
    for (var i=0; i<extraParams.length; i++) {
      var val = JSON.parse(extraParams[i]);
      if ((val !== null) && (val !== false) && val.hasOwnProperty("OpenIDAuthParameters")) {
        var valStr = "" + val.OpenIDAuthParameters;
        icDebug("getOpenIDAuthParameters: OpenIDAuthParameters = " + valStr);
        return valStr;
      } else {
        icDebug("getOpenIDAuthParameters: extraParams[" + i + "] = " + extraParams[i]);
      }
    }
  } catch (e) {
    icDebug("getOpenIDAuthParameters threw exception: " + e);
  }
//  return undefined;
}

function handleOK(policy, aCard) {
  icDebug("handleOK " + aCard);
    var tokenToReturn;
    if (policy === null) {
      icDebug("policy === null");
      return;
    }

    if (aCard.type.toString() === "selfAsserted") {
      policy.type = "selfAsserted";
      policy.card = aCard.toString();
      try {
        if (setOptionalClaimsSelf) {
          // this is not defined when called from the sidebar
          setOptionalClaimsSelf(document, policy);
        }
      } catch (e) {
        icDebug("setOptionalClaimsSelf failed:" + e);
        finish(null);
        return;
      }
      //TRUE or FALSE on the second param enabled debug
      policy = processCard(policy,selectorDebugging);
      finish(policy.tokenToReturn);
      updateRPs(policy);
    } else if (aCard.type == "managedCard"){
      var requiredClaims = policy.requiredClaims;
      var optionalClaims = policy.optionalClaims;
      var tokenType = null;
      if (policy.hasOwnProperty("tokenType")) {
        tokenType = policy.tokenType;
      }
      var url = policy.url; // RP url
      var relyingPartyCertB64 = null;
      if (policy.hasOwnProperty("cert")) {
        relyingPartyCertB64 = policy.cert;
      }
      var issuerPolicy = null;
      if (policy.hasOwnProperty("issuerPolicy")) {
        issuerPolicy = policy.issuerPolicy;
      }
      var clientPseudonym = OICCrypto.hex_sha1(url + aCard.id);
      
      var assertion = processManagedCard(document,
            aCard, requiredClaims, optionalClaims, tokenType, 
            clientPseudonym, url, relyingPartyCertB64, issuerPolicy);
          icDebug("assertion:" + assertion);
      if (assertion === null) {
        return;
      }
      updateRPs();
        

      if (!(aCard.carddata.managed.requireAppliesTo)) {
        // STS is in auditing mode -> just return the unencrypted assertion
        tokenToReturn = assertion;
      } else {
        policy.type = "managedCard";
        policy.assertion = assertion;
        // STS is NOT in auditing mode -> encrypt the assertion
        // TRUE or FALSE on the second param enabled debug
        policy = processCard(policy,selectorDebugging);
      }
      
      finish(policy.tokenToReturn);

    } else if (aCard.type == "openid"){
      icDebug("ok: openid setup aCard.id=" + aCard.id);
      if (gOpenIdManager) {
        try {
            var extraParamsOpenIdReturnTo = null;
            var extraParamsOpenIDAuthParameters = null;
            if ((policy !== null) && policy.hasOwnProperty("extraParams")) {
              var extraParams = policy.extraParams;
              extraParamsOpenIDAuthParameters = getOpenIDAuthParameters(extraParams);
              icDebug("ok: extraParamsOpenIDAuthParameters=" + extraParamsOpenIDAuthParameters);
            }
          
            try {
              gOpenIdManager.setParams(aCard.id, newFinalizeOpenId, document, extraParamsOpenIDAuthParameters);
            } catch (ee) {
              icDebug("cardManagerLoad start. Exception: " + ee );
            }
          
            icDebug("ok: typeof(gOpenIdManager.registerSetupUrl)=" + typeof(gOpenIdManager.registerSetupUrl));
            icDebug("ok: typeof(gOpenIdManager.registerSetupUrl)=" + typeof(gOpenIdManager.registerOpenId));
            
            icDebug("ok: openid 1");
            gOpenIdManager.doit();
            icDebug("ok: openid started");
        } catch (eee) {
          icDebug("ok: openid setup failed: " + eee);
        }
      }
    }

}

function saveChangedCard(){
  if (!selectedCard) {
    icDebug("saveChangedCard: selectedCard is undefined or null");
    return;
  }
  if (selectedCard.type.toString() !== "selfAsserted" )  {
    icDebug("saveChangedCard: selectedCard.type is not selfAsserted but " + selectedCard.type);
    return;
  }
  if (!selectedCard.claimsValuesChanged) {
    icDebug("saveChangedCard: selectedCard.claimsValuesChanged = " + selectedCard.claimsValuesChanged);
    return;
  }
  
  var ic = new Namespace("ic", "http://schemas.xmlsoap.org/ws/2005/05/identity");
  var value = "";
  var claimValues = selectedCard.ic::InformationCardPrivateData.ic::ClaimValueList.ic::ClaimValue;
  if (!claimValues) {
    icDebug("saveChangedCard: claimValues is null or undefined");
    return;
  }
  var wasUpdated = false;
  for (var ci=0; ci<claimValues.length(); ci++) {
   var claimValue = claimValues[ci];
   var claimUri = claimValue.@Uri.toXMLString();
   var textbox = document.getElementById(claimUri);
   if (textbox) {
     value = "" + claimValue.ic::Value.text();
     if ((textbox.value) && (textbox.value !== value)) {
       icDebug("saveChangedCard: textbox.value=" + textbox.value + " !== " + value);
       claimValue.ic::Value = <ic:Value xmlns:ic="http://schemas.xmlsoap.org/ws/2005/05/identity">{textbox.value}</ic:Value>;
       wasUpdated = true;
     }
   }
  }
  if (wasUpdated) {
    var prompts = Components.classes["@mozilla.org/embedcomp/prompt-service;1"]
                                     .getService(Components.interfaces.nsIPromptService);
    var savePromptTitle = stringsBundle.getString('saveprompttitle');
    var savePromptLabel = stringsBundle.getString('savepromptlabel');
    var result = prompts.confirm(window, savePromptTitle, savePromptLabel);
    if (!result) {
      return;
    }
    delete selectedCard.claimsValuesChanged;

    icDebug("saveChangedCard: updated selectedCard=" + selectedCard);
    updateCard(selectedCard); // save to disk
  }
}

function ok(event){
  saveChangedCard();
  var policy = getPolicy();
  if (!policy) { 
 
  } else {
    handleOK(policy, selectedCard);
  }
}

function showPrivacyStatement() {
  var policy = getPolicy();
  if (policy !== null) {
      var privacyUrl = policy.privacyUrl;
      if (privacyUrl === null) {
        InformationCardHelper.alert("relying party did not specify a privacy statement URL");
       return;
      }
      // prevent file:// and chrome:// etc
      if (privacyUrl.indexOf("http") !== 0) {
       InformationCardHelper.alert("The relying party's privacy statement URL does not start with 'http'\n" + privacyUrl);
       return;
      }
      
      window.open(privacyUrl, "privacyStatement");
  }
}

function cancel(){
  icDebug("cancel");
  var doc = window.document;
  var event = doc.createEvent("Events");
  event.initEvent("CancelIdentitySelector", true, true);
  window.dispatchEvent(event);

  try {
    saveChangedCard();
  } catch (e) {
    icDebug("cancel: saveChangedCard threw exception = " + e);
  }
  if ((window.hasOwnProperty("arguments")) && (window.arguments) && (window.arguments.length > 0)) {
    window.arguments[1](null);
  }
  window.close();
}

function disable(){
  var prefService = Components.classes[ 
    "@mozilla.org/preferences-service;1"].
      getService( Components.interfaces.nsIPrefBranch);
  var disabled = prefService.getBoolPref( "identityselector.disabled");
  icDebug("disabled=" + disabled);
  prefService.setBoolPref( "identityselector.disabled", true);
  disabled = prefService.getBoolPref( "identityselector.disabled");
  icDebug("disabled=" + disabled);

    var doc = window.document;
    var event = doc.createEvent("Events");
    event.initEvent("DisableIdentitySelector", true, true);
    window.dispatchEvent(event);

  cancel();
}

function getCardId(extraParams){
  try {
    for (var i=0; i<extraParams.length; i++) {
      var val = JSON.parse(extraParams[i]);
      if ((val !== null) && (val !== false) && val.hasOwnProperty("cardid")) {
        var cardId = "" + val.cardid;
        icDebug("getCardId: cardId = " + cardId);
        return cardId;
      } else {
        icDebug("getCardId: extraParams[" + i + "] = " + extraParams[i]);
      }
    }
  } catch (e) {
    icDebug("getCardId threw exception: " + e);
  }
//  return undefined;
}

function registerOpenIdListener(gOpenIdManager) {
  try {
    icDebug("registerOpenIdListener start." );
      var claszInstance = getXmldapHttpListener();
      
      if (claszInstance !== null) {
        icDebug("registerOpenIdListener addOpenidListener");
        icDebug("registerOpenIdListener typeof(gOpenIdManager.registerSetupUrl)="+typeof(gOpenIdManager.registerSetupUrl));
        icDebug("registerOpenIdListener typeof(gOpenIdManager.registerOpenId)="+typeof(gOpenIdManager.registerOpenId));
        claszInstance.addOpenidListener(gOpenIdManager);
      } else {
        icDebug("registerOpenIdListener Could not register openid listener" );
      }
  } catch(e) {
    icDebug("registerOpenIdListener exception:"+e );
      Components.utils.reportError(e);
  }
}

//this function is intended to compute the visualization class
//for this card. It returns one of contactGreen, contactYellow
//or contactRed
//or contact of we are managing cards that is: there is no RP
//green - card is matching the requirements of the RP
//yellow - card is matching the requirements of the RP but was never sent to RP
//red - card is not matching
//
function computeCardClass(card, policy) {
  var cardClass;

  if (policy !== null) {
   var matching = computeMatching(card, policy);
   if (matching === true) {
    var hasBeenSent = computeHasBeenSend(card, policy);
    if (hasBeenSent === true) {
     cardClass = "contactGreen";
    } else {
     cardClass = "contactYellow";
    }
   } else {
    cardClass = "contactRed";
   }
  } else {
    cardClass = "contact";
  }
  icDebug("cardClass " + cardClass + " " + card.name);
  return cardClass;
}

function cardManagerUnload(){
  icDebug("cardManagerUnload start. href=" + window.document.location.href );
  TokenIssuer.finalize();
}

function handleCardChoice(event){

  var choice = event.originalTarget;
  if (choice === undefined) {
    InformationCardHelper.alert("internal error: handleCardChoice: choice === undefined");
  }
  var selectedCardId = choice.getAttribute("cardid");
  if (!selectedCardId) {
    InformationCardHelper.alert("internal error: handleCardChoice: selectedCardId === undefined");
  }
  icDebug("selectedCardId="+selectedCardId);
  var choosenCard = getCard(selectedCardId);
  if (choosenCard === null) {
    Component.utils.reportError("internal error: card not found: " + selectedCardId);
    InformationCardHelper.alert("internal error: card not found: " + selectedCardId);
    return;
  }
  icDebug("choosenCard="+choosenCard);
  setCard(choosenCard);

}

function dblclick(event) {
  handleCardChoice(event);
  if ((window.arguments !== undefined) && (window.arguments.length > 0)) {
    icDebug("dblclick: ok");
    ok();
  } else {
    // else cardManager.xul called from preferences
    icDebug("dblclick: not calling ok");
  }
}

function fillCardArea(cardFile, policy, rpIdentifier){
  try {
    var cardArea = document.getElementById("cardselection");
    var latestCard;
    var selectMe;
    var beenThere = false;
    var count = 0;
    var scrolledIntoView = false;
    if (typeof(cardFile) === "string") {
      cardFile = new XML(cardFile);
    }
    var cardXmllist = cardFile.infocard;
    for (var i=0; i<cardXmllist.length(); i++) {
      var c = cardXmllist[i];
      var cardClass = "contact";
      if (policy !== null) {
        cardClass = computeCardClass(c, policy);
      }
      if ((cardClass === "contactGreen") || (cardClass === "contactYellow") || (cardClass === "contact")) {
        latestCard = createItem(c, cardClass, handleCardChoice, dblclick);
        selectMe = c;
        cardArea.appendChild(latestCard);
        count++;

        if (!beenThere) {
          if (rpIdentifier !== null) {
            var rpXmllist = c.rpIds;
            for (var j=0;j<rpXmllist.length();j++) {
              rpId = rpXmllist[j];
              IdentitySelectorDiag.logMessage("cardmanagerOnLoad", "RpId:" + rpId + " RpIdentifier:" + rpIdentifier);
              if (rpId == rpIdentifier) {
                beenThere = true;
                if (scrolledIntoView === false) {
                  var xpcomInterface = cardArea.scrollBoxObject.QueryInterface(Components.interfaces.nsIScrollBoxObject);
                  xpcomInterface.ensureElementIsVisible(latestCard);
                  scrolledIntoView = true;
                }
                break;
              }
            }
          }
        }
      } else {
        icDebug("card does not match cardClass: " + cardClass + " card.id: " + c.id);
      }
    }
    return count;
  } catch(e) {
    icDebug("fillCardArea threw: " + e);
    throw e;
  }
}

function setNotifyLabel(count, policy, stringsBundle){
  var label = document.getElementById("notify");
  if ( count !== 0) {
    if (policy !== null) {
      if (label !== null) {
        var site = "Unknown";
        if (policy.hasOwnProperty("cn")) {
          site = policy.cn;
        } else if (policy.hasOwnProperty("url")) {
          site = policy.url;
        }
        var please = stringsBundle.getFormattedString('pleaseselectacard', [site]);
        label.setAttribute("value", please);
      }
    } else {
      if (label !== null) {
        label.setAttribute("value", "card management");
      }
    }
  } else {
    if (label !== null) {
      var button = stringsBundle.getString('newcard');
      var youdont = stringsBundle.getFormattedString('youdonthaveanycards', [button]);
      label.setAttribute("value", youdont);
    }
  }
}

function setFirstTimeVisit(policy, stringsBundle) {
  try {
    var firstTimeVisitBox = document.getElementById('firstTimeVisitBox');
    if (policy) { // no card management
      var firstTimeVisit = document.getElementById('firstTimeVisit');
      if (firstTimeVisit && firstTimeVisitBox) {
        var labelText;
        try {
          labelText = stringsBundle.getString('firsttimevisit');
        } catch (e) {
         icDebug("firstTime: exception=" + e);
         labelText = "This is your first visit to this site.";
        }
        icDebug("firstTime: " + labelText);
        firstTimeVisit.setAttribute("value", labelText);
        firstTimeVisitBox.setAttribute("hidden", "false");
      }
    } else { // else card management
      firstTimeVisitBox.setAttribute("hidden", "true");
    }
  } catch(ee) {
    icDebug("cardManagerOnLoad firsttime threw: " + ee);
  }
}

function setCard(card){
  try {
    var policy = getPolicy();

    if (policy !== null) {
      var select = document.getElementById('selectcontrol');
      select.setAttribute('hidden', 'false');
    }
  
    var showPrivacyStatementElm = document.getElementById('privacy_label');
    if (showPrivacyStatementElm !== null) {
      showPrivacyStatementElm.hidden = true;
    }
    
    var issuerlogo = document.getElementById("issuerlogo");
    if (issuerlogo !== null) {
      issuerlogo.src = "";
      issuerlogo.hidden = true;
      var issuerlogo_label = document.getElementById("issuerlogo_label");
      issuerlogo_label.hidden = true;
      var issuer_hbox = document.getElementById("issuer_hbox");
      issuer_hbox.hidden = true;
    }
  
    selectedCard = card;

    icDebug("TYPE: " + selectedCard.type);
    icDebug("selectedCard: " + selectedCard);

    var selfassertedClaims = document.getElementById('selfassertedClaims');
    var managedClaims = document.getElementById('managedClaims');

    var requiredClaims = null;
    var optionalClaims = null;
    if (selectedCard.type == "selfAsserted" )  {
       if (policy !== null) {
         requiredClaims = policy.requiredClaims;
         optionalClaims = policy.optionalClaims;
      }  
      if (selfassertedClaims !== null) {
        selfassertedClaims.setAttribute("hidden", "true");
      }
      if (managedClaims !== null) {
        managedClaims.setAttribute("hidden", "false");
      }
      var cardname = document.getElementById("cardname");
      if (cardname !== null) {
        cardname.value = selectedCard.name;
        cardname.hidden = false;
      }
  
      var ic = new Namespace("ic", "http://schemas.xmlsoap.org/ws/2005/05/identity");
      var list = selectedCard.ic::SupportedClaimTypeList.ic::SupportedClaimType;
  
      var claimValues = selectedCard.ic::InformationCardPrivateData.ic::ClaimValueList.ic::ClaimValue;
      icDebug("claimValues: typeof(claimValues)=" + typeof(claimValues));
      icDebug("claimValues: claimValues.length()=" + claimValues.length());
      
      var cardManagerOnInput = function() {
        if (selectedCard) {
          icDebug("cardManagerOnInput start");
          selectedCard.claimsValuesChanged = "true";
          var policy = getPolicy();
          if (policy === null) { // cardmanagement
            var selectlabel = document.getElementById('select');
            if (selectlabel) {
              selectlabel.setAttribute('value', 'save');
              var selectcontrol = document.getElementById('selectcontrol');
              if (selectcontrol) {
                selectcontrol.setAttribute('hidden', 'false');
              }
            }
          }

        }
      };


      setCardManaged(requiredClaims, optionalClaims, list, 
          "managedRows0", claimValues, cardManagerOnInput);
    }  else if (selectedCard.type == "managedCard" )   {
       if (policy !== null) {
           requiredClaims = policy.requiredClaims;
           optionalClaims = policy.optionalClaims;
      }  
      if (selfassertedClaims !== null) {
        selfassertedClaims.setAttribute("hidden", "true");
      }
      if (managedClaims !== null) {
        managedClaims.setAttribute("hidden", "false");
      }

    var cardname = document.getElementById("cardname");
    if (cardname !== null) {
          cardname.value = selectedCard.name;
          cardname.hidden = false;
    }
    var ic = new Namespace("ic", "http://schemas.xmlsoap.org/ws/2005/05/identity");
    var list = selectedCard.carddata.managed.ic::SupportedClaimTypeList.ic::SupportedClaimType;

    setCardManaged(requiredClaims, optionalClaims, list, "managedRows0", null);
    } else if (selectedCard.type == "openid" )  {


        var label = document.getElementById("notify");
        if (label !== null) {
          label.setAttribute("value", "Use OpenID with Identity URL: " + selectedCard.id);
        }
        
    var cardname = document.getElementById("cardname");
    if (cardname !== null) {
          cardname.value = "";
          cardname.hidden = true;
    }
    
      if (selfassertedClaims !== null) {
        selfassertedClaims.setAttribute("hidden", "true");
      }
      if (managedClaims !== null) {
        managedClaims.setAttribute("hidden", "true");
      }

    } else  {
      InformationCardHelper.alert("unsupported card type\n" + selectedCard.type);
      return;
    }
  } catch (setCardException) {
    icDebug("setCard: exception: " + setCardException);
  }
}

function cardManagerLoad(policyParam){
  // infocard: cardManagerLoad start. href=chrome://infocard/content/cardSidebar.xul
  // infocard: cardManagerLoad start.
  // href=chrome://infocard/content/cardManager.xul
  icDebug("cardManagerLoad start. href=" + window.document.location.href );
  
  try {
    gOpenIdManager = new openidRP();
    registerOpenIdListener(gOpenIdManager);
  } catch (ee) {
    icDebug("cardManagerLoad start. Exception: " + ee );
//    throw ee;
  }

  var controlarea = document.getElementById('selectcontrol');
  if (controlarea) {
      var select = document.getElementById('selectcontrol');
      select.addEventListener("click", ok, false);
  
  
      var disableElm = document.getElementById('disableSelector');
      disableElm.addEventListener("click", disable, false);
  
      var newCardElm = document.getElementById('newCard');
      newCardElm.addEventListener("click", newCard, false);
  
      var deleteCardElm = document.getElementById('deleteCard');
      deleteCardElm.addEventListener("click", deleteCard, false);
  
      var cancelselector = document.getElementById('cancelselector');
      cancelselector.addEventListener("click", cancel, false);
  }
  
    var stringsBundle = document.getElementById("string-bundle");

    var policy;
    if (policyParam === undefined) {
      policy = getPolicy();
    } else {
      policy = policyParam;
    }
    
    if (policy === null) {
      icDebug("cardManagerLoad policy is null!" );
    }
    
    try {
      if (policy && policy.hasOwnProperty("backgroundImage")) {
        var mainbar = document.getElementById('mainbar');
        if (mainbar) {
          mainbar.style.backgroundImage = policy.backgroundImage;
        }
      }
    } catch(eBackgroundImage) {
      icDebug("cardManagerLoad. Exception: " + eBackgroundImage );
      throw eBackgroundImage;
    }
    
    var rpIdentifier = null;

    if (policy !== null && policy.hasOwnProperty("cert")) {
    var relyingPartyCertB64 = policy.cert;
      rpIdentifier = computeRpIdentifier(relyingPartyCertB64);
    }

  var extraParams = null;
  var extraParamsCardId = null;
  if ((policy !== null) && policy.hasOwnProperty("extraParams")) {
    extraParams = policy.extraParams;
    extraParamsCardId = getCardId(extraParams);
    icDebug("extraParams length = " + extraParams.length);
    icDebug("extraParams cardId = " + extraParamsCardId);
  }

  var cardFile;
  try {
    cardFile = CardstoreToolkit.readCardStore();
    //icDebug("cardManagerLoad cardFile = " + cardFile)
  } catch (eee) {
    icDebug("cardManagerLoad = exception" + eee);
    throw eee;
  }
  
  var count = fillCardArea(cardFile, policy, rpIdentifier);
  setNotifyLabel(count, policy, stringsBundle);

  if (policy !== null) {
    var serializedPolicy = JSON.stringify(policy);
    if (TokenIssuer.initialize(java) === true) {
      var issuerLogoURL = TokenIssuer.getIssuerLogoURL(serializedPolicy);
      icDebug("issuerLogoURL=" + issuerLogoURL);
      if (issuerLogoURL) {
        var issuerlogo = document.getElementById("issuerlogo");
        issuerlogo.src = issuerLogoURL;
        issuerlogo.hidden = false;
        var issuerlogo_label = document.getElementById("issuerlogo_label");
        issuerlogo_label.hidden = false;
        var issuer_hbox = document.getElementById("issuer_hbox");
        issuer_hbox.hidden = false;
      }
    } else {
      icDebug("load: error initializing the TokenIssuer");
      icDebug("load: window.java=" + window.java + " window.document.location.href=" + window.document.location.href);
// alert("Error: Initializing the TokenIssuer");
      // return;
    }
  }
  
  try {
    if (policy && policy.hasOwnProperty("privacyUrl")) {
      var privacyUrl = policy.privacyUrl;
      if (privacyUrl !== null) {
        icDebug("privacyUrl " + privacyUrl);
        var showPrivacyStatementElm = document.getElementById('privacy_label');
        if (showPrivacyStatementElm) {
          showPrivacyStatementElm.addEventListener("click", showPrivacyStatement, false);
          showPrivacyStatementElm.hidden = false;
        }
      }
    }
  } catch(e) {
    icDebug("setting privacy url threw " + e);
  }
  icDebug("foo bar baz");

//  if (!beenThere) {
//    setFirstTimeVisit(policy, stringsBundle);
//  }
  icDebug("foo foo bar bar baz baz");
  
  icDebug("extraParamsCardId =" + extraParamsCardId);
  if (extraParamsCardId) {
    try {
      var choosenCard = getCard(extraParamsCardId);
      if (!choosenCard) {
        Components.utils.reportError("cardManagerLoad: extraParamsCardId=" + extraParamsCardId + " but card not found");
        InformationCardHelper.alert("internal error: card not found in cardstore.");
        window.close();
        return;
      }
      setCard(choosenCard);
      var choosenCardElement = document.getElementById(extraParamsCardId);
      var cardArea = document.getElementById("cardselection");
      if (choosenCardElement && cardArea) {
        var xpcomInterface = cardArea.scrollBoxObject.QueryInterface(Components.interfaces.nsIScrollBoxObject);
        xpcomInterface.ensureElementIsVisible(choosenCardElement);
      }
    } catch (eeee) {
      icDebug("cardManagerLoad threw: " + eeee);
    }
  } else {
    icDebug("extraParamsCardId === undefined");
  }

}

//returns true of card tokentype and RP's policy tokentype match
// if something unexcpected happens then return false
function computeMatchingProtocol(card, policy) {
   var protocol = null;
   if (policy.hasOwnProperty("protocol")) {
     protocol = policy.protocol;
   }
   if (protocol === null) { return true; }
   icDebug("protocol: " + protocol + " card:" + card.name);
   if (card.type == "managedCard") {
     return true;
   } else if (card.type == "selfAsserted") {
     return true;
   } else if (card.type == "openid") {
     if (protocol === "urn:oasis:names:tc:OPENID:2.0:assertion") {
       return true;
     } else {
       icDebug("computeMatchingProtocol: does not match openid card:" + card.name);
       return false;
     }
   } else {
     icDebug("computeMatchingProtocol: unsupported protocol card:" + card.name);
   }
   icDebug("computeMatchingProtocol: does not match OpenId card:" + card.name);
   return false;
}

//returns true if card's supported claims and RP's required claims match
// if something unexcpected happens then return false
function computeMatchingRequiredClaims(card, policy) {
  try {
    var requiredClaims = policy.requiredClaims;
    if (!requiredClaims) { return true; }
    
    if (requiredClaims) {
      requiredClaims = requiredClaims.replace(/\s+/g,' ');
    }
    var claims = requiredClaims.split(' ');

    var ic = new Namespace("ic", "http://schemas.xmlsoap.org/ws/2005/05/identity");

    var list;
    if (card.type == "selfAsserted" ) {
      list = card.ic::SupportedClaimTypeList.ic::SupportedClaimType;
    } else {
      if (card.type == "managedCard") {
        list = card.carddata.managed.ic::SupportedClaimTypeList.ic::SupportedClaimType;
      } else {
        return true; // FIXME is this the best behaviour?
      }
    }
    var found = false;
    for (var i=0; i<claims.length; i++) {
      var aClaim = claims[i];
      if ((!aClaim) || (aClaim === "") || (aClaim === ' ')) {
        continue;
      }
      for (var index=0; index<list.length(); index++) {
        var supportedClaim = list[index];
        var uri = supportedClaim.@Uri.toXMLString();
        //icDebug("computeMatchingRequiredClaims: uri=" + uri);
        if (uri === aClaim) {
          found = true;
          break;
        }
      }
      if (!found) {
        icDebug("computeMatchingRequiredClaims: card does not support=" + aClaim + ";");
        return false;
      }
    }
    return true;
   } catch (e) {
    icDebug("computeMatchingRequiredClaims: exception:" + e);
    return false;
  }
  // other card types
  return true;
}

//returns true if the card's tokentype and RP's policy tokentype match
//if something unexcpected happens then return false
function computeMatchingTokenType(card, policy) {
 var matchingTokenType = false;
 var tokenType = null;
 tokenType = null;
 if (policy.hasOwnProperty("tokenType")) {
  tokenType = policy.tokenType;
 }

 if (tokenType !== null) {
  icDebug("tokenType: " + tokenType + " card:" + card.name);
  if (card.type == "managedCard") {
    var ic = new Namespace("ic", "http://schemas.xmlsoap.org/ws/2005/05/identity");
    var trust = new Namespace("trust", "http://schemas.xmlsoap.org/ws/2005/02/trust");
    var list = card.carddata.managed.ic::SupportedTokenTypeList.trust::TokenType;
    
    for (var index = 0; index<list.length(); index++) {
     var cardTokenType = list[index];
     if (tokenType == cardTokenType) {
      matchingTokenType = true;
      icDebug("matchingTokenType:" + tokenType);
      var relyingPartyUrl = policy.url;
      if (card.carddata.managed.requireStrongRecipientIdentity !== undefined) {
        if (card.carddata.managed.requireStrongRecipientIdentity === true) {
          if (relyingPartyUrl.indexOf("https") == 0) {
            icDebug("matchingRequireStrongRecipientIdentity");
            return true;
          } else {
            icDebug("computeMatchingTokenType: does not match managed card: " + card.name + "matchingRequireStrongRecipientIdentity");
            return false;
          }
        }
      } // else do not care about requireStrongRecipientIdentity
      return matchingTokenType;
     } else {
      icDebug("notMatchingTokenType:" + cardTokenType);
     }
    }
  } else if (card.type == "selfAsserted") {
   if (tokenType == "urn:oasis:names:tc:SAML:1.0:assertion") {
    matchingTokenType = true;
   } else if (tokenType ==  "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1") {
    matchingTokenType = true;
   } else {
     matchingTokenType = false;
     icDebug("tokenType does not match tokenTypes for self-issued cards:" + tokenType);
   }
  } else if (card.type == "openid") {
    if ((tokenType == "urn:oasis:names:tc:OPENID:2.0:assertion") || (tokenType == "http://specs.openid.net/auth/2.0"))
    {
      matchingTokenType = true;
    } else {
      icDebug("computeMatchingTokenType: does not match openid card: " + card.name + " tokenType: " + tokenType);
      matchingTokenType = false;
    }
  } else {
   icDebug("computeMatchingTokenType: unsupported card type: " + card.type);
   matchingTokenType = false;
  }
 } else { // RP does not require a special tokentype
  matchingTokenType = true;
 }
 return matchingTokenType;
}

function computeRpIdentifier(cert) {
  return OICCrypto.hex_sha1(cert);
}

function computeHasBeenSend(card, policy) {
  if (!policy.hasOwnProperty("cert")) {
    return false;
  }
  var relyingPartyCertB64 = policy.cert;
  var rpIdentifier = computeRpIdentifier(relyingPartyCertB64);
  var beenThere = false;
  for each (rpId in card.rpIds) {
   icDebug("computeHasBeenSend: " + card.name + " RpId:" + rpId + " RpIdentifier:" + rpIdentifier);
   if (rpId == rpIdentifier) {
    icDebug(card.name + " has been sent to: " + policy.cn);
    beenThere = true;
    break;
   }
  }
  return beenThere;
}

function matchOpenIdIssuerFQDN(openid_url, issuer) {
  var i = openid_url.indexOf("https://");
  if (i>=0) {
    openid_url = openid_url.substring("https://".length);
  }
  i = openid_url.indexOf("http://");
  if (i>=0) {
    openid_url = openid_url.substring("http://".length);
  }
  icDebug("matchOpenIdIssuerFQDN: openid_url=" + openid_url);
  var i = issuer.indexOf("https://");
  if (i>=0) {
    issuer = issuer.substring("https://".length);
  }
  i = issuer.indexOf("http://");
  if (i>=0) {
    issuer = issuer.substring("http://".length);
  }
  icDebug("matchOpenIdIssuerFQDN: issuer=" + issuer);
  // issuer and openid_url now do not begin with the scheme
  i = issuer.indexOf("/");
  if (i>0) {
    issuer = issuer.substring(0,i);
  }
  icDebug("matchOpenIdIssuerFQDN: issuer=" + issuer);
  i = openid_url.indexOf("/");
  if (i>0) {
    openid_url = openid_url.substring(0,i);
  }
  icDebug("matchOpenIdIssuerFQDN: openid_url=" + openid_url);
  if (issuer === openid_url) {
    icDebug("matchOpenIdIssuerFQDN: issuer === openid_url");
    return true;
  } else {
    icDebug("matchOpenIdIssuerFQDN: issuer !== openid_url");
    return false;
  }
}

// match only if one host is the end of the other
function matchOpenIdIssuerDomain(openid_url, issuer) {
  var i = openid_url.indexOf("https://");
  if (i>=0) {
    openid_url = openid_url.substring("https://".length);
  }
  i = openid_url.indexOf("http://");
  if (i>=0) {
    openid_url = openid_url.substring("http://".length);
  }
  icDebug("matchOpenIdIssuerDomain: openid_url=" + openid_url);
  var i = issuer.indexOf("https://");
  if (i>=0) {
    issuer = issuer.substring("https://".length);
  }
  i = issuer.indexOf("http://");
  if (i>=0) {
    issuer = issuer.substring("http://".length);
  }
  icDebug("matchOpenIdIssuerDomain: issuer=" + issuer);
  // issuer and openid_url now do not begin with the scheme
  i = issuer.indexOf("/");
  if (i>0) {
    issuer = issuer.substring(0,i);
  }
  issuer = issuer.toLowerCase();
  icDebug("matchOpenIdIssuerDomain: issuer=" + issuer);
  i = openid_url.indexOf("/");
  if (i>0) {
    openid_url = openid_url.substring(0,i);
  }
  openid_url = openid_url.toLowerCase();
  icDebug("matchOpenIdIssuerDomain: openid_url=" + openid_url);
  var m = openid_url.match(issuer+"$");
  if (m) {
    m = m.toString();
  }
  if (m === issuer) {
    icDebug("matchOpenIdIssuerDomain: host matches");
    return true;
  } else {
    m = issuer.match(openid_url+"$");
    if (m) {
      m = m.toString();
    }
    if (m === openid_url) {
      icDebug("matchOpenIdIssuerDomain: HOST matches");
      return true;
    } else {
      icDebug("matchOpenIdIssuerDomain: host does not match");
      return false;
    }
}
}

function matchOpenIdIssuerHost(openid_url, issuer) {
  var i = openid_url.indexOf("https://");
  if (i>=0) {
    openid_url = openid_url.substring("https://".length);
  }
  i = openid_url.indexOf("http://");
  if (i>=0) {
    openid_url = openid_url.substring("http://".length);
  }
  icDebug("matchOpenIdIssuerHost: openid_url=" + openid_url);
  var i = issuer.indexOf("https://");
  if (i>=0) {
    issuer = issuer.substring("https://".length);
  }
  i = issuer.indexOf("http://");
  if (i>=0) {
    issuer = issuer.substring("http://".length);
  }
  icDebug("matchOpenIdIssuerHost: issuer=" + issuer);
  // issuer and openid_url now do not begin with the scheme
  i = issuer.indexOf("/");
  if (i>0) {
    issuer = issuer.substring(0,i);
  }
  issuer = issuer.toLowerCase();
  icDebug("matchOpenIdIssuerHost: issuer=" + issuer);
  i = openid_url.indexOf("/");
  if (i>0) {
    openid_url = openid_url.substring(0,i);
  }
  openid_url = openid_url.toLowerCase();
  icDebug("matchOpenIdIssuerHost: openid_url=" + openid_url);
  var m = openid_url.match(issuer+"$");
  if (m) {
    m = m.toString();
  }
  if (m === issuer) {
    icDebug("matchOpenIdIssuerFQDN: host matches");
    return true;
  } else {
    icDebug("matchOpenIdIssuerHost: host does not match");
    return false;
  }
}

function matchOpenIdIssuerScheme(openid_url, issuer) {
  if ((issuer.indexOf("https://") === 0) && (openid_url.indexOf("https://") === 0)) {
    return true;
  }
  if ((issuer.indexOf("http://") === 0) && (openid_url.indexOf("http://") === 0)) {
    return true;
  }
  // card provides SSL but RP does not request it
  if ((issuer.indexOf("http://") === 0) && (openid_url.indexOf("https://") === 0)) {
    return true;
  }
  if ((issuer.indexOf("https://") < 0) && (openid_url.indexOf("https://") < 0)) {
    return true;
  }
  if ((issuer.indexOf("http://") < 0) && (openid_url.indexOf("http://") < 0)) {
    return true;
  }
  icDebug("matchOpenIdIssuerScheme: scheme does not match");
  return false;
}

function matchOpenIdIssuer(card, policy, issuer) {
  var openid_url = card.id;
  var match = matchOpenIdIssuerScheme(openid_url, issuer);
  if (!match) {
    return false;
  }
  match = matchOpenIdIssuerFQDN(openid_url, issuer);
  if (!match) {
    match = matchOpenIdIssuerHost(openid_url, issuer);matchOpenIdIssuerDomain
    if (!match) {
      match = matchOpenIdIssuerDomain(openid_url, issuer);
      if (!match) {
        return false;
      }
    }
  }
  return true;
}

function doesIssuerMatch(card, policy, issuer) {
  var cardIssuer;
  if (card.type == "managedCard") {
    cardIssuer = card.carddata.managed.issuer;
    if (issuer === cardIssuer) {
      return true;
    } else {
      icDebug("doesIssuerMatch: " + card.name + " does not match. " + issuer);
      return false;
    }
  } else if (card.type == "selfAsserted") {
    cardIssuer="http://schemas.xmlsoap.org/ws/2005/05/identity/issuer/self";
    if (issuer === cardIssuer) {
      return true;
    } else {
      icDebug("doesIssuerMatch: " + card.name + " does NOT match. " + issuer);
      return false;
    }
  } else if (card.type == "openid") {
    var match = matchOpenIdIssuer(card, policy, issuer);
    if (match) {
      return match;
    }
    
//    var protocol = null;
//    if (policy.hasOwnProperty("protocol")) {
//      protocol = policy.protocol;
//    } else {
//      icDebug("doesIssuerMatch: openid " + card.name + " does not match. ");
//      return false;
//    }
//    return (protocol === "urn:oasis:names:tc:OPENID:2.0:assertion");
  } else {
    Components.utils.reportError("doesIssuerMatch: unsupported card.type=" + card.type);
    return false;
  }
}

function computeMatchingIssuer(card, policy) {
  if (!policy.hasOwnProperty("issuer")) {
    // RP does not require a specific issuer
    return true;
  }
  var issuer = policy.issuer;
  if (!issuer) {
    return true;
  }
  // issuer can be a whitespace separated list of issuer URLs
  issuer = issuer.replace(/\s+/g,' ');
  var issuers = issuer.split(' ');
  for (var i=0; i<issuers.length; i++) {
    var aIssuer = issuers[i];
    var matches = doesIssuerMatch(card, policy, aIssuer);
    if (matches) {
      return true;
    }
  }
  return false;
}

function computeMatching(card, policy) {
  var matching = computeMatchingTokenType(card, policy);
  if (matching === false) return false;
  matching = computeMatchingIssuer(card, policy);
  if (matching === false) return false;
  matching = computeMatchingRequiredClaims(card, policy);
  if (matching === false) return false;
  return true;
}

var listObserver = {
    onDragStart: function (event, transferData, action) {
      var data;
      if (event.target.nodeName == 'image') {
        data = event.target.getAttribute("cardid");
        icDebug("onDragStart: DATA=" + data);
      } else {
        icDebug("onDragStart: target.nodeName=" + event.target.nodeName);
        data = event.target.getAttribute("id");
        if ("" + data !== "") {
          icDebug("onDragStart: data=" + data);
        } else {
          icDebug("onDragStart: Data" + "boink");
          return;
        }
      }
      transferData.data = new TransferData();
      transferData.data.addDataForFlavour("application/x-informationcard+id", "" + data);
    },
    
    onDragExit : function (event, session) {
      icDebug("onDragExit: event.target.nodeName=" + event.target.nodeName);
//var targetId = event.target.getAttribute("id");
//icDebug("onDragExit: targetId=" + targetId);
//var doc = event.target.ownerDocument;
//if (doc.__identityselector__ === undefined) {
//icDebug("onDragExit: doc.__identityselector__ === undefined");
//} else {
//icDebug("onDragExit: doc.__identityselector__ !== undefined");
//}
//for (var i in session) {
//        
//icDebug("onDragExit: session." + i + "=" + eval("session." + i));
//}
//icDebug("onDragExit: session.sourceNode=" + session.sourceNode.nodeName);
//if (session.sourceNode.nodeName == 'image') {
//var data = event.target.getAttribute("cardid");
//icDebug("onDragExit: DATA=" + data);
//} else {
//var data = event.target.getAttribute("id");
//if ("" + data !== "") {
//icDebug("onDragExit: data=" + data);
//} else {
//icDebug("onDragExit: data" + "boink");
//}
//}
//transferData.data = new TransferData();
//transferData.data.addDataForFlavour("text/unicode", data);
      },
      
    onDrop : function (evt, transferData, session) {
        icDebug("onDrop: " + transferData.data);
//event.target.setAttribute("value",transferData.data);
    },
    
    getSupportedFlavours: function ()
    {
      var flavourSet = new FlavourSet();
      flavourSet.appendFlavour("application/x-informationcard");
      flavourSet.appendFlavour("application/x-informationcard+id");
      return flavourSet;
    }

};

function createItem(c, classStr, aHandleCardChoice, aDblclick){


    var hbox = document.createElement("hbox");
    hbox.setAttribute("class",classStr);
    hbox.setAttribute("cardid",c.id);
    hbox.setAttribute("id",c.id);
    hbox.setAttribute("draggable","true");
    hbox.setAttribute("ondraggesture", 
      "nsDragAndDrop.startDrag(event, listObserver);");
    hbox.setAttribute("ondragexit", 
      "nsDragAndDrop.dragExit(event, listObserver);");
    hbox.setAttribute("ondragdrop", 
    "nsDragAndDrop.drop(event, listObserver);");
    var vbox = document.createElement("vbox");
    vbox.setAttribute("class","databox");
    vbox.setAttribute("flex","1");
    var labelName = document.createElement("label");
    labelName.setAttribute("class","lblname");
    labelName.setAttribute("value",c.name);
    labelName.setAttribute("cardid",c.id);
    var labelVersion = document.createElement("label");
    labelVersion.setAttribute("class","lblmail");
    labelVersion.setAttribute("value", "Version " + c.version);
    labelVersion.setAttribute("cardid",c.id);

    var imgurl = "";
    if ( c.type == "selfAsserted") {
//        imgurl = c.carddata.selfasserted.imgurl;
    var ic = new Namespace("ic", "http://schemas.xmlsoap.org/ws/2005/05/identity");
    var claimValues = c.ic::InformationCardPrivateData.ic::ClaimValueList.ic::ClaimValue;
    var value;
    if ((claimValues !== undefined) && (claimValues !== null)) {
      var uri = "imgurl";
// icDebug("createItem: number of claimValues: " + claimValues.length());
      for (var ci=0; ci<claimValues.length(); ci++) {
        var claimValue = claimValues[ci];
// icDebug("createItem: claimValue=" + claimValue.toXMLString());
        var claimUri = claimValue.@Uri.toXMLString();
        if (claimUri === uri) {
          imgurl = claimValue.ic::Value.text();
// icDebug("createItem: CLAIMVALUE=" + claimValue.toXMLString());
        } else {
//          icDebug("createItem: claimUri=" + claimUri + " uri=" + uri);
        }
      }
    }
    } else if ( c.type == "managedCard") {
        imgurl = c.carddata.managed.image;
    }
     //var picture = document.createElement("html:img");
    var picturebox = document.createElement("hbox");
    picturebox.setAttribute("flex", "0");
    picturebox.setAttribute("align", "center");
    var picture = document.createElement("image");
    // icDebug("setcard imgurl: " + imgurl);
    if ( (imgurl == "") || (imgurl === undefined)) {

        if (c.type == "selfAsserted") {
            picture.setAttribute("src", "chrome://infocard/content/img/card.png");
        } else if (c.type == "openid") {
            picture.setAttribute("src", "chrome://infocard/content/img/openid.png");
        }
    } else {
        picture.setAttribute("src", imgurl);
    }

    picture.setAttribute("cardid", c.id);
    picture.setAttribute("class", "cardClass");
    picturebox.appendChild(picture);
    vbox.appendChild(picturebox);
    vbox.appendChild(labelName);
    vbox.appendChild(labelVersion);
    hbox.appendChild(vbox);
    if (aHandleCardChoice && (typeof(aHandleCardChoice) === "function")) {
      hbox.addEventListener("click", aHandleCardChoice, false);
    }
    if (aDblclick && (typeof(aDblclick) === "function")) {
      hbox.addEventListener("dblclick", aDblclick, false);
    }
// icDebug ("Setting cardid " + hbox.getAttribute("cardid"));
    return hbox;

}

function saveCard(card){
  if (card === undefined) {
    throw "saveCard: internal error: the card is undefined";
  }
    storeCard(card);
    var cardArea = document.getElementById("cardselection");
    if (cardArea) {
      var policy = getPolicy();
      var cardClass = computeCardClass(card, policy);
      var newCardElement = createItem(card, cardClass, handleCardChoice, dblclick);
      cardArea.appendChild(newCardElement);
      var xpcomInterface = cardArea.scrollBoxObject.QueryInterface(Components.interfaces.nsIScrollBoxObject);
      xpcomInterface.ensureElementIsVisible(newCardElement);
      setCard(card);
    } // else called from cardWizard and not from cardManager!
    return true;

}


function newCard(){

    var callback;
    var cardWiz = window.openDialog("chrome://infocard/content/cardWizard.xul","Card Wizard", "modal,chrome,resizable=yes,width=640,height=480",
                                    getPolicy(), function (callbackData) { callback = callbackData;});
  digestNewCard(callback);
}

function validateSignature(callback) {
  var cardFile = CardstoreToolkit.readCardStore();
  
  var importedCardJSONStr = null;
  try {
    importedCardJSONStr = JSON.stringify(callback);
  } catch (e) {
    icDebug("error JSON.stringifying(callback) " + e);
  }
  icDebug2("importedCardJSONStr="+importedCardJSONStr, 120);
  var cardFileStr = null;
  try {
    cardFileStr = "" + cardFile + "";
  } catch (e) {
    icDebug("error JSON.stringifying(cardFile) " + e);
  }
  if (tokenIssuerInitialized = TokenIssuer.initialize(java) == false) {
    icDebug("validateSignature: could not initialize TokenIssuer. Signature will not be validated");
    icDebug("validateSignature: window.java = " + window.java + "window.document.location.href=" + window.document.location.href);
// alert("Could not initialize java. The card's signature will not be
// validated!");
  } else {
    var currentRoamingStore = readRoamingStore();
    icDebug2("currentRoamingStore = " + currentRoamingStore, 120);
    var importedCardStr = null;

    try {
      importedCardStr = TokenIssuer.importManagedCard(importedCardJSONStr, currentRoamingStore);
    } catch (e1) {
      icDebug("TokenIssuer.importManagedCard threw exception " + e1);
    }
      if ((importedCardStr !== null) && (importedCardStr !== undefined)){
        icDebug2("importedCardStr = " + importedCardStr, 120);
        icDebug("importedCardStr type=" + typeof(importedCardStr));
        var importedCard = JSON.parse("" + importedCardStr + ""); // convert
                                                                  // java.lang.String
                                                                  // to
                                                                  // javascript
                                                                  // string
        if (importedCard == false) {
          // oops. Could not parse json
          icDebug2("Internal error: could not parse json=" + importedCardStr, 120);
          InformationCardHelper.alert("Internal error: could not parse json=" + importedCardStr);
          return;
        }
        if (importedCard === null) {
          InformationCardHelper.alert("The managed card is NOT imported");
          return;
        }
        
        if (importedCard.error) {
             InformationCardHelper.alert("The card is NOT imported\n" + importedCard.error);
          return;
        } 
        var result = importedCard.result;
        icDebug2("RoamingStore: " + result, 160);
        
        var roamingstore = new XML(result);
        // icDebug("RoamingStoreXML: " + roamingstore);
        saveRoamingStore(roamingstore);
      } else {
        InformationCardHelper.alert("Could not verify SIGNATURE of card: " + callback.cardName + "\nContinuing anyways with import.");
      }
  }
}
function digestNewCard(callback) {
  icDebug("digestNewCard");
  if (callback === undefined) {
   InformationCardHelper.alert("no new card was imported");
   return;
  }
  if (callback === null) {
   InformationCardHelper.alert("No new card was imported");
   return;
  }
  
  var cardName = "" + callback.cardName;
  if (cardName == "") {
    InformationCardHelper.alert("No new card was imported!");
    return;
  }
  
    var type = "" + callback.type;
    var cardId = "" + callback.cardId;
    var card = null;
    
    if (isCardInStore(cardId)) {
      InformationCardHelper.alert("This card is already in the card store. Please delete it first.");
    return;
    }
  
    if ( type === "selfAsserted") {
      
        card = newSelfIssuedCard(callback);
        if (card === null) {
          icDebug("digestNewCard: card is null. callback = " + callback);
          InformationCardHelper.alert("This card is null. This might be an internal error");
          return;
        }
        saveCard(card);
        return;
    }

    if ( type === "managedCard") {
      validateSignature(callback);
      card = newManagedCard(callback);
        if (card === null) {
          icDebug("digestNewCard: card is null. callback = " + callback);
          InformationCardHelper.alert("This card is null. This might be an internal error");
          return;
        }
        saveCard(card);
    }


    if ( type == "openid") {
      card = newOpenIdCard(callback);
        if (card === null) {
          icDebug("digestNewCard: card is null. callback = " + callback);
          InformationCardHelper.alert("This card is null. This might be an internal error");
          return;
        }
        saveCard(card);

    }


}

function reload(policyParam) {
    var cardArea = document.getElementById("cardselection");
    while (cardArea.hasChildNodes())
  {
    cardArea.removeChild(cardArea.firstChild);
  }


    var grid = document.getElementById("editgrid");
    if (grid !== null) {
      grid.setAttribute("hidden", "true");
    }
    grid = document.getElementById("editgrid1");
    if (grid !== null) {
      grid.setAttribute("hidden", "true");
    }

    grid = document.getElementById("editgrid2");
    if (grid !== null) {
      grid.setAttribute("hidden", "true");
    }

    grid = document.getElementById("editgrid3");
    if (grid !== null) {
      grid.setAttribute("hidden", "true");
    }

    var label = document.getElementById("notify");
    if (label !== null) {
      label.setAttribute("value", "Please select another card");
    }
    
    var select = document.getElementById('selectcontrol');
    if (select !== null) {
      select.setAttribute('hidden', 'true');
    }
    
  var cardname = document.getElementById("cardname");
  if (cardname !== null) {
        cardname.value = "";
        cardname.hidden = false;
  }
  
    selectedCard = null;

    cardManagerLoad(policyParam);
}

function deleteCard(){

  if (selectedCard === undefined) return;
  if (selectedCard === null) return;
  
    var selectedCardId = selectedCard.id;
    icDebug("Delete Card : " + selectedCardId);
    removeCard(selectedCardId);
  reload();
}

function processCard(policy, enableDebug){
  icDebug("processCard: {");
    try {
      var tokenIssuerInitialized = TokenIssuer.initialize(java);
      if (tokenIssuerInitialized == false) {
        icDebug("processCard: could not initialize TokenIssuer. window.document.location.href=" + window.document.location.href);
        icDebug("processCard: window.java=" + window.java);
        // alert("Could not initialize the TokenIssuer. This is probably an java
        // issuer");
        throw "processCard: could not initialize TokenIssuer";
      }
      icDebug("processCard: here");
      var token;
      
      var serializedPolicy = JSON.stringify(policy);
      icDebug("processCard: serializedPolicy=" + serializedPolicy);
      var sp = TokenIssuer.getToken(serializedPolicy);
      var newPolicy = JSON.parse(sp);

      return newPolicy;
    } catch (e) {
      icDebug("processCard: threw " + e);
      throw e;
    } finally {
      icDebug("processCard: }");
    }
}

