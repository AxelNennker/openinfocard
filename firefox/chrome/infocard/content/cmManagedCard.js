Components.utils.import("resource://infocard/cmCommon.jsm");
Components.utils.import("resource://infocard/IdentitySelectorDiag.jsm");

function findBackingCard(managedCard, rpPPID, tsEndpointAddressStr, tsIdentityX509CertificateStr) {
  var aCardstore = InformationCardHelper.getCardstore();
  if (!aCardstore) {
    IdentitySelectorDiag.reportError( "cmManagedCard.js findBackingCard",
              "Unable to locate a card store.  " +
              "Please make sure one is installed.");
    return null;
  }
  var cardFile = aCardstore.readCardStore();
  var cardXmllist = cardFile.infocard;
  icDebug("findBackingCard cardXmllist.length()=" + cardXmllist.length());
  for (var i=0; i<cardXmllist.length(); i++) {
    var c = cardXmllist[i];
    if (c.type.toString() === "selfAsserted") {
      var rpPPIdList = c.rpPPID;
      var count = 0;
      for (var j=0; j<rpPPIdList.length(); j++) {
        var aRpPPID = rpPPIdList[j].toString();
        count++;
        icDebug("findBackingCard:" + c.name + " aRpPPID:" + aRpPPID + " rpPPID:" + rpPPID);
        if (aRpPPID == rpPPID) {
          // this rpPPID is already in list of rpPPID
          return c;
        }
      }
    }
  }
  return null;
}

function processManagedCard(
    managedCard, requiredClaims, optionalClaims, tokenType, clientPseudonym, 
    relyingPartyURL, relyingPartyCertB64, issuerPolicy) {

    var tokenToReturn = null;

    var ic = new Namespace("ic", "http://schemas.xmlsoap.org/ws/2005/05/identity");
    var wsa = new Namespace("wsa", "http://www.w3.org/2005/08/addressing");
    
    var tokenServiceList = managedCard.carddata.managed.ic::TokenServiceList;
    icDebug("processManagedCard::tokenServiceList>>>" + tokenServiceList);
    if (tokenServiceList === null || tokenServiceList.length() == 0) {
      IdentitySelectorDiag.reportError("processManagedCard", 
          "This is probably a managed card that is stored in an old and now unsupported internal format.\n" +
          "Please delete the card. Sorry for the inconvenience.");
      return null;
    }
    
    var tslNamespace = tokenServiceList.namespace();
    icDebug("processManagedCard::tslNamespace>>>" + tslNamespace);
    icDebug("processManagedCard::tslNamespace.prefix>>>" + tslNamespace.prefix + "<<<");

    var usercredential = null;
    var mexResponse = null;
    
    var mexes = {}; // mex response cache
    
    var tokenServices = tokenServiceList.ic::TokenService;
  for each (var ts in tokenServices) {
    icDebug("processManagedCard::tokenService>>>" + ts);
    
    var icUserCredential = ts.ic::UserCredential;
    icDebug("processManagedCard::icUserCredential>>>" + icUserCredential);
    var icUserCredentialChild;
    if (icUserCredential.*.length() == 1) {
      icUserCredentialChild = icUserCredential.child(0);
    } else {
      icUserCredentialChild = icUserCredential.child(1);
    }
    icDebug("processManagedCard::isUserCredentialChild>>>" + icUserCredentialChild);
    var localName = icUserCredentialChild.name().localName;
    icDebug("processManagedCard::isUserCredentialChild.name().localname>>>" + localName);

     // currently only UsernamePasswordCredential is supported
    var tsEndpointAddress = ts.wsa::EndpointReference.wsa::Address; 
    icDebug("processManagedCard::tsEndpointAddress>>>" + tsEndpointAddress);
    
    var wsai = new Namespace("wsai", "http://schemas.xmlsoap.org/ws/2006/02/addressingidentity");
    var tsWsaiIdentity = ts.wsa::EndpointReference.wsai::Identity;
    icDebug("processManagedCard::tsWsaiIdentity>>>" + tsWsaiIdentity);
    var dsig = new Namespace("dsig", "http://www.w3.org/2000/09/xmldsig#");
    var tsIdentityX509Certificate = tsWsaiIdentity..dsig::X509Certificate;
    icDebug("processManagedCard::tsIdentityX509Certificate>>>" + tsIdentityX509Certificate);
    
    var tsWsaMetadata = ts.wsa::EndpointReference.wsa::Metadata;
    icDebug("processManagedCard::tsMetadata>>>" + tsWsaMetadata);
    var wsx = new Namespace("wsx", "http://schemas.xmlsoap.org/ws/2004/09/mex");
    var tsWsxMetadata = tsWsaMetadata.wsx::Metadata;
    icDebug("processManagedCard::tsWsxMetadata>>>" + tsWsxMetadata);
    var tsMetadataSection = tsWsxMetadata.wsx::MetadataSection; 
    icDebug("processManagedCard::tsMetadataSection>>>" + tsMetadataSection);
    var tsMetadataReference = tsMetadataSection.wsx::MetadataReference;
    icDebug("processManagedCard::tsMetadataReference>>>" + tsMetadataReference);
    var tsMexAddress = tsMetadataReference.wsa::Address;
    if ((tsMexAddress === null) || (tsMexAddress.length() == 0)) {
      icDebug("processManagedCard::wsa:tsMexAddress not found in >>>" + tsMetadataReference.toXMLString());
      tsMexAddress = tsMetadataReference.*[0];
      if (tsMexAddress.name().localName !== "Address") {
        throw("processManagedCard::tsMexAddress.name().localName >>>" + tsMexAddress.name().localName);
        return null;
      }
    }
    icDebug("processManagedCard::tsMexAddress>>>" + tsMexAddress);
    var tsMexAddressStr = tsMexAddress.toString();
    if (mexes[tsMexAddressStr] !== undefined) {
      mexResponse = mexes[tsMexAddressStr];
    } else {
      icDebug("processManagedCard::tsMexAddressStr>>>" + tsMexAddressStr);
      var aTsMexAddress = xmlreplace(tsMexAddressStr);
      icDebug("processManagedCard::aTsMexAddress>>>" + aTsMexAddress);
      try {
        mexResponse = getMex1(aTsMexAddress, tsMexAddress);
      } catch(getMexException) {
        icDebug("processManagedCard::getMex1 Exception>>>" + getMexException);
      }
      icDebug("xxx getMex1 xxx");
    }
    if (mexResponse !== null) {
      icDebug("processManagedCard::mexResponse>>>" + mexResponse);
      mexes[tsMexAddressStr] = mexResponse;
      
      var mexXml = new XML(mexResponse);
      var wsdl = new Namespace("http://schemas.xmlsoap.org/wsdl/");
      var wsa10 = new Namespace("http://www.w3.org/2005/08/addressing");
      var wsp = new Namespace("http://schemas.xmlsoap.org/ws/2004/09/policy");
      var wsu = new Namespace("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
      
      var addresses = mexXml..wsdl::port.wsa10::EndpointReference.wsa10::Address;
      var tsEndpointAddressStr = tsEndpointAddress.toString();

      for each (var anAddress in addresses) {
        var theAddress = anAddress.child(0);
// icDebug("processManagedCard::typeof("+theAddress+")>>>" +
// typeof(theAddress));
// icDebug("processManagedCard::typeof("+tsEndpointAddress+")>>>" +
// typeof(tsEndpointAddress));
        if (theAddress.toString() === tsEndpointAddressStr) {
          icDebug("processManagedCard::address>>>" + theAddress);
          var addressParent = anAddress.parent(); // EndpointReference
          icDebug("processManagedCard::parent >>>" + addressParent);
          var endpointReferenceParent = addressParent.parent(); // wsdl::port
          icDebug("processManagedCard::port   >>>" + endpointReferenceParent);
          var binding = endpointReferenceParent.@binding;
          icDebug("processManagedCard::port.@binding>>>" + binding);
          var colonIndex = binding.indexOf(":");
          binding = binding.substring(colonIndex+1); // works even if
                                                      // colonIndex == -1
          var bindingStr = binding.toString();
          
          var bindings = mexXml..wsdl::binding;
          for each (var aBinding in bindings) {
            var bindingNameAttrValueStr = aBinding.@name.toString();
            if (bindingNameAttrValueStr === bindingStr) {
              icDebug("processManagedCard::bindingNameAttrValueStr>>>" + bindingNameAttrValueStr);
              var wspPolicyReference = aBinding.wsp::PolicyReference;
              if (wspPolicyReference !== null) {
                icDebug("processManagedCard::wspPolicyReference>>>" + wspPolicyReference.toXMLString());
                var wspPolicyReferenceURIStr = wspPolicyReference.@URI.toString();
                icDebug("processManagedCard::wspPolicyReferenceURI>>>" + wspPolicyReferenceURIStr);
                var hashmarkIndex = wspPolicyReferenceURIStr.indexOf("#");
                if (hashmarkIndex == 0) {
                  var wspPolicyReferenceURIStr = wspPolicyReferenceURIStr.substring(1);
                  icDebug("processManagedCard::wspPolicyReferenceURIStr>>>" + wspPolicyReferenceURIStr);
                  var wsdlPolicies = mexXml..wsdl::definitions.wsp::Policy;
                  icDebug("processManagedCard::wsdlPolicies.length()>>>" + wsdlPolicies.length());
                  for each (var aPolicy in wsdlPolicies) {
                    //icDebug("processManagedCard::aPolicy>>>" + aPolicy.toXMLString());
                    var wsuId = aPolicy.@wsu::Id;
                    var wsuIdStr = wsuId.toString();
                    if (wsuIdStr === wspPolicyReferenceURIStr) {
                      icDebug("processManagedCard::wsuIdStr>>>" + wsuIdStr);
                      // try both security policies
                      var sp2005 = new Namespace("http://schemas.xmlsoap.org/ws/2005/07/securitypolicy");
                      var sp2007 = new Namespace("http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702");
                      var spTransportBinding = aPolicy..sp2005::TransportBinding;
                      if (spTransportBinding === null || spTransportBinding.length() == 0) {
                        icDebug("processManagedCard::spTransportBinding (2005) null in sPolicy>>>" + aPolicy.toString());
// var spTransportBinding = aPolicy..sp2007::TransportBinding;
// if (spTransportBinding === null || spTransportBinding.length() == 0) {
// icDebug("processManagedCard::spTransportBinding (2007) null too>>>");
// continue;
// }
                        continue;
                      }
                      icDebug("processManagedCard::before sendRST: tsEndpointAddressStr=" + tsEndpointAddressStr);
                      icDebug("processManagedCard::before sendRST: tsEndpointCertStr=" + tsIdentityX509Certificate.toString());
                        icDebug("processManagedCard::typeof(tsEndpointAddressStr):" + typeof(tsEndpointAddressStr));
                      icDebug("processManagedCard::before sendRST: icUserCredential=" + icUserCredential);
                        icDebug("processManagedCard::typeof(icUserCredential):" + typeof(icUserCredential));
                      try {
                        var backingCard;
                        try { 
                          var ic = new Namespace("ic", "http://schemas.xmlsoap.org/ws/2005/05/identity");
                          if (icUserCredential.ic::SelfIssuedCredential.toString() === "") {
                            icDebug("findBackingCard not selfIssuedCredential:" + icUserCredential);
                            return null;
                          }
                          var rpPPID = icUserCredential.ic::SelfIssuedCredential.ic::PrivatePersonalIdentifier.toString();
                          icDebug("findBackingCard expectedPpid:" + rpPPID);
                          rpPPID = window.atob(rpPPID);
                          icDebug("findBackingCard expectedPpid(decoded):" + rpPPID);
                          backingCard = findBackingCard(managedCard, rpPPID, tsEndpointAddressStr, 
                              tsIdentityX509Certificate.toString());
                        } catch (findBackingCardException) {
                          icDebug("processManagedCard: findBackingCard threw: " + findBackingCardException);
                          // ignore
                        }

                        var sendRstParameter = {};
                        sendRstParameter.backingCard = backingCard;
                        sendRstParameter.tsEndpointAddressStr = tsEndpointAddressStr;
                        sendRstParameter.tsEndpointCertStr = tsIdentityX509Certificate.toString();
                        sendRstParameter.icUserCredential = icUserCredential;
                        sendRstParameter.managedCard = managedCard;
                        sendRstParameter.requiredClaims = requiredClaims;
                        sendRstParameter.optionalClaims = optionalClaims;
                        sendRstParameter.tokenType = tokenType;
                        sendRstParameter.clientPseudonym = clientPseudonym;
                        sendRstParameter.relyingPartyURL = relyingPartyURL;
                        sendRstParameter.relyingPartyCertB64 = relyingPartyCertB64;
                        sendRstParameter.issuerPolicy = issuerPolicy;
                        var aToken = sendRST(sendRstParameter);
                        if ((aToken !== undefined) && (aToken !== null)) {
                          return aToken;
                        } else {
                          icDebug("processManagedCard: sendRST returned null or undefined for: " + tsEndpointAddressStr);
                        }
                      } catch (sendRstException) {
                        icDebug("processManagedCard: sendRST threw: " + sendRstException);
                      }
                    } else {
                      //icDebug("processManagedCard::WSUID   >>>" + wsuIdStr);
                    }
                  }
                } else {
                  icDebug("processManagedCard::hasmarkIndex>>>" + hashmarkIndex);
                }
              } else {
                Components.utils.reportError("processManagedCard::wspPolicyReference===null! aBinding=" + aBinding);
                return null;
              }
            }
          }
        } else {
          // icDebug("processManagedCard::ADDRESS>>>" + theAddress);    
        }
      }
    } else {
      icDebug("processManagedCard::mexResponse is null for " + tsMexAddress);
    }
  

  }
    return null;
}

function createCheckbox(optionalClaims, requiredClaims, displayTag, uri) {
  try {
    if (uri == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier") {
      icDebug("createCheckbox: typeof(displayTag)=" + typeof(displayTag));
      if (!displayTag) {
        displayTag = "PPID";
      }
    }
    var checkbox = document.createElement("checkbox");
    var label;
    label = displayTag;
    icDebug("createCheckbox: uri=" + uri);
    icDebug("createCheckbox: label=" + label);
    label = xmlreplace(label);
    icDebug("createCheckbox: xmlreplace(label)=" + label);
    checkbox.setAttribute("label", label);
    checkbox.setAttribute("id", "label_"+uri);
    checkbox.setAttribute("class", "claimLabel");
    checkbox.setAttribute("crop", "end");

    try {
    // DisplayTag should be changed to Description when description is supported
      checkbox.setAttribute("tooltiptext", displayTag); // this is not cropped
    } catch (err) {
      // tooltiptext barfs on "invalid character" while value does not... Axel
      icDebug(err + "(" + displayTag + ")");
    }

   if ((requiredClaims) && (requiredClaims.indexOf(uri) >= 0)) {
     checkbox.setAttribute("checked", "true");
     checkbox.setAttribute("disabled", "true");
     icDebug("uri: " + uri + " is required");
     return checkbox;
   } else {
     if ((optionalClaims) && (optionalClaims.indexOf(uri) >= 0)) {
       checkbox.setAttribute("checked", "false");
       checkbox.setAttribute("disabled", "false");
       icDebug("uri: " + uri + "is optional");
       return checkbox;
     } else {
       icDebug("uri: " + uri + " is neither optional nor required");
       return null;
     }
   } 
  } catch (e) {
    icDebug("Exception in " + createCheckbox + "(" + e + ")");
    return null;
  }
}

function getVariableClaimValue(thisClaim) {
  try {
     var value = "";
     var ws = thisClaim.indexOf(' '); // space
     if (ws == -1) {
       ws = thisClaim.indexOf('  '); // tab
       if (ws == -1) {
         ws = thisClaim.indexOf(String.fromCharCode(10));  // line-feed
         if (ws == -1) {
           ws = thisClaim.indexOf(String.fromCharCode(13)); // carriage return
         }
       }
     }
     if (ws != -1) {
       thisClaim = thisClaim.substring(0,ws);
       icDebug("thisClaim: " + thisClaim);
     }
     var qi = thisClaim.indexOf('?');
     icDebug("qi claim:" + thisClaim + " " + qi);
     if (qi >= 0) {
      value = thisClaim.substr(qi);
      icDebug("variable claim value: " + value);  
     }
     return value;
  } catch (e) {
    icDebug("getVariableClaimValue threw: " + e);
  }
}

function cardManagerOnInput() {
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
}

function setCardManaged(requiredClaims, optionalClaims, list, row1Id, claimValues) {
  try {
    var ic = new Namespace("ic", "http://schemas.xmlsoap.org/ws/2005/05/identity");

    icDebug("setCardManaged requiredClaims: " + requiredClaims);
    icDebug("setCardManaged optionalClaims: " + optionalClaims);
    if (requiredClaims) {
      requiredClaims = requiredClaims.replace(/\s+/g,' ');
    }
    icDebug("setCardManaged requiredClaims: " + requiredClaims);
    if (optionalClaims) {
      optionalClaims = optionalClaims.replace(/\s+/g,' ');
    }
    icDebug("setCardManaged optionalClaims: " + optionalClaims);
    
    var managedRows = document.getElementById(row1Id);
      
    // remove child rows before appending new ones
    while (managedRows.hasChildNodes()) { 
       managedRows.removeChild(managedRows.childNodes[0]);
    }
      
    icDebug("setCardManaged: number of supported claims: " + list.length());

    for (var index=0; index<list.length(); index++) {
      var supportedClaim = list[index];
      var uri = supportedClaim.@Uri.toXMLString();
      icDebug("setCardManaged: uri=" + uri);
      
// if (uri ==
// "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier")
// {
// continue;
// }
//      
      var row = document.createElement("row");
      row.setAttribute("class", "rowClass");

      var displayTag = "" + supportedClaim.ic::DisplayTag;
      var checkbox = createCheckbox(optionalClaims, requiredClaims, displayTag, uri);
      if (!checkbox) {
        if (uri == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier") {
          if (!displayTag) {
            displayTag = "PPID";
          }
        }
        icDebug("setCardManaged: label displayTag="+displayTag + " uri=" + uri);
        checkbox = document.createElement("label");
        checkbox.setAttribute("value", displayTag);
        checkbox.setAttribute("control", uri);
        checkbox.setAttribute("class", "claimLabel");
        checkbox.setAttribute("crop", "end");
      }
      icDebug("setCardManaged: after createCheckbox");
      var value = "";
      if (optionalClaims != null) {
       var ui = optionalClaims.indexOf(uri);
       if (ui != -1) {
         icDebug("optional claim:" + uri);
         var thisClaim = optionalClaims.substr(ui);
         value = getVariableClaimValue(thisClaim);
       }
      }
      if (requiredClaims != null) {
       var ui = requiredClaims.indexOf(uri);
       if (ui != -1) {
         icDebug("requiredClaim claim:" + uri);
         var thisClaim = requiredClaims.substr(ui);
         value = getVariableClaimValue(thisClaim);
       }
      }
      
      if ((claimValues !== undefined) && (claimValues !== null)) {
        icDebug("setCardManaged: number of claimValues: " + claimValues.length());
        for (var ci=0; ci<claimValues.length(); ci++) {
         var claimValue = claimValues[ci];
         icDebug("setCardManaged: claimValue=" + claimValue.toXMLString());
         var claimUri = claimValue.@Uri.toXMLString();
         if (claimUri === uri) {
           value = claimValue.ic::Value.text();
         } else {
  //           icDebug("setCardManaged: claimUri=" + claimUri + " uri=" + uri);
         }
        }
      }

      icDebug("setCardManaged: hier");
       
      var textbox = document.createElement("textbox");
      var id = uri;
      textbox.setAttribute("id", id);
      textbox.setAttribute("class", "claimText");
      textbox.setAttribute("value", value);
      textbox.setAttribute("oninput", "cardManagerOnInput();");
      // textbox.setAttribute("readonly", "true");
      if (checkbox) {
        row.appendChild(checkbox);
      }
      row.appendChild(textbox);
      managedRows.appendChild(row);
      
    }
    
    if (managedRows.hasChildNodes()) {
      var grid = document.getElementById("editgrid2");
      grid.setAttribute("hidden", "false");
    }

   icDebug("setCardManaged: da");
    
   var stringsBundle = document.getElementById("string-bundle");
   var label = document.getElementById("notify");
   if (label != null) {
     if (selectedCard.type == "managedCard" ) {
       var managedcardfromissuer = stringsBundle.getFormattedString('managedcardfromissuer', [selectedCard.carddata.managed.issuer]);
       label.setAttribute("value", managedcardfromissuer );
     } else {
       if (selectedCard.type == "selfAsserted" )  {
         var selfassertedcard = stringsBundle.getString('selfassertedcard');
         label.setAttribute("value", selfassertedcard);
       }
     }
   }
   icDebug("setCardManaged: boink");
    
  } catch (e) {
    icDebug("setCardManaged: threw: " + e);
    Components.utils.reportError("setCardManaged: threw: " + e);
  }
}

