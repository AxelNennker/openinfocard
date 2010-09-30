Components.utils.import("resource://infocard/tokenissuer.jsm");
Components.utils.import("resource://infocard/OICCrypto.jsm");
Components.utils.import("resource://infocard/CardstoreToolkit.jsm");
Components.utils.import("resource://infocard/IdentitySelectorDiag.jsm");

var db = "cardDb.xml";

function isCardInStore(cardId) {
    var cardFile = CardstoreToolkit.readCardStore();
    for each (c in cardFile.infocard) {
    	if ("" + c.id === cardId) {
    		return true;
    	}
	}
    return false;
}

function clearOpeninfocardHistory() {
    var cardFile = read(db);
    var nDB = newDB();
    
    for each (c in cardFile.infocard) {
    	delete c.rpIds;
    	dump("clearOpeninfocardHistory: " + c.id);
    	nDB.infocard += c;
    }
    save(db,nDB.toString());
}

function saveRoamingStore(roamingstore) {
	//saveLocalFile(getDir() + "roamingstore.xml", roamingstore);
	save("roamingstore.xml", roamingstore);
}

function readRoamingStore() {
	return readALocalFile(getDir() + "roamingstore.xml");
}

function getCard(cardid){
//	cardstoreDebug("storeCard: cardid=" + cardid);
//	cardstoreDebug("storeCard: typeof(cardid)=" + typeof(cardid));
    var cardFile = read(db);
//	cardstoreDebug("storeCard: cardFile=" + cardFile);
//	cardstoreDebug("storeCard: typeof(cardFile)=" + typeof(cardFile));
//	cardstoreDebug("storeCard: typeof(cardFile.infocard)=" + typeof(cardFile.infocard));
    
    for each (c in cardFile.infocard) {
    	if (c.id == cardid) {
    		cardstoreDebug("getCard: c.id=" + c.id + "==" + cardid);
    		return c;
    	} else {
    		cardstoreDebug("getCard: c.id=" + c.id + "!=" + cardid);
    	}
    }
    return null;
// the following line stopped to work in Firefox 3.1    
//    var card = cardFile.infocard.(id == cardid);
//    return card;
}

//function readCardStore() {
// var cardFile = read(db);
//// cardstoreDebug("readCardStore:" + cardFile);
// return cardFile;
//}

function storeCard(card){
cardstoreDebug("storeCard");
cardstoreDebug(card);
	if (card === undefined) {
		throw "storeCard: internal error: the card is undefined";
	}
    var cardFile = read(db);
    cardFile.infocard += card;
    save(db,cardFile.toString());
}

function removeCard(selectedCardId) {
    var cardFile = read(db);
    var count = 0;
    for each (c in cardFile.infocard) {
        var latestId = c.id;
        if (latestId == selectedCardId) delete cardFile.infocard[count];
        count++;
    }
    save(db,cardFile.toString());
}

// make a copy of the db replacing one card
function updateCard(card) {
    var cardFile = read(db);
    var nDB = newDB();
    
    for each (c in cardFile.infocard) {
        var latestId = c.id;
        if (latestId == card.id) {
         nDB.infocard += card;
        } else {
         nDB.infocard += c;
        }
    }
    save(db,nDB.toString());
}

function login(cardStorePath) {
	// Get Password Manager (does not exist in Firefox 3)
	var CC_passwordManager = Components.classes["@mozilla.org/passwordmanager;1"];
	var CC_loginManager = Components.classes["@mozilla.org/login-manager;1"];
     
	if (CC_passwordManager != null) {
	  	// Password Manager exists so this is not Firefox 3 (could be Firefox 2, Netscape, SeaMonkey, etc).
	  	// Password Manager code
	  	// the host name of the password we are looking for
		var queryString = 'chrome://infocard/cardstore?' + encodeURIComponent(cardStorePath);
		// ask the password manager for an enumerator:
		var e = passwordManager.enumerator;
		// step through each password in the password manager until we find the one we want:
		while (e.hasMoreElements()) {
		    try {
		        // get an nsIPassword object out of the password manager.
		        // This contains the actual password...
		        var pass = e.getNext().QueryInterface(Components.interfaces.nsIPassword);
		        if (pass.host == queryString) {
		             // found it!
//		             alert(pass.user); // the username
//		             alert(pass.password); // the password
		             break;
		        }
		    } catch (ex) {
		        // do something if decrypting the password failed--probably a continue
		    }
		}
	}
	else if (CC_loginManager!= null) {
 	  // Login Manager exists so this is Firefox 3
 	  // Login Manager code
 	  IdentitySelectorDiag.reportError("cardstore.js", "loginManager support is not implemented.");
	}
}

function save(fileName, fileContents) {
	var prefs = Components.classes["@mozilla.org/preferences-service;1"].
                    getService(Components.interfaces.nsIPrefService);
	prefs = prefs.getBranch("extensions.infocard.");

	var encrypt = prefs.getBoolPref("cardStoreMasterPasswordEncryption");
	if (encrypt) {
	    var sdr = Components.classes["@mozilla.org/security/sdr;1"]
	                            .getService(Components.interfaces.nsISecretDecoderRing);
	    fileContents = sdr.encryptString(fileContents);
	}    

	var useProfile = prefs.getBoolPref("cardStoreCurrentProfile");
	if (useProfile) {
	    cardstoreDebug("saving profile cardstore");
		fileName = getDir() + fileName;
		saveLocalFile(fileName, fileContents);
		return;
	}

	var localFilePath = prefs.getComplexValue("cardStoreLocalFilePath",
      Components.interfaces.nsISupportsString).data;
    if ((localFilePath != null) && (localFilePath != "")) {
	    cardstoreDebug("using local file as cardstore: " + localFilePath);
	    try {
	    	saveLocalFile(localFilePath, fileContents);
	    	return;
	    } catch(e) {
	    	IdentitySelectorDiag.reportError("cardstore.js", "writing local file cardstore failed:" + e);
	    } 
	    return;
    }

	var url = prefs.getComplexValue("cardStoreUrl",
      Components.interfaces.nsISupportsString).data;
    if ((url != null) && (url != "")) {
	    cardstoreDebug("writing url cardstore: " + url);
	    var req = new XMLHttpRequest();
	    req.open('POST', url, false);
	    req.setRequestHeader("Content-type", "application/xml; charset=utf-8");
	    req.setRequestHeader("Cache-Control", "no-cache");
	    req.setRequestHeader("User-Agent", "xmldap infocard stack");
	    req.send(fileContents);
        cardstoreDebug("POST request status="+req.status);
        if(req.status == 200) {
        	return;
		} else {
			IdentitySelectorDiag.logMessage("cardstore.js", req.responseText);    
	    	return;
	    }
    }
	aIdentitySelectorDiag.logMessage("cardstore.js", writing cardstore failed");
}

function saveLocalFile(fileName, contents) {

    try {
		netscape.security.PrivilegeManager.enablePrivilege("UniversalXPConnect");
	} catch (e) {
		cardstoreDebug("cardstore::save: " + e);
	}
	
	var file = Components.classes["@mozilla.org/file/local;1"].createInstance(Components.interfaces.nsILocalFile);
	file.initWithPath( fileName );
	if ( file.exists() == false ) {
		file.create( Components.interfaces.nsIFile.NORMAL_FILE_TYPE, 420 );
	}
	var outputStream = Components.classes["@mozilla.org/network/file-output-stream;1"].createInstance( Components.interfaces.nsIFileOutputStream );
	try {
		outputStream.init( file, 0x04 | 0x08 | 0x20, 420, 0 );
		
		var charset = "UTF-8"; // Can be any character encoding name that Mozilla supports
	
		var converter = Components.classes["@mozilla.org/intl/converter-output-stream;1"]
	                   .createInstance(Components.interfaces.nsIConverterOutputStream);
		try {
			converter.init(outputStream, charset, 0, 0x0000);
			converter.writeString(contents);
		}
		finally {
			converter.close();
		}
	}
	finally {    
	    //var result = outputStream.write( fileContents, fileContents.length );
	    outputStream.close();
	}
}

// http://forums.mozillazine.org/viewtopic.php?p=921150#921150
function getContents(aURL){
  var str = null;
  var ioService=Components.classes["@mozilla.org/network/io-service;1"]
    .getService(Components.interfaces.nsIIOService);
  var scriptableStream=Components
    .classes["@mozilla.org/scriptableinputstream;1"]
    .getService(Components.interfaces.nsIScriptableInputStream);
  try {
	  var channel=ioService.newChannel(aURL,null,null);
	  var input=channel.open();
	  try {
		  scriptableStream.init(input);
		  
		  var length; 
		
		  if (channel.contentLength > 0)
		    length = channel.contentLength;
		  else
		    length = input.available();
		     
		  str = "";
		  while (str.length < length)
		    str += scriptableStream.read(length - str.length);
	  }
	  finally {
		input.close();
	  }
  }
  finally {
	scriptableStream.close();
  }
  return str;
} 

function read(fileName) {
	var prefs = Components.classes["@mozilla.org/preferences-service;1"].
                    getService(Components.interfaces.nsIPrefService);
	prefs = prefs.getBranch("extensions.infocard.");

	var useProfile = prefs.getBoolPref("cardStoreCurrentProfile");
	if (useProfile) {
	    fileName = getDir() + fileName;
	    cardstoreDebug("using profile cardstore: " + fileName);
		return readLocalFile(fileName);
	}
	
	var localFilePath = prefs.getComplexValue("cardStoreLocalFilePath",
      Components.interfaces.nsISupportsString).data;
    if ((localFilePath != null) && (localFilePath != "")) {
	    cardstoreDebug("using local file as cardstore: " + localFilePath);
	    try {
	    	return readLocalFile(localFilePath);
	    } catch(e) {
	    	IdentitySelectorDiag.reportError("cardstore.js", "reading local file cardstore failed:" + e);
	    } 
	    return new XML(newDB());
    }

	var url = prefs.getComplexValue("cardStoreUrl",
      Components.interfaces.nsISupportsString).data;
    if ((url != null) && (url != "")) {
	    cardstoreDebug("using url cardstore: " + url);
	    var req = new XMLHttpRequest();
	    req.open('GET', url, false);
//	    req.setRequestHeader("Content-type", "application/xml; charset=utf-8");
	    req.setRequestHeader("Cache-Control", "no-cache");
	    req.setRequestHeader("User-Agent", "xmldap infocard stack");
	    req.send(null);
        cardstoreDebug("GET request status="+req.status);
        if(req.status == 200) {
        	try { // try to decrypt
        		var decrypted = "";
	            var sdr = Components.classes["@mozilla.org/security/sdr;1"]
                            .getService(Components.interfaces.nsISecretDecoderRing);
                decrypted = sdr.decryptString(req.responseText);
                return new XML(decrypted);
        	}
        	catch (e) {
        		cardstoreDebug("decrypting cardstore returned from " + url + " failed");
        		try {
        			return new XML(req.responseText);
        		}
        		catch (e) {
        			cardstoreDebug("no valid xml returned from " + url);
        			return new XML(newDB());
        		}
        	}
		} else {
			cardstoreDebug("req.status = " + req.status);
			IdentitySelectorDiag.logMessage("cardstore.js", req.responseText);    
	    	return new XML(newDB());
	    }
    }
    
    IdentitySelectorDiag.reportError("cardstore.js", "reading cardstore failed");
    return new XML(newDB());
} 

function readALocalFile(fileName) {
    try {
		netscape.security.PrivilegeManager.enablePrivilege("UniversalXPConnect");
	} catch (e) {
		cardstoreDebug("readALocalFile: Permission to read file was denied. " + e);
	}

	var file = Components.classes["@mozilla.org/file/local;1"].createInstance(Components.interfaces.nsILocalFile);
	file.initWithPath( fileName );

    if ( file.exists() == false ) {
		cardstoreDebug("readALocalFile: " + fileName + " not found.");
        return null;
	}

    var output = null;
    
    var is = null;
    try {
    	is = Components.classes["@mozilla.org/network/file-input-stream;1"].createInstance( Components.interfaces.nsIFileInputStream );
		is.init( file,0x01, 00004, null);
		var sis = null;
		try {
			sis = Components.classes["@mozilla.org/scriptableinputstream;1"].createInstance( Components.interfaces.nsIScriptableInputStream );
			sis.init( is );
			output = sis.read( sis.available() );
		} catch (e) {
			cardstoreDebug("readALocalFile threw exception " + e);
			if (sis != null) {
				sis.close();
			}
		} finally {
			if (sis != null) {
				sis.close();
			}
		}
    } catch (e) {
		cardstoreDebug("readALocalFile threw an exception " + e);
		if (is != null) {
			is.close();
		}
	} finally {
		if (is != null) {
			is.close();
		}
	}
	return output;
} 

function readLocalFile(fileName) {

	cardstoreDebug("readLocalFile: reading: " + fileName);
	
	var output = readALocalFile(fileName);
	if (output == null) {
		cardstoreDebug("readALocalFile returned null: " + fileName);
		return newDB();
	}

    if (!output) {
    	output = newDB();
    } else {
		var prefs = Components.classes["@mozilla.org/preferences-service;1"].
                getService(Components.interfaces.nsIPrefService);
		prefs = prefs.getBranch("extensions.infocard.");
    	var encrypt = prefs.getBoolPref("cardStoreMasterPasswordEncryption");
		if (encrypt) {
            var sdr = Components.classes["@mozilla.org/security/sdr;1"]
                            .getService(Components.interfaces.nsISecretDecoderRing);
            var decrypted = "";
            try {
	    		decrypted = sdr.decryptString(output);
            } catch (e) {
            	try {
            		cardstoreDebug(e + "\nerror decypting the cardstore: " + fileName);
	            	return new XML(output);
            	} catch (e) {
            		cardstoreDebug(e + "\ndeencrypted cardstore is no valid xml: " + fileName);
            		return newDB();
            	}
            }
        
        	//cardstoreDebug(decrypted);
        	return new XML(decrypted);
		} else {
			try {
//				var cardstoreXML = new XML(output);
				
				var parser = new DOMParser();
				var dom = parser.parseFromString(output, "text/xml");
				if (dom.documentElement.nodeName == "parsererror") {
					throw "parseerror";
				} else {
					var cardstoreXML = new XML(Components.classes['@mozilla.org/xmlextras/xmlserializer;1'].createInstance(Components.interfaces.nsIDOMSerializer).serializeToString(dom.documentElement));
					return cardstoreXML;
				}

				cardstoreDebug("unencrypted cardstore: " + cardstoreXML);
				return cardstoreXML;
			}
			catch (e) {
				cardstoreDebug(e + "\nunencrypted cardstore is no valid xml:\n" + output);
				// try to decrypt
	            var sdr = Components.classes["@mozilla.org/security/sdr;1"]
	                            .getService(Components.interfaces.nsISecretDecoderRing);
	            var decrypted = "";
	            try {
		    		decrypted = sdr.decryptString(output);
		    		cardstoreDebug("decrypted cardstore:\n" + decrypted);
		    		try {
						var cardstoreXML = new XML(Components.classes['@mozilla.org/xmlextras/xmlserializer;1'].createInstance(Components.interfaces.nsIDOMSerializer).serializeToString(decrypted));
	
						cardstoreDebug("Unencrypted cardstore: " + cardstoreXML);
						saveLocalFile(fileName, cardstoreXML); // save decrypted card store
						return cardstoreXML;
		    		} catch (e) {
		    			cardstoreDebug(e + "Error reading XML:\n" + decrypted);
		    			try {
		    				// new XML is less picky than xmlserializer
		    				cardstoreXML = new XML(decrypted);
		    				saveLocalFile(fileName, cardstoreXML); // save decrypted card store
		    				return cardstoreXML;
		    			} catch (e) {
		    				cardstoreDebug(e + "Error Reading XML:\n" + decrypted);
		    				return newDB();
		    			}
		    			return newDB();
		    		}
	            } catch (e) {
	            	cardstoreDebug("Error decrypting the cardstore:\n" + output);
		            return newDB();
	            }
			}
		}
    }
    var dbFile = new XML(output);
    return dbFile;
}

function getDir(){
    var path;

    try {
        netscape.security.PrivilegeManager.enablePrivilege("UniversalXPConnect");
    } catch (e) {
        IdentitySelectorDiag.reportError("cardstore.js", "Permission to save file was denied." + e);
    }
    // get the path to the user's home (profile) directory
    const DIR_SERVICE = new Components.Constructor("@mozilla.org/file/directory_service;1","nsIProperties");
    try {
        path=(new DIR_SERVICE()).get("ProfD", Components.interfaces.nsIFile).path;
    } catch (e) {
        IdentitySelectorDiag.reportError("cardstore.js", "error");
    }
    // determine the file-separator
    if (path.search(/\\/) != -1) {
        path = path + "\\";
    } else {
        path = path + "/";
    }

    return path;

}

function newInfocard(){
    var card = new XML("<infocard/>");
    return card;
}

function newManagedCard(callback) {
    var card = newInfocard();
    card.name = "" + callback.cardName + "";
    card.type = "" + callback.type;
    card.version = "" + callback.cardVersion + "";
    card.id = "" + callback.cardId + "";

    var data = new XML("<managed/>");
    data.issuer = "" + callback.issuer + "";
    if (callback.cardImage !== undefined) {
	    if (callback.cardImageMimeType === undefined) {
	    	data.image = "data:image/png;base64," + callback.cardImage + "";
	    } else {
	    	data.image = "data:" + callback.cardImageMimeType + ";base64," + callback.cardImage + "";
	    }
    }

    data.supportedClaims = callback.supportedClaims;

    	  cardstoreDebug("new card: tokenServiceList:" + callback.tokenServiceList);
	data.tokenServiceList = callback.tokenServiceList;

	data.stsCert = callback.stsCert;
	if (callback.requireAppliesTo) {
		data.requireAppliesTo = true;
	}
	if (callback.requireStrongRecipientIdentity) {
		data.requireStrongRecipientIdentity = true;
	}
	
	data.supportedTokenTypeList = callback.supportedTokenTypeList;

    card.carddata.data = data;
    cardstoreDebug("saving card: " + callback.cardName);
//	alert("importedCard="+importedCard);
//	//TODO remove return when it is working
//	return;
    return card;
}

function newSelfIssuedCard(callback) {
    card = newInfocard();
    
    card.name = callback.cardName;
    card.type = callback.type;
    if (callback["cardVersion"] == undefined) {
        card.version = 1;
    } else {
    	card.version = callback["cardVersion"];
    }
    var id = Math.floor(Math.random()*100000+1);
    card.id = id;
    card.privatepersonalidentifier = OICCrypto.hex_sha1(callback.cardName + card.version + id);

    var count = 0;
    
    var supportedClaims = "";
    var claims = "";
    
    for (var claim in callback) {
    	if (claim === "type") continue;
    	if (claim === "cardName") continue;
    	if (callback.hasOwnProperty(claim)) {
    		if (callback[claim]) {
    		    var displayTag = callback[claim].displayTag;
    		    supportedClaims += "<ic:SupportedClaimType Uri=\"" + claim + "\">" + 
    		    	"<ic:DisplayTag>" + displayTag +"</ic:DisplayTag></ic:SupportedClaimType>";
    		    var claimValue = callback[claim].claimValue;
	    		claims += "<ic:ClaimValue Uri=\"" + claim + "\"><ic:Value>" + claimValue + "</ic:Value></ic:ClaimValue>";
	    		count++;
    		}
    	}
    }

    var masterKey = "<ic:MasterKey>" + card.privatepersonalidentifier + "</ic:MasterKey>";
    
    var privateCardData;
    if (count > 0) {
    	var claimValueList = "<ic:ClaimValueList>" + claims + "</ic:ClaimValueList>";
    	privateCardData = "<ic:InformationCardPrivateData xmlns:ic=\"http://schemas.xmlsoap.org/ws/2005/05/identity\">"
    		+ masterKey
    		+ claimValueList + "</ic:InformationCardPrivateData>";
    } else {
    	privateCardData = "<ic:InformationCardPrivateData xmlns:ic=\"http://schemas.xmlsoap.org/ws/2005/05/identity\">"
    		+ masterKey
    		+ "</ic:InformationCardPrivateData>";
    }
    
    supportedClaims += "<ic:SupportedClaimType " +
    	"Uri=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier\"/>";
    var supportedClaimTypeList = "<ic:SupportedClaimTypeList xmlns:ic=\"http://schemas.xmlsoap.org/ws/2005/05/identity\">" +
    	supportedClaims + "</ic:SupportedClaimTypeList>";

    card.carddata += new XML(privateCardData);
    card.carddata += new XML(supportedClaimTypeList);
    
//    var givenName = callback.givenname;
//    if (givenName) {
//        card.supportedclaim[count] = "givenname";
//        data.givenname = givenName;
//        count++;
//    }
//    var surname = callback.surname;
//    if (surname) {
//        card.supportedclaim[count] = "surname";
//        data.surname = surname;
//        count++;
//    }
//    var emailAddress = callback.email;
//    if (emailAddress) {
//        card.supportedclaim[count] = "emailaddress";
//        data.emailaddress = emailAddress;
//        count++;
//    }
//    var streetAddress = callback.streetAddress;
//    if (streetAddress) {
//        card.supportedclaim[count] = "streetaddress";
//        data.streetaddress = streetAddress;
//        count++;
//    }
//    var locality = callback.locality;
//    if (locality) {
//        card.supportedclaim[count] = "locality";
//        data.locality = locality;
//        count++;
//    }
//    var stateOrProvince = callback.stateOrProvince;
//    if (stateOrProvince) {
//        card.supportedclaim[count] = "stateorprovince";
//        data.stateorprovince = stateOrProvince;
//        count++;
//    }
//    var postalCode = callback.postalCode;
//    if (postalCode) {
//        card.supportedclaim[count] = "postalcode";
//        data.postalcode = postalCode;
//        count++;
//    }
//    var country = callback.country;
//    if (country) {
//        card.supportedclaim[count] = "country";
//        data.country = country;
//        count++;
//    }
//    var primaryPhone = callback.primaryPhone;
//    if (primaryPhone) {
//        card.supportedclaim[count] = "primaryphone";
//        data.primaryphone = primaryPhone;
//        count++;
//    }
//    var otherPhone = callback.otherPhone;
//    if (otherPhone) {
//        card.supportedclaim[count] = "otherphone";
//        data.otherphone = otherPhone;
//        count++;
//    }
//    var mobilePhone = callback.mobilePhone;
//    if (mobilePhone) {
//        card.supportedclaim[count] = "mobilephone";
//        data.mobilephone = mobilePhone;
//        count++;
//    }
//    var dateOfBirth = callback.dateOfBirth;
//    if (dateOfBirth) {
//        card.supportedclaim[count] = "dateofbirth";
//        data.dateofbirth = dateOfBirth;
//        count++;
//    }
//    var gender = callback.gender;
//    if (gender) {
//        card.supportedclaim[count] = "gender";
//        data.gender = gender;
//        count++;
//    }
//    var imgurl = callback.imgurl;
//    if (imgurl) {
//        card.supportedclaim[count] = "imgurl";
//        data.imgurl = imgurl;
//        count++;
//    }
//
//    card.carddata.data = data;
    return card;
}

function newOpenIdCard(callback) {
    var card = newInfocard();
    card.name = "" + callback.cardName + "";
    card.type = "" + callback.type;
    var version = "1";
    card.version = version;
    card.id = "" + callback.cardId + "";
    return card;
}

function newDB(){

    var dbFile = new XML("<infocards/>");
    dbFile.version = "1";
    return dbFile;
//cardstoreDebug("newDB start");
//	if (TokenIssuer.initialize() == true) {
//	    var dbFile = TokenIssuer.newCardStore();
//	    cardstoreDebug ( "New DB: " + dbFile.toString());
//	    return dbFile;
//	} else {
//		cardstoreDebug("error initializing the TokenIssuer");
//		return null;
//	}
}

function cardstoreDebug(msg) {
  var debug = Components.classes["@mozilla.org/consoleservice;1"].getService(Components.interfaces.nsIConsoleService);
  debug.logStringMessage("cardstore: " + msg);
}

