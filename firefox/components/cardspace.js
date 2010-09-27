/*
 * Copyright (c) 2010, Axel Nennker
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

Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");
Components.utils.import("resource://gre/modules/Services.jsm");
Components.utils.import("resource://gre/modules/ctypes.jsm");

const nsISupports = Ci.nsISupports;
const IIdentitySelector = Ci.IIdentitySelector;

const IIDENTITYSELECTOR_IID_STR = "ddd9bc02-c964-4bd5-b5bc-943e483c6c57";

const CLASS_ID = Components.ID("72e894fd-0d6c-484d-abe8-5903b5f8bf3d");
const CLASS_NAME = "Microsoft Cardspace";
const CONTRACT_ID = "@openinfocard/cardspace;1";
const SELECTOR_CLASS_NAME = "cardspace";

const nsIX509Cert = Ci.nsIX509Cert;

const CATMAN_CONTRACTID = "@mozilla.org/categorymanager;1";
const nsICategoryManager = Ci.nsICategoryManager;

function debug(msg) {
    var cs = Components.classes["@mozilla.org/consoleservice;1"].getService(Components.interfaces.nsIConsoleService);
    cs.logStringMessage("Cardspace: " + msg);
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

function Cardspace() {
  this.wrappedJSObject = this;  
  this.init();
}

Cardspace.prototype = {
    // properties required for XPCOM registration:  
    classDescription: CLASS_NAME,  
    classID:          CLASS_ID,  
    contractID:       CONTRACT_ID,  
    _xpcom_categories : [ {
      category : IIDENTITYSELECTOR_IID_STR,
      entry : CLASS_NAME,
      value : SELECTOR_CLASS_NAME + ':' + CONTRACT_ID,
      service : false
    } ],

    prefBranch : null,
    debug      : true,  // extensions.infocard.log.cardspaceDebug
    dll        : null,
    dll_t      : null,

    observer : {
        _self : null,

        QueryInterface : XPCOMUtils.generateQI([Ci.nsIObserver,
                                                Ci.nsISupportsWeakReference]),

        observe : function (subject, topic, data) {
            let self = this._self;
            self.log("Observed " + topic + " topic.");
            if (topic == "nsPref:changed") {
                self.debug = self.prefBranch.getBoolPref("cardspaceDebug");
            }
        }
    },

    init : function() {
        try {
            // Preferences. Add observer so we get notified of changes.
            this.prefBranch = Services.prefs.getBranch("extensions.infocard.log.");
            this.prefBranch.QueryInterface(Ci.nsIPrefBranch2);
            this.prefBranch.addObserver("cardspaceDebug", this.observer, false);
            this.observer._self = this;
            this.debug = this.prefBranch.getBoolPref("cardspaceDebug");

            this.useDLL();
        } catch (e) {
            this.log("init failed: " + e);
            throw e;
        }
    },

    log : function (message) {
        if (!this.debug)
            return;
        dump("Cardspace: " + message + "\n");
        Services.console.logStringMessage("Cardspace: " + message);
    },

    useDLL : function() {


        let lib = ctypes.open("infocardapi.dll");
        if (!lib) {
          this.log("can not open infocardapi.dll");
          throw "can not open infocardapi.dll";
        }
        this.log("Initializing Cardspace types and function declarations...");

        this.dll = {};
        this.dll_t = {};

        this.dll_t.LPCWSTR = ctypes.ustring;
        this.dll_t.DATA_BLOB = ctypes.voidptr_t;
        this.dll_t.DWORD = ctypes.int;
        this.dll_t.PVOID = ctypes.voidptr_t;
        this.dll_t.UINT = ctypes.unsigned_int;
        this.dll_t.BYTE = ctypes.unsigned_char;

//      typedef struct _CRYPTOAPI_BLOB
//      {
//          DWORD     cbData;
//          __field_bcount(cbData) BYTE *pbData;
//      } DATA_BLOB;
      this.dll_t.DATA_BLOB = ctypes.StructType(
          "DATA_BLOB", [{ cbData:      this.dll_t.DWORD},
                        { pbData:      this.dll_t.BYTE.ptr}]);

//    typedef struct _ENDPOINTADDRESS
//    {
//        LPCWSTR     serviceUrl;
//        LPCWSTR     policyUrl;
//        DATA_BLOB    rawCertificate;
//    }ENDPOINTADDRESS, *PENDPOINTADDRESS;
    this.dll_t._ENDPOINTADDRESS = ctypes.StructType(
        "_ENDPOINTADDRESS", [{ serviceUrl:      this.dll_t.LPCWSTR},
                             { policyUrl:       this.dll_t.LPCWSTR},
                             { rawCertificate:  this.dll_t.DATA_BLOB}]);

//      typedef struct _ENDPOINTADDRESS2
//      {
//          LPCWSTR     serviceUrl;
//          LPCWSTR     policyUrl;
//          DWORD       identityType;
//          PVOID       identityBytes;
//      }ENDPOINTADDRESS2, *PENDPOINTADDRESS2;
      this.dll_t._ENDPOINTADDRESS2 = ctypes.StructType(
          "_ENDPOINTADDRESS2", [{ serviceUrl:    this.dll_t.LPCWSTR},
                                { policyUrl:     this.dll_t.LPCWSTR},
                                { identityType:  this.dll_t.DWORD},
                                { identityBytes: this.dll_t.PVOID}]);

//        typedef struct _CLAIMLIST
//        {
//            DWORD       count;
//            LPCWSTR*    claims;
//        }CLAIMLIST, *PCLAIMLIST;
      this.dll_t._CLAIMLIST = ctypes.StructType(
          "_CLAIMLIST", [{ count:    this.dll_t.DWORD},
                         { claims:   this.dll_t.LPCWSTR.ptr}]);

        // infocard.h line 147
//      typedef struct _RECIPIENTPOLICY
//      {
//          ENDPOINTADDRESS recipient;
//          ENDPOINTADDRESS issuer;
//          LPCWSTR         tokenType;
//          CLAIMLIST       requiredClaims;
//          CLAIMLIST       optionalClaims;
//          LPCWSTR         privacyUrl;
//          UINT            privacyVersion;
//      }RECIPIENTPOLICY, *PRECIPIENTPOLICY;
      this.dll_t.RECIPIENTPOLICY = ctypes.StructType(
          "RECIPIENTPOLICY", [{ recipient:      this.dll_t.ENDPOINTADDRESS },
                              { issuer:         this.dll_t.ENDPOINTADDRESS  },
                              { tokenType:      this.dll_t.LPCWSTR         },
                              { requiredClaims: this.dll_t.CLAIMLIST         },
                              { optionalClaims: this.dll_t.CLAIMLIST         },
                              { privacyUrl:     this.dll_t.LPCWSTR         },
                              { privacyVersion: this.dll_t.UINT         }]);

      // infocard.h line 158
//    typedef struct _RECIPIENTPOLICY2
//    {
//        ENDPOINTADDRESS2 recipient;
//        ENDPOINTADDRESS2 issuer;
//        LPCWSTR          tokenType;
//        CLAIMLIST        requiredClaims;
//        CLAIMLIST        optionalClaims;
//        LPCWSTR          privacyUrl;
//        UINT             privacyVersion;
//    }RECIPIENTPOLICY2, *PRECIPIENTPOLICY2;
    this.dll_t.RECIPIENTPOLICY2 = ctypes.StructType(
        "RECIPIENTPOLICY2", [{ recipient:      this.dll_t.ENDPOINTADDRESS2 },
                            { issuer:         this.dll_t.ENDPOINTADDRESS2  },
                            { tokenType:      this.dll_t.LPCWSTR         },
                            { requiredClaims: this.dll_t.CLAIMLIST         },
                            { optionalClaims: this.dll_t.CLAIMLIST         },
                            { privacyUrl:     this.dll_t.LPCWSTR         },
                            { privacyVersion: this.dll_t.UINT         }]);

        // infocard.h line 169
        this.dll.RECIPIENTPOLICYV1 = 1;
        this.dll.RECIPIENTPOLICYV2 = 2;
        
//      HRESULT
//      ___stdcall GetBrowserToken(
//                          __in    DWORD   dwParamType,
//                          __in    PVOID   pParam,
//                          __out_opt    DWORD*  pcbToken,
//                          __out_bcount_opt(*pcbToken)    PBYTE*  ppToken );
        this.dll.GetBrowserToken = lib.declare("GetBrowserToken",
            ctypes.stdcall_abi, 
            this.dll_t.HRESULT,
            this.dll_t.DWORD,
            this.dll_t.PVOID,
            this.dll_t.DWORD.ptr,
            this.dll_t.PBYTE);

//        RESULT
//        CARDSPACECALL
//        ManageCardSpace();
        this.dll.ManageCardSpace = lib.declare("ManageCardSpace",
            ctypes.stdcall_abi, 
            this.dll_t.HRESULT);

//        HRESULT
//        CARDSPACECALL
//        ImportInformationCard(  __in LPCWSTR fileName );
        this.dll.ImportInformationCard = lib.declare("ImportInformationCard",
            ctypes.stdcall_abi, 
            this.dll_t.HRESULT,
            this.dll_t.LPCWSTR);
        
    },


    //
    // ICardspace interfaces
    //


    GetBrowserToken : function(issuer,
        recipient, requiredClaims,
        optionalClaims, tokenType, privacyUrl,
        privacyVersion, sslCert, issuerPolicy,
        extraParams_length, extraParams) 
    {
        this.log("GetBrowserToken() called");
    },
    
    ManageCardSpace : function() 
    {
        this.log("ManageCardSpace() called");
        return this.dll.ManageCardSpace();
    },
    
    ImportInformationCard : function(fileName) 
    {
        this.log("ImportInformationCard() called");
        return this.dll.ImportInformationCard(fileName);
    }
    
};

/**
* XPCOMUtils.generateNSGetFactory was introduced in Mozilla 2 (Firefox 4).
* XPCOMUtils.generateNSGetModule is for Mozilla 1.9.2 (Firefox 3.6).
*/
if (XPCOMUtils.generateNSGetFactory) {
  var NSGetFactory = XPCOMUtils.generateNSGetFactory([Cardspace]);
} else {
  var NSGetModule = XPCOMUtils.generateNSGetModule([Cardspace]);
}