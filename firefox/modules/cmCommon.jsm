var EXPORTED_SYMBOLS = ["isClaimChecked", "xmlreplace"];

Components.utils.import("resource://infocard/cmDebug.jsm");

function isClaimChecked(doc, elementId, uri) {
	 var checkbox = docgetElementById(elementId);
//	 icDebug("isClaimChecked: typeof(checkbox)=" + typeof(checkbox));
	 if (checkbox) {
icDebug("isClaimChecked: found " + elementId);
		 if (!(checkbox.checked === undefined)) {
icDebug("isClaimChecked: is a checkbox ");
		  if (checkbox.checked) {
icDebug("isClaimChecked: is checked ");
		   if ( uri === undefined ) {
		     return "";
		   } else {
			 return uri;
		   }
		  } else {
icDebug("isClaimChecked: is not checked ");
		  }
		 } else {
		  icDebug( "expected type checkbox, but found: " + typeof(checkbox));
		 } 
	 } else {
	  icDebug("checkbox not defined for uri: " + uri );
	 }
	 return null;
}

function xmlreplace(text) {
	 var str;
	 if (typeof(text) == 'string') {
	  str = text;
	 } else {
	  str = "" + text + "";
	 }
	 var result = str.replace(/&/g, "&amp;");
	 result = result.replace(/</g, "&lt;");
	 result = result.replace(/>/g, "&gt;");
	 result = result.replace(/\?/g, "%3F");
	 return(result);
	}

