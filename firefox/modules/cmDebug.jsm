var EXPORTED_SYMBOLS = ["icDebug", "icDebug2"];

function icDebug2(msg, width) {
	  var debug = Components.classes["@mozilla.org/consoleservice;1"].getService(Components.interfaces.nsIConsoleService);
	  var message = "";
	  while (msg.length > width) {
		  message += msg.substr(0,width) + "\n";
		  msg = msg.substring(width);
	  }
	  if (msg.length > 0) {
		  message += msg;
	  }
	  debug.logStringMessage("infocard: " + message);
}
function icDebug(msg) {
	  var debug = Components.classes["@mozilla.org/consoleservice;1"].getService(Components.interfaces.nsIConsoleService);
	  debug.logStringMessage("infocard: " + msg);
}
