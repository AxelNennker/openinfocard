var EXPORTED_SYMBOLS = ["OICCrypto"];

var OICCrypto = {
  hex_sha1 : function(input){
    var converter = Components.classes["@mozilla.org/intl/scriptableunicodeconverter"].createInstance(Components.interfaces.nsIScriptableUnicodeConverter);
    converter.charset = "UTF-8";
    // result is an out parameter,
    // result.value will contain the array length
    var result = {};
    // data is an array of bytes
    var data = converter.convertToByteArray(input, result);
    var ch = Components.classes["@mozilla.org/security/hash;1"].createInstance(Components.interfaces.nsICryptoHash);
    ch.init(ch.SHA1);
    ch.update(data, data.length);
    var hash = ch.finish(false);
  
    // return the two-digit hexadecimal code for a byte
    function toHexString(charCode)
    {
      return ("0" + charCode.toString(16)).slice(-2);
    }
  
    // convert the binary hash data to a hex string.
    var s = [toHexString(hash.charCodeAt(i)) for (i in hash)].join("");
    return s;
  }
};