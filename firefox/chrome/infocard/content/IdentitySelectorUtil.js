//------------------------------------------------------------------------------
// Desc:
// Tabs: 3
//
// Copyright (c) 2007-2008 Novell, Inc. All Rights Reserved.
//
// This program and the accompanying materials are made available
// under, alternatively, the terms of:  a) the Eclipse Public License v1.0
// which accompanies this distribution, and is available at
// http://www.eclipse.org/legal/epl-v10.html; or, b) the Apache License,
// Version 2.0 which accompanies this distribution as is available at
// www.opensource.org/licenses/apache2.0.php.
//
// To contact Novell about this file by physical or electronic mail,
// you may find current contact information at www.novell.com.
//
// Author: Andrew Hodgkinson <ahodgkinson@novell.com>
//------------------------------------------------------------------------------

Components.utils.import("resource://infocard/IdentitySelectorDiag.jsm");

// **************************************************************************
// Desc: Platform detection
// **************************************************************************

var gNavPlat = navigator.platform;
var gbIsWin = ((gNavPlat.indexOf( "Win") > -1) ? true : false);
var gbIsMac = ((gNavPlat.indexOf( "Mac") > -1) ? true : false);
var gbIsLinux = ((gNavPlat.indexOf( "Linux") > -1) ? true : false);
                                       
// **************************************************************************
// Desc:
// **************************************************************************

var IdentitySelectorUtil =
{
        // ***********************************************************************
        // Method: isWinPlatform
        // ***********************************************************************
       
        isWinPlatform : function()
        {
                return( gbIsWin);
        },
       
        // ***********************************************************************
        // Method: isMacPlatform
        // ***********************************************************************
       
        isMacPlatform : function()
        {
                return( gbIsMac);
        },
       
        // ***********************************************************************
        // Method: isLinuxPlatform
        // ***********************************************************************
       
        isLinuxPlatform : function()
        {
                return( gbIsLinux);
        },
       
        // ***********************************************************************
        // Method: isLinuxPlatform
        // ***********************************************************************
       
        isJavaScriptEnabled : function()
        {
                return( gIcPrefService.getBoolPref( "javascript.enabled"));
        },
       
        // ***********************************************************************
        // Method: arrayToHexStr
        // ***********************************************************************
       
        arrayToHexStr : function( data)
        {
                var newStr = "";
               
                for( var i in data)
                {
                        newStr += ( "0" + data.charCodeAt( i).toString( 16)).slice( -2);
                }
               
                return( newStr);
        },

        // ***********************************************************************
        // Method: generateTmpFilePath
        // ***********************************************************************
       
        generateTmpFilePath : function()
        {
                var file = Components.classes[
                                "@mozilla.org/file/directory_service;1"].
                                getService( Components.interfaces.nsIProperties).
                                get( "TmpD", Components.interfaces.nsIFile);
                var ch = Components.classes[
                                "@mozilla.org/security/hash;1"].
                                createInstance( Components.interfaces.nsICryptoHash);
                var converter = Components.classes[
                                "@mozilla.org/intl/scriptableunicodeconverter"].
                                createInstance( Components.interfaces.nsIScriptableUnicodeConverter);
                var result = {};
                var data;
                var now = new Date();
                var datestr = (Date.UTC( now.getFullYear(),
                                now.getMonth(), now.getDate(), now.getHours(),
                                now.getMinutes(), now.getSeconds())).toString( 10);
                var hash;
               
                converter.charset = "UTF-8";
                data = converter.convertToByteArray( datestr, result);
               
                ch.init( ch.MD5);
                ch.update( data, data.length);
                hash = ch.finish( false);
       
                file.append( IdentitySelectorUtil.arrayToHexStr( hash));
                file.createUnique(
                        Components.interfaces.nsIFile.NORMAL_FILE_TYPE, 0x01B6);
       
                return( file.path);
        },
       
        // ***********************************************************************
        // Method: readFile
        // ***********************************************************************
       
        readFile : function( filename)
        {
                try
                {
                        var file = Components.classes[
                                "@mozilla.org/file/local;1"].createInstance(
                                        Components.interfaces.nsILocalFile);
                                       
                        file.initWithPath( filename);
                       
                        if( file.exists() && file.isReadable())
                        {
                                var fileIStream = Components.classes[
                                        "@mozilla.org/network/file-input-stream;1"].createInstance(
                                                Components.interfaces.nsIFileInputStream);
                                var sis = Components.classes[
                                        "@mozilla.org/scriptableinputstream;1"].createInstance(
                                                Components.interfaces.nsIScriptableInputStream);
                                var fileData = null;
                                               
                                fileIStream.init( file, 0x01, 0x04, 0);
                                sis.init( fileIStream);
                                fileData = sis.read( sis.available());
                                sis.close();
                               
                                return( fileData);
                        }
                        else 
                        {
                                IdentitySelectorDiag.reportError(
                                        "readFile", "Unable to open file.");
                                return( null);
                        }
                }
                catch( e)
                {
                        IdentitySelectorDiag.reportError(
                                "readFile", "Unable to read file.");
                }
               
                return( null);
        },
       
        // ***********************************************************************
        // Method: writeFile
        // ***********************************************************************

        writeFile : function( filename, data)
        {
                try
                {
                        var file = Components.classes[ nsLocalFile].
                                                                createInstance( nsILocalFile);
                        var fileOStream = Components.classes[ nsFileOutputStream].
                                                                createInstance( nsIFileOutputStream);
                                       
                        file.initWithPath( filename);
                        fileOStream.init( file, 0x02 | 0x08 | 0x20, 0x01B6, 0);
                        fileOStream.write( data, data.length);
                        fileOStream.close();
                }               
                catch( e)
                {
                        IdentitySelectorDiag.throwError(
                                "writeFile", "Unable to write file.");
                }
        }
};