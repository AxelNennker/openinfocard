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

package org.xmldap.sts.servlet;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.util.Iterator;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.xmldap.infocard.roaming.EncryptedStore;
import org.xmldap.util.XmlFileUtil;


public class DecryptCardspaceBackupServlet extends HttpServlet {

	private static String toHex(String array) {
        StringBuffer sb = new StringBuffer();
        for (int j = 0; j < array.length(); ++j) {
        	sb.append(" ");
        	sb.append(array.charAt(j));
        	sb.append(":0x");
            int b = array.charAt(j) & 0xFF;
            if (b < 0x10) sb.append('0');
            sb.append(Integer.toHexString(b));
        }

        return sb.toString();
		
	}
	
    private static String escapeHtmlEntities(String html) {
		StringBuffer result = new StringBuffer();
		for (int i = 0; i < html.length(); i++) {
			char ch = html.charAt(i);
			if (ch == '<') {
				result.append("&lt;");
			} else if (ch == '>') {
				result.append("&gt;");
			} else if (ch == '\"') {
				result.append("&quot;");
			} else if (ch == '\'') {
				result.append("&#039;");
			} else if (ch == '&') {
				result.append("&amp;");
			} else if (ch == 0xc3) {
				System.out.println("!!");
				char n = html.charAt(i+1);
				if ( n == 0x78) {
					result.append("&szlig;");
					i += 1;
				} else {
					System.out.println("##" + Integer.valueOf(n));
					result.append(ch);
				}
			} else {
				result.append(ch);
			}
		}
		return result.toString();
	}

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        InputStream store = null;
        String password = null;

        boolean isMultipart = ServletFileUpload.isMultipartContent(request);

        if ( ! isMultipart ) {
            PrintWriter out = response.getWriter();
            out.println("Invalid form posting - not multipart");
            out.flush();
            out.close();
            return;
        }


        DiskFileItemFactory factory = new DiskFileItemFactory();
        factory.setSizeThreshold(500000);
        ServletFileUpload upload = new ServletFileUpload(factory);
        upload.setSizeMax(1000000);
        try {
            List items = upload.parseRequest(request);
            Iterator iter = items.iterator();
            while (iter.hasNext()) {
                FileItem item = (FileItem) iter.next();

                if (item.isFormField()) {
                    password = item.getString();

                } else {

                    store = item.getInputStream();
                }
            }


        } catch (FileUploadException e) {
            PrintWriter out = response.getWriter();
            out.println("There was an error receiving your backup file.");
            out.flush();
            out.close();
            return;
        }


        if ( store.available() <= 0 ) {
            PrintWriter out = response.getWriter();
            out.println("You must provide a valid backup file");
            out.flush();
            out.close();
            return;
        }



        if ( (password == null) || ( password.equals(""))) {
            PrintWriter out = response.getWriter();
            out.println("You must provide a password");
            out.flush();
            out.close();
            return;
        }

        //System.out.println(store);

        EncryptedStore encryptedStore = null;
        String encoding = null;
        try {
            encoding = XmlFileUtil.getEncoding(store);
            encryptedStore = new EncryptedStore(store, password);
            System.out.println("xxx:" + toHex(encryptedStore.getRoamingStoreString()));
        } catch (Exception e) {
            PrintWriter out = response.getWriter();
            out.println("There was an error decrypting your backup: " + e.getMessage());
            e.printStackTrace();
            out.flush();
            out.close();
            return;
        }

        PrintWriter out = response.getWriter();

    	encoding = "UTF-16LE";
        out.println("<?xml version=\"1.0\" encoding=\"" + encoding + "\" ?>");
        out.println("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\"     \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">");
		out.println("<html xmlns=\"http://www.w3.org/1999/xhtml\">");
        out.println("<title>Backup File</title><style>BODY {color:#000;font-family: verdana, arial, sans-serif;}</style>\n" +
                "<body>\n" +
                "<b>Your Backup File:</b><br/><br/>" +
                "<textarea cols=\"80\" rows=\"20\">" + escapeHtmlEntities(encryptedStore.getParsedRoamingStore()) + "</textarea>\n" +
                "</body>\n" +
                "</html>");
        out.flush();
        out.close();

    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        PrintWriter out = response.getWriter();
        out.println("<html><head>");
        out.println("\n" +
                "    <style>\n" +
                "    BODY {background: #FFFFFF;\n" +
                "         color:#000000;\n" +
                "         font-family: verdana, arial, sans-serif;}\n" +
                "\n" +
                "        h2 { color:#000000;\n" +
                "         font-family: verdana, arial, sans-serif;}" +
                "</style>" +
                "<title>CardSpace Backup Decrypt</title>" +
                "</head>" +
                "<body>");
        out.println("<h2>Take a peek inside Cardspace Backups</h2>\n" +
                "\n" +
                "<form action=\"\" method=\"POST\" ENCTYPE=\"multipart/form-data\" >\n" +
                "<table border=0 cellpadding=5><tr>" +
                "<td>Select a Cardspace backup file: </td><td><input name=\"store\" type=\"file\" size=\"50\"><br></td></tr>\n" +
                "<tr><td>Password used to secure the file:</td><td><input name=\"password\" type=\"password\" size=\"50\"><br></td></tr>\n" +
                "<tr><td colspan=2><input type=\"submit\" value=\"Decrypt your backup\"></td></tr></table>\n" +
                "</form>" +
                "</body>");
        out.flush();
        out.close();

    }
}
