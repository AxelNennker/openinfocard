/*
 * Copyright (c) 2006, Axel Nennker - http://axel.nennker.de/
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
 *     * The names of the contributors may NOT be used to endorse or promote products
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
 *
 */
package org.xmldap.util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import nu.xom.Attribute;
import nu.xom.Document;
import nu.xom.Element;
import nu.xom.Node;
import nu.xom.Nodes;
import nu.xom.ParsingException;
import nu.xom.Serializer;
import nu.xom.Text;
import nu.xom.ValidityException;

public class Crds {

	static public final String CRDS_CHAR_ENCODING = "UTF-8";

	private Crds() {
	}

	static public Crds getInstance() {
		return new Crds();
	}

	private Node findInNodes(Nodes nodes, String ppi) {
		for (int i = 0; i < nodes.size() - 1; i++) {
			Node node = nodes.get(i);
			String p = node.getValue();
			if (ppi.equals(p)) {
				return node;
			}
		}
		return null;
	}

	private static void xmlAdd(Element to, Element element) {
		Element newElt = new Element(element.getLocalName());
		// Show the tag, along with its attributes
		for (int i = 0; i < element.getAttributeCount(); i++) {
			Attribute attr = element.getAttribute(i);
			newElt.addAttribute(attr);
		}
		to.appendChild(newElt);
		// Now loop through child nodes
		for (int i = 0; i < element.getChildCount(); i++) {
			Node node = element.getChild(i);

			if (node instanceof Text) {
				String value = node.getValue();
				Text text = new Text(value);
				newElt.appendChild(text);
			} else if (node instanceof Element) {
				xmlAdd(newElt, (Element) node);
			}
		}
	}

	public String getAllCards(String dirName, String password) {
		try {
			Document cardStore = XmlFileUtil.readXmlFile(dirName
					+ "cardStore.xml");
			return cardStore.toXML();
		} catch (ValidityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ParsingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public String getCard(String dirName, String password, String id) {
		try {
			Document cardStore = XmlFileUtil.readXmlFile(dirName
					+ "cardStore.xml");
			Nodes nodes = cardStore.query("//infocard/id");
			Node card = findInNodes(nodes, id);
			if (card != null) {
				return card.toXML();
			} else {
				return null;
			}
		} catch (ValidityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ParsingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return "";
	}

	public String newCard(String dirName, String password, Document infocard) {
		try {
			File file = new File(dirName + "cardStore.xml");

			// Create file if it does not exist
			boolean success = file.createNewFile();
			if (success) {
				// File did not exist and was created
				Element root = new Element("infocards");
				Document cardStore = new Document(root);
				Element fromRoot = infocard.getRootElement();
				System.out.println(fromRoot.toXML());
				xmlAdd(cardStore.getRootElement(), fromRoot);
				FileOutputStream fos = new FileOutputStream(file);
				Serializer ser = new Serializer(fos, "UTF-8");
				ser.setIndent(1);
				ser.write(cardStore);
				ser.flush();
				fos.close();
			} else {
				// File already exists
				try {
					String ppi = infocard.query(
							"//infocard/privatepersonalidentifier").get(0)
							.getValue();

					Document cardStore = XmlFileUtil.readXmlFile(dirName
							+ "cardStore.xml");
					Nodes ppis = cardStore
							.query("//infocard/privatepersonalidentifier");
					Node ppiNode = findInNodes(ppis, ppi);
					if (ppiNode != null) {
						// this should never happen as the ppi is updated when a
						// card is edited
					} else {
						// infocard is a new card. Add it
						Element fromRoot = infocard.getRootElement();
						xmlAdd(cardStore.getRootElement(), fromRoot);
					}
					FileOutputStream fos = new FileOutputStream(file);
					Serializer ser = new Serializer(fos, "UTF-8");
					ser.setIndent(1);
					ser.write(cardStore);
					ser.flush();
					fos.close();
				} catch (ValidityException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (ParsingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		} catch (IOException e) {
		}

		return "";
	}

}
