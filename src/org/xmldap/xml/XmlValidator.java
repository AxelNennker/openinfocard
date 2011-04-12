package org.xmldap.xml;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import org.w3c.dom.DOMImplementation;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

public class XmlValidator {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		FileOutputStream fos = null;
		try {

			// Parse an XML document into a DOM tree.
			DocumentBuilder parser = DocumentBuilderFactory.newInstance()
					.newDocumentBuilder();
			Document document = parser.parse(new File("I4-badidp1.crd"));
			System.out.println("read and parsed");
			// Create a SchemaFactory capable of understanding WXS schemas.
			SchemaFactory factory = SchemaFactory
					.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);

			// Load a WXS schema, represented by a Schema instance.
			Source schemaFile = new StreamSource(new File("identity.xsd"));
			Schema schema = factory.newSchema(schemaFile);
			System.out.println("schema loaded");
			// Create a Validator object, which can be used to validate
			// an instance document.
			Validator validator = schema.newValidator();

			DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory
					.newInstance();
			DocumentBuilder builder = docBuilderFactory.newDocumentBuilder();
			DOMImplementation impl = builder.getDOMImplementation();

			Document doc = impl.createDocument(null, null, null);
			DOMResult domResult = new DOMResult(doc);

			fos = new FileOutputStream("result.xml");

			System.out.println("starting validation");
			// Validate the DOM tree.
			validator.validate(new DOMSource(document), domResult);
			System.out.println("finished validation");

			DOMSource domSource = new DOMSource(domResult.getNode());
			TransformerFactory tf = TransformerFactory.newInstance();
			Transformer transformer = tf.newTransformer();
			// transformer.setOutputProperty
			// (OutputKeys.OMIT_XML_DECLARATION, "yes");
			transformer.setOutputProperty(OutputKeys.METHOD, "xml");
			transformer.setOutputProperty(OutputKeys.ENCODING, "ISO-8859-1");
			transformer.setOutputProperty(
					"{http://xml.apache.org/xslt}indent-amount", "4");
			transformer.setOutputProperty(OutputKeys.INDENT, "yes");

			StreamResult sr = new StreamResult(fos);
			transformer.transform(domSource, sr);

		} catch (ParserConfigurationException e) {
			e.printStackTrace();
		} catch (SAXException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (TransformerConfigurationException e) {
			e.printStackTrace();
		} catch (TransformerException e) {
			e.printStackTrace();
		} finally {
			if (fos != null) {
				try {
					fos.close();
				} catch (IOException e) {
				}
				fos = null;
			}
		}
	}

}
