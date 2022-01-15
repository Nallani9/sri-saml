package com.nallani.saml.service.util;


import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.impl.ResponseUnmarshaller;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

;

@Service
public class SamlUnmarshallUtil {
    private final Logger logger = LogManager.getLogger(getClass());

    public XMLObject unmarshall(String xmlString) {
        try {
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            documentBuilderFactory.setNamespaceAware(true);
            documentBuilderFactory.setXIncludeAware(false);
            documentBuilderFactory.setExpandEntityReferences(false);
            DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
            Document document =
                    docBuilder.parse(
                            new ByteArrayInputStream(xmlString.trim().getBytes(StandardCharsets.UTF_8)));
            Element element = document.getDocumentElement();
            ResponseUnmarshaller unmarshaller = new ResponseUnmarshaller();
            return unmarshaller.unmarshall(element);
        } catch (Exception e) {
            logger.error(
                    e.getMessage());
        }
        return null;
    }
}
