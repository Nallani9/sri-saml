package com.nallani.saml.service.util;


import com.nallani.saml.model.SamlAttribute;
import com.nallani.saml.model.SamlAttributesPayload;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class SamlProcessUtil {
    private final Logger logger = LogManager.getLogger(getClass());

    public SamlAttributesPayload processResponse(Assertion assertion) {
        SamlAttributesPayload output = new SamlAttributesPayload();
        try {
            String subject = assertion.getSubject().getNameID().getValue();
            String issuer = assertion.getIssuer().getValue();
            output.setSubject(subject);
            output.setIssuer(issuer);

            AttributeStatement attributeStatement = assertion.getAttributeStatements().get(0);
            List<Attribute> attributeList = attributeStatement.getAttributes();
            for (Attribute attr : attributeList) {
                List<XMLObject> attrValues = attr.getAttributeValues();
                List<String> values = new ArrayList<>();
                for (XMLObject valObj : attrValues) {
                    values.add(((XSString) valObj).getValue());
                }
                SamlAttribute samlAttribute = new SamlAttribute();
                samlAttribute.setName(attr.getName());
                samlAttribute.setValue(values);
                output.getAttributes().add(samlAttribute);
            }
        } catch (Exception e) {
            logger.error(e.getMessage());
        }
        return output;
    }
}
