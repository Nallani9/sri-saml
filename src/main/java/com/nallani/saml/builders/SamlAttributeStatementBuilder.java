package com.nallani.saml.builders;

import com.nallani.saml.model.SamlAttribute;
import com.nallani.saml.model.SamlAttributesPayload;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSStringBuilder;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml.saml2.core.impl.AttributeStatementBuilder;
import org.springframework.stereotype.Service;

import java.util.List;

import static com.nallani.saml.service.constants.Constants.NAMESPACE_PREFIX;

@Service
public class SamlAttributeStatementBuilder {

    public AttributeStatement buildAttributeStatement(SamlAttributesPayload content) {
        // create authentication statement object
        AttributeStatementBuilder attributeStatementBuilder = new AttributeStatementBuilder();
        AttributeStatement attributeStatement =
                attributeStatementBuilder.buildObject(
                        SAMLConstants.SAML20_NS,
                        AttributeStatement.DEFAULT_ELEMENT_LOCAL_NAME,
                        NAMESPACE_PREFIX);

        AttributeBuilder attributeBuilder = new AttributeBuilder();
        List<SamlAttribute> attributes = content.getAttributes();
        if (attributes != null) {
            for (SamlAttribute entry : attributes) {
                Attribute attribute =
                        attributeBuilder.buildObject(
                                SAMLConstants.SAML20_NS, Attribute.DEFAULT_ELEMENT_LOCAL_NAME, NAMESPACE_PREFIX);
                attribute.setName(entry.getName());
                XSString attributeValue;
                for (String value : entry.getValue()) {
                    XSStringBuilder stringBuilder = new XSStringBuilder();
                    attributeValue =
                            stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
                    attributeValue.setValue(value);
                    attribute.getAttributeValues().add(attributeValue);
                }
                attributeStatement.getAttributes().add(attribute);
            }
        }
        return attributeStatement;
    }
}
