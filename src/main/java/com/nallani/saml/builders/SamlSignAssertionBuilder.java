package com.nallani.saml.builders;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.Signer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Service
public class SamlSignAssertionBuilder {
    private static final Logger logger = LogManager.getLogger(SamlSignAssertionBuilder.class);

    @Autowired
    private SamlSignatureBuilder samlSignatureBuilder;

    public void signAssertion(Assertion assertion) {
        Signature signature = samlSignatureBuilder.buildSignature();
        assertion.setSignature(signature);
        try {
            Objects.requireNonNull(
                    XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(assertion))
                    .marshall(assertion);
            Signer.signObject(signature);
        } catch (Exception e) {
            e.getMessage();
        }
    }
}
