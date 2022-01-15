package com.nallani.saml.builders;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.Signer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Service
public class SamlSignResponseBuilder {
    private final Logger logger = LogManager.getLogger(getClass());

    @Autowired
    private SamlEncryptAssertionBuilder samlEncryptAssertionBuilder;
    @Autowired
    private SamlSignatureBuilder signatureBuilder;

    public void signResponse(Response response, Assertion assertion) {
        Signature signature;
        try {
            response
                    .getEncryptedAssertions()
                    .add(samlEncryptAssertionBuilder.encryptAssertion(assertion));
            signature = signatureBuilder.buildSignature();
            response.setSignature(signature);
            Objects.requireNonNull(
                    XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(response))
                    .marshall(response);
            Signer.signObject(signature);
        } catch (Exception e) {
            logger.error(
                    e.getMessage());
        }
    }
}
