package com.nallani.saml.builders;

import com.nallani.saml.model.SPMetadata;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.springframework.stereotype.Service;

import static com.nallani.saml.service.constants.Constants.NAMESPACE_PREFIX;

@Service
public class SamlIssuerBuilder {

    public Issuer buildIssuer(SPMetadata metadata) {
        // create Issuer object
        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer =
                issuerBuilder.buildObject(
                        SAMLConstants.SAML20_NS, Issuer.DEFAULT_ELEMENT_LOCAL_NAME, NAMESPACE_PREFIX);
        issuer.setValue(metadata.getIssuer());
        return issuer;
    }
}
