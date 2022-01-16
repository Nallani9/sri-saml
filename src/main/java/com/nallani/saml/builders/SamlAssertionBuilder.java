package com.nallani.saml.builders;

import com.nallani.saml.model.SPMetadata;
import com.nallani.saml.model.SamlRequest;
import net.shibboleth.utilities.java.support.security.impl.RandomIdentifierGenerationStrategy;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.impl.AssertionBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

import static com.nallani.saml.service.constants.Constants.NAMESPACE_PREFIX;

@Service
public class SamlAssertionBuilder {

    @Autowired
    private com.nallani.saml.builders.SamlSubjectBuilder samlSubjectBuilder;
    @Autowired
    private com.nallani.saml.builders.SamlIssuerBuilder samlIssuerBuilder;
    @Autowired
    private com.nallani.saml.builders.SamlConditionsBuilder samlConditionsBuilder;
    @Autowired
    private com.nallani.saml.builders.SamlAuthnStatementBuilder samlAuthnStatementBuilder;
    @Autowired
    private com.nallani.saml.builders.SamlAttributeStatementBuilder samlAttributeStatementBuilder;

    public Assertion buildAssertion(SamlRequest content, SPMetadata metadata) {
        AssertionBuilder assertionBuilder = new AssertionBuilder();
        Assertion assertion =
                assertionBuilder.buildObject(
                        SAMLConstants.SAML20_NS, Assertion.DEFAULT_ELEMENT_LOCAL_NAME, NAMESPACE_PREFIX);
        assertion.setID(UUID.randomUUID().toString());
        Instant currentTime = Instant.now();
        assertion.setIssueInstant(currentTime);

        assertion.setSubject(samlSubjectBuilder.buildSubject(content, metadata));
        assertion.setIssuer(samlIssuerBuilder.buildIssuer(metadata));
        assertion.setIssueInstant(currentTime);
        assertion.setID(new RandomIdentifierGenerationStrategy().generateIdentifier());
        // create the conditions
        assertion.setConditions(samlConditionsBuilder.buildConditions(content));
        // create the authn Statement
        assertion.getAuthnStatements().add(samlAuthnStatementBuilder.buildAuthnStatement());
        // create the attribute Statement
        assertion
                .getAttributeStatements()
                .add(samlAttributeStatementBuilder.buildAttributeStatement(content));
        return assertion;
    }
}
