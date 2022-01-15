package com.nallani.saml.builders;

import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.impl.AuthnContextBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnStatementBuilder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

import static com.nallani.saml.service.constants.Constants.NAMESPACE_PREFIX;

@Service
public class SamlAuthnStatementBuilder {

    public AuthnStatement buildAuthnStatement() {
        AuthnContextClassRefBuilder classRefBuilder = new AuthnContextClassRefBuilder();
        AuthnContextClassRef classRef =
                classRefBuilder.buildObject(
                        SAMLConstants.SAML20_NS,
                        AuthnContextClassRef.DEFAULT_ELEMENT_LOCAL_NAME,
                        NAMESPACE_PREFIX);
        classRef.setAuthnContextClassRef(
                AuthnContext.PPT_AUTHN_CTX); // we need this for rewards to work

        // create auth context object
        AuthnContextBuilder authContextBuilder = new AuthnContextBuilder();
        AuthnContext authnContext =
                authContextBuilder.buildObject(
                        SAMLConstants.SAML20_NS, AuthnContext.DEFAULT_ELEMENT_LOCAL_NAME, NAMESPACE_PREFIX);
        authnContext.setAuthnContextClassRef(classRef);

        // create authentication statement object
        AuthnStatementBuilder authStatementBuilder =
                new org.opensaml.saml.saml2.core.impl.AuthnStatementBuilder();
        AuthnStatement authnStatement =
                authStatementBuilder.buildObject(
                        SAMLConstants.SAML20_NS, AuthnStatement.DEFAULT_ELEMENT_LOCAL_NAME, NAMESPACE_PREFIX);
        authnStatement.setAuthnInstant(Instant.now());
        authnStatement.setSessionIndex(UUID.randomUUID().toString());
        authnStatement.setAuthnContext(authnContext);
        return authnStatement;
    }
}
