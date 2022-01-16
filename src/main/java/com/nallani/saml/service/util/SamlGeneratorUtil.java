package com.nallani.saml.service.util;

import com.nallani.saml.builders.*;
import com.nallani.saml.model.SPMetadata;
import com.nallani.saml.model.SamlRequest;
import lombok.extern.java.Log;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;


@Log
@Service
public class SamlGeneratorUtil {

    @Autowired
    private SamlResponseBuilder responseBuilder;
    @Autowired
    private SamlSignAssertionBuilder samlSignAssertionBuilder;
    @Autowired
    private SamlAssertionBuilder samlAssertionBuilder;
    @Autowired
    private SamlIssuerBuilder samlIssuerBuilder;
    @Autowired
    private SamlStatusBuilder samlStatusBuilder;
    @Autowired
    private SamlSignResponseBuilder signResponseBuilder;

    public Response generateSaml(SamlRequest content, SPMetadata metadata) {
        // create the issuer/status & creating the response
        Response response =
                responseBuilder.buildResponse(
                        samlIssuerBuilder.buildIssuer(metadata), samlStatusBuilder.buildStatus(), content);
        // create the assertion
        Assertion assertion = samlAssertionBuilder.buildAssertion(content, metadata);
        if (metadata.isAssertionEncrypted()) {
            //encrypt assertion and sign response
            signResponseBuilder.signResponse(response, assertion);
        } else {
            // sign the assertion
            samlSignAssertionBuilder.signAssertion(assertion);
            // set the assertion
            response.getAssertions().add(assertion);
        }
        return response;
    }
}
