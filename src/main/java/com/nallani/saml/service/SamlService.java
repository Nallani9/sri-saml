package com.nallani.saml.service;

import com.nallani.saml.model.GetAssertionRequest;
import com.nallani.saml.model.SamlAttributesPayload;
import com.nallani.saml.model.SamlRequest;
import com.nallani.saml.model.SamlResponse;

public interface SamlService {

    SamlResponse generateSaml(
            SamlAttributesPayload input,
            Boolean isEncryptedPayload,
            Boolean isResponseEncoded,
            String spName);

    SamlAttributesPayload validateSaml(
            SamlRequest input, String spName);

    String getAssertion(GetAssertionRequest input, String spName, Boolean isUrlEncoded);
}
