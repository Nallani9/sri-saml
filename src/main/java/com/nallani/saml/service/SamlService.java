package com.nallani.saml.service;

import com.nallani.saml.model.GetAssertionRequest;
import com.nallani.saml.model.SamlRequest;
import com.nallani.saml.model.SamlResponse;
import com.nallani.saml.model.SamlValidateRequest;

public interface SamlService {

    SamlResponse generateSaml(
            SamlRequest input,
            Boolean isEncryptedPayload,
            Boolean isResponseEncoded,
            String spName);

    SamlRequest validateSaml(
            SamlValidateRequest input, String spName);

    String getAssertion(GetAssertionRequest input, String spName, Boolean isUrlEncoded);
}
