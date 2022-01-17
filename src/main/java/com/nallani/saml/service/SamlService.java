package com.nallani.saml.service;

import com.nallani.saml.model.GetAssertionRequest;
import com.nallani.saml.model.SamlRequest;
import com.nallani.saml.model.SamlResponse;
import com.nallani.saml.model.SamlValidateRequest;
import org.opensaml.core.xml.io.MarshallingException;

public interface SamlService {

    SamlResponse generateSaml(
            SamlRequest input,
            Boolean isEncryptedPayload,
            Boolean isResponseEncoded,
            Boolean isHtmlEncoded, String spName) throws MarshallingException;

    SamlRequest validateSaml(
            SamlValidateRequest input, String spName, Boolean isHtmlEncoded);

    String getAssertion(GetAssertionRequest input, String spName, Boolean isUrlEncoded);
}
