package com.nallani.saml.service.validators;

import com.nallani.saml.model.SamlAttributesPayload;
import com.nallani.saml.model.SamlRequest;

public interface UserRequestDataRule {
    void validateForGenerate(
            SamlAttributesPayload input,
            Boolean isEncryptedPayload,
            String spName);

    void validateForValidate(SamlRequest input, String spName);
}
