package com.nallani.saml.service.validators;

import com.nallani.saml.model.SamlAttributesPayload;
import com.nallani.saml.model.SamlRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;


@Service
public class SamlRequestValidator implements UserRequestDataRule {

    @Autowired
    private EncryptedPayloadValidator encryptedPayloadValidator;
    @Autowired
    private InputPayloadValidator inputPayloadValidator;

    @Override
    public void validateForGenerate(
            SamlAttributesPayload input,
            Boolean isEncryptedPayload,
            String spName) {
        validate(input, isEncryptedPayload, spName);
    }

    @Override
    public void validateForValidate(
            SamlRequest input, String spName) {
        validate(input, spName);
    }

    private void validate(
            SamlAttributesPayload input,
            Boolean isEncryptedPayload,
            String spName) {
        encryptedPayloadValidator.validate(isEncryptedPayload);
        inputPayloadValidator.validate(input.getEncryptedAttributes());
    }

    private void validate(SamlRequest input, String spName) {
        inputPayloadValidator.validate(input.getSamlResponse());
    }
}
