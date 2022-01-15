package com.nallani.saml.service.validators;

import com.nallani.saml.model.SPMetadata;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;


@Service
public class MetadataValidator {

    @Autowired
    private HeaderValidator headerValidator;

    public void validate(SPMetadata metadata, String input, boolean isSession) {
        if (isSession) {
            headerValidator.validate(input);
        }
    }
}
