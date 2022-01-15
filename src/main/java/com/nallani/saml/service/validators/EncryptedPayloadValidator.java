package com.nallani.saml.service.validators;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;

@Service
public class EncryptedPayloadValidator {
    private static final Logger logger = LogManager.getLogger(EncryptedPayloadValidator.class);

    public void validate(Boolean inputHeader) {
        if (null == inputHeader) {
            logger.error(
                    "Header parameter 'isEncryptedPayload' can not be null",
                    inputHeader);
        } else if (!inputHeader) {
            logger.error(
                    "Header parameter 'isEncryptedPayload' can not be false",
                    inputHeader);
        }
    }
}
