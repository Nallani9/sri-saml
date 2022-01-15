package com.nallani.saml.service.validators;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;

import static org.apache.commons.lang3.StringUtils.isBlank;

@Service
public class CustomerInfoDecryptValidation {
    private static final Logger logger = LogManager.getLogger(CustomerInfoDecryptValidation.class);

    public void validate(String decryptedInput) {
        if (isBlank(decryptedInput)) {
            logger.error(
                    decryptedInput,
                    "Decrypted customer info is null");
        }
    }
}
