package com.nallani.saml.service.validators;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;

import static org.apache.commons.lang3.StringUtils.isBlank;

@Service
public class InputPayloadValidator {
    private static final Logger logger = LogManager.getLogger(InputPayloadValidator.class);

    public void validate(String input) {
        if (isBlank(input)) {
            logger.error(
                    input,
                    "Encrypted attributes is null or empty");
        }
    }
}
