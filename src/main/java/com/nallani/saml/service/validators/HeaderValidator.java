package com.nallani.saml.service.validators;


import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;

@Service
public class HeaderValidator {
    private static final Logger logger = LogManager.getLogger(HeaderValidator.class);

    public void validate(String input) {
        if (StringUtils.isBlank(input)) {
            logger.error(
                    input,
                    "Header can not be null");
        }
    }
}

