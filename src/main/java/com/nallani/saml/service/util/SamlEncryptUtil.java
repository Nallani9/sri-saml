package com.nallani.saml.service.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;

import java.util.Base64;

@Service
public class SamlEncryptUtil {
    private final Logger logger = LogManager.getLogger(getClass());

    public String encryptSaml(String xml) {
        String encodedString = Base64.getEncoder().encodeToString(xml.getBytes());
        logger.info(
                " Base64-encoded string is {} ",
                encodedString);
        return encodedString;
    }
}
