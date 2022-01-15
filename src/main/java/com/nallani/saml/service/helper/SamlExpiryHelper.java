package com.nallani.saml.service.helper;


import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensaml.saml.saml2.core.Assertion;
import org.springframework.stereotype.Service;

import java.time.Instant;

;

@Service
public class SamlExpiryHelper {
    private static final Logger logger = LogManager.getLogger(SamlExpiryHelper.class);

    public void validateExpiry(Assertion assertion) {
        if (assertion.getConditions().getNotOnOrAfter() != null
                && (assertion.getConditions().getNotOnOrAfter().isBefore(Instant.now()))) {
            logger.error(
                    "Saml assertion is no longer valid");
        }

        if (assertion.getConditions().getNotBefore() != null
                && assertion.getConditions().getNotBefore().isAfter(Instant.now())) {
            logger.error(
                    "Saml assertion is not valid yet");
        }
    }
}
