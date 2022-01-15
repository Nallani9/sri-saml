package com.nallani.saml.service.validators;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;

@Service
public class QueryParameterValidator {
    private static final Logger logger = LogManager.getLogger(QueryParameterValidator.class);

    public void validate(String queryParam) {
        if (StringUtils.isBlank(queryParam)) {
            logger.error(queryParam, "query parameter 'sp' can not be null");
        }
    }
}
