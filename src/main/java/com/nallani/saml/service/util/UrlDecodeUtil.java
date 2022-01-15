package com.nallani.saml.service.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Service
public class UrlDecodeUtil {
    private final Logger logger = LogManager.getLogger(getClass());

    public String decode(String inputToDecode) {
        String urlDecodedString = URLDecoder.decode(inputToDecode, StandardCharsets.UTF_8);
        logger.info(
                "URL decoded string is {} ",
                urlDecodedString);
        return urlDecodedString;
    }

    // used for test endpoint getAssertion
    public String encode(String inputToEncode) {
        String urlEncodedString = URLEncoder.encode(inputToEncode, StandardCharsets.UTF_8);
        logger.info(
                "URL encoded string is {} ",
                urlEncodedString);
        return urlEncodedString;
    }
}
