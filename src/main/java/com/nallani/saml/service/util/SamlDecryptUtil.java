package com.nallani.saml.service.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Service
public class SamlDecryptUtil {
    private final Logger logger = LogManager.getLogger(getClass());

    @Autowired
    private UrlDecodeUtil urlDecodeUtil;

    public String decryptSaml(String samlData, boolean metadata) {
        try {
            if (metadata) {
                samlData = urlDecodeUtil.decode(samlData);
            }
            byte[] decodedByte = Base64.getDecoder().decode(samlData);
            String decodedString = new String(decodedByte, StandardCharsets.UTF_8);
            logger.info(
                    "decoded string is {} ",
                    decodedString);
            return decodedString;
        } catch (Exception e) {
            logger.info(
                    "Error while decoding is {} ",
                    e.getMessage());
        }
        return null;
    }
}
