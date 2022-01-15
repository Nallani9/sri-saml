package com.nallani.saml.service.helper;


import lombok.extern.java.Log;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static com.nallani.saml.service.constants.Constants.RSA_ALGORITHM;

@Service
@Log
public class GetPublicKeyHelper {
    private static final Logger logger = LoggerFactory.getLogger(GetPublicKeyHelper.class);

    public PublicKey getPublicKey(String keyStore) {
        try {
            if (StringUtils.isBlank(keyStore)) {
                logger.error("keyStore cannot be null");
            }
            byte[] byteKey = Base64.getDecoder().decode(keyStore.getBytes());
            X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(byteKey);
            KeyFactory kf = KeyFactory.getInstance(RSA_ALGORITHM);
            return kf.generatePublic(encodedKeySpec);
        } catch (Exception e) {
            logger.error(
                    "Error while getting public key");
        }
        return null;
    }
}
