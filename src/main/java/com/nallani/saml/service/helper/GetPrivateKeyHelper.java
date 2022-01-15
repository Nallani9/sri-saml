package com.nallani.saml.service.helper;


import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import static com.nallani.saml.service.constants.Constants.RSA_ALGORITHM;

@Service
public class GetPrivateKeyHelper {
    private static final Logger logger = LoggerFactory.getLogger(GetPrivateKeyHelper.class);

    public PrivateKey getPrivateKey(String keyStore) {
        StringBuilder pkcs8Lines = new StringBuilder();
        try {
            if (StringUtils.isBlank(keyStore)) {
                logger.error("key Store value cannot be null");
            }

            BufferedReader rdr = new BufferedReader(new StringReader(keyStore));
            String line;
            while ((line = rdr.readLine()) != null) {
                pkcs8Lines.append(line);
            }
            // Remove any whitespace
            String pkcs8Pem = pkcs8Lines.toString();
            pkcs8Pem = pkcs8Pem.replaceAll("\\s+", "");
            // Base64 decode the result
            byte[] pkcs8EncodedBytes = Base64.decode(pkcs8Pem);
            // extract the private key
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
            KeyFactory kf = KeyFactory.getInstance(RSA_ALGORITHM);
            return kf.generatePrivate(keySpec);
        } catch (Exception e) {
            logger.error("Error while getting private key");
        }
        return null;
    }
}
