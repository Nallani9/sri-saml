package com.nallani.saml.service.helper;

import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class GetKeysHelper {
    private static final Logger logger = LoggerFactory.getLogger(GetKeysHelper.class);

    @Autowired
    private GetPrivateKeyHelper privateKeyHelper;
    @Autowired
    private GetPublicKeyHelper publicKeyHelper;

    @Value("${saml.public.key}")
    private String publicKeyStore;

    @Value("${saml.private.key}")
    private String privateKeyStore;

    public Credential generateKeyCred() {

        Credential credential = null;
        try {
            credential =
                    CredentialSupport.getSimpleCredential(
                            publicKeyHelper.getPublicKey(publicKeyStore),
                            privateKeyHelper.getPrivateKey(privateKeyStore));

        } catch (Exception ex) {
            logger.error(
                    ex.getMessage());
        }
        return credential;
    }
}
