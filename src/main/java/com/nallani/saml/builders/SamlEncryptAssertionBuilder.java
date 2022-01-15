package com.nallani.saml.builders;

import com.nallani.saml.service.helper.GetKeysHelper;
import com.nallani.saml.service.util.CustomEncryptorUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import static com.nallani.saml.service.constants.Constants.NAMESPACE_PREFIX;

@Service
public class SamlEncryptAssertionBuilder {
    private final Logger logger = LogManager.getLogger(getClass());

    @Autowired
    private GetKeysHelper getKeysHelper;

    public EncryptedAssertion encryptAssertion(Assertion assertion) {
        EncryptedAssertion encryptedAssertion = null;
        DataEncryptionParameters encryptionParameters = new DataEncryptionParameters();
        encryptionParameters.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256);

        KeyEncryptionParameters keyEncryptionParameters = new KeyEncryptionParameters();
        keyEncryptionParameters.setEncryptionCredential(getKeysHelper.generateKeyCred());
        keyEncryptionParameters.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSA15);
        CustomEncryptorUtil encryptor =
                new CustomEncryptorUtil(encryptionParameters, keyEncryptionParameters, NAMESPACE_PREFIX);
        encryptor.setKeyPlacement(Encrypter.KeyPlacement.INLINE);
        try {
            encryptedAssertion = encryptor.encrypt(assertion);
        } catch (Exception ex) {
            logger.error(
                    "Unable to encrypt assertion");
        }
        return encryptedAssertion;
    }
}
