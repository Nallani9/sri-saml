package com.nallani.saml.service.util;

import com.nallani.saml.service.helper.GetKeysHelper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.encryption.support.ChainingEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.EncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.SimpleRetrievalMethodEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class AssertionDecryptUtil {
    private final Logger logger = LogManager.getLogger(getClass());

    @Autowired
    private GetKeysHelper getKeysHelper;

    public Assertion decryptAssertion(Response samlResponseObject, boolean spMetadata) {
        try {
            if (spMetadata) {
                List<EncryptedAssertion> assertionList = samlResponseObject.getEncryptedAssertions();
                EncryptedAssertion getFirstAssertion = assertionList.get(0);
                return decryptAssertion(getFirstAssertion);
            } else {
                List<Assertion> assertionList = samlResponseObject.getAssertions();
                return assertionList.get(0);
            }
        } catch (Exception e) {
            logger.error(e.getMessage());
        }
        return null;
    }

    private Assertion decryptAssertion(EncryptedAssertion encryptedAssertion) {
        Assertion assertion = null;
        Credential credential = getKeysHelper.generateKeyCred();
        StaticKeyInfoCredentialResolver resolver = new StaticKeyInfoCredentialResolver(credential);
        List<EncryptedKeyResolver> resolvers = new ArrayList<>();
        resolvers.add(new InlineEncryptedKeyResolver());
        resolvers.add(new EncryptedElementTypeEncryptedKeyResolver());
        resolvers.add(new SimpleRetrievalMethodEncryptedKeyResolver());
        ChainingEncryptedKeyResolver keyResolver = new ChainingEncryptedKeyResolver(resolvers);
        Decrypter decrypter = new Decrypter(null, resolver, keyResolver);
        try {
            assertion = decrypter.decrypt(encryptedAssertion);
        } catch (Exception e) {
            logger.error(
                    e.getMessage());
        }
        return assertion;
    }
}
