package com.nallani.saml.service.helper;


import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

;

@Service
public class SamlSignatureValidationHelper {
    private static final Logger logger = LogManager.getLogger(SamlSignatureValidationHelper.class);

    @Autowired
    private GetKeysHelper getKeysHelper;

    public void validate(Response samlResponseObject) {
        try {
            Signature signature = samlResponseObject.getSignature();
            if (signature != null) {
                SignatureValidator.validate(signature, getKeysHelper.generateKeyCred());
            }
        } catch (Exception e) {
            logger.error(
                    samlResponseObject.toString(),
                    "Error while validating signature");
        }
    }
}
