package com.nallani.saml.service.impl;

import com.nallani.saml.model.GetAssertionRequest;
import com.nallani.saml.model.SamlRequest;
import com.nallani.saml.model.SamlResponse;
import com.nallani.saml.model.SamlValidateRequest;
import com.nallani.saml.service.SamlService;
import com.nallani.saml.service.helper.SamlExpiryHelper;
import com.nallani.saml.service.helper.SamlHelper;
import com.nallani.saml.service.helper.SamlSignatureValidationHelper;
import com.nallani.saml.service.util.*;
import com.nallani.saml.service.validators.InputPayloadValidator;
import lombok.extern.java.Log;
import net.shibboleth.utilities.java.support.codec.HTMLEncoder;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Log
@Service
public class SamlResourceImpl implements SamlService {
    private static final Logger logger = LoggerFactory.getLogger(SamlResourceImpl.class);

    @Autowired
    private InputPayloadValidator inputPayloadValidator;
    @Autowired
    private SamlHelper samlHelper;
    @Autowired
    private SamlUnmarshallUtil samlUnmarshallUtil;
    @Autowired
    private SamlSignatureValidationHelper signatureValidation;
    @Autowired
    private SamlExpiryHelper samlExpiryHelper;
    @Autowired
    private SamlProcessUtil samlValidator;
    @Autowired
    private AssertionDecryptUtil assertionDecryptUtil;
    @Autowired
    private SamlDecryptUtil samlDecryptUtil;
    @Autowired
    private SamlEncryptUtil samlEncryptUtil;
    @Autowired
    private UrlDecodeUtil urlDecodeUtil;

    @Override
    public SamlResponse generateSaml(
            SamlRequest input,
            Boolean isEncryptedPayload,
            Boolean isResponseEncoded,
            Boolean isHtmlEncoded, String spName) throws MarshallingException {
        try {
            SamlResponse samlResponse = samlHelper.generateSAMLResponse(input, input.getSpMetadata());
            htmlEncoder(samlResponse, isHtmlEncoded);
            return samlResponse;
        } catch (Exception e) {
            logger.error(e.getMessage());
            throw e;
        }
    }

    @Override
    public SamlRequest validateSaml(
            SamlValidateRequest samlValidateRequest, String spName, Boolean isHtmlEncoded) {
        SamlRequest payload = null;
        Response samlResponseObject;
        Assertion decryptedAssertion;
        String decryptedSaml;
        try {
            // Base64 decrypt saml
            decryptedSaml = samlDecryptUtil.decryptSaml(samlValidateRequest.getSamlResponse());
            // unmarshall
            samlResponseObject =
                    (Response) samlUnmarshallUtil.unmarshall(decryptedSaml);
            // Validate signature
            signatureValidation.validate(samlResponseObject);
            // decrypt assertion
            decryptedAssertion = assertionDecryptUtil.decryptAssertion(samlResponseObject, false);
            // validate expiry
            samlExpiryHelper.validateExpiry(decryptedAssertion);
            // process
            payload = samlValidator.processResponse(decryptedAssertion);
        } catch (Exception e) {
            logger.error(e.getMessage());
        }
        return payload;
    }

    @Override
    public String getAssertion(GetAssertionRequest input, String spName, Boolean isUrlEncoded) {
        inputPayloadValidator.validate(input.getSamlResponse());
        String encodedSaml = input.getSamlResponse();
        if (isUrlEncoded) {
            encodedSaml = urlDecodeUtil.encode(input.getSamlResponse());
        }
        return samlDecryptUtil.decryptSaml(encodedSaml);
    }

    private void htmlEncoder(SamlResponse samlResponse, Boolean isHtmlEncoded) {
        if (isHtmlEncoded) {
            samlResponse.setSamlResponse(HTMLEncoder.encodeForHTML(samlEncryptUtil.encryptSaml(samlResponse.getSamlResponse())));
        } else {
            samlResponse.setSamlResponse(samlEncryptUtil.encryptSaml(samlResponse.getSamlResponse()));
        }
    }
}
