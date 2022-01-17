package com.nallani.saml.resources;

import com.nallani.saml.model.GetAssertionRequest;
import com.nallani.saml.model.SamlRequest;
import com.nallani.saml.model.SamlResponse;
import com.nallani.saml.model.SamlValidateRequest;
import com.nallani.saml.service.SamlService;
import com.nallani.saml.service.validators.RequestParameterValidator;
import org.opensaml.core.xml.io.MarshallingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import static com.nallani.saml.service.constants.Constants.*;

@RestController
public class SamlResource {

    @Autowired
    private RequestParameterValidator requestParameterValidator;
    @Autowired
    private SamlService samlService;

    @PostMapping(path = "/generate", consumes = "application/json", produces = "application/json")
    public SamlResponse generateSAML(
            @RequestBody SamlRequest input,
            @RequestHeader(value = IS_ENCRYPTED_PAYLOAD, defaultValue = "false") Boolean isEncryptedPayload,
            @RequestHeader(value = IS_RESPONSE_ENCODED, defaultValue = "false") Boolean isResponseEncoded,
            @RequestHeader(value = IS_HTML_ENCODED, defaultValue = "false") Boolean isHtmlEncoded,
            @RequestParam(SP) String spName) throws MarshallingException {

        // validate mandatory request param
        requestParameterValidator.validate(spName);
        return samlService.generateSaml(input, isEncryptedPayload, isResponseEncoded, isHtmlEncoded, spName);
    }

    @PostMapping(path = "/validate", consumes = "application/json", produces = "application/json")
    public SamlRequest validateSAML(
            @RequestBody SamlValidateRequest samlRequest,
            @RequestHeader(value = IS_HTML_ENCODED, defaultValue = "true") Boolean isHtmlEncoded,
            @RequestParam(SP) String spName) {

        // validate mandatory query param
        requestParameterValidator.validate(spName);
        return samlService.validateSaml(samlRequest, spName, isHtmlEncoded);
    }

    @PostMapping(path = "/getAssertion", consumes = "application/json", produces = "application/xml")
    public String getAssertion(
            @RequestBody GetAssertionRequest request,
            @RequestHeader(value = IS_URL_ENCODED, defaultValue = "false") Boolean isUrlEncoded,
            @RequestParam(SP) String spName) {

        // validate mandatory query param
        requestParameterValidator.validate(spName);
        return samlService.getAssertion(request, spName, isUrlEncoded);
    }
}
