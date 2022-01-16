package com.nallani.saml.resources;

import com.nallani.saml.model.GetAssertionRequest;
import com.nallani.saml.model.SamlRequest;
import com.nallani.saml.model.SamlResponse;
import com.nallani.saml.model.SamlValidateRequest;
import com.nallani.saml.service.SamlService;
import com.nallani.saml.service.validators.QueryParameterValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import static com.nallani.saml.service.constants.Constants.*;

@RestController
public class SamlResource {

    @Autowired
    private QueryParameterValidator queryParameterValidator;
    @Autowired
    private SamlService samlService;

    @PostMapping(path = "/generate", consumes = "application/json", produces = "application/json")
    public SamlResponse generateSAML(
            @RequestBody SamlRequest input,
            @RequestHeader(value = IS_ENCRYPTED_PAYLOAD, defaultValue = "false") Boolean isEncryptedPayload,
            @RequestHeader(value = IS_RESPONSE_ENCODED, defaultValue = "true") Boolean isResponseEncoded,
            @RequestParam(SP) String spName) {

        // validate mandatory query param
        queryParameterValidator.validate(spName);
        return samlService.generateSaml(input, isEncryptedPayload, isResponseEncoded, spName);
    }

    @PostMapping(path = "/validate", consumes = "application/json", produces = "application/json")
    public SamlRequest validateSAML(
            @RequestBody SamlValidateRequest samlRequest,
            @RequestParam(SP) String spName) {

        // validate mandatory query param
        queryParameterValidator.validate(spName);
        return samlService.validateSaml(samlRequest, spName);
    }

    @PostMapping(path = "/getAssertion", consumes = "application/json", produces = "application/xml")
    public String getAssertion(
            @RequestBody GetAssertionRequest request,
            @RequestParam(SP) String spName) {

        // validate mandatory query param
        queryParameterValidator.validate(spName);
        return samlService.getAssertion(request, spName, true);
    }
}
