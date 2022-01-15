package com.nallani.saml.builders;

import com.nallani.saml.model.SamlAttributesPayload;
import com.nallani.saml.service.constants.Constants;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.impl.ResponseBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
public class SamlResponseBuilder {

    @Value("${saml.version.major:2}")
    private int samlVersionMajor;

    @Value("${saml.version.minor:0}")
    private int samlVersionMinor;

    public Response buildResponse(Issuer issuer, Status status, SamlAttributesPayload content) {
        ResponseBuilder responseBuilder = new ResponseBuilder();
        Response response =
                responseBuilder.buildObject(
                        SAMLConstants.SAML20P_NS,
                        Response.DEFAULT_ELEMENT_LOCAL_NAME,
                        Constants.NAMESPACE_SAMLP);
        response.setID(UUID.randomUUID().toString());
        response.setIssueInstant(Instant.now());
        response.setVersion(SAMLVersion.valueOf(samlVersionMajor, samlVersionMinor));
        response.setIssuer(issuer);
        response.setStatus(status);
        response.setDestination(content.getSpMetadata().getDestination());
        return response;
    }
}
