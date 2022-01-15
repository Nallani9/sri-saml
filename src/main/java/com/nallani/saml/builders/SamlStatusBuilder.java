package com.nallani.saml.builders;

import com.nallani.saml.service.constants.Constants;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml.saml2.core.impl.StatusCodeBuilder;
import org.springframework.stereotype.Service;

@Service
public class SamlStatusBuilder {
    public Status buildStatus() {
        StatusBuilder statusBuilder = new StatusBuilder();
        Status status =
                statusBuilder.buildObject(
                        SAMLConstants.SAML20P_NS, Status.DEFAULT_ELEMENT_LOCAL_NAME, Constants.NAMESPACE_SAMLP);

        // status code builder
        StatusCodeBuilder statusCodeBuilder = new StatusCodeBuilder();
        StatusCode statusCode =
                statusCodeBuilder.buildObject(
                        SAMLConstants.SAML20P_NS,
                        StatusCode.DEFAULT_ELEMENT_LOCAL_NAME,
                        Constants.NAMESPACE_SAMLP);
        statusCode.setValue(StatusCode.SUCCESS);
        status.setStatusCode(statusCode);
        return status;
    }
}
