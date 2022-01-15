package com.nallani.saml.service.helper;

import com.nallani.saml.model.SPMetadata;
import com.nallani.saml.model.SamlAttributesPayload;
import com.nallani.saml.model.SamlResponse;
import com.nallani.saml.service.util.SamlGeneratorUtil;
import lombok.extern.java.Log;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensaml.core.config.InitializationService;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.impl.ResponseMarshaller;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.w3c.dom.Element;

import java.io.ByteArrayOutputStream;

@Log
@Service
public class SamlHelper {
    private final Logger logger = LogManager.getLogger(getClass());

    @Autowired
    private SamlGeneratorUtil samlGenerator;

    public SamlHelper() {
        initialize();
    }

    public SamlResponse initialize() {
        try {
            InitializationService.initialize();
        } catch (Exception e) {
            logger.error(
                    "Unable to initialize saml service");
        }
        return null;
    }

    public SamlResponse generateSAMLResponse(SamlAttributesPayload content, SPMetadata metadata) {
        SamlResponse response = new SamlResponse();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        try {
            ResponseMarshaller marshaller = new ResponseMarshaller();
            Response samlResp = samlGenerator.generateSaml(content, metadata);
            Element element = marshaller.marshall(samlResp);
            SerializeSupport.writeNode(element, baos);
            response.setSamlResponse(baos.toString());
            response.setRelayEndpoint(samlResp.getDestination());
        } catch (Exception e) {
            logger.error(
                    e.getMessage());
        }
        return response;
    }
}
