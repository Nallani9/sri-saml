package com.nallani.saml.builders;

import com.nallani.saml.service.helper.GetKeysHelper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.impl.SignatureBuilder;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import static org.opensaml.core.xml.util.XMLObjectSupport.buildXMLObject;

@Service
public class SamlSignatureBuilder {
    private static final Logger logger = LogManager.getLogger(SamlSignatureBuilder.class);

    @Autowired
    private GetKeysHelper getKeysHelper;

    @Value("${saml.public.cert}")
    private String samlPublicCert;

    public Signature buildSignature() {
        // build signature
        SignatureBuilder signatureBuilder = new SignatureBuilder();
        try {
            Signature signature = signatureBuilder.buildObject();
            signature.setSigningCredential(getKeysHelper.generateKeyCred());
            signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
            signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

            // setting key info
            KeyInfo keyInfo = (KeyInfo) buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);
            X509Data data = (X509Data) buildXMLObject(X509Data.DEFAULT_ELEMENT_NAME);
            X509Certificate cert = (X509Certificate) buildXMLObject(X509Certificate.DEFAULT_ELEMENT_NAME);
            cert.setValue(samlPublicCert);
            data.getX509Certificates().add(cert);
            keyInfo.getX509Datas().add(data);
            signature.setKeyInfo(keyInfo);
            return signature;
        } catch (Exception e) {
            logger.error("Unable to build signature");
        }
        return null;
    }
}
