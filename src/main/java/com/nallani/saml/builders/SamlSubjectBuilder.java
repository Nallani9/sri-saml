package com.nallani.saml.builders;

import com.nallani.saml.model.SPMetadata;
import com.nallani.saml.model.SamlRequest;
import org.apache.commons.lang3.RandomStringUtils;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectConfirmationBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectConfirmationDataBuilder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static com.nallani.saml.service.constants.Constants.NAMESPACE_PREFIX;

@Service
public class SamlSubjectBuilder {

    public Subject buildSubject(SamlRequest content, SPMetadata metadata) {
        Instant currentDate = Instant.now();
        currentDate = currentDate.plus(content.getSpMetadata().getNotOnOrAfter(), ChronoUnit.SECONDS);

        // create nameId element
        NameIDBuilder nameIdBuilder = new NameIDBuilder();
        NameID nameId =
                nameIdBuilder.buildObject(
                        SAMLConstants.SAML20_NS, NameID.DEFAULT_ELEMENT_LOCAL_NAME, NAMESPACE_PREFIX);

        nameId.setValue(RandomStringUtils.random(28, true, true));
        nameId.setFormat(NameIDType.TRANSIENT);
        nameId.setNameQualifier(metadata.getIssuer());
        nameId.setSPNameQualifier(content.getSpMetadata().getSpNameQualifier());

        // create Subject Confirmation
        SubjectConfirmationDataBuilder dataBuilder = new SubjectConfirmationDataBuilder();
        SubjectConfirmationData subjectConfirmationData =
                dataBuilder.buildObject(
                        SAMLConstants.SAML20_NS,
                        SubjectConfirmationData.DEFAULT_ELEMENT_LOCAL_NAME,
                        NAMESPACE_PREFIX);
        subjectConfirmationData.setNotOnOrAfter(currentDate);
        subjectConfirmationData.setRecipient(content.getSpMetadata().getDestination());

        SubjectConfirmationBuilder subjectConfirmationBuilder = new SubjectConfirmationBuilder();
        SubjectConfirmation subjectConfirmation =
                subjectConfirmationBuilder.buildObject(
                        SAMLConstants.SAML20_NS,
                        SubjectConfirmation.DEFAULT_ELEMENT_LOCAL_NAME,
                        NAMESPACE_PREFIX);
        subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);

        // create subject element
        org.opensaml.saml.saml2.core.impl.SubjectBuilder subjectBuilder =
                new org.opensaml.saml.saml2.core.impl.SubjectBuilder();
        Subject subject =
                subjectBuilder.buildObject(
                        SAMLConstants.SAML20_NS, Subject.DEFAULT_ELEMENT_LOCAL_NAME, NAMESPACE_PREFIX);
        subject.setNameID(nameId);
        subject.getSubjectConfirmations().add(subjectConfirmation);
        return subject;
    }
}
