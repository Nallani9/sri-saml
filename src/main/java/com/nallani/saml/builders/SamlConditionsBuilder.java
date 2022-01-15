package com.nallani.saml.builders;

import com.nallani.saml.model.SamlAttributesPayload;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.impl.AudienceBuilder;
import org.opensaml.saml.saml2.core.impl.AudienceRestrictionBuilder;
import org.opensaml.saml.saml2.core.impl.ConditionsBuilder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static com.nallani.saml.service.constants.Constants.NAMESPACE_PREFIX;

@Service
public class SamlConditionsBuilder {

    public Conditions buildConditions(SamlAttributesPayload content) {
        ConditionsBuilder conditionsBuilder = new ConditionsBuilder();
        Conditions conditions =
                conditionsBuilder.buildObject(
                        SAMLConstants.SAML20_NS, Conditions.DEFAULT_ELEMENT_LOCAL_NAME, NAMESPACE_PREFIX);
        Instant currentDate = Instant.now();
        conditions.setNotBefore(currentDate);
        Instant updatedDate =
                currentDate.plus(content.getSpMetadata().getNotOnOrAfter(), ChronoUnit.SECONDS);
        conditions.setNotOnOrAfter(updatedDate);

        // Build Audience Restriction
        AudienceRestrictionBuilder audienceRestrictionBuilder = new AudienceRestrictionBuilder();
        AudienceRestriction audienceRestriction =
                audienceRestrictionBuilder.buildObject(
                        SAMLConstants.SAML20_NS,
                        AudienceRestriction.DEFAULT_ELEMENT_LOCAL_NAME,
                        NAMESPACE_PREFIX);

        // Build Audience
        AudienceBuilder audienceBuilder = new AudienceBuilder();
        Audience audience =
                audienceBuilder.buildObject(
                        SAMLConstants.SAML20_NS, Audience.DEFAULT_ELEMENT_LOCAL_NAME, NAMESPACE_PREFIX);
        audience.setValue(
                content.getSpMetadata().getSpNameQualifier()); // we need this for rewards to work
        audienceRestriction.getAudiences().add(audience);
        conditions.getAudienceRestrictions().add(audienceRestriction);
        return conditions;
    }
}
