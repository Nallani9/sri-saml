package com.nallani.saml.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@NoArgsConstructor
public class SPMetadata {
    private String spName;
    private String destination;
    private String issuer;
    private String spNameQualifier;
    private boolean isAssertionEncrypted;
    private String inputAttributesType;
    private int notOnAfter;
    private int notOnOrAfter;
    private boolean isUrlEncoded;
}
