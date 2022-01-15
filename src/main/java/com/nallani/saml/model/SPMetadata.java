package com.nallani.saml.model;

import lombok.Data;

@Data
public abstract class SPMetadata {
    private String spName;
    private String destination;
    private String issuer;
    private String spNameQualifier;
    private boolean isAssertionEncrypted;
    private String inputAttributesType;
    private Long notOnAfter;
    private Long notOnOrAfter;
    private boolean isUrlEncoded;

    public abstract void initialize();
}
