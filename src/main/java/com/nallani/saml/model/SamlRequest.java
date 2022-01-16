package com.nallani.saml.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(Include.NON_EMPTY)
@NoArgsConstructor
public class SamlRequest {
    private String subject;
    private String issuer;
    private String encryptedAttributes;
    private SPMetadata spMetadata;
    @JsonIgnore
    private List<SamlAttribute> samlAttributes = new ArrayList<>();
}
