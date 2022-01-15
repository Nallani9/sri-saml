package com.nallani.saml.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import lombok.Data;

import javax.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.List;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(Include.NON_EMPTY)
@XmlRootElement
public class SamlAttributesPayload {
    private String subject;
    private String issuer;
    @JsonIgnore
    private SPMetadata spMetadata;
    private List<SamlAttribute> attributes = new ArrayList<>();
    private String encryptedAttributes;
}
