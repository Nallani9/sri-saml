package com.nallani.saml.model;

import lombok.Data;

import java.util.List;

@Data
public class SamlAttribute {
    private String name;
    private List<String> value;
}
