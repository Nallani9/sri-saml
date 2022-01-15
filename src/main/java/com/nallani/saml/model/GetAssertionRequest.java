package com.nallani.saml.model;

import lombok.Data;

@Data
public class GetAssertionRequest {
    private String samlResponse;
}
