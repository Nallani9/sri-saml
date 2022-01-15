package com.nallani.saml;

import org.apache.catalina.connector.Connector;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.servlet.server.ServletWebServerFactory;
import org.springframework.context.annotation.Bean;


@SpringBootApplication
public class SriSamlApplication {

    //public static void main(String[] args) {SpringApplication.run(SriSamlApplication.class, args);}

    @Value("${server.http.port}")
    private String httpPortPropVal;

    public static void main(String[] args) {
        SpringApplication.run(SriSamlApplication.class, args);
    }

    @Bean
    public ServletWebServerFactory servletContainer() {
        TomcatServletWebServerFactory tomcat = new TomcatServletWebServerFactory();
        tomcat.addAdditionalTomcatConnectors(createStandardConnector());
        return tomcat;
    }

    private Connector createStandardConnector() {
        Connector connector = new Connector("org.apache.coyote.http11.Http11NioProtocol");
        connector.setPort(getHttpPort());
        return connector;
    }

    private int getHttpPort() {
        int httpPort = 9090;
        if (StringUtils.isNotBlank(httpPortPropVal)) {
            httpPort = Integer.parseInt(httpPortPropVal);
        }
        return httpPort;
    }
}
