/*
 * (c) Copyright 2016 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.websecurity.examples;

import com.google.common.net.HttpHeaders;
import io.dropwizard.client.JerseyClientBuilder;
import io.dropwizard.testing.junit.DropwizardAppRule;
import org.glassfish.jersey.client.ClientProperties;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;

import javax.ws.rs.client.Client;
import javax.ws.rs.core.Response;

import static org.junit.Assert.assertEquals;

/**
 * Tests for {@link Example.ExampleRestApplication}.
 */
public final class ExampleRestTests {

    public static final String ORIGIN_VALUE = "http://origin.com";

    @ClassRule
    public static final DropwizardAppRule<Example.ExampleConfiguration> RULE = new DropwizardAppRule<>(
            Example.ExampleRestApplication.class,
            Example.ExampleRestApplication.class.getClassLoader().getResource("example-rest.yml").getPath());

    private static Client client;

    @BeforeClass
    public static void beforeClass() {
        client = new JerseyClientBuilder(RULE.getEnvironment())
                .withProperty(ClientProperties.CONNECT_TIMEOUT, 10000)
                .withProperty(ClientProperties.READ_TIMEOUT, 10000)
                .build("tests");
    }

    @Test
    public void testCorsHeadersAppliedToApi() {
        Response response = client
                .target(String.format("http://localhost:%d/example-context/hello", RULE.getLocalPort())).request()
                .header(HttpHeaders.ORIGIN, ORIGIN_VALUE)
                .get();

        // check basic functionality
        assertEquals(200, response.getStatus());
        assertEquals(Example.EXAMPLES_RESOURCE_RESPONSE, response.readEntity(String.class));

        // check for a YAML defined CORS entry
        assertEquals(ORIGIN_VALUE, response.getHeaderString(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
    }

}
