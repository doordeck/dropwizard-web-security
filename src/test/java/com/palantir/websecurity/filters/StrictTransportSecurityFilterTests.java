package com.palantir.websecurity.filters;

import com.google.common.net.HttpHeaders;
import com.palantir.websecurity.WebSecurityConfiguration;
import io.dropwizard.testing.junit.ResourceTestRule;
import org.junit.ClassRule;
import org.junit.Test;

import javax.ws.rs.core.Response;

import static org.junit.Assert.assertEquals;

public class StrictTransportSecurityFilterTests {

    private static final WebSecurityConfiguration CONFIG = WebSecurityConfiguration.builder()
            .from(WebSecurityConfiguration.DEFAULT)
            .strictTransportSecurity("strict-transport")
            .build();

    @ClassRule
    public static final ResourceTestRule resources = ResourceTestRule.builder()
            .addResource(new StrictTransportSecurityFilter(CONFIG))
            .build();

    @Test
    public void testStrictTransportSecurityFilterInjection() {
        Response response = resources.client().target("/").request().get();

        assertEquals("strict-transport", response.getHeaderString(HttpHeaders.STRICT_TRANSPORT_SECURITY));
    }

}
