package com.palantir.websecurity.filters;

import com.google.common.net.HttpHeaders;
import com.palantir.websecurity.WebSecurityConfiguration;

import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;
import java.io.IOException;

import static java.util.Objects.requireNonNull;

/**
 * A filter that injects adds the {@link com.google.common.net.HttpHeaders#STRICT_TRANSPORT_SECURITY} header and
 * value onto all responses
 */
@Priority(Priorities.HEADER_DECORATOR)
public class StrictTransportSecurityFilter implements ContainerResponseFilter {

    private final String strictTransportSecurity;

    public StrictTransportSecurityFilter(WebSecurityConfiguration config) {
        requireNonNull(config);

        this.strictTransportSecurity = config.strictTransportSecurity().orNull();
    }

    @Override
    public void filter(ContainerRequestContext request, ContainerResponseContext response) throws IOException {
        requireNonNull(request);
        requireNonNull(response);

        if (strictTransportSecurity != null) {
            response.getHeaders().putSingle(HttpHeaders.STRICT_TRANSPORT_SECURITY, strictTransportSecurity);
        }
    }
}