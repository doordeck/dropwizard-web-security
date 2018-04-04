/*
 * (c) Copyright 2016 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.websecurity.filters;

import com.google.common.net.HttpHeaders;
import com.palantir.websecurity.WebSecurityConfiguration;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link JerseyAwareWebSecurityFilter}.
 */
public final class JerseyAwareWebSecurityFilterTests {

    private static final WebSecurityConfiguration DEFAULT_CONFIG = WebSecurityConfiguration.DEFAULT;

    private final MockHttpServletResponse response = new MockHttpServletResponse();
    private final FilterChain chain = mock(FilterChain.class);

    @Test
    public void testInjectInHttpServletRequests() throws IOException, ServletException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/index.html");

        JerseyAwareWebSecurityFilter filter = new JerseyAwareWebSecurityFilter(DEFAULT_CONFIG);
        request.setPathInfo("/api");

        filter.doFilter(request, response, chain);

        // only testing 1 header, since the WebSecurityHeaderInjector is tested separately
        assertEquals(WebSecurityHeaderInjector.DEFAULT_FRAME_OPTIONS, response.getHeader(HttpHeaders.X_FRAME_OPTIONS));
    }

}
