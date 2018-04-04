/*
 * (c) Copyright 2016 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.websecurity.filters;

import com.palantir.websecurity.WebSecurityConfiguration;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static java.util.Objects.requireNonNull;

/**
 * A filter that injects the Strict-Transport-Security to every request.
 */
public final class WebSecurityFilter implements Filter {

    private final WebSecurityHeaderInjector injector;

    public WebSecurityFilter(WebSecurityConfiguration config) {
        requireNonNull(config);

        this.injector = new WebSecurityHeaderInjector(config);
    }

    @Override
    public void init(FilterConfig filterConfig) {
        // intentionally left blank
    }

    @Override
    public void destroy() {
        // intentionally left blank
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        requireNonNull(request);
        requireNonNull(response);
        requireNonNull(chain);

        if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
            this.injector.injectHeaders((HttpServletRequest) request, (HttpServletResponse) response);
        }

        chain.doFilter(request, response);
    }
}
