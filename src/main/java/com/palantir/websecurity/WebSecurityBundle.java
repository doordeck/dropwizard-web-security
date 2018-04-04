/*
 * (c) Copyright 2016 Palantir Technologies Inc. All rights reserved.
 */

package com.palantir.websecurity;

import com.google.common.collect.ImmutableMap;
import com.palantir.websecurity.filters.JerseyAwareWebSecurityFilter;
import com.palantir.websecurity.filters.StrictTransportSecurityFilter;
import io.dropwizard.ConfiguredBundle;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import org.eclipse.jetty.servlets.CrossOriginFilter;

import javax.servlet.DispatcherType;
import javax.servlet.FilterRegistration;
import java.util.EnumSet;
import java.util.Map;

import static java.util.Objects.requireNonNull;

/**
 * Applies and configures security filters to the application.
 */
public final class WebSecurityBundle implements ConfiguredBundle<WebSecurityConfigurable> {

    /**
     * The default value of CORS Allowed Methods. It includes commonly used methods.
     */
    public static final String DEFAULT_ALLOWED_METHODS = "DELETE,GET,HEAD,POST,PUT";

    /**
     * The default value of CORS Allowed Headers. It includes {@code Authorization} for auth purposes.
     */
    public static final String DEFAULT_ALLOWED_HEADERS = "Accept,Authorization,Content-Type,Origin,X-Requested-With";

    /**
     * The default value of CORS Allow Credentials. Credentials should be passed via the {@code Authorization} header.
     */
    public static final boolean DEFAULT_ALLOW_CREDENTIALS = false;

    private static final String ROOT_PATH = "/*";

    private final WebSecurityConfiguration applicationDefaults;
    private WebSecurityConfiguration derivedConfiguration = null;

    /**
     * Constructs a bundle with the out of the box defaults.
     */
    public WebSecurityBundle() {
        this(WebSecurityConfiguration.builder().build());
    }

    /**
     * Constructs a bundle with the {@link #applicationDefaults} as the application defaults.
     */
    public WebSecurityBundle(WebSecurityConfiguration applicationDefaults) {
        this.applicationDefaults = requireNonNull(applicationDefaults);
    }

    @Override
    public void initialize(Bootstrap<?> bootstrap) {
        // do nothing
    }

    @Override
    public void run(WebSecurityConfigurable configuration, Environment environment) {
        requireNonNull(configuration);
        requireNonNull(environment);

        this.derivedConfiguration = WebSecurityConfiguration.builder()
                .from(applicationDefaults)
                .from(configuration.getWebSecurityConfiguration())
                .build();

        applyCors(this.derivedConfiguration, environment);
        applyWebSecurity(this.derivedConfiguration, environment);
        applyStrictTransportSecurity(this.derivedConfiguration, environment);
    }

    /**
     * Returns the derived configuration. Must be called after {@link #run(WebSecurityConfigurable, Environment)}.
     */
    public WebSecurityConfiguration getDerivedConfiguration() {
        return requireNonNull(derivedConfiguration);
    }

    private static void applyCors(WebSecurityConfiguration derivedConfig, Environment environment) {
        if (!derivedConfig.cors().isPresent() || !derivedConfig.cors().get().enabled()) {
            return;
        }

        CrossOriginFilter filter = new CrossOriginFilter();

        FilterRegistration.Dynamic dynamic = environment.servlets().addFilter("CrossOriginFilter", filter);
        dynamic.addMappingForUrlPatterns(EnumSet.allOf(DispatcherType.class), true, ROOT_PATH);
        dynamic.setInitParameters(buildCorsPropertyMap(derivedConfig.cors().get()));
    }

    private static Map<String, String> buildCorsPropertyMap(CorsConfiguration cors) {
        ImmutableMap.Builder<String, String> propertyBuilder = ImmutableMap.builder();

        propertyBuilder.put(CrossOriginFilter.ALLOWED_ORIGINS_PARAM, cors.allowedOrigins().get());
        propertyBuilder.put(CrossOriginFilter.ALLOWED_METHODS_PARAM, cors.allowedMethods().orElse(DEFAULT_ALLOWED_METHODS));
        propertyBuilder.put(CrossOriginFilter.ALLOWED_HEADERS_PARAM, cors.allowedHeaders().orElse(DEFAULT_ALLOWED_HEADERS));

        String allowCredentials = Boolean.toString(cors.allowCredentials().orElse(DEFAULT_ALLOW_CREDENTIALS));
        propertyBuilder.put(CrossOriginFilter.ALLOW_CREDENTIALS_PARAM, allowCredentials);

        cors.chainPreflight().ifPresent(chainPreflight -> propertyBuilder.put(CrossOriginFilter.CHAIN_PREFLIGHT_PARAM, Boolean.toString(chainPreflight)));
        cors.preflightMaxAge().ifPresent(preflightMaxAge -> propertyBuilder.put(CrossOriginFilter.PREFLIGHT_MAX_AGE_PARAM, Long.toString(preflightMaxAge)));
        cors.exposedHeaders().ifPresent(exposedHeaders -> propertyBuilder.put(CrossOriginFilter.EXPOSED_HEADERS_PARAM, exposedHeaders));

        return propertyBuilder.build();
    }

    private static void applyWebSecurity(WebSecurityConfiguration derivedConfig, Environment env) {
        JerseyAwareWebSecurityFilter filter = new JerseyAwareWebSecurityFilter(derivedConfig);
        env.servlets()
                .addFilter("JerseyAwareWebSecurityFilter", filter)
                .addMappingForUrlPatterns(EnumSet.allOf(DispatcherType.class), true, ROOT_PATH);
    }

    private static void applyStrictTransportSecurity(WebSecurityConfiguration derivedConfig, Environment environment) {
        if (!derivedConfig.strictTransportSecurity().isPresent() || derivedConfig.strictTransportSecurity().get().isEmpty()) {
            return;
        }

        environment.jersey().register(new StrictTransportSecurityFilter(derivedConfig));
    }
}
