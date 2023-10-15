package org.keycloak.protocol.saml.descriptor.impl;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.saml.descriptor.SamlMetadataDescriptorProvider;
import org.keycloak.protocol.saml.descriptor.SamlMetadataDescriptorProviderFactory;

public class DefaultSamlMetadataDescriptorProviderFactory implements SamlMetadataDescriptorProviderFactory {

    protected static final String FALLBACK_ERROR_URL_STRING = "ERROR:ENDPOINT_NOT_SET";

    @Override
    public SamlMetadataDescriptorProvider create(KeycloakSession session) {
        return new DefaultSamlMetadataDescriptorProvider(session);
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return "default-saml-metadata-descriptor";
    }

    @Override
    public int getPriority() {
        return 1000;
    }
}
