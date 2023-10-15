package org.keycloak.protocol.saml.descriptor;

import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

public class SamlMetadataDescriptorSpi implements Spi {

    @Override
    public boolean isInternal() {
        return true;
    }

    @Override
    public String getName() {
        return "saml-metadata-descriptor";
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return SamlMetadataDescriptorProvider.class;
    }

    @Override
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return SamlMetadataDescriptorProviderFactory.class;
    }
}
