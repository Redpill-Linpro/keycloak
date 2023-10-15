package org.keycloak.protocol.saml.descriptor;

import org.keycloak.provider.ProviderFactory;

public interface SamlMetadataDescriptorProviderFactory extends ProviderFactory<SamlMetadataDescriptorProvider> {

    default String getAlias() {
        return getId();
    }

    default int getPriority() {
        return 1;
    }
}
