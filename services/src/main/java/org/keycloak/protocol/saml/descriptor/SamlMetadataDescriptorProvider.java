package org.keycloak.protocol.saml.descriptor;

import org.keycloak.models.ClientModel;
import org.keycloak.provider.Provider;
import org.w3c.dom.Document;

public interface SamlMetadataDescriptorProvider extends Provider {

    /**
     * Retrieves the EntityDescriptor document representing the Identity Provider (IdP) metadata.
     *
     * This method returns an XML Document that contains the metadata information for the
     * Identity Provider (IdP). The EntityDescriptor document typically includes details such as
     * the IdP's entityID, public keys, and single sign-on (SSO) settings. The document adheres to
     * the SAML (Security Assertion Markup Language) metadata schema.
     *
     * @return The EntityDescriptor document representing the IdP metadata.
     */
    Document getIdpMetadataDescriptor();

    /**
     * Retrieves the EntityDescriptor document representing the Service Provider (SP) metadata.
     *
     * This method returns an XML Document that contains the metadata information for the
     * Service Provider (SP) associated with the provided client. The EntityDescriptor document
     * typically includes details such as the SP's entityID, public keys, and single sign-on (SSO)
     * settings. The document adheres to the SAML (Security Assertion Markup Language) metadata schema.
     *
     * @param client The client model associated with the Service Provider for which the metadata
     *              is requested.
     * @return The EntityDescriptor document representing the SP metadata.
     */
    Document getSpMetadataDescriptor(ClientModel client);
}
