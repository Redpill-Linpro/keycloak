package org.keycloak.protocol.saml.descriptor.impl;

import org.keycloak.common.util.PemUtils;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.dom.saml.v2.metadata.EntityDescriptorType;
import org.keycloak.dom.saml.v2.metadata.KeyDescriptorType;
import org.keycloak.dom.saml.v2.metadata.KeyTypes;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.saml.IDPMetadataDescriptor;
import org.keycloak.protocol.saml.SamlClient;
import org.keycloak.protocol.saml.SamlProtocol;
import org.keycloak.protocol.saml.SamlService;
import org.keycloak.protocol.saml.descriptor.SamlMetadataDescriptorProvider;
import org.keycloak.saml.SPMetadataDescriptor;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.util.DocumentUtil;
import org.keycloak.saml.common.util.StaxUtil;
import org.keycloak.saml.processing.core.saml.v2.writers.SAMLMetadataWriter;
import org.keycloak.services.resources.RealmsResource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLStreamWriter;
import java.io.StringWriter;
import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import static org.keycloak.protocol.saml.descriptor.impl.DefaultSamlMetadataDescriptorProviderFactory.FALLBACK_ERROR_URL_STRING;


public class DefaultSamlMetadataDescriptorProvider implements SamlMetadataDescriptorProvider {

    private final KeycloakSession session;

    private static final Logger LOGGER = Logger.getLogger(DefaultSamlMetadataDescriptorProvider.class.getName());

    public DefaultSamlMetadataDescriptorProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void close() {

    }

    @Override
    public Document getIdpMetadataDescriptor() {
        final KeycloakUriInfo uriInfo = session.getContext().getUri();
        final RealmModel realm = session.getContext().getRealm();
        try {
            List<Element> signingKeys = session.keys().getKeysStream(realm, KeyUse.SIG, Algorithm.RS256)
                    .sorted(SamlService::compareKeys)
                    .map(key -> {
                        try {
                            return IDPMetadataDescriptor.buildKeyInfoElement(
                                    key.getKid(),
                                    PemUtils.encodeCertificate(key.getCertificate())
                            );
                        } catch (ParserConfigurationException e) {
                            throw new RuntimeException(e);
                        }
                    })
                    .collect(Collectors.toList());

            String idpDescriptor = IDPMetadataDescriptor.getIDPDescriptor(
                    RealmsResource.protocolUrl(uriInfo).build(realm.getName(), SamlProtocol.LOGIN_PROTOCOL),
                    RealmsResource.protocolUrl(uriInfo).build(realm.getName(), SamlProtocol.LOGIN_PROTOCOL),
                    RealmsResource.protocolUrl(uriInfo).build(realm.getName(), SamlProtocol.LOGIN_PROTOCOL),
                    RealmsResource.protocolUrl(uriInfo).path(SamlService.ARTIFACT_RESOLUTION_SERVICE_PATH)
                            .build(realm.getName(), SamlProtocol.LOGIN_PROTOCOL),
                    RealmsResource.realmBaseUrl(uriInfo).build(realm.getName()).toString(),
                    true,
                    signingKeys
            );
            return DocumentUtil.getDocument(idpDescriptor);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Cannot generate IdP metadata", e);
        }
        return null;
    }

    @Override
    public Document getSpMetadataDescriptor(ClientModel client) {
        try {
            SamlClient samlClient = new SamlClient(client);
            String assertionUrl;
            String logoutUrl;
            URI loginBinding;
            URI logoutBinding = null;

            if (samlClient.forcePostBinding()) {
                assertionUrl = client.getAttribute(SamlProtocol.SAML_ASSERTION_CONSUMER_URL_POST_ATTRIBUTE);
                logoutUrl = client.getAttribute(SamlProtocol.SAML_SINGLE_LOGOUT_SERVICE_URL_POST_ATTRIBUTE);
                loginBinding = JBossSAMLURIConstants.SAML_HTTP_POST_BINDING.getUri();
            } else { //redirect binding
                assertionUrl = client.getAttribute(SamlProtocol.SAML_ASSERTION_CONSUMER_URL_REDIRECT_ATTRIBUTE);
                logoutUrl = client.getAttribute(SamlProtocol.SAML_SINGLE_LOGOUT_SERVICE_URL_REDIRECT_ATTRIBUTE);
                loginBinding = JBossSAMLURIConstants.SAML_HTTP_REDIRECT_BINDING.getUri();
            }

            if (samlClient.forceArtifactBinding()) {
                if (client.getAttribute(SamlProtocol.SAML_SINGLE_LOGOUT_SERVICE_URL_ARTIFACT_ATTRIBUTE) != null) {
                    logoutBinding = JBossSAMLURIConstants.SAML_HTTP_ARTIFACT_BINDING.getUri();
                    logoutUrl = client.getAttribute(SamlProtocol.SAML_SINGLE_LOGOUT_SERVICE_URL_ARTIFACT_ATTRIBUTE);
                } else {
                    logoutBinding = loginBinding;
                }
                assertionUrl = client.getAttribute(SamlProtocol.SAML_ASSERTION_CONSUMER_URL_ARTIFACT_ATTRIBUTE);
                loginBinding = JBossSAMLURIConstants.SAML_HTTP_ARTIFACT_BINDING.getUri();

            }

            if (assertionUrl == null || assertionUrl.trim().isEmpty()) assertionUrl = client.getManagementUrl();
            if (assertionUrl == null || assertionUrl.trim().isEmpty()) assertionUrl = FALLBACK_ERROR_URL_STRING;
            if (logoutUrl == null || logoutUrl.trim().isEmpty()) logoutUrl = client.getManagementUrl();
            if (logoutUrl == null || logoutUrl.trim().isEmpty()) logoutUrl = FALLBACK_ERROR_URL_STRING;
            if (logoutBinding == null) logoutBinding = loginBinding;

            String nameIdFormat = samlClient.getNameIDFormat();
            if (nameIdFormat == null) nameIdFormat = SamlProtocol.SAML_DEFAULT_NAMEID_FORMAT;
            KeyDescriptorType spCertificate = SPMetadataDescriptor.buildKeyDescriptorType(
                    SPMetadataDescriptor.buildKeyInfoElement(null, samlClient.getClientSigningCertificate()),
                    KeyTypes.SIGNING,
                    null
            );

            KeyDescriptorType encCertificate = SPMetadataDescriptor.buildKeyDescriptorType(
                    SPMetadataDescriptor.buildKeyInfoElement(null, samlClient.getClientEncryptingCertificate()),
                    KeyTypes.ENCRYPTION,
                    null);

            StringWriter sw = new StringWriter();
            XMLStreamWriter writer = StaxUtil.getXMLStreamWriter(sw);
            SAMLMetadataWriter metadataWriter = new SAMLMetadataWriter(writer);

            EntityDescriptorType entityDescriptor = SPMetadataDescriptor.buildSPDescriptor(
                    loginBinding,
                    logoutBinding,
                    new URI(assertionUrl),
                    new URI(logoutUrl),
                    samlClient.requiresClientSignature(),
                    samlClient.requiresAssertionSignature(),
                    samlClient.requiresEncryption(),
                    client.getClientId(),
                    nameIdFormat,
                    Collections.singletonList(spCertificate),
                    Collections.singletonList(encCertificate)
            );

            metadataWriter.writeEntityDescriptor(entityDescriptor);

            return DocumentUtil.getDocument(sw.toString());
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Cannot generate SP metadata", e);
        }
        return null;
    }
}
