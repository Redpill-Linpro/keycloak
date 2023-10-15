/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.protocol.saml.installation;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.ClientInstallationProvider;
import org.keycloak.protocol.saml.SamlProtocol;
import org.keycloak.protocol.saml.descriptor.SamlMetadataDescriptorProvider;
import org.keycloak.saml.common.util.DocumentUtil;

import java.net.URI;
import java.util.Objects;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.services.ErrorResponseException;


/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class SamlSPDescriptorClientInstallation implements ClientInstallationProvider {

    protected static final Logger logger = Logger.getLogger(SamlSPDescriptorClientInstallation.class);

    public static final String SAML_CLIENT_INSTALATION_SP_DESCRIPTOR = "saml-sp-descriptor";

    @Override
    public Response generateInstallation(KeycloakSession session, RealmModel realm, ClientModel client, URI serverBaseUri) {
        SamlMetadataDescriptorProvider samlMetadataDescriptorProvider =
                session.getProvider(SamlMetadataDescriptorProvider.class);
        if (Objects.isNull(samlMetadataDescriptorProvider)) {
            Response response = Response
                    .status(Response.Status.NOT_FOUND)
                    .type(org.keycloak.utils.MediaType.TEXT_PLAIN_UTF_8)
                    .build();
            throw new ErrorResponseException(response);
        }
        return Response
                .ok(DocumentUtil.asString(samlMetadataDescriptorProvider.getSpMetadataDescriptor(client)))
                .type(MediaType.APPLICATION_XML)
                .build();
    }

    @Override
    public String getProtocol() {
        return SamlProtocol.LOGIN_PROTOCOL;
    }

    @Override
    public String getDisplayType() {
        return "SAML Metadata SPSSODescriptor";
    }

    @Override
    public String getHelpText() {
        return "SAML SP Metadata EntityDescriptor or rather SPSSODescriptor. This is an XML file.";
    }

    @Override
    public String getFilename() {
        return "saml-sp-metadata.xml";
    }

    public String getMediaType() {
        return MediaType.APPLICATION_XML;
    }

    @Override
    public boolean isDownloadOnly() {
        return false;
    }

    @Override
    public void close() {

    }

    @Override
    public ClientInstallationProvider create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getId() {
        return SAML_CLIENT_INSTALATION_SP_DESCRIPTOR;
    }
}
