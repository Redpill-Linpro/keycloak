package org.keycloak.testsuite.saml;

import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.protocol.saml.SamlService;
import org.keycloak.representations.idm.KeysMetadataRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.DocumentUtil;
import org.keycloak.saml.processing.core.util.NamespaceContext;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.testsuite.AbstractKeycloakTest;
import org.keycloak.testsuite.admin.AbstractAdminTest;
import org.keycloak.testsuite.util.AdminClientUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.keycloak.testsuite.util.ServerURLs.getAuthServerContextRoot;

public class SamlMetadataDescriptorProviderTest extends AbstractKeycloakTest {

    @Override
    public void addTestRealms(List<RealmRepresentation> testRealms) {
        RealmRepresentation realm = AbstractAdminTest
                .loadJson(getClass().getResourceAsStream("/testrealm.json"), RealmRepresentation.class);
        testRealms.add(realm);
    }

    private CloseableHttpClient client;

    @Before
    public void before() {
        client = HttpClientBuilder.create().build();
    }

    @After
    public void after() {
        try {
            client.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // TODO add tests for SPSSODescriptor

    @Test
    public void testDefaultSamlIdpMetadataDescriptorProvider() {
        // TODO don't assume nodes positions in the xml document
        try (Client client = AdminClientUtil.createResteasyClient()) {
            Document metadataDescriptor = fetchSamlIdPMetadataDescriptor(client);

            // validate metadata descriptor
            SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            StreamSource[] schemaSources = Stream.of(
                    new StreamSource(
                            this.getClass().getResourceAsStream("/saml/saml-schema-assertion-2.0.xsd")
                    ),
                    new StreamSource(
                            this.getClass().getResourceAsStream("/saml/saml-schema-metadata-2.0.xsd")
                    )
            ).toArray(StreamSource[]::new);

            Schema schema = schemaFactory.newSchema(schemaSources);

            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            DOMSource domSource = new DOMSource(metadataDescriptor);
            StreamResult streamResult = new StreamResult(byteArrayOutputStream);
            TransformerFactory.newInstance().newTransformer().transform(domSource, streamResult);
            Validator validator = schema.newValidator();
            validator.validate(new StreamSource(new ByteArrayInputStream(byteArrayOutputStream.toByteArray())));

            // verify entityDescriptor attribute values
            Element entityDescriptor = metadataDescriptor.getDocumentElement();
            assertEquals(
                    "https://localhost:8543/auth/realms/test",
                    entityDescriptor.getAttribute("entityID")
            );
            assertEquals(
                    "true",
                    entityDescriptor
                            .getFirstChild()
                            .getAttributes()
                            .getNamedItem("WantAuthnRequestsSigned")
                            .getNodeValue()
            );

            XPath xPath = XPathFactory.newInstance().newXPath();
            NamespaceContext namespaceContext = new NamespaceContext();
            namespaceContext.addNsUriPair("md", "urn:oasis:names:tc:SAML:2.0:metadata");
            namespaceContext.addNsUriPair("ds", "http://www.w3.org/2000/09/xmldsig#");
            namespaceContext.addNsUriPair("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
            xPath.setNamespaceContext(namespaceContext);

            // verify nameIDFormat values
            NodeList nameIDFormat = (NodeList) xPath
                    .evaluate("//md:NameIDFormat", metadataDescriptor, XPathConstants.NODESET);

            Set<String> expectedNameIDFormatValues = Set.of(
                    "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
                    "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
                    "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
            );
            assertEquals(expectedNameIDFormatValues.size(), nameIDFormat.getLength());
            IntStream
                    .range(0, nameIDFormat.getLength())
                    .mapToObj(nameIDFormat::item)
                    .filter(Objects::nonNull)
                    .forEach(node -> {
                        assertTrue(
                                String.format(
                                        "Expected one of: %s, got: %s",
                                        expectedNameIDFormatValues,
                                        node.getFirstChild().getNodeValue()
                                ),
                                expectedNameIDFormatValues.contains(node.getFirstChild().getNodeValue())
                        );
                    });

            final String expectedLocation = "https://localhost:8543/auth/realms/test/protocol/saml";

            Set<String> expectedSSOBindingValues = Set.of(
                    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                    "urn:oasis:names:tc:SAML:2.0:bindings:SOAP",
                    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
            );

            final String expectedArtifactResolutionServiceLocation = String.format("%s/resolve", expectedLocation);

            // verify ArtifactResolutionService values
            NodeList artifactResolutionService = (NodeList) xPath
                    .evaluate("//md:ArtifactResolutionService", metadataDescriptor, XPathConstants.NODESET);

            assertEquals(1, artifactResolutionService.getLength());

            NamedNodeMap artifactResolutionServiceAttributes = artifactResolutionService
                    .item(0)
                    .getAttributes();

            assertEquals(String.format(
                            "Expected 3 attributes from ArtifactResolutionService, got: %s",
                            artifactResolutionServiceAttributes.getLength()
                    ),
                    3, artifactResolutionServiceAttributes.getLength());
            assertEquals(
                    String.format(
                            "Expected: %s, got: %s",
                            "urn:oasis:names:tc:SAML:2.0:bindings:SOAP",
                            artifactResolutionServiceAttributes.item(0).getNodeValue()
                    ),
                    "urn:oasis:names:tc:SAML:2.0:bindings:SOAP",
                    artifactResolutionServiceAttributes.item(0).getNodeValue()
            );
            assertEquals(
                    String.format(
                            "Expected: %s, got: %s",
                            expectedArtifactResolutionServiceLocation,
                            artifactResolutionServiceAttributes.item(1).getNodeValue()
                    ),
                    expectedArtifactResolutionServiceLocation,
                    artifactResolutionServiceAttributes.item(1).getNodeValue()
            );
            assertEquals(
                    String.format(
                            "Expected: 0, got: %s",
                            artifactResolutionServiceAttributes.item(2).getNodeValue()
                    ),
                    "0",
                    artifactResolutionServiceAttributes.item(2).getNodeValue()
            );

            // verify SingleSignOnService values
            NodeList singleSignOnService = (NodeList) xPath
                    .evaluate("//md:SingleSignOnService", metadataDescriptor, XPathConstants.NODESET);

            assertEquals(expectedSSOBindingValues.size(), singleSignOnService.getLength());
            IntStream
                    .range(0, singleSignOnService.getLength())
                    .mapToObj(singleSignOnService::item)
                    .filter(Objects::nonNull)
                    .forEach(node -> {
                        assertEquals(String.format(
                                "Expected 2 attributes from SingleSignOnService, got: %s",
                                node.getAttributes().getLength()
                        ), 2, node.getAttributes().getLength());
                        assertTrue(
                                String.format(
                                        "Expected one of: %s, got: %s",
                                        expectedSSOBindingValues,
                                        node.getAttributes().item(0).getNodeValue()
                                ),
                                expectedSSOBindingValues
                                        .contains(node.getAttributes().item(0).getNodeValue())
                        );
                        assertEquals(
                                String.format(
                                        "Expected: %s, got: %s",
                                        expectedLocation,
                                        node.getAttributes().item(1).getNodeValue()
                                ),
                                expectedLocation,
                                node.getAttributes().item(1).getNodeValue()
                        );
                    });

            // verify SingleLogoutService values
            NodeList singleLogoutService = (NodeList) xPath
                    .evaluate("//md:SingleLogoutService", metadataDescriptor, XPathConstants.NODESET);

            assertEquals(expectedSSOBindingValues.size(), singleSignOnService.getLength());
            IntStream
                    .range(0, singleLogoutService.getLength())
                    .mapToObj(singleLogoutService::item)
                    .filter(Objects::nonNull)
                    .forEach(node -> {
                        assertEquals(String.format(
                                "Expected 2 attributes from SingleLogoutService, got: %s",
                                node.getAttributes().getLength()
                        ), 2, node.getAttributes().getLength());
                        assertTrue(
                                String.format(
                                        "Expected one of: %s, got: %s",
                                        expectedSSOBindingValues,
                                        node.getAttributes().item(0).getNodeValue()
                                ),
                                expectedSSOBindingValues
                                        .contains(node.getAttributes().item(0).getNodeValue())
                        );
                        assertEquals(
                                String.format(
                                        "Expected: %s, got: %s",
                                        expectedLocation,
                                        node.getAttributes().item(1).getNodeValue()
                                ),
                                expectedLocation,
                                node.getAttributes().item(1).getNodeValue()
                        );
                    });

            // verify data provided in the KeyDescriptor
            KeysMetadataRepresentation keys = adminClient.realm("test").keys().getKeyMetadata();

            NodeList keyDescriptors = (NodeList) xPath
                    .evaluate("//md:KeyDescriptor", metadataDescriptor, XPathConstants.NODESET);

            assertEquals(1, keyDescriptors.getLength());
            Node keyDescriptor = keyDescriptors.item(0);
            assertEquals(1, keyDescriptor.getAttributes().getLength());
            String keyUse = keyDescriptor.getAttributes().item(0).getNodeValue();
            assertEquals(String.format("Expected key use to be: signing, got: %s", keyUse), "signing", keyUse);

            Node keyInfo = keyDescriptor.getFirstChild();
            assertEquals(2, keyInfo.getChildNodes().getLength());
            String samlMetadataDescriptorProvidedKid = keyInfo.getFirstChild().getFirstChild().getNodeValue();
            String samlMetadataDescriptorProvidedCert = keyInfo.getLastChild().getLastChild().getFirstChild().getNodeValue();
            Optional<KeysMetadataRepresentation.KeyMetadataRepresentation> maybeKey = keys
                    .getKeys()
                    .stream()
                    .filter(key -> key.getKid().equals(samlMetadataDescriptorProvidedKid))
                    .findFirst();
            assertTrue(String.format("Expected to find key with kid: %s", samlMetadataDescriptorProvidedKid), maybeKey.isPresent());
            KeysMetadataRepresentation.KeyMetadataRepresentation desiredKeyMetadataRepresentation = maybeKey.get();
            assertEquals(
                    String.format(
                            "Expected certificate: %s, got: %s",
                            desiredKeyMetadataRepresentation,
                            samlMetadataDescriptorProvidedCert
                    ),
                    maybeKey.get().getCertificate(),
                    samlMetadataDescriptorProvidedCert
            );

        } catch (ConfigurationException | ParsingException | ProcessingException e) {
            fail(String.format("Failed to fetch SAML IdP metadata descriptor: %s", e));
        } catch (SAXException e) {
            fail(String.format("Failed to read schema for SAML metadata descriptor: %s", e));
        } catch (IOException e) {
            fail(String.format("Failed to validate SAML metadata descriptor: %s", e));
        } catch (TransformerException e) {
            fail(String.format("Failed to transform SAML metadata descriptor: %s", e));
        } catch (XPathExpressionException e) {
            fail(String.format("Failed to find elements in SAML metadata descriptor: %s", e));
        }
    }

    private Document fetchSamlIdPMetadataDescriptor(Client client)
            throws ConfigurationException, ParsingException, ProcessingException {
        String basePath = String.format("%s/auth", getAuthServerContextRoot());
        UriBuilder uriBuilder = UriBuilder.fromUri(basePath);
        URI samlMetadataDescriptorUri = uriBuilder
                .path(RealmsResource.class)
                .path(RealmsResource.class, "getProtocol")
                .path(SamlService.class, "getDescriptor")
                .build("test", "saml");
        WebTarget samlMetadataDescriptorTarget = client.target(samlMetadataDescriptorUri);
        Response response = samlMetadataDescriptorTarget.request().get();
        assertEquals(200, response.getStatus());
        assertEquals(
                "no-cache",
                response.getHeaders().getFirst("Cache-Control")
        );
        String xml = response.readEntity(String.class);
        return DocumentUtil.getDocument(xml);
    }
}
