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
package org.keycloak.dom.saml.v2.metadata;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import org.keycloak.dom.saml.v2.mdattr.EntityAttributes;
import org.keycloak.dom.saml.v2.mdui.UIInfoType;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import static org.keycloak.saml.common.constants.JBossSAMLURIConstants.METADATA_UI;
import static org.keycloak.saml.common.constants.JBossSAMLURIConstants.XML;

/**
 * <p>
 * Java class for ExtensionsType complex type.
 *
 * <p>
 * The following schema fragment specifies the expected content contained within this class.
 *
 * <pre>
 * &lt;complexType name="ExtensionsType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;any/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 */
public class ExtensionsType {

    protected List<Object> any = new ArrayList<>();

    /**
     * Function is obsoleted with getAny
     * @return
     */
    @Deprecated
    public Element getElement() {
        return (any.isEmpty()) ? null : (Element) any.get(0);
    }

    /**
     * Function is obsoleted with addExtension
     * @return
     */
    @Deprecated
    public void setElement(Element element) {
        any.clear();
        any.add(element);
    }

    /**
     * Add an extension
     *
     * @param extension
     */
    public void addExtension(Object extension) {
        any.add(extension);
    }

    /**
     * Remove an extension
     *
     * @param extension
     */
    public void removeExtension(Object extension) {
        any.remove(extension);
    }

    /**
     * Gets the value of the any property.
     */
    public List<Object> getAny() {
        return Collections.unmodifiableList(this.any);
    }

    public List<Element> getDomElements() {
        List<Element> output = new ArrayList<Element>();

        for (Object o : this.any) {
            if (o instanceof Element) {
                output.add((Element) o);
            }
        }
        UIInfoType uiInfoType = getUIInfo();
        if (Objects.nonNull(uiInfoType)) {
            try {
                DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
                DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
                Document document = documentBuilder.newDocument();
                Element uiInfo = document.createElementNS(METADATA_UI.get(), "mdui:UIInfo");
                uiInfoType.getDisplayName().forEach(localizedDisplayName -> {
                    Element displayName = document.createElementNS(METADATA_UI.get(), "mdui:DisplayName");
                    displayName.setTextContent(localizedDisplayName.getValue());
                    displayName.setAttributeNS(
                            XML.get(),
                            "xml:lang",
                            localizedDisplayName.getLang()
                    );
                    uiInfo.appendChild(displayName);
                });

                uiInfoType.getDescription().forEach(localizedDescription -> {
                    Element description = document.createElementNS(METADATA_UI.get(), "mdui:Description");
                    description.setTextContent(localizedDescription.getValue());
                    description.setAttributeNS(
                            XML.get(),
                            "xml:lang",
                            localizedDescription.getLang()
                    );
                    uiInfo.appendChild(description);
                });

                uiInfoType.getInformationURL().forEach(localizedInformationUrl -> {
                    Element informationUrl =
                            document.createElementNS(METADATA_UI.get(), "mdui:InformationURL");
                    informationUrl.setTextContent(localizedInformationUrl.getValue().toString());
                    informationUrl.setAttributeNS(
                            XML.get(),
                            "xml:lang",
                            localizedInformationUrl.getLang()
                    );
                    uiInfo.appendChild(informationUrl);
                });

                uiInfoType.getPrivacyStatementURL().forEach(localizedPrivacyStatementUrl -> {
                    Element privacyStatementUrl =
                            document.createElementNS(METADATA_UI.get(), "mdui:PrivacyStatementURL");
                    privacyStatementUrl.setTextContent(localizedPrivacyStatementUrl.getValue().toString());
                    privacyStatementUrl.setAttributeNS(
                            XML.get(),
                            "xml:lang",
                            localizedPrivacyStatementUrl.getLang()
                    );
                    uiInfo.appendChild(privacyStatementUrl);
                });

                uiInfoType.getKeywords().forEach(localizedKeywords -> {
                    Element keywords =
                            document.createElementNS(METADATA_UI.get(), "mdui:Keywords");
                    keywords.setTextContent(String.join("+", localizedKeywords.getValues()));
                    keywords.setAttributeNS(
                            XML.get(),
                            "xml:lang",
                            localizedKeywords.getLang()
                    );
                    uiInfo.appendChild(keywords);
                });
                output.add(uiInfo);
            } catch (ParserConfigurationException e) {
                throw new RuntimeException(e);
            }
        }

        return Collections.unmodifiableList(output);
    }

    public EntityAttributes getEntityAttributes() {
        for (Object o : this.any) {
            if (o instanceof EntityAttributes) {
                return (EntityAttributes) o;
            }
        }
        return null;
    }

    public UIInfoType getUIInfo() {
        for (Object o : this.any) {
            if (o instanceof UIInfoType) {
                return (UIInfoType) o;
            }
        }
        return null;
    }

}
