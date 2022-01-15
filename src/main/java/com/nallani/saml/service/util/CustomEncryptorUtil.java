package com.nallani.saml.service.util;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.EncryptedElementType;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.xmlsec.encryption.EncryptedData;
import org.opensaml.xmlsec.encryption.EncryptedKey;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.w3c.dom.Document;

import javax.xml.namespace.QName;
import java.security.Key;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class CustomEncryptorUtil extends Encrypter {

    private final DataEncryptionParameters encParams;
    private final List<KeyEncryptionParameters> kekParamsList;
    private final QName qNameElement;
    private final XMLObjectBuilderFactory builderFactory;

    // custom encryptor for building matching element with openam
    public CustomEncryptorUtil(
            DataEncryptionParameters dataEncParams, KeyEncryptionParameters keyEncParam, String prefix) {
        super(dataEncParams, keyEncParam);
        List<KeyEncryptionParameters> keks = new ArrayList<>();
        keks.add(keyEncParam);
        this.encParams = dataEncParams;
        this.kekParamsList = keks;
        qNameElement =
                new QName(
                        EncryptedAssertion.DEFAULT_ELEMENT_NAME.getNamespaceURI(),
                        EncryptedAssertion.DEFAULT_ELEMENT_LOCAL_NAME,
                        prefix);
        this.builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
    }

    @Override
    public EncryptedAssertion encrypt(Assertion assertion) throws EncryptionException {
        return (EncryptedAssertion) this.encryptData(assertion, qNameElement);
    }

    private EncryptedElementType encryptData(XMLObject xmlObject, QName encElementName)
            throws EncryptionException {
        this.checkParams(this.encParams, this.kekParamsList);
        EncryptedElementType encElement =
                (EncryptedElementType)
                        Objects.requireNonNull(this.builderFactory.getBuilder(encElementName))
                                .buildObject(encElementName);
        this.checkAndMarshall(encElement);
        Document ownerDocument = Objects.requireNonNull(encElement.getDOM()).getOwnerDocument();

        String encryptionAlgorithmURI = this.encParams.getAlgorithm();
        Key encryptionKey =
                CredentialSupport.extractEncryptionKey(this.encParams.getEncryptionCredential());
        if (encryptionKey == null && encryptionAlgorithmURI != null) {
            encryptionKey = this.generateEncryptionKey(encryptionAlgorithmURI);
        }

        EncryptedData encryptedData = null;
        if (encryptionKey != null && encryptionAlgorithmURI != null) {
            encryptedData = this.encryptElement(xmlObject, encryptionKey, encryptionAlgorithmURI, false);
        }
        if (this.encParams.getKeyInfoGenerator() != null) {
            KeyInfoGenerator generator = this.encParams.getKeyInfoGenerator();

            try {
                Objects.requireNonNull(encryptedData)
                        .setKeyInfo(generator.generate(this.encParams.getEncryptionCredential()));
            } catch (SecurityException var10) {
                throw new EncryptionException("Error generating encrypted data key info", var10);
            }
        }

        List<EncryptedKey> encryptedKeys = new ArrayList<>();
        if (this.kekParamsList != null && !this.kekParamsList.isEmpty()) {
            encryptedKeys.addAll(
                    this.encryptKey(
                            Objects.requireNonNull(encryptionKey), this.kekParamsList, ownerDocument));
        }
        return this.processElements(encElement, encryptedData, encryptedKeys);
    }
}
