/*
 * SAMLClient - Main interface module for service providers.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 * Copyright (c) 2014-2015 LastPass, Inc.
 */
package com.lastpass.saml;



import org.joda.time.DateTime;

import org.w3c.dom.Element;
import java.io.StringReader;
import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.io.IOException;

import java.util.HashMap;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.zip.Deflater;
import java.util.zip.Inflater;
import java.util.zip.InflaterOutputStream;

import javax.xml.bind.DatatypeConverter;
import javax.xml.bind.ValidationException;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.KeyInfoSupport;
import org.opensaml.xmlsec.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.impl.SignatureBuilder;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.Signer;


/**
 * A SAMLClient acts as on behalf of a SAML Service
 * Provider to generate requests and process responses.
 *
 * To integrate a service, one must generally do the
 * following:
 *
 *  1. Change the login process to call
 *     generateAuthnRequest() to get a request and link,
 *     and then GET/POST that to the IdP login URL.
 *
 *  2. Create a new URL that acts as the
 *     AssertionConsumerService -- it will call
 *     validateResponse on the response body to
 *     verify the assertion; on success it will
 *     use the subject as the authenticated user for
 *     the web application.
 *
 * The specific changes needed to the application are
 * outside the scope of this SDK.
 */
public class SAMLClient
{
    private SPConfig spConfig;
    private IdPConfig idpConfig;
    private BasicParserPool parsers;
    private final BasicCredential cred;

    /* do date comparisons +/- this many seconds */
    private static final int slack = (int) TimeUnit.MINUTES.toSeconds(5);

    private Credential spCredential;

    private String canonicalizationAlgorithm = SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS;
    private String signatureAlgorithm = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;


    /**
     * Create a new SAMLClient, using the IdPConfig for
     * endpoints and validation.
     */
    public SAMLClient(SPConfig spConfig, IdPConfig idpConfig)
        throws SAMLException
    {
        this.spConfig = spConfig;
        this.idpConfig = idpConfig;

        cred = new BasicCredential(idpConfig.getCert().getPublicKey());
        cred.setEntityId(idpConfig.getEntityId());

        // create xml parsers
        parsers = new BasicParserPool();
        parsers.setNamespaceAware(true);
        try {
            parsers.initialize();
        } catch (ComponentInitializationException e) {
            throw new SAMLException("Failed to initialize BasicParserPool", e);
        }
    }

    /**
     * Get the configured IdpConfig.
     *
     * @return the IdPConfig associated with this client
     */
    public IdPConfig getIdPConfig()
    {
        return idpConfig;
    }

    /**
     * Get the configured SPConfig.
     *
     * @return the SPConfig associated with this client
     */
    public SPConfig getSPConfig()
    {
        return spConfig;
    }

    private Response parseResponse(String authnResponse)
        throws SAMLException
    {
        try {
            XMLObject obj
                    = XMLObjectSupport.
                    unmarshallFromReader(parsers, new StringReader(authnResponse));

            return (Response) obj;
        }
        catch (XMLParserException e) {
            throw new SAMLException(e);
        }
        catch (UnmarshallingException e) {
            throw new SAMLException(e);
        }
    }

    private void validate(Response response)
        throws ValidationException
    {
        // response signature must match IdP's key, if present
        Signature sig = response.getSignature();
        if (sig != null)
        {
            try {
                SignatureValidator.validate(sig, cred);
            } catch (SignatureException ex) {
                throw new ValidationException("Signature validation failed", ex);
            }
        }

        // response must be successful
        if (response.getStatus() == null ||
            response.getStatus().getStatusCode() == null ||
            !(StatusCode.SUCCESS
                .equals(response.getStatus().getStatusCode().getValue()))) {
            throw new ValidationException(
                "Response has an unsuccessful status code");
        }

        // response destination must match ACS
        if (!spConfig.getAcs().equals(response.getDestination()))
            throw new ValidationException(
                "Response is destined for a different endpoint");

        DateTime now = DateTime.now();

        // issue instant must be within a day
        DateTime issueInstant = response.getIssueInstant();

        if (issueInstant != null) {
            if (issueInstant.isBefore(now.minusSeconds(slack)))
                throw new ValidationException(
                    "Response IssueInstant is in the past");

            if (issueInstant.isAfter(now.plusSeconds(slack)))
                throw new ValidationException(
                    "Response IssueInstant is in the future");
        }

        if (response.getEncryptedAssertions() != null) {
            for (EncryptedAssertion encryptedAssertion : response.getEncryptedAssertions()) {
                Assertion assertion = decryptEncryptedAssertion(encryptedAssertion);
                //Don't need to be signed if the whole assertion is encrypted
                verifyAssertion(assertion, false);
            }
        }

        for (Assertion assertion: response.getAssertions()) {
            verifyAssertion(assertion, true);
        }
    }

    private void verifyAssertion(Assertion assertion, boolean requireSigned) throws ValidationException {

        // Assertion must be signed correctly
        if (requireSigned) {

            if (!assertion.isSigned()) {
                throw new ValidationException(
                        "Assertion must be signed");
            }

            Signature sig = assertion.getSignature();
            try {
                SignatureValidator.validate(sig, cred);
            } catch (SignatureException e) {
                throw new ValidationException("Assertion signature validation failed", e);
            }
        }

        // Assertion must contain an authnstatement
        // with an unexpired session
        if (assertion.getAuthnStatements().isEmpty()) {
            throw new ValidationException(
                    "Assertion should contain an AuthnStatement");
        }

        DateTime now = DateTime.now();
        for (AuthnStatement as : assertion.getAuthnStatements()) {
            DateTime sessionTime = as.getSessionNotOnOrAfter();
            if (sessionTime != null) {
                DateTime exp = sessionTime.plusSeconds(slack);
                if (exp != null && (now.isEqual(exp) || now.isAfter(exp))) {
                    throw new ValidationException(
                            "AuthnStatement has expired");
                }
            }
        }

        if (assertion.getConditions() == null) {
            throw new ValidationException(
                    "Assertion should contain conditions");
        }

        // Assertion IssueInstant must be within a day
        DateTime instant = assertion.getIssueInstant();
        if (instant != null) {
            if (instant.isBefore(now.minusSeconds(slack))) {
                throw new ValidationException(
                        "Response IssueInstant is in the past");
            }

            if (instant.isAfter(now.plusSeconds(slack))) {
                throw new ValidationException(
                        "Response IssueInstant is in the future");
            }
        }

        // Conditions must be met by current time
        Conditions conditions = assertion.getConditions();
        DateTime notBefore = conditions.getNotBefore();
        DateTime notOnOrAfter = conditions.getNotOnOrAfter();

        if (notBefore == null || notOnOrAfter == null) {
            throw new ValidationException(
                    "Assertion conditions must have limits");
        }

        notBefore = notBefore.minusSeconds(slack);
        notOnOrAfter = notOnOrAfter.plusSeconds(slack);

        if (now.isBefore(notBefore)) {
            throw new ValidationException(
                    "Assertion conditions is in the future");
        }

        if (now.isEqual(notOnOrAfter) || now.isAfter(notOnOrAfter)) {
            throw new ValidationException(
                    "Assertion conditions is in the past");
        }

        // If subjectConfirmationData is included, it must
        // have a recipient that matches ACS, with a valid
        // NotOnOrAfter
        Subject subject = assertion.getSubject();
        if (subject != null && !subject.getSubjectConfirmations().isEmpty()) {
            boolean foundRecipient = false;
            for (SubjectConfirmation sc : subject.getSubjectConfirmations()) {
                if (sc.getSubjectConfirmationData() == null) {
                    continue;
                }

                SubjectConfirmationData scd = sc.getSubjectConfirmationData();
                if (scd.getNotOnOrAfter() != null) {
                    DateTime chkdate = scd.getNotOnOrAfter().plusSeconds(slack);
                    if (now.isEqual(chkdate) || now.isAfter(chkdate)) {
                        throw new ValidationException(
                                "SubjectConfirmationData is in the past");
                    }
                }

                if (spConfig.getAcs().equals(scd.getRecipient())) {
                    foundRecipient = true;
                }
            }

            if (!foundRecipient) {
                throw new ValidationException(
                        "No SubjectConfirmationData found for ACS");
            }
        }

        // audience must include intended SP issuer
        if (conditions.getAudienceRestrictions().isEmpty()) {
            throw new ValidationException(
                    "Assertion conditions must have audience restrictions");
        }

        // only one audience restriction supported: we can only
        // check against the single SP.
        if (conditions.getAudienceRestrictions().size() > 1) {
            throw new ValidationException(
                    "Assertion contains multiple audience restrictions");
        }

        AudienceRestriction ar = conditions.getAudienceRestrictions()
                .get(0);

        // at least one of the audiences must match our SP
        boolean foundSP = false;
        for (Audience a : ar.getAudiences()) {
            if (spConfig.getEntityId().equals(a.getAudienceURI())) {
                foundSP = true;
            }
        }
        if (!foundSP) {
            throw new ValidationException(
                    "Assertion audience does not include issuer");
        }
    }

    private Assertion decryptEncryptedAssertion(EncryptedAssertion encryptedAssertion) throws ValidationException
    {
        if (spCredential == null) {
            throw new ValidationException("Encrypted assertion but no SP credential specified");
        }

        StaticKeyInfoCredentialResolver staticKeyResolver = new StaticKeyInfoCredentialResolver(spCredential);
        InlineEncryptedKeyResolver inlineEncryptedKeyResolver = new InlineEncryptedKeyResolver();

        Decrypter decrypter = new Decrypter(null, staticKeyResolver, inlineEncryptedKeyResolver);
        decrypter.setRootInNewDocument(true);

        try {
            return decrypter.decrypt(encryptedAssertion);
        } catch (DecryptionException e) {
            throw new ValidationException("Failed to decrypt encrypted assertion", e);
        }
    }

    @SuppressWarnings("unchecked")
    private String createAuthnRequest(String requestId)
        throws SAMLException
    {
        SAMLObjectBuilder<AuthnRequest> builder =
            (SAMLObjectBuilder<AuthnRequest>)
                XMLObjectSupport.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);

        SAMLObjectBuilder<Issuer> issuerBuilder =
            (SAMLObjectBuilder<Issuer>) XMLObjectSupport.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);

        AuthnRequest request = builder.buildObject();
        request.setAssertionConsumerServiceURL(spConfig.getAcs().toString());
        request.setDestination(idpConfig.getLoginUrl().toString());
        request.setIssueInstant(new DateTime());
        request.setID(requestId);
        request.setProtocolBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);

        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(spConfig.getEntityId());
        request.setIssuer(issuer);

        if (spCredential != null) {
            createAndSetSignature(request);
        }

        try {
            Element element = XMLObjectSupport.marshall(request);

            if (request.getSignature() != null) {
                try {
                    Signer.signObject(request.getSignature());
                } catch (SignatureException ex) {
                    throw new SAMLException("Failed to sign request", ex);
                }
            }

            return SerializeSupport.nodeToString(element);
        }
        catch (MarshallingException e) {
            throw new SAMLException(e);
        }
    }

    private byte[] deflate(byte[] input)
        throws IOException
    {
        // deflate and base-64 encode it
        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        deflater.setInput(input);
        deflater.finish();

        byte[] tmp = new byte[8192];
        int count;

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        while (!deflater.finished()) {
            count = deflater.deflate(tmp);
            bos.write(tmp, 0, count);
        }
        bos.close();
        deflater.end();

        return bos.toByteArray();
    }

    private byte[] inflate(byte[] input) throws IOException {
        Inflater inflater = new Inflater(true);

        ByteArrayOutputStream baos = new ByteArrayOutputStream(2048);
        InflaterOutputStream outputStream = new InflaterOutputStream(baos, inflater);
        outputStream.write(input);
        outputStream.close();

        return baos.toByteArray();
    }

    /**
     * Create a new AuthnRequest suitable for sending to an HTTPRedirect
     * binding endpoint on the IdP.  The SPConfig will be used to fill
     * in the ACS and issuer, and the IdP will be used to set the
     * destination.
     *
     * @return a deflated, base64-encoded AuthnRequest
     */
    public String generateAuthnRequest(String requestId)
        throws SAMLException
    {
        String request = createAuthnRequest(requestId);

        try {
            byte[] compressed = deflate(request.getBytes("UTF-8"));
            return DatatypeConverter.printBase64Binary(compressed);
        } catch (UnsupportedEncodingException e) {
            throw new SAMLException(
                "Apparently your platform lacks UTF-8.  That's too bad.", e);
        } catch (IOException e) {
            throw new SAMLException("Unable to compress the AuthnRequest", e);
        }
    }

    /**
     * Check an authnResponse and return the subject if validation
     * succeeds.  The NameID from the subject in the first valid
     * assertion is returned along with the attributes.
     *
     * @param authnResponse a base64-encoded AuthnResponse from the SP
     * @throws SAMLException if validation failed.
     * @return the authenticated subject/attributes as an AttributeSet
     */
    public AttributeSet validateResponse(String authnResponse)
        throws SAMLException
    {
        byte[] decoded = DatatypeConverter.parseBase64Binary(authnResponse);
        try {
            decoded = inflate(decoded);
        } catch (IOException ex) {
            //Ignore this - it might be an uncompressed response
            throw new SAMLException(ex);
        }
        try {
            authnResponse = new String(decoded, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new SAMLException("UTF-8 is missing, oh well.", e);
        }

        Response response = parseResponse(authnResponse);

        try {
            validate(response);
        } catch (ValidationException e) {
            throw new SAMLException(e);
        }

        // we only look at first assertion
        if (response.getAssertions().size() != 1) {
            throw new SAMLException(
                "Response should have a single assertion.");
        }
        Assertion assertion = response.getAssertions().get(0);

        Subject subject = assertion.getSubject();
        if (subject == null) {
            throw new SAMLException(
                "No subject contained in the assertion.");
        }
        if (subject.getNameID() == null) {
            throw new SAMLException("No NameID found in the subject.");
        }

        String nameId = subject.getNameID().getValue();

        HashMap<String, List<String>> attributes =
            new HashMap<String, List<String>>();

        for (AttributeStatement atbs : assertion.getAttributeStatements()) {
            for (Attribute atb: atbs.getAttributes()) {
                String name = atb.getName();
                List<String> values = new ArrayList<String>();
                for (XMLObject obj : atb.getAttributeValues()) {
                    values.add(obj.getDOM().getTextContent());
                }
                attributes.put(name, values);
            }
        }
        return new AttributeSet(nameId, attributes);
    }

    /**
     * Sets the Service Provider (SP) credential. If this credential is set the login request
     * will be signed. Also if set this credential will be used when decrypting encrypted assertions.
     *
     * @param signingCredential A credential instance or {@code null}.
     */
    public void setSPCredential(Credential signingCredential) {
        this.spCredential = signingCredential;
    }

    /**
     * Sets the canonicalization algorithm used when signing AuthnRequest instances.
     * The default value is {@code http://www.w3.org/2001/10/xml-exc-c14n#}.
     *
     * @param canonicalizationAlgorithm
     */
    public void setCanonicalizationAlgorithm(String canonicalizationAlgorithm) {
        this.canonicalizationAlgorithm = canonicalizationAlgorithm;
    }

    /**
     * Sets the signing algorithm used when signing AuthnRequest instances.
     * The default value is {@code http://www.w3.org/2001/04/xmldsig-more#rsa-sha256}.
     *
     * @param signatureAlgorithm A String with a valid XML Signature 1.0/1.1 signature algorithm
     *
     * @see SignatureConstants
     */
    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }



    private void createAndSetSignature(AuthnRequest request) throws SAMLException {
        Signature signature = new SignatureBuilder().buildObject();
        signature.setSigningCredential(spCredential);
        signature.setSignatureAlgorithm(signatureAlgorithm);
        signature.setCanonicalizationAlgorithm(canonicalizationAlgorithm);
        KeyInfo keyInfo = getKeyInfo();
        signature.setKeyInfo(keyInfo);

        request.setSignature(signature);
    }

    private KeyInfo getKeyInfo() throws SAMLException {
        EncryptionConfiguration encConf = ConfigurationService.get(EncryptionConfiguration.class);
        NamedKeyInfoGeneratorManager keygenMgr = encConf.getDataKeyInfoGeneratorManager();

        KeyInfoGenerator keyInfoGenerator = KeyInfoSupport.getKeyInfoGenerator(spCredential,
                keygenMgr, null);

        try {
            return keyInfoGenerator.generate(spCredential);
        } catch (org.opensaml.security.SecurityException ex) {
            String msg
                    = "Can't obtain key from the keystore or generate key info for credential: "
                    + spCredential;

            throw new SAMLException(msg);
        }
    }

}
