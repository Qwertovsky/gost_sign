package com.qwertovsky.cert_gost;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.Hashtable;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.io.Streams;

import com.qwertovsky.cert_gost.store.GostStore;


public class CmsSigner {
	
	private Clock clock = Clock.systemDefaultZone();
	
	private final GostStore store;
	
	public CmsSigner(GostStore store) {
		this.store = store;
	}

	public byte[] sign(InputStream is, Instant signingTime, boolean encapsulate) throws Exception {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Streams.pipeAll(is, baos, 32 * 1024);
        CMSTypedData cmsData = new CMSProcessableByteArray(baos.toByteArray());

        CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
        
        ContentSigner contentSigner = new ByteArrayContentSigner(
        		this.store.getSignatureAlgorithm(),
        		t -> {
					try {
						return store.signRaw(t);
					} catch (Exception e) {
						throw new RuntimeException("Sign raw", e);
					}
				});
        
        JcaSignerInfoGeneratorBuilder jcaSignerInfoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(
        		new DigestCalculatorProvider() {
					@Override
					public DigestCalculator get(AlgorithmIdentifier digestAlgorithmIdentifier)
							throws OperatorCreationException {
						Digest digest;
						try {
							digest = store.getDigest(digestAlgorithmIdentifier);
							StreamDigestCalculator digestCalculator = new StreamDigestCalculator(digest);
							return digestCalculator;
						} catch (Exception e) {
							throw new OperatorCreationException("Digest not found", e);
						}
					}
        });
        
        Hashtable<ASN1ObjectIdentifier, Attribute> attributesHashTable = new Hashtable<>();
        if (signingTime == null) {
        	signingTime = Instant.now(clock);
        }
        Date time = new Date(signingTime.toEpochMilli());
		Attribute attr = new Attribute(CMSAttributes.signingTime, new DERSet(new Time(time)));
        attributesHashTable.put(attr.getAttrType(), attr);
        
        DefaultSignedAttributeTableGenerator signedAttributeTableGenerator = new DefaultSignedAttributeTableGenerator(new AttributeTable(attributesHashTable));
        jcaSignerInfoGeneratorBuilder.setSignedAttributeGenerator(signedAttributeTableGenerator);
		X509CertificateHolder certificateHolder = this.store.getCertificateHolder();
		SignerInfoGenerator signerInfoGenerator = jcaSignerInfoGeneratorBuilder.build(contentSigner, certificateHolder);

		cmsGenerator.addSignerInfoGenerator(signerInfoGenerator);
        for (X509CertificateHolder cert : this.store.getCertChain()) {
        	cmsGenerator.addCertificate(cert);
        }
        
        CMSSignedData cms = cmsGenerator.generate(cmsData, encapsulate);
        byte[] signature = cms.getEncoded();
		return signature;
	}
	
	public void setClock(Clock clock) {
		this.clock = clock;
	}

}
