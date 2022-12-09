package com.qwertovsky.cert_gost.store;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DefaultSignatureNameFinder;
import org.bouncycastle.operator.bc.BcDefaultDigestProvider;

public class PfxStore implements GostStore {
	
	private KeyStore keyStore;
	private String alias;
	
	public PfxStore(File pfxFile, String alias, char[] pin) throws Exception {
		this.keyStore = KeyStore.getInstance("PKCS12", "BC");
		try (FileInputStream fis = new FileInputStream(pfxFile)) {
			keyStore.load(fis, pin);
		}
		this.alias = alias;
	}

	@Override
	public X509CertificateHolder getCertificateHolder() throws Exception {
		Certificate certificate = this.keyStore.getCertificate(this.alias);
		return new X509CertificateHolder(certificate.getEncoded());
	}

	@Override
	public List<X509CertificateHolder> getCertChain() throws Exception {
		List<X509CertificateHolder> result = new ArrayList<>();
		Certificate[] chain = this.keyStore.getCertificateChain(this.alias);
		for (Certificate cert : chain) {
			result.add(new X509CertificateHolder(cert.getEncoded()));
		}
		return result;
	}
	
	private PrivateKey getPrivateKey() throws Exception {
		return (PrivateKey) this.keyStore.getKey(this.alias, null);
	}

	@Override
	public byte[] signRaw(byte[] data) {
		try {
			AlgorithmIdentifier algId = getSignatureAlgorithm();
			String algorithmName = new DefaultSignatureNameFinder().getAlgorithmName(algId);
			Signature sig;
			sig = Signature.getInstance(algorithmName, BouncyCastleProvider.PROVIDER_NAME);
			sig.initSign(getPrivateKey());
			sig.update(data);
			return sig.sign();
		} catch (Exception e) {
			throw new RuntimeException("Sign raw", e);
		}
	}
	
	@Override
	public Digest getDigest(AlgorithmIdentifier digestAlg) throws Exception {
		ExtendedDigest digest = BcDefaultDigestProvider.INSTANCE.get(digestAlg);
		return digest;
	}

}
