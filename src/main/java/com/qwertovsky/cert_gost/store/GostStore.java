package com.qwertovsky.cert_gost.store;

import java.util.List;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.Digest;

public interface GostStore {
	
	byte[] signRaw(byte[] data) throws Exception;
	
	X509CertificateHolder getCertificateHolder() throws Exception;

	List<X509CertificateHolder> getCertChain() throws Exception;

	Digest getDigest(AlgorithmIdentifier digestAlg) throws Exception;
	
	default AlgorithmIdentifier getSignatureAlgorithm() throws Exception {
		return getCertificateHolder().getSignatureAlgorithm();
	}

}
