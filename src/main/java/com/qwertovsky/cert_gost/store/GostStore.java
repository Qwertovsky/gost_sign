package com.qwertovsky.cert_gost.store;

import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.Digest;

public interface GostStore {
	
	byte[] signRaw(byte[] data) throws Exception;
	
	X509CertificateHolder getCertificateHolder() throws Exception;

	List<X509CertificateHolder> getCertChain() throws Exception;

	Digest getDigest(AlgorithmIdentifier digestAlg) throws Exception;
	
	default AlgorithmIdentifier getSignatureAlgorithm(X509CertificateHolder certificateHolder) throws Exception {
		AlgorithmIdentifier result = null;
		AlgorithmIdentifier algorithm = certificateHolder.getSubjectPublicKeyInfo().getAlgorithm();
		ASN1ObjectIdentifier identifier = algorithm.getAlgorithm();
		if (RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256.equals(identifier)) {
			result = new AlgorithmIdentifier(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256);
		} else if (RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512.equals(identifier)) {
			result = new AlgorithmIdentifier(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512);
		} else {
			result = algorithm;
		}
		return result;
	}

	default AlgorithmIdentifier getSignatureAlgorithm() throws Exception {
		X509CertificateHolder certificateHolder = getCertificateHolder();
		return this.getSignatureAlgorithm(certificateHolder);
	}
}
