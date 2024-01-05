package com.qwertovsky.cert_gost.store;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.Digest;

import com.qwertovsky.cert_gost.StreamDigestCalculator;
import com.sun.jna.NativeLong;

import ru.rutoken.pkcs11jna.CK_ATTRIBUTE;
import ru.rutoken.pkcs11jna.Pkcs11;
import ru.rutoken.pkcs11jna.Pkcs11Constants;
import ru.rutoken.samples.bouncycastle.bcprimitives.RtDigest;
import ru.rutoken.samples.pkcs11utils.DigestAlgorithm;
import ru.rutoken.samples.pkcs11utils.Pkcs11Operations;
import ru.rutoken.samples.pkcs11utils.Pkcs11Signer;
import ru.rutoken.samples.pkcs11utils.SignAlgorithm;

public class PkcsStore implements GostStore {
	
	private final Pkcs11 pkcs11;
	private final NativeLong session;
	private final X509CertificateHolder certificateHolder;
	private NativeLong privateKey;
	private Pkcs11Signer pkcs11Signer;
	private StreamDigestCalculator digestCalculator;
	
	public PkcsStore(Pkcs11 pkcs11, NativeLong session, String certId) throws Exception {
		this.pkcs11 = pkcs11;
		this.session = session;

		this.certificateHolder = getCertificateHolder(certId);
		this.init(pkcs11, session, certificateHolder);
	}

	public PkcsStore(Pkcs11 pkcs11, NativeLong session, File certFile) throws Exception {
		this.pkcs11 = pkcs11;
		this.session = session;

		try(FileInputStream fis = new FileInputStream(certFile)) {
			this.certificateHolder = new X509CertificateHolder(fis.readAllBytes());
		}
		this.init(pkcs11, session, certificateHolder);
	}

	private final void init(Pkcs11 pkcs11, NativeLong session, X509CertificateHolder certificateHolder) throws Exception {
		privateKey = Pkcs11Operations.findPrivateKeyByCertificateValue(pkcs11, session, certificateHolder.getEncoded());
		AlgorithmIdentifier algorithm = certificateHolder.getSignatureAlgorithm();
		SignAlgorithm signAlgorithm = SignAlgorithm.byAlgorithm(algorithm);
		pkcs11Signer = new Pkcs11Signer(signAlgorithm, pkcs11, session.longValue(), privateKey.longValue());
		digestCalculator = new StreamDigestCalculator(getDigest(signAlgorithm.getDigestAlgorithm().getAlgorithmIdentifier()));
	}

	@Override
	public byte[] signRaw(byte[] data) throws Exception {
		digestCalculator.getOutputStream().write(data);
	    byte[] digest = digestCalculator.getDigest();
		if (!pkcs11Signer.getSignAlgorithm().isGost()) {
            digest = createRsaDigestInfo(digest);
		}
		return pkcs11Signer.sign(digest);
	}
	
	private byte[] createRsaDigestInfo(byte[] digest) throws IOException {
        DigestInfo digestInfo = new DigestInfo(pkcs11Signer.getDigestAlgorithm().getAlgorithmIdentifier(), digest);
        return digestInfo.getEncoded();
    }

	@Override
	public Digest getDigest(AlgorithmIdentifier digestAlg) throws Exception {
		for (DigestAlgorithm alg : DigestAlgorithm.values()) {
			if (alg.getAlgorithmIdentifier().equals(digestAlg)) {
				Digest digest = new RtDigest(pkcs11, alg, session.longValue());
				return digest;
			}
		}
		throw new Exception("Digest not found: " + digestAlg.toString());
	}
	
	@Override
	public X509CertificateHolder getCertificateHolder() throws Exception {
        return certificateHolder;
	}

	private X509CertificateHolder getCertificateHolder(String certId) throws Exception {
        System.out.println("Finding signer certificate");
        final CK_ATTRIBUTE[] certificateTemplate;
        certificateTemplate = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(3);
        certificateTemplate[0].setAttr(Pkcs11Constants.CKA_CLASS, Pkcs11Constants.CKO_CERTIFICATE);
        certificateTemplate[1].setAttr(Pkcs11Constants.CKA_ID, certId.getBytes()); // Certificate ID
        certificateTemplate[2].setAttr(Pkcs11Constants.CKA_CERTIFICATE_TYPE, Pkcs11Constants.CKC_X_509);
        
//        certificateTemplate[3].setAttr(Pkcs11Constants.CKA_CERTIFICATE_CATEGORY, Pkcs11Constants.CK_CERTIFICATE_CATEGORY_TOKEN_USER);
        byte[] signerCertificateValue = Pkcs11Operations.getFirstCertificateValue(pkcs11, session, certificateTemplate);
        X509CertificateHolder certificateHolder = new X509CertificateHolder(signerCertificateValue);
        return certificateHolder;
	}

	@Override
	public List<X509CertificateHolder> getCertChain() throws Exception {
		X509CertificateHolder signer = getCertificateHolder();
		List<X509CertificateHolder> chain = new ArrayList<>();
		List<X509CertificateHolder> certificates = Pkcs11Operations.getAllCertificates(this.pkcs11, session);
		chain.add(signer);
		chain.addAll(getCertChain(signer, certificates));
		
		return chain;
	}
	
	private List<X509CertificateHolder> getCertChain(X509CertificateHolder signer, List<X509CertificateHolder> certificates) throws Exception {
		List<X509CertificateHolder> chain = new ArrayList<>();
		ASN1ObjectIdentifier ogrnAttribute = new ASN1ObjectIdentifier("1.2.643.100.1");
		RDN issuerOgrnRdn = signer.getIssuer().getRDNs(ogrnAttribute)[0];
		RDN[] subjectOgrnRdn = signer.getSubject().getRDNs(ogrnAttribute);
		if (subjectOgrnRdn.length > 0 && issuerOgrnRdn.equals(subjectOgrnRdn[0])) {
			// self issued - end of chain
			return chain;
		}

		for (X509CertificateHolder cert : certificates) {
			if (signer.equals(cert)) {
				// self
				continue;
			}
			RDN[] ogrnRdn = cert.getSubject().getRDNs(ogrnAttribute);
			if (ogrnRdn.length == 0) {
				// personal
				continue;
			}
			if (issuerOgrnRdn.equals(ogrnRdn[0])) {
				chain.add(cert);
				chain.addAll(getCertChain(cert, certificates));
				break;
			}
		}
		
		return chain;
	}


}
