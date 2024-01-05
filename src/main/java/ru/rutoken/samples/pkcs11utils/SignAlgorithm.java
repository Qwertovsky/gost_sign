/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2022, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.pkcs11utils;

import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import ru.rutoken.pkcs11jna.Pkcs11Constants;
import ru.rutoken.pkcs11jna.RtPkcs11Constants;

public enum SignAlgorithm {
    GOSTR3410_2001(
            RtPkcs11Constants.CKM_GOSTR3410,
            new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_2001),
            DigestAlgorithm.GOSTR3411_1994,
            true
    ),
    GOSTR3410_2012_256(
            RtPkcs11Constants.CKM_GOSTR3410,
            new AlgorithmIdentifier(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256),
            DigestAlgorithm.GOSTR3411_2012_256,
            true
    ),
    GOSTR3410_2012_512(
            RtPkcs11Constants.CKM_GOSTR3410_512,
            new AlgorithmIdentifier(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512),
            DigestAlgorithm.GOSTR3411_2012_512,
            true
    ),
    RSA_SHA1(
            Pkcs11Constants.CKM_RSA_PKCS,
            new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption),
            DigestAlgorithm.SHA1,
            false
    ),
    RSA_SHA224(
            Pkcs11Constants.CKM_RSA_PKCS,
            new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption),
            DigestAlgorithm.SHA224,
            false
    ),
    RSA_SHA256(
            Pkcs11Constants.CKM_RSA_PKCS,
            new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption),
            DigestAlgorithm.SHA256,
            false
    ),
    RSA_SHA384(
            Pkcs11Constants.CKM_RSA_PKCS,
            new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption),
            DigestAlgorithm.SHA384,
            false
    ),
    RSA_SHA512(
            Pkcs11Constants.CKM_RSA_PKCS,
            new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption),
            DigestAlgorithm.SHA512,
            false
    ),
    RSA_MD5(
            Pkcs11Constants.CKM_RSA_PKCS,
            new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption),
            DigestAlgorithm.MD5,
            false
    ),
    RSA_RIPEMD128(
            Pkcs11Constants.CKM_RSA_PKCS,
            new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption),
            DigestAlgorithm.RIPEMD128,
            false
    ),
    RSA_RIPEMD160(
            Pkcs11Constants.CKM_RSA_PKCS,
            new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption),
            DigestAlgorithm.RSA_RIPEMD160,
            false
    ),
    RSA_RIPEMD256(
            Pkcs11Constants.CKM_RSA_PKCS,
            new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption),
            DigestAlgorithm.RIPEMD256,
            false
    );

    private final long mPkcsMechanism;
    private final AlgorithmIdentifier mAlgorithmIdentifier;
    private final DigestAlgorithm mDigestAlgorithm;
    private final boolean mIsGost;

    SignAlgorithm(long pkcsMechanism, AlgorithmIdentifier algorithmIdentifier, DigestAlgorithm digestAlgorithm,
                  boolean isGost) {
        mPkcsMechanism = pkcsMechanism;
        mAlgorithmIdentifier = algorithmIdentifier;
        mDigestAlgorithm = digestAlgorithm;
        mIsGost = isGost;
    }

    public long getPkcsMechanism() {
        return mPkcsMechanism;
    }

    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return mAlgorithmIdentifier;
    }

    public DigestAlgorithm getDigestAlgorithm() {
        return mDigestAlgorithm;
    }

    public boolean isGost() {
        return mIsGost;
    }
    
    public static SignAlgorithm byAlgorithm(AlgorithmIdentifier id) {
    	for (SignAlgorithm alg : SignAlgorithm.values()) {
    		if (alg.getAlgorithmIdentifier().getAlgorithm().equals(id.getAlgorithm())) {
    			return alg;
    		}
    	}
    	return null;
    }
}
