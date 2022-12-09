/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2022, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.pkcs11utils;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;

import ru.rutoken.pkcs11jna.Pkcs11Constants;
import ru.rutoken.pkcs11jna.RtPkcs11Constants;

public enum DigestAlgorithm {
    GOSTR3411_1994(
            RtPkcs11Constants.CKM_GOSTR3411,
            new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3411),
            Constants.ATTR_GOSTR3411_1994,
            new DefaultAlgorithmNameFinder().getAlgorithmName(CryptoProObjectIdentifiers.gostR3411),
            32
    ),
    GOSTR3411_2012_256(
            RtPkcs11Constants.CKM_GOSTR3411_12_256,
            new AlgorithmIdentifier(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256),
            Constants.ATTR_GOSTR3411_2012_256,
            // We do not use DefaultAlgorithmNameFinder as it supports only CryptoProObjectIdentifiers.gostR3411
            "GOST3411-2012-256",
            32
    ),
    GOSTR3411_2012_512(
            RtPkcs11Constants.CKM_GOSTR3411_12_512,
            new AlgorithmIdentifier(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512),
            Constants.ATTR_GOSTR3411_2012_512,
            // We do not use DefaultAlgorithmNameFinder as it supports only CryptoProObjectIdentifiers.gostR3411
            "GOST3411-2012-512",
            64
    ),
    SHA1(
            Pkcs11Constants.CKM_SHA_1,
            new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE),
            null,
            new DefaultAlgorithmNameFinder().getAlgorithmName(OIWObjectIdentifiers.idSHA1),
            20
    ),
    SHA224(
            Pkcs11Constants.CKM_SHA224,
            new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha224),
            null,
            new DefaultAlgorithmNameFinder().getAlgorithmName(NISTObjectIdentifiers.id_sha224),
            28
    ),
    SHA256(
            Pkcs11Constants.CKM_SHA256,
            new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256),
            null,
            new DefaultAlgorithmNameFinder().getAlgorithmName(NISTObjectIdentifiers.id_sha256),
            32
    ),
    SHA384(
            Pkcs11Constants.CKM_SHA384,
            new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384),
            null,
            new DefaultAlgorithmNameFinder().getAlgorithmName(NISTObjectIdentifiers.id_sha384),
            48
    ),
    SHA512(
            Pkcs11Constants.CKM_SHA512,
            new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512),
            null,
            new DefaultAlgorithmNameFinder().getAlgorithmName(NISTObjectIdentifiers.id_sha512),
            64
    ),
    MD5(
            Pkcs11Constants.CKM_MD5,
            new AlgorithmIdentifier(PKCSObjectIdentifiers.md5),
            null,
            new DefaultAlgorithmNameFinder().getAlgorithmName(PKCSObjectIdentifiers.md5),
            16
    ),
    RIPEMD128(
            Pkcs11Constants.CKM_RIPEMD128,
            new AlgorithmIdentifier(TeleTrusTObjectIdentifiers.ripemd128),
            null,
            new DefaultAlgorithmNameFinder().getAlgorithmName(TeleTrusTObjectIdentifiers.ripemd128),
            16
    ),
    RSA_RIPEMD160(
            Pkcs11Constants.CKM_RIPEMD160,
            new AlgorithmIdentifier(TeleTrusTObjectIdentifiers.ripemd160),
            null,
            new DefaultAlgorithmNameFinder().getAlgorithmName(TeleTrusTObjectIdentifiers.ripemd160),
            20
    ),
    RIPEMD256(
            0, // not supported in pkcs
            new AlgorithmIdentifier(TeleTrusTObjectIdentifiers.ripemd256),
            null,
            new DefaultAlgorithmNameFinder().getAlgorithmName(TeleTrusTObjectIdentifiers.ripemd256),
            32
    )
    ;

    private final long mPkcsMechanism;
    private final AlgorithmIdentifier mAlgorithmIdentifier;
    private final byte[] mParamset;
    private final String mAlgorithmName;
    private final int mDigestSize; // in bytes

    DigestAlgorithm(long pkcsMechanism, AlgorithmIdentifier algorithmIdentifier, byte[] paramset,
                    String algorithmName, int digestSize) {
        mPkcsMechanism = pkcsMechanism;
        mAlgorithmIdentifier = algorithmIdentifier;
        mParamset = paramset;
        mAlgorithmName = algorithmName;
        mDigestSize = digestSize;
    }

    public long getPkcsMechanism() {
        return mPkcsMechanism;
    }

    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return mAlgorithmIdentifier;
    }

    public byte[] getAlgorithmParamset() {
        return mParamset;
    }

    public String getAlgorithmName() {
        return mAlgorithmName;
    }

    public int getDigestSize() {
        return mDigestSize;
    }

}
