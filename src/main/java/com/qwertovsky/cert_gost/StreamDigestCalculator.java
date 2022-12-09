/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2022, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package com.qwertovsky.cert_gost;

import java.io.OutputStream;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.io.DigestOutputStream;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;

public class StreamDigestCalculator implements DigestCalculator {
	private final DigestOutputStream stream;
	private final AlgorithmIdentifier alg;

	public StreamDigestCalculator(Digest digest) {
        stream = new DigestOutputStream(digest);
        alg = new DefaultDigestAlgorithmIdentifierFinder().find(digest.getAlgorithmName());
    }

	@Override
	public AlgorithmIdentifier getAlgorithmIdentifier() {
		return alg;
	}

	@Override
	public byte[] getDigest() {
		return stream.getDigest();
	}

	@Override
	public OutputStream getOutputStream() {
		return stream;
	}

}
