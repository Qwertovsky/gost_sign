package com.qwertovsky.cert_gost;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.util.function.Function;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;

public class ByteArrayContentSigner implements ContentSigner {
	
	private AlgorithmIdentifier algId;
	private ByteArrayOutputStream stream = new ByteArrayOutputStream();
	private Function<byte[], byte[]> method;
	
	public ByteArrayContentSigner(AlgorithmIdentifier algId, Function<byte[], byte[]> method) {
		this.algId = algId;
		this.method = method;
	}

	@Override
	public AlgorithmIdentifier getAlgorithmIdentifier() {
		return algId;
	}

	@Override
	public OutputStream getOutputStream() {
		return stream;
	}

	@Override
	public byte[] getSignature() {
		return method.apply(stream.toByteArray());
	}

}
