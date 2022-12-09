/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2022, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.bouncycastle.bcprimitives;

import com.sun.jna.Memory;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.NativeLongByReference;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.RuntimeCryptoException;
import ru.rutoken.pkcs11jna.CK_MECHANISM;
import ru.rutoken.pkcs11jna.Pkcs11;
import ru.rutoken.pkcs11jna.Pkcs11Constants;
import ru.rutoken.samples.pkcs11utils.DigestAlgorithm;

import java.util.Arrays;
import java.util.Objects;

public class RtDigest implements Digest {
    private final DigestAlgorithm digestAlgorithm;
    private final Pkcs11 pkcs11;
    private final long sessionHandle;
    private boolean mIsOperationInitialized = false;
    
    public RtDigest(Pkcs11 pkcs11, DigestAlgorithm digestAlgorithm, long sessionHandle) {
    	this.pkcs11 = pkcs11;
        this.digestAlgorithm = Objects.requireNonNull(digestAlgorithm);
        this.sessionHandle = sessionHandle;
    }

    private static void checkReturnValue(NativeLong rv, String functionName) {
        if (rv.longValue() != Pkcs11Constants.CKR_OK)
            throw new RuntimeCryptoException(functionName + " failed with rv: " + rv.intValue());
    }

    @Override
    public String getAlgorithmName() {
        return digestAlgorithm.getAlgorithmName();
    }

    @Override
    public int getDigestSize() {
        return digestAlgorithm.getDigestSize();
    }

    @Override
    public void update(byte in) {
        update(new byte[]{in});
    }

    @Override
    public void update(byte[] in, int inOff, int len) {
        final byte[] chunk = Arrays.copyOfRange(in, inOff, inOff + len);
        update(chunk);
    }

    @Override
    public int doFinal(byte[] out, int outOff) {
        final NativeLongByReference count = new NativeLongByReference();
        NativeLong rv = pkcs11.C_DigestFinal(new NativeLong(sessionHandle), null, count);
        checkReturnValue(rv, "C_DigestFinal");

        final byte[] digest = new byte[count.getValue().intValue()];
        rv = pkcs11.C_DigestFinal(new NativeLong(sessionHandle), digest, count);
        checkReturnValue(rv, "C_DigestFinal");

        mIsOperationInitialized = false;

        final int length = count.getValue().intValue();
        System.arraycopy(digest, 0, out, outOff, length);
        return length;
    }

    @Override
    public void reset() {
        if (mIsOperationInitialized) {
            final byte[] result = new byte[getDigestSize()];
            doFinal(result, 0);
        }
    }

    private void update(byte[] chunk) {
        NativeLong rv;
        if (!mIsOperationInitialized) {
        	
        	CK_MECHANISM mechanism;
        	if (digestAlgorithm.getAlgorithmParamset() != null) {
        		final Pointer parameter = new Memory(digestAlgorithm.getAlgorithmParamset().length);
	            parameter.write(0, digestAlgorithm.getAlgorithmParamset(), 0,
	                    digestAlgorithm.getAlgorithmParamset().length);
	            mechanism = new CK_MECHANISM(digestAlgorithm.getPkcsMechanism(), parameter,
	                    digestAlgorithm.getAlgorithmParamset().length);
        	} else {
        		// Pass null as parameter and 0 as parameter length if you want to perform hardware digest
        		mechanism = new CK_MECHANISM(digestAlgorithm.getPkcsMechanism(), null, 0);
        	}

            rv = pkcs11.C_DigestInit(new NativeLong(sessionHandle), mechanism);
            checkReturnValue(rv, "C_DigestInit");
            mIsOperationInitialized = true;
        }

        rv = pkcs11.C_DigestUpdate(new NativeLong(sessionHandle), chunk, new NativeLong(chunk.length));
        checkReturnValue(rv, "C_DigestUpdate");
    }
}
