/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2022, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.pkcs11utils;

import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.NativeLongByReference;
import ru.rutoken.pkcs11jna.CK_MECHANISM;
import ru.rutoken.pkcs11jna.Pkcs11;

public class Pkcs11Signer {
    private final SignAlgorithm signAlgorithm;
    private final Pkcs11 pkcs11;
    private final long sessionHandle;
    private final long privateKeyHandle;

    public Pkcs11Signer(SignAlgorithm signAlgorithm, Pkcs11 pkcs11, long sessionHandle, long privateKeyHandle) {
    	this.pkcs11 = pkcs11;
        this.signAlgorithm = signAlgorithm;
        this.sessionHandle = sessionHandle;
        this.privateKeyHandle = privateKeyHandle;
    }

    public SignAlgorithm getSignAlgorithm() {
        return signAlgorithm;
    }

    public DigestAlgorithm getDigestAlgorithm() {
        return signAlgorithm.getDigestAlgorithm();
    }

    public byte[] sign(byte[] data) throws Pkcs11Exception {
        final CK_MECHANISM mechanism = new CK_MECHANISM(signAlgorithm.getPkcsMechanism(), Pointer.NULL, 0);
        NativeLong rv = pkcs11.C_SignInit(new NativeLong(sessionHandle), mechanism, new NativeLong(privateKeyHandle));
        Pkcs11Exception.throwIfNotOk("C_SignInit failed", rv);

        final NativeLongByReference count = new NativeLongByReference();
        rv = pkcs11.C_Sign(new NativeLong(sessionHandle), data, new NativeLong(data.length), null, count);
        Pkcs11Exception.throwIfNotOk("C_Sign failed", rv);

        final byte[] signature = new byte[count.getValue().intValue()];
        rv = pkcs11.C_Sign(new NativeLong(sessionHandle), data, new NativeLong(data.length), signature, count);
        Pkcs11Exception.throwIfNotOk("C_Sign failed", rv);

        return signature;
    }
}
