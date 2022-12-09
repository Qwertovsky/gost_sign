/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2022, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.pkcs11utils;

import com.sun.jna.NativeLong;

import java.util.Objects;

public class KeyPair {
    public final NativeLong publicKey;
    public final NativeLong privateKey;

    public KeyPair(NativeLong publicKey, NativeLong privateKey) {
        this.publicKey = Objects.requireNonNull(publicKey);
        this.privateKey = Objects.requireNonNull(privateKey);
    }
}
