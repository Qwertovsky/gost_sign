/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2022, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.pkcs11utils;

import com.sun.jna.NativeLong;
import ru.rutoken.pkcs11jna.Pkcs11Constants;

public class Pkcs11Exception extends Exception {

    private Pkcs11Exception(String message) {
        super(message);
    }

    public static void throwIfNotOk(String message, NativeLong code) throws Pkcs11Exception {
        if (!Pkcs11Constants.equalsPkcsRV(Pkcs11Constants.CKR_OK, code))
            throw new Pkcs11Exception(message + ", error code: 0x" + Long.toHexString(code.longValue()));
    }
}
