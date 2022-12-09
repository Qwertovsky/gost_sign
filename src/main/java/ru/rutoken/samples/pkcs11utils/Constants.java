/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2022, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.pkcs11utils;

public final class Constants {
    public static final byte[] ATTR_CRYPTO_PRO_A_GOST28147_89 =
            {0x06, 0x07, 0x2A, (byte) 0x85, 0x03, 0x02, 0x02, 0x1f, 0x01};
    public static final byte[] ATTR_CRYPTO_PRO_A_GOSTR3410_2001 =
            {0x06, 0x07, 0x2A, (byte) 0x85, 0x03, 0x02, 0x02, 0x23, 0x01};
    public static final byte[] ATTR_CRYPTO_PRO_A_GOSTR3410_2012_256 = ATTR_CRYPTO_PRO_A_GOSTR3410_2001;
    public static final byte[] ATTR_CRYPTO_PRO_A_GOSTR3410_2012_512 =
            {0x06, 0x09, 0x2A, (byte) 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x02, 0x01};

    public final static byte[] ATTR_GOSTR3411_1994 = {0x06, 0x07, 0x2a, (byte) 0x85, 0x03, 0x02, 0x02, 0x1e, 0x01};
    public final static byte[] ATTR_GOSTR3411_2012_256 =
            {0x06, 0x08, 0x2a, (byte) 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x02};
    public final static byte[] ATTR_GOSTR3411_2012_512 =
            {0x06, 0x08, 0x2a, (byte) 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x03};

    public static final byte[] DEFAULT_USER_PIN = {'1', '2', '3', '4', '5', '6', '7', '8'};
    public static final byte[] DEFAULT_SO_PIN = {'8', '7', '6', '5', '4', '3', '2', '1'};

    // These constants are from PKCS #11 standard v.2.40
    public static final int CK_CERTIFICATE_CATEGORY_UNSPECIFIED = 0;
    public static final int CK_CERTIFICATE_CATEGORY_TOKEN_USER = 1;
    public static final int CK_CERTIFICATE_CATEGORY_AUTHORITY = 2;
    public static final int CK_CERTIFICATE_CATEGORY_OTHER_ENTITY = 3;

    private Constants() {
    }
}
