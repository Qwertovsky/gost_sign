/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2022, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.utils;

import com.sun.jna.Memory;
import com.sun.jna.NativeLong;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import ru.rutoken.pkcs11jna.Pkcs11Constants;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Random;

public final class Util {
    public static final byte[] RECIPIENT_PUBLIC_KEY_256 = {
            (byte) 0x76, (byte) 0x25, (byte) 0x13, (byte) 0x0F, (byte) 0x19, (byte) 0x17, (byte) 0x3D, (byte) 0x3B,
            (byte) 0x24, (byte) 0xCC, (byte) 0xA7, (byte) 0xC7, (byte) 0x72, (byte) 0xB3, (byte) 0x5D, (byte) 0x83,
            (byte) 0xB0, (byte) 0xBB, (byte) 0x42, (byte) 0xC9, (byte) 0x66, (byte) 0xD5, (byte) 0xC1, (byte) 0x5A,
            (byte) 0x0A, (byte) 0x9F, (byte) 0xD4, (byte) 0x24, (byte) 0xF0, (byte) 0x46, (byte) 0xB2, (byte) 0xCD,
            (byte) 0x85, (byte) 0xDD, (byte) 0xC5, (byte) 0x73, (byte) 0xAE, (byte) 0x72, (byte) 0x8D, (byte) 0x6F,
            (byte) 0xC8, (byte) 0x9C, (byte) 0xE2, (byte) 0x5B, (byte) 0x89, (byte) 0x05, (byte) 0xE8, (byte) 0x9D,
            (byte) 0x75, (byte) 0x93, (byte) 0xBF, (byte) 0xE9, (byte) 0x38, (byte) 0xC3, (byte) 0x43, (byte) 0x27,
            (byte) 0x09, (byte) 0x59, (byte) 0x7E, (byte) 0x7D, (byte) 0x51, (byte) 0xA8, (byte) 0x35, (byte) 0x53
    };

    public static final byte[] RECIPIENT_PUBLIC_KEY_512 = {
            (byte) 0xFC, (byte) 0xD5, (byte) 0xD3, (byte) 0x91, (byte) 0xEF, (byte) 0x58, (byte) 0x66, (byte) 0x50,
            (byte) 0x26, (byte) 0x59, (byte) 0x6C, (byte) 0x71, (byte) 0xE5, (byte) 0x89, (byte) 0x35, (byte) 0xC7,
            (byte) 0x35, (byte) 0x71, (byte) 0x28, (byte) 0xA4, (byte) 0xAD, (byte) 0x3C, (byte) 0xD5, (byte) 0x0A,
            (byte) 0xA3, (byte) 0xF8, (byte) 0xB1, (byte) 0xD9, (byte) 0xC1, (byte) 0x77, (byte) 0xB3, (byte) 0x17,
            (byte) 0x65, (byte) 0x0C, (byte) 0x7E, (byte) 0x6E, (byte) 0x11, (byte) 0x12, (byte) 0xC2, (byte) 0x62,
            (byte) 0xB3, (byte) 0xDF, (byte) 0x43, (byte) 0x32, (byte) 0x54, (byte) 0xB4, (byte) 0x7C, (byte) 0x7D,
            (byte) 0xF3, (byte) 0x3C, (byte) 0x1F, (byte) 0xD7, (byte) 0xEA, (byte) 0x02, (byte) 0xE7, (byte) 0x70,
            (byte) 0x15, (byte) 0xCC, (byte) 0xFC, (byte) 0x28, (byte) 0xC6, (byte) 0xAE, (byte) 0x91, (byte) 0x29,
            (byte) 0x58, (byte) 0xFB, (byte) 0x75, (byte) 0x14, (byte) 0x7B, (byte) 0x0E, (byte) 0x99, (byte) 0x59,
            (byte) 0xF9, (byte) 0x4B, (byte) 0xE9, (byte) 0x80, (byte) 0xA5, (byte) 0xBB, (byte) 0x18, (byte) 0x8E,
            (byte) 0xED, (byte) 0x43, (byte) 0xCC, (byte) 0x8D, (byte) 0x9E, (byte) 0x39, (byte) 0x14, (byte) 0x6A,
            (byte) 0xBA, (byte) 0xC7, (byte) 0x5F, (byte) 0xFF, (byte) 0x02, (byte) 0x4C, (byte) 0x1C, (byte) 0x9E,
            (byte) 0xFE, (byte) 0x71, (byte) 0xF2, (byte) 0xC3, (byte) 0xFD, (byte) 0xD6, (byte) 0x1C, (byte) 0x76,
            (byte) 0xBE, (byte) 0xCF, (byte) 0x77, (byte) 0xB6, (byte) 0xD7, (byte) 0x5D, (byte) 0xFF, (byte) 0x35,
            (byte) 0x3C, (byte) 0x35, (byte) 0x70, (byte) 0x78, (byte) 0x03, (byte) 0xED, (byte) 0x6E, (byte) 0x0A,
            (byte) 0x03, (byte) 0x65, (byte) 0xDC, (byte) 0xA4, (byte) 0xAA, (byte) 0x59, (byte) 0x8B, (byte) 0xDB
    };

    /**
     * List of DN (Distinguished Name) fields
     */
    public final static String[] DN = {
            "CN",
            "Ivanoff",
            "C",
            "RU",
            "2.5.4.5",
            "12312312312",
            "1.2.840.113549.1.9.1",
            "ivanov@mail.ru",
            "ST",
            "Moscow",
    };

    /**
     * List of extension fields
     */
    public final static String[] EXTS = {
            "keyUsage",
            "digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment",
            "extendedKeyUsage",
            "1.2.643.2.2.34.6,1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4",
    };


    private Util() {
    }

    public static void println(String text) {
        System.out.println(text);
    }

    public static void printCsr(String label, byte[] csrDer) {
        println(label);

        final int lineWidth = 64;
        // Encode from der to base64
        String csrBase64 = Base64.getEncoder().encodeToString(csrDer);
        int k = 0;
        while (k < csrBase64.length() / lineWidth) {
            println(csrBase64.substring(k * lineWidth, (k + 1) * lineWidth));
            k++;
        }
        println(csrBase64.substring(k * lineWidth));
        System.out.println();
    }

    public static void printString(String label, String data) {
        println(label);
        println(data);
    }

    public static void printHex(String label, byte[] data) {
        println(label);
        printHex(data);
    }

    public static void printHex(byte[] data) {
        for (int i = 0; i < data.length; ++i) {
            System.out.printf(" %02X", data[i]);
            if ((i + 1) % 16 == 0)
                System.out.println();
        }
        System.out.println();
    }

    public static void checkIfNotOk(String function, NativeLong rv) {
        if (!Pkcs11Constants.equalsPkcsRV(Pkcs11Constants.CKR_OK, rv))
            println(function + ", error code: " + Long.toHexString(rv.longValue()));
    }

    public static Memory allocateDeriveParamsGOSTR3410_2012(int kdf, byte[] key, byte[] ukm) {
        ByteBuffer s = ByteBuffer.allocate(3 * Integer.BYTES + key.length * Byte.BYTES + ukm.length * Byte.BYTES);
        s.order(ByteOrder.LITTLE_ENDIAN);
        s.putInt(kdf);
        s.putInt(key.length);
        s.put(key);
        s.putInt(ukm.length);
        s.put(ukm);

        Memory p = new Memory(s.capacity());
        p.write(0, s.array(), 0, s.capacity());

        return p;
    }

    public static String cmsToPem(byte[] encodedCms) throws IOException {
        try (StringWriter stringWriter = new StringWriter();
             JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(ContentInfo.getInstance(encodedCms));
            pemWriter.flush();
            return stringWriter.toString();
        }
    }

    public static String certificateToPem(byte[] encodedCertificate) throws IOException {
        try (StringWriter stringWriter = new StringWriter();
             JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(new X509CertificateHolder(encodedCertificate));
            pemWriter.flush();
            return stringWriter.toString();
        }
    }

    public static String getCertificateInfo(byte[] certificateValue) throws IOException {
        X509CertificateHolder certificateHolder = new X509CertificateHolder(certificateValue);
        SimpleDateFormat dateFormat = new SimpleDateFormat("dd.MM.yyyy HH:mm");
        return certificateHolder.getSubject().toString() +
        		" insurer=" + certificateHolder.getIssuer().toString() +
                " from " + dateFormat.format(certificateHolder.getNotBefore()) +
                " to " + dateFormat.format(certificateHolder.getNotAfter());
    }

    public static X509CertificateHolder getX509CertificateHolder(String fileName)
            throws IOException, CertificateException {
        InputStream in = new FileInputStream(fileName);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) factory.generateCertificate(in);
        return new X509CertificateHolder(cert.getEncoded());
    }

    public static X509Certificate getX509Certificate(X509CertificateHolder certificateHolder)
            throws CertificateException {
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(certificateHolder);
    }

    public static CMSSignedData readCmsFromFile(String filename) throws IOException, CMSException {
        File f = new File(filename);
        try (PemReader reader = new PemReader(new FileReader(f))) {
            PemObject pemObject = reader.readPemObject();
            return new CMSSignedData(pemObject.getContent());
        }
    }

    public static CMSSignedData getCmsFromBytes(byte[] encodedCms) throws IOException, CMSException {
        ContentInfo contentInfo = ContentInfo.getInstance(ASN1Sequence.fromByteArray(encodedCms));
        return new CMSSignedData(contentInfo);
    }

    public static <T> T TODO(String reason) {
        throw new UnsupportedOperationException(reason);
    }

    public static byte[] generateRandom(int size) {
        Random r = new Random();
        byte[] randomBytes = new byte[size];
        r.nextBytes(randomBytes);
        return randomBytes;
    }
}
