/*************************************************************************
* Rutoken                                                                *
* Copyright (c) 2003-2022, Aktiv-Soft JSC. All rights reserved.          *
* Подробная информация:  http://www.rutoken.ru                           *
*************************************************************************/

package ru.rutoken.samples.pkcs11utils;

import com.sun.jna.Memory;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.cert.X509CertificateHolder;

import ru.rutoken.pkcs11jna.CK_ATTRIBUTE;
import ru.rutoken.pkcs11jna.CK_C_INITIALIZE_ARGS;
import ru.rutoken.pkcs11jna.CK_TOKEN_INFO;
import ru.rutoken.pkcs11jna.Pkcs11;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static ru.rutoken.pkcs11jna.Pkcs11Constants.*;
import static ru.rutoken.samples.utils.Util.*;

/**
 * Common operations on pkcs11
 */
public final class Pkcs11Operations {
    private Pkcs11Operations() {
    }

    public static NativeLong initializePkcs11AndGetFirstToken(Pkcs11 pkcs11) throws Pkcs11Exception {
        CK_C_INITIALIZE_ARGS initializeArgs = new CK_C_INITIALIZE_ARGS(
                null, null, null, null,
                new NativeLong(CKF_OS_LOCKING_OK), null);

        NativeLong rv = pkcs11.C_Initialize(initializeArgs);
        Pkcs11Exception.throwIfNotOk("C_Initialize failed", rv);

        NativeLong[] slots = getSlotList(pkcs11, true);
        if (slots.length == 0)
            throw new IllegalStateException("Rutoken is not found");

        println("Getting info about tokens");
        // You can select appropriate token by serial number
        List<CK_TOKEN_INFO> tokenInfos = getTokenInfos(pkcs11, slots);
        for (CK_TOKEN_INFO tokenInfo : tokenInfos) {
            println("Token serial: " + new String(tokenInfo.serialNumber));
        }
        // We'll just take the first one for simplicity
        return slots[0];
    }

    public static void initializePkcs11AndLoginToFirstToken(Pkcs11 pkcs11, NativeLong session, byte[] userPin) throws Pkcs11Exception {
        NativeLong token = initializePkcs11AndGetFirstToken(pkcs11);

        NativeLongByReference sessionPointer = new NativeLongByReference();
        NativeLong rv = pkcs11.C_OpenSession(token, new NativeLong(CKF_SERIAL_SESSION | CKF_RW_SESSION),
                null, null, sessionPointer);
        Pkcs11Exception.throwIfNotOk("C_OpenSession failed", rv);
        session.setValue(sessionPointer.getValue().longValue());

		rv = pkcs11.C_Login(session, new NativeLong(CKU_USER), userPin,
                new NativeLong(userPin.length));
        Pkcs11Exception.throwIfNotOk("C_Login failed", rv);
    }

    public static void logoutAndFinalizePkcs11Library(Pkcs11 pkcs11, NativeLong session) {
        NativeLong rv = pkcs11.C_Logout(session);
        checkIfNotOk("C_Logout failed", rv);

        rv = pkcs11.C_CloseSession(session);
        checkIfNotOk("C_CloseSession failed", rv);

        rv = pkcs11.C_Finalize(null);
        checkIfNotOk("C_Finalize failed", rv);
    }

    public static NativeLong[] getSlotList(Pkcs11 pkcs11, boolean tokenPresent) throws Pkcs11Exception {
        byte presentFlag = tokenPresent ? CK_TRUE : CK_FALSE;
        NativeLongByReference slotsCount = new NativeLongByReference();
        NativeLong rv = pkcs11.C_GetSlotList(presentFlag, null, slotsCount);
        Pkcs11Exception.throwIfNotOk("C_GetSlotList failed", rv);

        if (0 == slotsCount.getValue().intValue())
            return new NativeLong[0];

        NativeLong[] slotList = new NativeLong[slotsCount.getValue().intValue()];
        rv = pkcs11.C_GetSlotList(presentFlag, slotList, slotsCount);
        Pkcs11Exception.throwIfNotOk("C_GetSlotList failed", rv);
        return slotList;
    }

    public static List<CK_TOKEN_INFO> getTokenInfos(Pkcs11 pkcs11, NativeLong[] slots) throws Pkcs11Exception {
        List<CK_TOKEN_INFO> tokenInfos = new ArrayList<>();
        for (NativeLong slot : slots) {
            CK_TOKEN_INFO ckTokenInfo = new CK_TOKEN_INFO();
            NativeLong rv = pkcs11.C_GetTokenInfo(slot, ckTokenInfo);
            Pkcs11Exception.throwIfNotOk("C_GetTokenInfo failed", rv);
            tokenInfos.add(ckTokenInfo);
        }
        return tokenInfos;
    }

    public static NativeLong[] findObjects(Pkcs11 pkcs11, NativeLong session, CK_ATTRIBUTE[] template, int maxCount)
            throws Pkcs11Exception {
        NativeLong rv = pkcs11.C_FindObjectsInit(session, template, new NativeLong(template.length));
        Pkcs11Exception.throwIfNotOk("C_FindObjectsInit failed", rv);
        NativeLong[] objectsBuffer = new NativeLong[maxCount];
        NativeLongByReference pulCount = new NativeLongByReference();
        rv = pkcs11.C_FindObjects(session, objectsBuffer, new NativeLong(objectsBuffer.length), pulCount);
        Pkcs11Exception.throwIfNotOk("C_FindObjects failed", rv);
        rv = pkcs11.C_FindObjectsFinal(session);
        Pkcs11Exception.throwIfNotOk("C_FindObjectsFinal failed", rv);
        return Arrays.copyOf(objectsBuffer, pulCount.getValue().intValue());
    }

    public static void getAttributeValues(Pkcs11 pkcs11, NativeLong session, NativeLong object,
                                          CK_ATTRIBUTE[] attributes) throws Pkcs11Exception {
        NativeLong rv = pkcs11.C_GetAttributeValue(session, object, attributes, new NativeLong(attributes.length));
        Pkcs11Exception.throwIfNotOk("C_GetAttributeValue failed", rv);
        for (CK_ATTRIBUTE attribute : attributes)
            attribute.pValue = new Memory(attribute.ulValueLen.intValue());

        rv = pkcs11.C_GetAttributeValue(session, object, attributes, new NativeLong(attributes.length));
        Pkcs11Exception.throwIfNotOk("C_GetAttributeValue failed", rv);
    }

    public static byte[] getCertificateValue(Pkcs11 pkcs11, NativeLong session, NativeLong certificate)
            throws Pkcs11Exception {
        CK_ATTRIBUTE[] certificateValueTemplate = (CK_ATTRIBUTE[]) new CK_ATTRIBUTE().toArray(1);
        certificateValueTemplate[0].setAttr(CKA_VALUE, null, 0);
        getAttributeValues(pkcs11, session, certificate, certificateValueTemplate);
        return certificateValueTemplate[0].pValue.getByteArray(0, certificateValueTemplate[0].ulValueLen.intValue());
    }

    public static void printAllCertificatesInfo(Pkcs11 pkcs11, NativeLong session) throws Pkcs11Exception, IOException {
        CK_ATTRIBUTE[] certificateTemplate = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(2);
        certificateTemplate[0].setAttr(CKA_CLASS, CKO_CERTIFICATE);
        certificateTemplate[1].setAttr(CKA_TOKEN, true);

        NativeLong[] certificates = findObjects(pkcs11, session, certificateTemplate, 100);
        for (NativeLong certificate : certificates) {
            byte[] certificateValue = getCertificateValue(pkcs11, session, certificate);
			println(getCertificateInfo(certificateValue));
			
            CK_ATTRIBUTE[] publicKeyIdTemplate = (CK_ATTRIBUTE[]) new CK_ATTRIBUTE().toArray(1);
            publicKeyIdTemplate[0].setAttr(CKA_ID, null, 0);
            getAttributeValues(pkcs11, session, certificate, publicKeyIdTemplate);
            byte[] id = publicKeyIdTemplate[0].pValue.getByteArray(0, publicKeyIdTemplate[0].ulValueLen.intValue());
            println(new String(id));
        }
    }

    public static List<X509CertificateHolder> getAllCertificates(Pkcs11 pkcs11, NativeLong session) throws Pkcs11Exception, IOException {
    	List<X509CertificateHolder> certificates = new ArrayList<>();
    	CK_ATTRIBUTE[] certificateTemplate = (CK_ATTRIBUTE[]) (new CK_ATTRIBUTE()).toArray(2);
        certificateTemplate[0].setAttr(CKA_CLASS, CKO_CERTIFICATE);
        certificateTemplate[1].setAttr(CKA_TOKEN, true);

        NativeLong[] certIds = findObjects(pkcs11, session, certificateTemplate, 100);
        for (NativeLong certId : certIds) {
            byte[] certificateValue = getCertificateValue(pkcs11, session, certId);
            X509CertificateHolder certificate = new X509CertificateHolder(certificateValue);
            certificates.add(certificate);
        }
        return certificates;
    }

    /**
     * For simplicity, we find first object matching template,
     * in production you should generally check that only single object matches template.
     */
    public static NativeLong findFirstObject(Pkcs11 pkcs11, NativeLong session, CK_ATTRIBUTE[] template)
            throws Pkcs11Exception {
        NativeLong[] objects = findObjects(pkcs11, session, template, 1);
        if (objects.length < 1)
            throw new IllegalStateException("Object not found");
        return objects[0];
    }

    public static byte[] getFirstCertificateValue(Pkcs11 pkcs11, NativeLong session, CK_ATTRIBUTE[] certificateTemplate)
            throws Pkcs11Exception {
        return getCertificateValue(pkcs11, session, findFirstObject(pkcs11, session, certificateTemplate));
    }

    public static NativeLong findPrivateKeyByCertificateValue(Pkcs11 pkcs11, NativeLong session,
                                                              byte[] certificateValue)
            throws Pkcs11Exception, CertificateException {
        return findKeyPairByCertificateValue(pkcs11, session, certificateValue).privateKey;
    }

    public static KeyPair findKeyPairByCertificateValue(Pkcs11 pkcs11, NativeLong session, byte[] certificateValue)
            throws CertificateException, Pkcs11Exception {
        // Find corresponding public key handle for certificate
        println("Parsing X.509 certificate");
        X509Certificate x509certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certificateValue));

        final CK_ATTRIBUTE[] publicKeyValueTemplate;
        if (x509certificate.getPublicKey() instanceof RSAPublicKey) {
            RSAPublicKey publicKey = (RSAPublicKey) x509certificate.getPublicKey();

            println("Finding public key by modulus and exponent");
            publicKeyValueTemplate = (CK_ATTRIBUTE[]) new CK_ATTRIBUTE().toArray(4);
            publicKeyValueTemplate[0].setAttr(CKA_CLASS, CKO_PUBLIC_KEY);
            publicKeyValueTemplate[1].setAttr(CKA_KEY_TYPE, CKK_RSA);
            publicKeyValueTemplate[2].setAttr(CKA_MODULUS, dropPrecedingZeros(publicKey.getModulus().toByteArray()));
            publicKeyValueTemplate[3].setAttr(CKA_PUBLIC_EXPONENT, publicKey.getPublicExponent().toByteArray());
        } else { // gost
            println("Decode public key from ASN.1 structure");
            ASN1Sequence sequence = ASN1Sequence.getInstance(x509certificate.getPublicKey().getEncoded());
            byte[] publicKeyValue = ASN1OctetString.getInstance(((ASN1BitString) sequence.getObjectAt(1)).getOctets())
                    .getOctets();
            printHex("Public key value is:", publicKeyValue);

            println("Finding public key by value");
            publicKeyValueTemplate = (CK_ATTRIBUTE[]) new CK_ATTRIBUTE().toArray(2);
            publicKeyValueTemplate[0].setAttr(CKA_CLASS, CKO_PUBLIC_KEY);
            publicKeyValueTemplate[1].setAttr(CKA_VALUE, publicKeyValue);
        }

        NativeLong publicKey = findFirstObject(pkcs11, session, publicKeyValueTemplate);

        // Using public key we can find private key handle
        println("Getting public key ID");
        CK_ATTRIBUTE[] publicKeyIdTemplate = (CK_ATTRIBUTE[]) new CK_ATTRIBUTE().toArray(1);
        publicKeyIdTemplate[0].setAttr(CKA_ID, null, 0);
        getAttributeValues(pkcs11, session, publicKey, publicKeyIdTemplate);

        println("Finding private key by public key ID");
        CK_ATTRIBUTE[] privateKeyTemplate = (CK_ATTRIBUTE[]) new CK_ATTRIBUTE().toArray(2);
        privateKeyTemplate[0].setAttr(CKA_CLASS, CKO_PRIVATE_KEY);
        privateKeyTemplate[1].setAttr(publicKeyIdTemplate[0].type, publicKeyIdTemplate[0].pValue,
                publicKeyIdTemplate[0].ulValueLen);
        NativeLong privateKey = findFirstObject(pkcs11, session, privateKeyTemplate);

        return new KeyPair(publicKey, privateKey);
    }

    private static byte[] dropPrecedingZeros(byte[] array) {
        if (array.length == 0)
            return array;

        int numPrecedingZeros = 0;
        for (int i = 0; i < array.length; i++)
            if (array[i] != 0) {
                numPrecedingZeros = i;
                break;
            }
        return Arrays.copyOfRange(array, numPrecedingZeros, array.length);
    }
}
