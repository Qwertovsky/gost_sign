# Program to sign file with GOST algorithm

It uses the Bouncy Castle algorithm implementation or the Rutoken implementation on token.

# Usage

## Sign file with token.

Result will be in file `file.pdf.sig`. Detached by default.
```
java -jar gost_sign.jar -i file.pdf --pkcs-id test --pkcs-library /usr/lib/librtpkcs11ecp.so -d 2022-12-31T23:59:59+03:00
```

Options:

option key | argument | default | description
---|---|---|---
-d,--date | text | now | Date of sign (use ISO 8601 format)
--attached | | | Include input document to SIG file
-h,--help | | | Print help
-i,--input | file | error | File to sign
--pkcs-id | text | | Certificate id on token. Private and public keys should share this id. pkcs-tool uses ASCII encoded version (74657374 = test).
--cert-file | text | | Insurer certificate on disk (DER or Base64 with boundaries). The program looks for keys according this certificate
--pkcs-library | file | | Path to PKCS library


## Sign file with private key in PKCS#12 container on disk
```
java -jar gost_sign.jar -i file.pdf --pfx-file private.pfx --pfx-alias test
```

## Create PFX container
```
java -jar gost_sign.jar --pfx-create --pfx-alias test --key-file private.key --cert-chain private.crt --cert-chain issuer.crt --cert-chain root.crt --pfx-file output.pfx
```
Options:
option key | argument | default | description
---|---|---|---
--pfx-create | | | Create pfx container. Try --pfx-create --help
--key-file | file | | Private key file
--cert-chain | file | | Certificate chain files (DER or Base64 with boundaries). Option may be defined more than once. The first is public certificate for private key.
--pfx-alias | text | | Key alias in pfx store
--pfx-file | file | | PFX key store file

## Verify signature
```
java -jar gost_sign.jar --verify -i file.pdf --sig-file file.pdf.sig
```

## Add signature to PDF document
```
java -jar gost_sign.jar -i file.pdf --pkcs-id test --pkcs-library /usr/lib/librtpkcs11ecp.so --pdf --pdf-visual --pdf-position-x 100 --pdf-position-y 100
```

PDF options:
option key | argument | default | description
---|---|---|---
--pdf | | | Signature is inside pdf file
--pdf-visual | | | Make visual field for sign. Text data from certificate or use your image
--pdf-page | number | 1 |Page for sign visualization. The fist page is 1
--pdf-position-x | number | error | Horizontal position on page in pixels
--pdf-position-y | number | error | Vertical position on page in pixels
--pdf-height | number | 85 | Sign field height in pixels
--pdf-width | number | 180 | Sign field width in pixels
--pdf-image | file | | Image to create visual pdf sign
--pdf-image-scale | | calculated | Image scale
--location | | | PDF sign attribute
--reason | | | PDF sign attribute

## Verify pdf

If the signature is inside PDF.
```
java -jar gost_sign.jar --verify -i file.pdf --pdf
```

## Write certificate on token:

```
pkcs11-tool --module /usr/lib/librtpkcs11ecp.so --type cert --login --write-object test.pem --id 74657374
```

## Make DER certificate from PEM:

```
openssl x509 -in certificate.pem -out certificate.der -outform DER 
```
    


