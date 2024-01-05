# Program to sign file with GOST algorithm

It uses the Bouncy Castle algorithm implementation or the Rutoken implementation on token.

# Usage

## Sign file with token. Result will be file.pdf.sig. Source file will be attached.
```
java -jar gost_sign.jar -i file.pdf --pkcs-id test --pkcs-library /usr/lib/librtpkcs11ecp.so -d 2022-12-31T23:59:59+03:00
```

Options:

option key | argument | default | description
---|---|---|---
-d,--date | text | now | Date of sign (use ISO 8601 format)
--detached | | | Don't include input document to SIG file
-h,--help | | | Print help
-i,--input | file | error | File to sign
--pkcs-id | text | | Certificate id on token. Private and public keys should share this id. pkcs-tool uses ASCII encoded version (74657374 = test).
--cert-file | text | | Insurer certificate on disk (DER format). The program looks for keys according this certificate
--pkcs-library | file | | Path to PKCS library

Write certificate on token:

```
pkcs11-tool --module /usr/lib/librtpkcs11ecp.so --type cert --login --write-object test.pem --id 74657374
```

Make DER certificate from PEM:

```
openssl x509 -in certificate.pem -out certificate.der -outform DER 
```

## Add signature to PDF document
```
java -jar gost_sign.jar -i file.pdf --pkcs-id test --pkcs-library /usr/lib/librtpkcs11ecp.so --pdf --pdf-visual --pdf-position-x 100 --pdf-position-y 100
```

PDf options:
option key | argument | default | description
---|---|---|---
--pdf | | | Signatue is inside pdf file
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
--cert-chain | file | | Certificate chain files. Option may be defined more than once. The first is public certificate for private key.
--pfx-alias | text | | Key alias in pfx store
--pfx-file | file | | PFX key store file

## Verify signature
```
java -jar gost_sign.jar --verify -i file.pdf --sig-file file.pdf.sig
```

## Verify pdf

If the signature is inside PDF.
```
java -jar gost_sign.jar --verify -i file.pdf --pdf
```


    


