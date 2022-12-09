package com.qwertovsky.cert_gost;

import java.awt.Color;
import java.awt.geom.AffineTransform;
import java.awt.geom.RectangularShape;
import java.awt.image.BufferedImage;
import java.awt.Rectangle;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.text.SimpleDateFormat;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Calendar;
import java.util.List;

import javax.imageio.ImageIO;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.common.PDStream;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType0Font;
import org.apache.pdfbox.pdmodel.graphics.form.PDFormXObject;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.apache.pdfbox.util.Matrix;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.X509CertificateHolder;

public class PdfSigner {
	
	private static final int SIGN_HEIGHT_DEFAULT = 85;
	private static final int SIGN_WIDTH_DEFAULT = 180;

	private final CmsSigner cmsSigner;
	private final X509CertificateHolder certificateHolder;
	
	private boolean visual;
	private int pageNumber;
	
	RectangularShape rect;
	
	private File imageFile;
	private float imageScale;
	
	private String location;
	private String reason;
	private Instant date;

	public static Builder builder(CmsSigner cmsSigner, X509CertificateHolder certificateHolder) {
		return new Builder(cmsSigner, certificateHolder);
	}
	
	public static class Builder {
		
		private final CmsSigner cmsSigner;
		private final X509CertificateHolder certificateHolder;
		
		private Clock clock = Clock.systemDefaultZone();
		
		private boolean visual;
		private int pageNumber = 0;
		
		private int x;
		private int y;
		private int width;
		private int height;
		
		private File imageFile;
		private float imageScale;
		
		private String location;
		private String reason;
		private Instant date;
		
		public Builder(CmsSigner cmsSigner, X509CertificateHolder certificateHolder) {
			this.cmsSigner = cmsSigner;
			this.certificateHolder = certificateHolder;
		}
		
		public PdfSigner build() throws IOException {
			PdfSigner pdfSigner = new PdfSigner(cmsSigner, certificateHolder);
			
			if (this.date == null) {
				pdfSigner.date = Instant.now(clock);
			} else {
				pdfSigner.date = this.date;
			}
			
			pdfSigner.reason = this.reason;
			pdfSigner.location = this.location;
			
			pdfSigner.visual = this.visual;
			pdfSigner.pageNumber = this.pageNumber;
			if (this.visual) {
				if (this.x <= 0 || this.y <= 0) {
					throw new IllegalArgumentException("Sign position is undefined");
				}
				if (this.imageFile != null) {
					if (!this.imageFile.exists()) {
						throw new IllegalArgumentException("Image file not found: " + this.imageFile);
					}
					pdfSigner.imageFile = this.imageFile;
					BufferedImage image = ImageIO.read(imageFile);
					if (this.imageScale > 0) {
						pdfSigner.imageScale = this.imageScale;
						this.width = Math.round(image.getWidth() * this.imageScale);
						this.height = Math.round(image.getHeight() * this.imageScale);
					} else {
						float imageScale = 1;
						if (this.width > 0 || this.height > 0) {
							float xScale = (float)this.width / image.getWidth();
							float yScale = (float)this.height / image.getHeight();
							imageScale = Math.min(xScale, yScale);
							if (imageScale == 0) {
								imageScale = Math.max(xScale, yScale);
							}
						}
						pdfSigner.imageScale = imageScale;
						System.out.println(imageScale);
						this.width = Math.round(image.getWidth() * imageScale);
						this.height = Math.round(image.getHeight() * imageScale);
					}
				} else {
					if (this.height == 0) {
						this.height = PdfSigner.SIGN_HEIGHT_DEFAULT;
					}
					if (this.width == 0) {
						this.width = PdfSigner.SIGN_WIDTH_DEFAULT;
					}
				}

				pdfSigner.rect = new Rectangle(this.x, this.y, this.width, this.height);
			}
			return pdfSigner;
		}

		/** 
		 * @param pageNumber 0-based
		 * @return
		 */
		public Builder pageNumber(int pageNumber) {
			this.pageNumber = pageNumber;
			return this;
		}
		
		public Builder location(String location) {
			this.location = location;
			return this;
		}
		
		public Builder reason(String reason) {
			this.reason = reason;
			return this;
		}

		public Builder date(Instant date) {
			this.date = date;
			return this;
		}

		public Builder visual(boolean visual) {
			this.visual = visual;
			return this;
		}
		
		public Builder x(int x) {
			this.x = x;
			return this;
		}
		
		public Builder y(int y) {
			this.y = y;
			return this;
		}
		
		public Builder width(int width) {
			this.width = width;
			return this;
		}
		
		public Builder height(int height) {
			this.height = height;
			return this;
		}
		
		public Builder imageFile(File imageFile) {
			this.imageFile = imageFile;
			return this;
		}

		public Builder imageScale(float imageScale) {
			this.imageScale = imageScale;
			return this;
		}

		public Builder clock(Clock clock) {
			this.clock = clock;
			return this;
		}
		
	}

	private PdfSigner(CmsSigner cmsSigner, X509CertificateHolder certificateHolder) {
		this.cmsSigner = cmsSigner;
		this.certificateHolder = certificateHolder;
	}

	public void sign(File fileToSig) throws Exception {
		
		String fileSignedName = fileToSig.getName().replaceAll(".pdf$","_signed.pdf");
		if (!fileSignedName.endsWith(".pdf")) {
			fileSignedName = fileToSig.getName() + "_signed.pdf";
		}
		
		File pdfFileSigned = new File(fileToSig.getParent(), fileSignedName);
		
        SignatureOptions signatureOptions = new SignatureOptions();
		try (
			PDDocument doc = PDDocument.load(fileToSig);
			FileOutputStream pdfFos = new FileOutputStream(pdfFileSigned);
			) {
		
			int accessPermissions = getMDPPermission(doc);
	        if (accessPermissions == 1) {
	            throw new IllegalStateException("No changes to the document are permitted due to DocMDP transform parameters dictionary");
	        }
	        
	        PDSignature pdfSignature = new PDSignature();

            // Optional: certify
            // can be done only if version is at least 1.5 and if not already set
            // doing this on a PDF/A-1b file fails validation by Adobe preflight (PDFBOX-3821)
            // PDF/A-1b requires PDF version 1.4 max, so don't increase the version on such files.
            if (doc.getVersion() >= 1.5f && accessPermissions == 0)
            {
                setMDPPermission(doc, pdfSignature, 2);
            }
            
            
	        pdfSignature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
	        pdfSignature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
	        X500Name x500Name = certificateHolder.getSubject();
	        RDN cn = x500Name.getRDNs(BCStyle.CN)[0];
	        String signerName = IETFUtils.valueToString(cn.getFirst().getValue());
	        pdfSignature.setName(signerName);
	        pdfSignature.setLocation(this.location);
	        pdfSignature.setReason(this.reason);
			Calendar calendar = Calendar.getInstance();
			calendar.setTimeInMillis(date.toEpochMilli());
			pdfSignature.setSignDate(calendar);
	        
			// visualization
			if (visual) {
		        signatureOptions.setVisualSignature(createVisualSignatureTemplate(certificateHolder, doc, pageNumber, this.rect, date));
		        signatureOptions.setPage(pageNumber);
			}
	        doc.addSignature(pdfSignature, null, signatureOptions);
	        
	        ExternalSigningSupport externalSigning = doc.saveIncrementalForExternalSigning(pdfFos);
	        InputStream isToSign = externalSigning.getContent();
	        
	        byte[] sign = cmsSigner.sign(isToSign, date, false);
	        externalSigning.setSignature(sign);
        
		}
		signatureOptions.close();
		
		System.out.println("Pdf: " + Verify.verifyPdf(pdfFileSigned));
	}
	
	/**
     * Get the access permissions granted for this document in the DocMDP transform parameters
     * dictionary. Details are described in the table "Entries in the DocMDP transform parameters
     * dictionary" in the PDF specification.
     *
     * @param doc document.
     * @return the permission value. 0 means no DocMDP transform parameters dictionary exists. Other
     * return values are 1, 2 or 3. 2 is also returned if the DocMDP transform parameters dictionary
     * is found but did not contain a /P entry, or if the value is outside the valid range.
     */
    private int getMDPPermission(PDDocument doc)
    {
        COSDictionary permsDict = doc.getDocumentCatalog().getCOSObject()
                .getCOSDictionary(COSName.PERMS);
        if (permsDict != null)
        {
            COSDictionary signatureDict = permsDict.getCOSDictionary(COSName.DOCMDP);
            if (signatureDict != null)
            {
                COSArray refArray = signatureDict.getCOSArray(COSName.REFERENCE);
                if (refArray != null)
                {
                    for (int i = 0; i < refArray.size(); ++i)
                    {
                        COSBase base = refArray.getObject(i);
                        if (base instanceof COSDictionary)
                        {
                            COSDictionary sigRefDict = (COSDictionary) base;
                            if (COSName.DOCMDP.equals(sigRefDict.getDictionaryObject(COSName.TRANSFORM_METHOD)))
                            {
                                base = sigRefDict.getDictionaryObject(COSName.TRANSFORM_PARAMS);
                                if (base instanceof COSDictionary)
                                {
                                    COSDictionary transformDict = (COSDictionary) base;
                                    int accessPermissions = transformDict.getInt(COSName.P, 2);
                                    if (accessPermissions < 1 || accessPermissions > 3)
                                    {
                                        accessPermissions = 2;
                                    }
                                    return accessPermissions;
                                }
                            }
                        }
                    }
                }
            }
        }
        return 0;
    }

	/**
     * Set the "modification detection and prevention" permissions granted for this document in the
     * DocMDP transform parameters dictionary. Details are described in the table "Entries in the
     * DocMDP transform parameters dictionary" in the PDF specification.
     *
     * @param doc The document.
     * @param signature The signature object.
     * @param accessPermissions The permission value (1, 2 or 3).
     *
     * @throws IOException if a signature exists.
     */
    private void setMDPPermission(PDDocument doc, PDSignature signature, int accessPermissions)
            throws IOException {
        for (PDSignature sig : doc.getSignatureDictionaries()) {
            // "Approval signatures shall follow the certification signature if one is present"
            // thus we don't care about timestamp signatures
            if (COSName.DOC_TIME_STAMP.equals(sig.getCOSObject().getItem(COSName.TYPE)))
            {
                continue;
            }
            if (sig.getCOSObject().containsKey(COSName.CONTENTS))
            {
                throw new IOException("DocMDP transform method not allowed if an approval signature exists");
            }
        }

        COSDictionary sigDict = signature.getCOSObject();

        // DocMDP specific stuff
        COSDictionary transformParameters = new COSDictionary();
        transformParameters.setItem(COSName.TYPE, COSName.TRANSFORM_PARAMS);
        transformParameters.setInt(COSName.P, accessPermissions);
        transformParameters.setName(COSName.V, "1.2");
        transformParameters.setNeedToBeUpdated(true);

        COSDictionary referenceDict = new COSDictionary();
        referenceDict.setItem(COSName.TYPE, COSName.SIG_REF);
        referenceDict.setItem(COSName.TRANSFORM_METHOD, COSName.DOCMDP);
        referenceDict.setItem(COSName.DIGEST_METHOD, COSName.getPDFName("SHA1"));
        referenceDict.setItem(COSName.TRANSFORM_PARAMS, transformParameters);
        referenceDict.setNeedToBeUpdated(true);

        COSArray referenceArray = new COSArray();
        referenceArray.add(referenceDict);
        sigDict.setItem(COSName.REFERENCE, referenceArray);
        referenceArray.setNeedToBeUpdated(true);

        // Catalog
        COSDictionary catalogDict = doc.getDocumentCatalog().getCOSObject();
        COSDictionary permsDict = new COSDictionary();
        catalogDict.setItem(COSName.PERMS, permsDict);
        permsDict.setItem(COSName.DOCMDP, signature);
        catalogDict.setNeedToBeUpdated(true);
        permsDict.setNeedToBeUpdated(true);
    }
	
	// create a template PDF document with empty signature and return it as a stream.
    private InputStream createVisualSignatureTemplate(X509CertificateHolder cert, PDDocument srcDoc,
    		int pageNum, RectangularShape pagePlace, Instant date)
    		throws Exception {
        try (PDDocument doc = new PDDocument()) {
            PDPage page = new PDPage(srcDoc.getPage(pageNum).getMediaBox());
            doc.addPage(page);
            PDAcroForm acroForm = new PDAcroForm(doc);
            doc.getDocumentCatalog().setAcroForm(acroForm);
            PDSignatureField signatureField = new PDSignatureField(acroForm);
            PDAnnotationWidget widget = signatureField.getWidgets().get(0);
            List<PDField> acroFormFields = acroForm.getFields();
            acroForm.setSignaturesExist(true);
            acroForm.setAppendOnly(true);
            acroForm.getCOSObject().setDirect(true);
            acroFormFields.add(signatureField);

	        PDRectangle rect = createSignatureRectangle(doc, pagePlace);
            widget.setRectangle(rect);

            // from PDVisualSigBuilder.createHolderForm()
            PDStream stream = new PDStream(doc);
            PDFormXObject form = new PDFormXObject(stream);
            PDResources res = new PDResources();
            form.setResources(res);
            form.setFormType(1);
            PDRectangle bbox = new PDRectangle(rect.getWidth(), rect.getHeight());
            float height = bbox.getHeight();
            Matrix initialScale = null;
            switch (srcDoc.getPage(pageNum).getRotation()) {
                case 90:
                    form.setMatrix(AffineTransform.getQuadrantRotateInstance(1));
                    initialScale = Matrix.getScaleInstance(bbox.getWidth() / bbox.getHeight(), bbox.getHeight() / bbox.getWidth());
                    height = bbox.getWidth();
                    break;
                case 180:
                    form.setMatrix(AffineTransform.getQuadrantRotateInstance(2)); 
                    break;
                case 270:
                    form.setMatrix(AffineTransform.getQuadrantRotateInstance(3));
                    initialScale = Matrix.getScaleInstance(bbox.getWidth() / bbox.getHeight(), bbox.getHeight() / bbox.getWidth());
                    height = bbox.getWidth();
                    break;
                case 0:
                default:
                    break;
            }
            form.setBBox(bbox);

            // from PDVisualSigBuilder.createAppearanceDictionary()
            PDAppearanceDictionary appearance = new PDAppearanceDictionary();
            appearance.getCOSObject().setDirect(true);
            PDAppearanceStream appearanceStream = new PDAppearanceStream(form.getCOSObject());
            appearance.setNormalAppearance(appearanceStream);
            widget.setAppearance(appearance);

            try (PDPageContentStream cs = new PDPageContentStream(doc, appearanceStream)) {
                // for 90Â° and 270Â° scale ratio of width / height
                // not really sure about this
                // why does scale have no effect when done in the form matrix???
                if (initialScale != null) {
                    cs.transform(initialScale);
                }

                
                Color color = new Color(102, 0, 255);
				cs.setStrokingColor(color);
				cs.setLineWidth(3);
                cs.addRect(0, 0, rect.getWidth(), rect.getHeight());
                cs.closeAndStroke();

                if (this.imageFile != null) {
                    // show background image
                    // save and restore graphics if the image is too large and needs to be scaled
                    cs.saveGraphicsState();
                    cs.transform(Matrix.getScaleInstance(this.imageScale, this.imageScale));
                    PDImageXObject img = PDImageXObject.createFromFileByExtension(this.imageFile, doc);
                    cs.drawImage(img, 0, 0);
                    cs.restoreGraphicsState();
                } else {
	                // show text
	                PDFont font = PDType0Font.load(doc, this.getClass().getResourceAsStream("/arial.ttf"));
	                float fontSize = 8;
	                float leading = fontSize * 1.2f;
	                cs.beginText();
	                cs.setFont(font, fontSize);
	                cs.setNonStrokingColor(color);
	                cs.newLineAtOffset(fontSize, height - leading);
	                cs.setLeading(leading);
	
	                // https://stackoverflow.com/questions/2914521/
	                X500Name x500Name = cert.getSubject();
	                RDN cn = x500Name.getRDNs(BCStyle.CN)[0];
	                String name = IETFUtils.valueToString(cn.getFirst().getValue());
	                RDN snilsRdn = x500Name.getRDNs(new ASN1ObjectIdentifier("1.2.643.100.3"))[0];
	                String snils = IETFUtils.valueToString(snilsRdn.getFirst().getValue());
	                RDN issuerCn = cert.getIssuer().getRDNs(BCStyle.CN)[0];
					String issuer = issuerCn.getFirst().getValue().toString();
					SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
					String validFrom = dateFormat.format(cert.getNotBefore());
					String validTo = dateFormat.format(cert.getNotAfter());
					String signDate = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mmZ").withZone(ZoneId.systemDefault()).format(date);
	
	                cs.showText("Документ подписан электронной подписью");
	                cs.newLine();
	                cs.showText("Дата подписания: " + signDate);
	                cs.newLine();
	                cs.showText("Сведения о сертификате ЭП:");
	                cs.newLine();
	                cs.showText(String.format("%034x", cert.getSerialNumber()).toUpperCase());
	                cs.newLine();
	                cs.showText("Владелец: " + name);
	                cs.newLine();
	                cs.showText("СНИЛС: " + snils);
	                cs.newLine();
	                cs.showText("Издатель: " + issuer);
	                cs.newLine();
	                cs.showText("Действителен с " + validFrom + " по " + validTo);
	                cs.endText();
                }
            }

            // no need to set annotations and /P entry

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            doc.save(baos);
            return new ByteArrayInputStream(baos.toByteArray());
        }
    }
    
    private static PDRectangle createSignatureRectangle(PDDocument doc, RectangularShape humanRect)
    {
        float x = (float) humanRect.getX();
        float y = (float) humanRect.getY();
        float width = (float) humanRect.getWidth();
        float height = (float) humanRect.getHeight();
        PDPage page = doc.getPage(0);
        PDRectangle pageRect = page.getCropBox();
        PDRectangle rect = new PDRectangle();
        // signing should be at the same position regardless of page rotation.
        switch (page.getRotation())
        {
            case 90:
                rect.setLowerLeftY(x);
                rect.setUpperRightY(x + width);
                rect.setLowerLeftX(y);
                rect.setUpperRightX(y + height);
                break;
            case 180:
                rect.setUpperRightX(pageRect.getWidth() - x);
                rect.setLowerLeftX(pageRect.getWidth() - x - width);
                rect.setLowerLeftY(y);
                rect.setUpperRightY(y + height);
                break;
            case 270:
                rect.setLowerLeftY(pageRect.getHeight() - x - width);
                rect.setUpperRightY(pageRect.getHeight() - x);
                rect.setLowerLeftX(pageRect.getWidth() - y - height);
                rect.setUpperRightX(pageRect.getWidth() - y);
                break;
            case 0:
            default:
                rect.setLowerLeftX(x);
                rect.setUpperRightX(x + width);
                rect.setLowerLeftY(pageRect.getHeight() - y - height);
                rect.setUpperRightY(pageRect.getHeight() - y);
                break;
        }
        return rect;
    }
}
