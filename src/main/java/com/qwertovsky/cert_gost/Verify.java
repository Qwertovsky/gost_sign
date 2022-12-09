package com.qwertovsky.cert_gost;

import java.io.File;
import java.io.FileInputStream;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;

public class Verify {

	public static void main(String... args) throws Exception {
		
		Options clOptions = createOptions();
		
		CommandLineParser clParser = DefaultParser.builder()
				.setAllowPartialMatching(false)
				.setStripLeadingAndTrailingQuotes(true)
				.build();
		
		CommandLine commandLine = null;
		try {
			commandLine = clParser.parse(clOptions , args);
		} catch (Exception e) {
			printHelp(clOptions);
			return;
		}
		
		if (commandLine.hasOption(CliOptions.HELP)) {
			printHelp(clOptions);
			return;
		}

		String filePath = commandLine.getOptionValue(CliOptions.INPUT);
		if (filePath == null) {
			System.err.println("File input is required");
			printHelp(clOptions);
			return;
		}
		File inputFile = new File(filePath);
		if (!inputFile.exists()) {
			System.err.println("File input not found");
			printHelp(clOptions);
			return;
		}
		
		Security.setProperty("crypto.policy", "unlimited");
	    Provider bcProvider = new BouncyCastleProvider();
		Security.addProvider(bcProvider);

		boolean pdfAttached = commandLine.hasOption(CliOptions.PDF);
		if (pdfAttached) {
			boolean verifyPdf = verifyPdf(inputFile);
			System.out.println("Pdf: " + verifyPdf);
		} else {
			FileInputStream is = new FileInputStream(inputFile);
			byte[] data = is.readAllBytes();
			is.close();
			
			String sigPath = commandLine.getOptionValue(CliOptions.SIG_FILE);
			if (sigPath == null) {
				sigPath = inputFile.getAbsolutePath().concat(".sig");
			}
			FileInputStream sigIs = new FileInputStream(new File(sigPath));
			byte[] sig = sigIs.readAllBytes();
			sigIs.close();
			
			boolean verifyDetachedData = verifyDetachedData(sig, data);
			System.out.println("Sig: " + verifyDetachedData);
		}
	}

	public static boolean verifyDetached(File file) throws Exception {
		FileInputStream is = new FileInputStream(file);
		byte[] data = is.readAllBytes();
		is.close();
		
		FileInputStream sigIs = new FileInputStream(new File(file.getParent(), file.getName().concat(".sig")));
		byte[] sig = sigIs.readAllBytes();
		sigIs.close();
		
		return verifyDetachedData(sig, data);
	}
	
	public static boolean verifyDetachedData(byte[] cmsSignedData, byte[] data)
			throws GeneralSecurityException, OperatorCreationException, CMSException {
		CMSSignedData signedData = new CMSSignedData(new CMSProcessableByteArray(data), cmsSignedData);
		Store<X509CertificateHolder> certStore = signedData.getCertificates();
		SignerInformationStore signerInformationStore = signedData.getSignerInfos();
		Collection<SignerInformation> signers = signerInformationStore.getSigners();
		Iterator<SignerInformation> it = signers.iterator();
		while (it.hasNext()) {
			SignerInformation signer = (SignerInformation) it.next();
			Collection<X509CertificateHolder> certCollection = certStore.getMatches(signer.getSID());
			Iterator<X509CertificateHolder> certIt = certCollection.iterator();
			X509CertificateHolder cert = (X509CertificateHolder) certIt.next();
			if (!signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert))) {
				return false;
			}
		}
		return true;
	}
	
	public static boolean verifyPdf(File signedFile) throws Exception {
		boolean isSignature = false;
        // We load the signed document.
        PDDocument document = PDDocument.load(signedFile);
        List<PDSignature> signatureDictionaries = document.getSignatureDictionaries();
        // Then we validate signatures one at the time.
        for (PDSignature signatureDictionary : signatureDictionaries) {
            // NOTE that this code currently supports only "adbe.pkcs7.detached", the most common signature /SubFilter anyway.
            byte[] signatureContent = signatureDictionary.getContents(new FileInputStream(signedFile));
            byte[] signedContent = signatureDictionary.getSignedContent(new FileInputStream(signedFile));
            // Now we construct a PKCS #7 or CMS.
            CMSProcessable cmsProcessableInputStream = new CMSProcessableByteArray(signedContent);
            CMSSignedData cmsSignedData = new CMSSignedData(cmsProcessableInputStream, signatureContent);
            SignerInformationStore signerInformationStore = cmsSignedData.getSignerInfos();
            Collection<SignerInformation> signers = signerInformationStore.getSigners();
            Store<X509CertificateHolder> certs = cmsSignedData.getCertificates();
            Iterator<SignerInformation> it = signers.iterator();
            while (it.hasNext()) {
                SignerInformation signer = (SignerInformation) it.next();
                Collection<X509CertificateHolder> certificates = certs.getMatches(signer.getSID());
                Iterator<X509CertificateHolder> certIt = certificates.iterator();
                X509CertificateHolder signerCertificate = (X509CertificateHolder) certIt.next();
                // And here we validate the document signature.
                SignerInformationVerifier signerInformationVerifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(signerCertificate);
                if (signer.verify(signerInformationVerifier)) {
                    System.out.println("PDF signature verification is correct.");
                    isSignature = true;
                } else {
                    System.out.println("PDF signature verification failed.");
                    return false;
                }
            }
        }
        return isSignature;
	}
	
	static Options createOptions() {
		Options clOptions = new Options();
		
		Option verifyOption = Option.builder()
				.longOpt(CliOptions.VERIFY)
				.desc("Verify. Try --" + CliOptions.VERIFY + " --" + CliOptions.HELP)
				.build();
		clOptions.addOption(verifyOption);
		
		Option inOption = Option.builder()
				.option("i")
				.longOpt(CliOptions.INPUT)
				.argName("./file_path.pdf")
				.desc("File to sign")
				.hasArg(true)
				.build();
		clOptions.addOption(inOption);
		
		Option helpOption = Option.builder()
				.option("h")
				.longOpt(CliOptions.HELP)
				.desc("Print help")
				.build();
		clOptions.addOption(helpOption);
		
		Option sigFileOption = Option.builder()
				.longOpt(CliOptions.SIG_FILE)
				.argName("./file_path.sig")
				.desc("Detached signature file")
				.hasArg(true)
				.build();
		clOptions.addOption(sigFileOption);
		
		Option pdfAttachedOption = Option.builder()
				.longOpt(CliOptions.PDF)
				.desc("Signatue is inside pdf file")
				.hasArg(false)
				.build();
		clOptions.addOption(pdfAttachedOption);
		
		return clOptions;
	}
	
	private static void printHelp(Options clOptions) {
		HelpFormatter formatter = new HelpFormatter();
		formatter.setWidth(120);
		formatter.printHelp("java -jar <jarfile>", clOptions, true);
	}
}
