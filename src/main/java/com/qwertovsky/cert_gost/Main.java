package com.qwertovsky.cert_gost;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import java.time.Instant;
import java.util.Properties;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.qwertovsky.cert_gost.store.GostStore;
import com.qwertovsky.cert_gost.store.PfxStore;
import com.qwertovsky.cert_gost.store.PkcsStore;
import com.qwertovsky.cert_gost.store.StoreType;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;

import ru.rutoken.pkcs11jna.Pkcs11;
import ru.rutoken.pkcs11jna.Pkcs11Constants;
import ru.rutoken.pkcs11jna.RtPkcs11;
import ru.rutoken.samples.pkcs11utils.Pkcs11Operations;

public class Main {

	public static void main(String[] args) throws Exception {
		
		Options cliOptions = createOptions();

		CommandLineParser clParser = DefaultParser.builder()
				.setAllowPartialMatching(false)
				.setStripLeadingAndTrailingQuotes(true)
				.build();
		
		CommandLine commandLine = null;
		try {
			commandLine = clParser.parse(cliOptions , args);
		} catch (Exception e) {
			printHelp(cliOptions);
			return;
		}
		
		if (commandLine.hasOption(CliOptions.PFX_CREATE)) {
			PfxCreator.main(args);
			return;
		}
		
		if (commandLine.hasOption(CliOptions.VERIFY)) {
			Verify.main(args);
			return;
		}

		if (commandLine.hasOption(CliOptions.HELP)) {
			printHelp(cliOptions);
			return;
		}

		String fileToSigPath = commandLine.getOptionValue(CliOptions.INPUT);
		if (fileToSigPath == null) {
			System.err.println("File input is required");
			printHelp(cliOptions);
			return;
		}
		File fileToSig = new File(fileToSigPath);
		if (!fileToSig.exists()) {
			System.err.println("File input not found");
			return;
		}
		
		Security.setProperty("crypto.policy", "unlimited");
		
		final String configName = "pkcs11.cfg";
	    Provider bcProvider = new BouncyCastleProvider();
		Security.addProvider(bcProvider);
		
	    
		
		Pkcs11 pkcs11 = null;
        NativeLong pkcsSession = null;
        try {
	        GostStore store = null;
	        
	        StoreType storeType = null;
		    if (commandLine.hasOption(CliOptions.PFX_FILE)) {
		    	storeType = StoreType.PFX;
		    } else if (commandLine.hasOption(CliOptions.PKCS_ID) || commandLine.hasOption(CliOptions.CERT_FILE)) {
		    	storeType = StoreType.PKCS11;
		    }
		    if (storeType == null) {
		    	System.err.println("Keystore is not specified");
		    	printHelp(cliOptions);
		    	return;
		    }
	        
	        System.out.println("Enter PIN:");
			char[] pinChars = System.console().readPassword();

	        switch (storeType) {
		        case PKCS11: {
		        	String libraryPath = commandLine.getOptionValue(CliOptions.PKCS_LIBRARY);
		        	
		        	if (!commandLine.hasOption(CliOptions.PKCS_LIBRARY)) {
			        	try (FileInputStream fis = new FileInputStream(new File(configName))) {
			            	Properties props = new Properties();
			            	props.load(fis);
			                libraryPath = props.getProperty("library");
			        	}
		        	}
		        	pkcs11 = Native.load(libraryPath, RtPkcs11.class);
		            pkcsSession = new NativeLong(Pkcs11Constants.CK_INVALID_HANDLE);
		            Pkcs11Operations.initializePkcs11AndLoginToFirstToken(pkcs11, pkcsSession, String.valueOf(pinChars).getBytes());
		            String certId = commandLine.getOptionValue(CliOptions.PKCS_ID);
		            if (certId != null) {
		            	store = new PkcsStore(pkcs11, pkcsSession, certId);
		            } else {
		            	String certPath = commandLine.getOptionValue(CliOptions.CERT_FILE);
		            	store = new PkcsStore(pkcs11, pkcsSession, new File(certPath));
		            }
		            
		            break;
		        }
		        case PFX: {
		        	String pfxPath = commandLine.getOptionValue(CliOptions.PFX_FILE);
		        	File pfxFile = new File(pfxPath);
		        	String alias = commandLine.getOptionValue(CliOptions.PFX_ALIAS);
		        	store = new PfxStore(pfxFile, alias, pinChars);
		        	break;
		        }
	        }
            
            CmsSigner cmsSigner = new CmsSigner(store);
        
            Instant date = null;
    		if (commandLine.hasOption(CliOptions.DATE)) {
    			date = Instant.parse(commandLine.getOptionValue(CliOptions.DATE));
    		}

            System.out.println("Creating CMS signature as SIG file");
            File fileSig = new File(fileToSig.getParent(), fileToSig.getName() + ".sig");
	        try (FileInputStream fis = new FileInputStream(fileToSig);
	        		FileOutputStream sigFos = new FileOutputStream(fileSig);) {
		        byte[] sign = cmsSigner.sign(fis, date, commandLine.hasOption(CliOptions.ATTACHED));
		        sigFos.write(sign);
	        }
	        System.out.println("Sig: " + Verify.verifyDetached(fileToSig));
	        
	        boolean pdfAttached = commandLine.hasOption(CliOptions.PDF);
			if (pdfAttached) {
				System.out.println("Creating PDF signature");
				
				signPdf(commandLine, store, cmsSigner, fileToSig, date);
			}
		} catch (Exception e) {
            System.err.println("Program has failed:");
            e.printStackTrace();
        } finally {
        	if (pkcsSession != null) {
        		Pkcs11Operations.logoutAndFinalizePkcs11Library(pkcs11, pkcsSession);
        	}
        }
			
	}

	private static void signPdf(CommandLine commandLine, GostStore store, CmsSigner cmsSigner, File fileToSig, Instant date)
			throws IOException, Exception {
		String reason = commandLine.getOptionValue(CliOptions.REASON);
		String location = commandLine.getOptionValue(CliOptions.LOCATION);
		boolean pdfVisual = commandLine.hasOption(CliOptions.PDF_VISUAL);
		int pdfPage = Integer.parseInt(commandLine.getOptionValue(CliOptions.PDF_PAGE, "1"));
		int pdfPositionX = Integer.parseInt(commandLine.getOptionValue(CliOptions.PDF_POSITION_X, "10"));
		int pdfPositionY = Integer.parseInt(commandLine.getOptionValue(CliOptions.PDF_POSITION_Y, "10"));
		int pdfWidth = Integer.parseInt(commandLine.getOptionValue(CliOptions.PDF_WIDTH, "0"));
		int pdfHeight = Integer.parseInt(commandLine.getOptionValue(CliOptions.PDF_HEIGHT, "0"));
		String imagePath = commandLine.getOptionValue(CliOptions.PDF_IMAGE);
		float imageScale = Float.parseFloat(commandLine.getOptionValue(CliOptions.PDF_IMAGE_SCALE, "0"));
		PdfSigner.Builder pdfSignerBuilder = PdfSigner.builder(cmsSigner, store.getCertificateHolder())
				.date(date)
				.reason(reason)
				.location(location)
				.visual(pdfVisual)
				.pageNumber(pdfPage - 1)
				.x(pdfPositionX)
				.y(pdfPositionY)
				.width(pdfWidth)
				.height(pdfHeight);
		if (imagePath != null) {
			pdfSignerBuilder = pdfSignerBuilder
					.imageFile(new File(imagePath))
					.imageScale(imageScale);
		}
		PdfSigner pdfSigner = pdfSignerBuilder.build();
		pdfSigner.sign(fileToSig);
	}

	private static Options createOptions() {
		Options cliOptions = new Options();
		
		Option helpOption = Option.builder()
				.option("h")
				.longOpt(CliOptions.HELP)
				.desc("Print help")
				.build();
		cliOptions.addOption(helpOption);
		
		Option inOption = Option.builder()
				.option("i")
				.longOpt(CliOptions.INPUT)
				.argName("./file_path.pdf")
				.desc("File to sign")
				.hasArg(true)
				.build();
		cliOptions.addOption(inOption);
		
		Option dateOption = Option.builder()
				.option("d")
				.longOpt(CliOptions.DATE)
				.argName("2022-12-31T23:59:59+03:00")
				.desc("Date of sign (use ISO 8601 format)")
				.hasArg(true)
				.build();
		cliOptions.addOption(dateOption);
		
		Option pkcsIdOption = Option.builder()
				.longOpt(CliOptions.PKCS_ID)
				.argName("cert id on token")
				.desc("Certificate id on token. Private and public keys should share this id."
						+ " id is expected in native encoding. pkcs11-tool uses ASCII encoding")
				.hasArg(true)
				.build();
		cliOptions.addOption(pkcsIdOption);
		
		Option certFileOption = Option.builder()
				.longOpt(CliOptions.CERT_FILE)
				.argName("cert file on disk")
				.desc("Insurer certificate DER file. Private and public keys for this certificate should be on token")
				.hasArg(true)
				.build();
		cliOptions.addOption(certFileOption);
		
		Option pkcsLibraryOption = Option.builder()
				.longOpt(CliOptions.PKCS_LIBRARY)
				.argName("/usr/lib/library_path.so")
				.desc("Path to PKCS library")
				.hasArg(true)
				.build();
		cliOptions.addOption(pkcsLibraryOption);
		
		Option pfxFileOption = Option.builder()
				.longOpt(CliOptions.PFX_FILE)
				.argName("./file_path.pfx")
				.desc("PFX key store file")
				.hasArg(true)
				.build();
		cliOptions.addOption(pfxFileOption);
		
		Option pfxAliasOption = Option.builder()
				.longOpt(CliOptions.PFX_ALIAS)
				.argName("alias")
				.desc("Key alias in pfx store")
				.hasArg(true)
				.build();
		cliOptions.addOption(pfxAliasOption);
		
		Option detachedOption = Option.builder()
				.longOpt(CliOptions.ATTACHED)
				.desc("Include input document to SIG file")
				.build();
		cliOptions.addOption(detachedOption);
		
		OptionGroup pdfOptionGroup = new OptionGroup();
		pdfOptionGroup.setRequired(false);
		cliOptions.addOptionGroup(pdfOptionGroup);
		
		Option pdfAttachedOption = Option.builder()
				.longOpt(CliOptions.PDF)
				.desc("Create sign inside pdf file")
				.hasArg(false)
				.build();
		cliOptions.addOption(pdfAttachedOption);
		
		Option locationOption = Option.builder()
				.longOpt(CliOptions.LOCATION)
				.hasArg(true)
				.argName("City")
				.desc("PDF sign attribute")
				.build();
		cliOptions.addOption(locationOption);
		pdfOptionGroup.addOption(locationOption);
		
		Option reasonOption = Option.builder()
				.longOpt(CliOptions.REASON)
				.hasArg(true)
				.argName("Accept document")
				.desc("PDF sign attribute")
				.build();
		cliOptions.addOption(reasonOption);
		pdfOptionGroup.addOption(reasonOption);
		
		
		Option pdfVisualOption = Option.builder()
				.longOpt(CliOptions.PDF_VISUAL)
				.hasArg(false)
				.desc("Make visual field for sign")
				.build();
		cliOptions.addOption(pdfVisualOption);
		pdfOptionGroup.addOption(pdfVisualOption);
		
		OptionGroup pdfVisualOG = new OptionGroup();
		pdfVisualOG.setRequired(false);
		cliOptions.addOptionGroup(pdfVisualOG);
		
		Option pdfPageOption = Option.builder()
				.longOpt(CliOptions.PDF_PAGE)
				.hasArg(true)
				.desc("Page for sign visualization. The fist page is 1")
				.build();
		cliOptions.addOption(pdfPageOption);
		pdfVisualOG.addOption(pdfPageOption);
		
		Option pdfPositionXOption = Option.builder()
				.longOpt(CliOptions.PDF_POSITION_X)
				.hasArg(true)
				.argName("100")
				.desc("Horizontal position on page")
				.build();
		cliOptions.addOption(pdfPositionXOption);
		pdfVisualOG.addOption(pdfPageOption);
		
		Option pdfPositionYOption = Option.builder()
				.longOpt(CliOptions.PDF_POSITION_Y)
				.hasArg(true)
				.argName("100")
				.desc("Vertical position on page")
				.build();
		cliOptions.addOption(pdfPositionYOption);
		pdfVisualOG.addOption(pdfPageOption);
		
		Option pdfWidthOption = Option.builder()
				.longOpt(CliOptions.PDF_WIDTH)
				.hasArg(true)
				.argName("100")
				.desc("Sign field width")
				.build();
		cliOptions.addOption(pdfWidthOption);
		pdfVisualOG.addOption(pdfPageOption);
		
		Option pdfHeightOption = Option.builder()
				.longOpt(CliOptions.PDF_HEIGHT)
				.hasArg(true)
				.argName("100")
				.desc("Sign field height")
				.build();
		cliOptions.addOption(pdfHeightOption);
		pdfVisualOG.addOption(pdfPageOption);
		
		Option pdfImageOption = Option.builder()
				.longOpt(CliOptions.PDF_IMAGE)
				.hasArg(true)
				.argName("./image.png")
				.desc("Image to create visual pdf sign")
				.build();
		cliOptions.addOption(pdfImageOption);
		pdfVisualOG.addOption(pdfImageOption);
		
		Option pdfImageScaleOption = Option.builder()
				.longOpt(CliOptions.PDF_IMAGE_SCALE)
				.hasArg(true)
				.argName("0.5")
				.desc("Image scale")
				.build();
		cliOptions.addOption(pdfImageScaleOption);
		pdfVisualOG.addOption(pdfImageScaleOption);
		
		PfxCreator.createOptions().getOptions().forEach(cliOptions::addOption);
		Verify.createOptions().getOptions().forEach(cliOptions::addOption);
		
		return cliOptions;
	}

	private static void printHelp(Options clOptions) {
		HelpFormatter formatter = new HelpFormatter();
		formatter.setWidth(120);
		formatter.printHelp("java -jar <jarfile>", clOptions, true);
	}

	
    
}
