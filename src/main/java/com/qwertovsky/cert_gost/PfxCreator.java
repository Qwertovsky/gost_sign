package com.qwertovsky.cert_gost;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.Streams;

public class PfxCreator {

	public static void main(String[] args) throws Exception {
		
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

		String keyAlias = commandLine.getOptionValue(CliOptions.PFX_ALIAS);
		String privateKeyPath = commandLine.getOptionValue(CliOptions.KEY_FILE);
		String pfxFilePath = commandLine.getOptionValue(CliOptions.PFX_FILE);
		String[] chainPaths = commandLine.getOptionValues(CliOptions.CERT_CHAIN);
		
		if (chainPaths == null || chainPaths.length == 0) {
			System.err.println("Cert chain must contains at least subject cert");
			return;
		}
		
		Security.setProperty("crypto.policy", "unlimited");
		
	    Provider bcProvider = new BouncyCastleProvider();
		Security.addProvider(bcProvider);
		
		System.out.println("Enter container password:");
		char[] pinChars = System.console().readPassword();
		
		KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
		keyStore.load(null, null);
		
		PrivateKey privateKey = getPrivateKey(privateKeyPath);
		Certificate[] chain = getCertChain(chainPaths);
		keyStore.setKeyEntry(keyAlias, privateKey, null, chain);
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		keyStore.store(bos, pinChars);
		try (FileOutputStream fos = new FileOutputStream(new File(pfxFilePath))) {
			fos.write(bos.toByteArray());
		}

	}

	static Options createOptions() {
		Options clOptions = new Options();
		
		Option pfxCreateOption = Option.builder()
				.longOpt(CliOptions.PFX_CREATE)
				.desc("Create pfx container. Try --" + CliOptions.PFX_CREATE + " --" + CliOptions.HELP)
				.build();
		clOptions.addOption(pfxCreateOption);
		
		Option helpOption = Option.builder()
				.option("h")
				.longOpt(CliOptions.HELP)
				.desc("Print help")
				.build();
		clOptions.addOption(helpOption);
		
		Option pfxFileOption = Option.builder()
				.longOpt(CliOptions.PFX_FILE)
				.argName("./file_path.pfx")
				.desc("PFX key store file")
				.hasArg(true)
				.build();
		clOptions.addOption(pfxFileOption);
		
		Option pfxAliasOption = Option.builder()
				.longOpt(CliOptions.PFX_ALIAS)
				.argName("alias")
				.desc("Key alias in pfx store")
				.hasArg(true)
				.build();
		clOptions.addOption(pfxAliasOption);
		
		Option keyFileOption = Option.builder()
				.longOpt(CliOptions.KEY_FILE)
				.argName("./file_path.key")
				.desc("Private key file")
				.hasArg(true)
				.build();
		clOptions.addOption(keyFileOption);
		
		Option certChainOption = Option.builder()
				.longOpt(CliOptions.CERT_CHAIN)
				.argName("./subject.cer")
				.desc("Certificate chain files. Option may be defined more than once. The first is public certificate for private key.")
				.hasArg(true)
				.build();
		clOptions.addOption(certChainOption);
		return clOptions;
	}
	
	private static Certificate[] getCertChain(String... chainPaths) throws Exception {
		int chainLength = chainPaths.length;
		Certificate[] chain = new Certificate[chainLength];

		for (String certPath : chainPaths) {
			try(FileInputStream fis = new FileInputStream(certPath)) {
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
		        Streams.pipeAll(fis, baos, 32 * 1024);
				X509CertificateHolder certificate = new X509CertificateHolder(baos.toByteArray());
				chain[1] = new JcaX509CertificateConverter().getCertificate(certificate);
			}
		}
		return chain;
	}
	
	private static PrivateKey getPrivateKey(String fileName) throws Exception {
		try (PEMParser parser = new PEMParser(new FileReader(fileName));) {
			PrivateKeyInfo pemKey = (PrivateKeyInfo) parser.readObject();
			return new JcaPEMKeyConverter().getPrivateKey(pemKey);
		}
		
	}
	
	private static void printHelp(Options clOptions) {
		HelpFormatter formatter = new HelpFormatter();
		formatter.setWidth(120);
		formatter.printHelp("java -jar <jarfile> --" + CliOptions.PFX_CREATE, clOptions, true);
	}
	
}
