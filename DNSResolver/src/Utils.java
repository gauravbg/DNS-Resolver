import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Scanner;
import java.util.StringTokenizer;

import org.xbill.DNS.DNSSEC.DNSSECException;
import org.xbill.DNS.DNSSEC.KeyMismatchException;
import org.xbill.DNS.DNSSEC.MalformedKeyException;
import org.xbill.DNS.DNSSEC.SignatureExpiredException;
import org.xbill.DNS.DNSSEC.SignatureNotYetValidException;
import org.xbill.DNS.DNSSEC.SignatureVerificationException;
import org.xbill.DNS.DNSSEC.UnsupportedAlgorithmException;
import org.xbill.DNS.Type;

public class Utils {
	
	private static String ROOT_HINTS_FILE = "res/root_hints";
	private static ArrayList<RootServer> rootServers;
	
	public static void createRootServerList() {
	
		rootServers = new ArrayList<>();
		File file = new File(ROOT_HINTS_FILE);
		Scanner in = null;
		try {
			in = new Scanner(new FileReader(file));
		} catch (FileNotFoundException e) {
			System.out.println("Error reading Root hints file.");
		}
		
		if(in != null) {	
			while(in.hasNextLine()) {
				String line = in.nextLine();
				StringTokenizer tokenizer = new StringTokenizer(line, "|");
				if(tokenizer.countTokens() == 3) {
					rootServers.add(new RootServer(tokenizer.nextToken(), tokenizer.nextToken(), tokenizer.nextToken()));
				} else {
					
				}
			}
		}
		
		
	}
	
	public static int getType(String type) {
		
		switch (type) {
		case "A":
			return Type.A;
		case "MX":
			return Type.MX;
		case "NS":
			return Type.NS;
		}
		return Type.A;
	}
	
	public static ArrayList<RootServer> getRootServerList() {
		if(rootServers == null) {
			createRootServerList();
		}
		
		return rootServers;
	}

	public static boolean isDnsSecNotSupported(DNSSECException e) {
		if(e instanceof UnsupportedAlgorithmException) {
			return true;
		}
		return false;
	}
	
	public static boolean isDnsSecNotVerified(DNSSECException e) {
		if (e instanceof MalformedKeyException || e instanceof KeyMismatchException
				|| e instanceof SignatureExpiredException || e instanceof SignatureNotYetValidException
				|| e instanceof SignatureVerificationException || e instanceof UnsupportedAlgorithmException) {
			return true;
		}
		return false;
	}

}
