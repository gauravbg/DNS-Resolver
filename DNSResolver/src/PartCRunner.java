import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;

import org.xbill.DNS.Lookup;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

public class PartCRunner {

	public static void main(String[] args) {

		ArrayList<String> websites = new ArrayList<>();
		websites.add("www.google.com");
		websites.add("www.youtube.com");
		websites.add("www.facebook.com");
		websites.add("www.baidu.com");
		websites.add("www.yahoo.com");
		websites.add("www.wikipedia.org");
		websites.add("www.google.co.in");
		websites.add("www.tmall.com");
		websites.add("www.Qq.com");
		websites.add("www.amazon.com");
		websites.add("www.sohu.com");
		websites.add("www.google.co.jp");
		websites.add("www.taobao.com");
		websites.add("www.live.com");
		websites.add("www.vk.com");
		websites.add("www.twitter.com");
		websites.add("www.360.cn");
		websites.add("www.linkedin.com");
		websites.add("www.instagram.com");
		websites.add("www.yahoo.co.jp");
		websites.add("www.sina.com.cn");
		websites.add("www.jd.com");
		websites.add("www.google.de");
		websites.add("www.reddit.com");
		websites.add("www.google.co.uk");

		for(String each: websites) {
			long timeTaken = 0;
		
			for (int i = 0; i < 10; i++) {
				long start = System.nanoTime();
				String arg[] = new String[2];
				arg[0] = each; 
				arg[1] = "A";
				MyDig.main(arg);
				long end = System.nanoTime();
				timeTaken = timeTaken + (end - start) / 1000000;
			}

			System.out.println("My DNS Time: " + timeTaken / 10);
		}

		System.out.println("-----------------------------------");
		
		for(String each: websites) {
			long timeTaken = 0;
		
			for (int i = 0; i < 10; i++) {
				long start = System.nanoTime();
				String arg[] = new String[2];
				arg[0] = each; 
				arg[1] = "A";
				try {
					InetAddress addr = InetAddress.getByName(arg[0]);
				} catch (UnknownHostException e) {
					e.printStackTrace();
				}
				long end = System.nanoTime();
				timeTaken = timeTaken + (end - start) / 1000000;
			}

			System.out.println("Local DNS Time: " + timeTaken / 10);
		}
		

		System.out.println("-----------------------------------");
		
		for(String each: websites) {
			long timeTaken = 0;
		
			for (int i = 0; i < 10; i++) {
				long start = System.nanoTime();
				SimpleResolver resolver = null;
				try {
					resolver = new SimpleResolver("8.8.8.8");
				} catch (UnknownHostException e) {
					e.printStackTrace();
				}
                Lookup lookup = null;
				try {
					lookup = new Lookup(each, Type.A);
				} catch (TextParseException e) {
					e.printStackTrace();
				}
                lookup.setResolver(resolver);
                lookup.run();
				long end = System.nanoTime();
				timeTaken = timeTaken + (end - start) / 1000000;
			}

			System.out.println("Public DNS Time: " + timeTaken / 10);
		}
		
		System.out.println("-----------------------------------");

	}
}
