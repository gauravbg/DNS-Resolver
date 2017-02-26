import java.util.ArrayList;

import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;

public class MyDig {

	private static String name = "";
	private static int type = Type.A;
	private static long start = 0;
	private static long end = 0;
	private static Object question = null;
	
	public static void main(String[] args) {
		
		if (args.length != 2) {
			System.out.println("Wrong input. Enter Domain name and type");
			return;
		}
		
		
		if (args[0] == null || args[0].length() == 0) {
			System.out.println("Not a valid Domain Name");
			return;
		}

		if (args[1] == null || args[1].length() == 0) {
			System.out.println("Incorrect type");
			return;
		}
		
		name = args[0] + ".";
		type = Utils.getType(args[1]);
		
		
		ArrayList<RootServer> rootServers = Utils.getRootServerList();
		Message query = null;
		Message response = null;
		SimpleResolver resolver = null;
		Message result = null;
		String ip = "";
		int counter = 0;
		boolean originalQuestion = true;
		
		while(counter < rootServers.size()) {
		
			start = System.nanoTime();
			try {
				String ipFull = rootServers.get(counter).ip;
				ip = ipFull.substring(0, ipFull.indexOf(','));
				
		        
				resolver = new SimpleResolver(ip);
				Name dnsName = Name.fromString(name);	
				Record record = Record.newRecord(dnsName, type, DClass.IN);
				query = Message.newQuery(record);
				response = resolver.send(query); //Querying root server
				if(originalQuestion) {
					question = response.getQuestion().toString();
					originalQuestion = false;
				}
				result = resolveDNS(response, query);
				break;
			} catch (Exception e) {
				if(e != null && e.getMessage() != null && !e.getMessage().equals("CNAME FOUND")) {
					System.out.println("Failed contacting Root Server: " + ip);
				}
				if(counter == rootServers.size()-1) {
					System.out.println("DNS could not be resolved. Check the input again.");
					return;
				}
				counter++;
				continue;
				
			} 
		}
			
		end = System.nanoTime();
		print(result); //Comment this when calculating average time. Prints add unnecessary time.
				
	}
	
	
	 
	private static void print(Message result) {
		Record[] ansArr = result.getSectionArray(Section.ANSWER);
		Record[] authArr = result.getSectionArray(Section.AUTHORITY);
		
		System.out.println("\n;QUESTION:");
		System.out.println(question);

		System.out.println("\n;ANSWER:");
		for (Record rec : ansArr)
			System.out.println(rec.toString());

		System.out.println("\n;AUTHORITY:");
		for (Record rec : authArr)
			System.out.println(rec.toString());
		
		long timeTaken = (end - start) / 1000000;
		System.out.println("\n;QUERY time: " + timeTaken + " msec");

	}


	private static Message resolveDNS(Message response, Message query) throws Exception {

		Record[] authRecords = response.getSectionArray(Section.AUTHORITY);
		
		while (authRecords[0].getType() != Type.SOA) {

			Record[] nextServers = response.getSectionArray(Section.AUTHORITY);
			for (int i=0; i<authRecords.length; i++) {
				Record record = nextServers[i];
				String addName = record.getAdditionalName().toString();
				try {
					Resolver resolver = new SimpleResolver(addName);
					response = resolver.send(query);
					authRecords = response.getSectionArray(Section.AUTHORITY);
					Record[] answer = response.getSectionArray(Section.ANSWER);
					
					if(answer != null) {
						if(answer.length >= 1) {
							Record lastAnswer = answer[answer.length - 1];
							if (lastAnswer.getType() == Type.CNAME) {
								name = lastAnswer.rdataToString();
								//Found a CNAME... Try again with this name.
								throw new Exception("CNAME FOUND");
							} else {
								return response;
							}
						}
					}
					break;
				} catch (Exception e) {
					if(e.getMessage().equals("CNAME FOUND")) {
						throw new Exception("CNAME FOUND");
					}
					continue;
				}
			}
				
			
		}
		return response;
	}
	
}
