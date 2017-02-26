import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Iterator;

import org.xbill.DNS.ARecord;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.DNSSEC.DNSSECException;
import org.xbill.DNS.ExtendedFlags;
import org.xbill.DNS.ExtendedResolver;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Options;
import org.xbill.DNS.RRSIGRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

public class DnsSecResolver {

	
	private static String name = "";
	private static int type = Type.A;
	private static long start = 0;
	private static long end = 0;
	private static Object question = null;
	private static boolean isDnsSecSupported = false;
	
	public static void main(String[] args) {
		
		
		if (args.length != 1) {
			System.out.println("Wrong input. Enter Domain name");
			return;
		}
		
		
		if (args[0] == null) {
			System.out.println("Not a valid Domain Name");
			return;
		}

		
		name = args[0] + ".";
		
		
		ArrayList<RootServer> rootServers = Utils.getRootServerList();
		Message query = null;
		Message response = null;
		ExtendedResolver resolver = null;
		ArrayList<InetAddress> result = null;
		String rootIp = "";
		int counter = 0;
		boolean originalQuestion = true;
		
		
		while(counter < rootServers.size()) {
		
			start = System.nanoTime();
			try {
				String ipFull = rootServers.get(counter).ip;
				rootIp = ipFull.substring(0, ipFull.indexOf(','));
				Name dnsName = Name.concatenate(Name.fromString(name), Name.root);
		        Record questionRecord = Record.newRecord(dnsName, Type.A, DClass.IN);
		        query = Message.newQuery(questionRecord);
		        resolver = new ExtendedResolver();
		        resolver.setEDNS(0, 0, ExtendedFlags.DO, null);
		        resolver.setTCP(true);
		        
				response = resolver.send(query);
				if(originalQuestion) {
					question = response.getQuestion().toString();
					originalQuestion = false;
				}
				result = resolveAndVerifyDNS(response);
				break;
			} catch (Exception e) {
				if(e != null && e.getMessage() != null && !e.getMessage().equals("CNAME FOUND")) {
					System.out.println("Failed contacting Root Server: " + rootIp);
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
		if(result!= null && result.size() != 0)
			System.out.println("Resolved IP: " + result.get(0).getHostAddress());
		else {
			System.out.println("DNSSEC verification failed");
			isDnsSecSupported = true;
		}
		
		if(!isDnsSecSupported) {
			System.out.println("DNSSEC not supported");
		}
		
	}
	
	
	@SuppressWarnings("unchecked")
    public static ArrayList<InetAddress> resolveAndVerifyDNS(Message response) 
        throws DNSSECException, IOException {
    	
        RRset[] answer = response.getSectionRRsets(Section.ANSWER);
        
        ArrayList<InetAddress> resultAddress = new ArrayList<InetAddress>();
        for (RRset rrSet : answer) {

        	//Looking up RRSET
            Iterator<Record> rrIterator = rrSet.rrs();
            boolean cnameFound = false;
            CNAMERecord cnameRecord = null;
            while (rrIterator.hasNext()) {
                Record record = rrIterator.next();
                if (record.getType() == Type.CNAME) {
                    cnameRecord = (CNAMERecord) record;
                    cnameFound = true;
                } 
            }
            
            rrIterator = rrSet.rrs();
            while (rrIterator.hasNext()) {
                Record record = rrIterator.next();
                if (record.getType() == Type.A) {
                    ARecord arec = (ARecord) record;
                    if (cnameFound) {
                        if (record.getName().equals(cnameRecord.getTarget())) {
                        	resultAddress.add(arec.getAddress());
                        }
                    } else {
                    	resultAddress.add(arec.getAddress());
                    }
                }
            }
            Iterator<Record> sigIterator = rrSet.sigs();
            while (sigIterator.hasNext()) {
            	//Found RRSIG
                RRSIGRecord record = (RRSIGRecord) sigIterator.next();
                verifyRRSIGRecord(rrSet, record);
            }
        }
        return resultAddress;
    }

	
	
	@SuppressWarnings("unchecked")
    private static void verifyRRSIGRecord(RRset set, RRSIGRecord sigRecord) 
        throws DNSSECException, IOException {

        DNSKEYRecord keyRecord = null;
        
        try {
            Resolver resolver = new ExtendedResolver();
            resolver.setEDNS(0, 0, ExtendedFlags.DO, null);
            resolver.setTCP(true);
            Options.set("multiline");
            
            Record queryRecord = Record.newRecord(sigRecord.getSigner(), Type.DNSKEY, DClass.IN); //Get DNS Key
            Message query = Message.newQuery(queryRecord);
            Message response = resolver.send(query);
            
            RRset[] answer = response.getSectionRRsets(Section.ANSWER);
            
            for (RRset rrSet : answer) {
                
				Iterator<Record> rrIterator = rrSet.rrs();
                while (rrIterator.hasNext()) {
                    Record record = rrIterator.next();
                    if (record instanceof DNSKEYRecord) {
                        DNSKEYRecord dnskKeyRecord = (DNSKEYRecord) record;
                        if (dnskKeyRecord.getFootprint() == sigRecord.getFootprint()) {
//                            System.out.println("Found KEY: " + sigRecord.getFootprint());
                            keyRecord = dnskKeyRecord;
                        }
                    }
                }
                Iterator<Record> sigIterator = rrSet.sigs();
                while (sigIterator.hasNext()) {
                    RRSIGRecord record = (RRSIGRecord) sigIterator.next();
                    if (record.getFootprint() == sigRecord.getFootprint()) {
                        DNSSEC.verify(rrSet, record, keyRecord);
                    } 
                }
                
            }

            if (keyRecord == null) {
//            	System.out.println("keyRecord == null");
            }
        } catch (org.xbill.DNS.DNSSEC.DNSSECException e) {
        	System.out.println("DNSSECException Exception: " + e.getMessage());
        } finally {
        	Options.unset("multiline");
        }
        
        
        try {
//        	System.out.println("trying verification");
            DNSSEC.verify(set, sigRecord, keyRecord);
            isDnsSecSupported = true;
//            System.out.println("DNSSEC Verification success");
        } catch (org.xbill.DNS.DNSSEC.DNSSECException e) {
        	if(Utils.isDnsSecNotVerified(e)){
        		System.out.println("DNSSEC verification failed");
        	}
        	System.out.println("DNSSECException Exception: " + e.getMessage());        		
        }
        
        verifyDsRecord(sigRecord);
    }

    @SuppressWarnings("unchecked")
    private static void verifyDsRecord(RRSIGRecord sigRecord) 
        throws IOException, DNSSECException {
    	
        Resolver resolver = new ExtendedResolver();
        resolver.setEDNS(0, 0, ExtendedFlags.DO, null);
        resolver.setTCP(true);

        Record queryRecord = Record.newRecord(sigRecord.getSigner(), Type.DS, DClass.IN); ////Get DS Key and verify again
        Message query = Message.newQuery(queryRecord);
        Message response = resolver.send(query);
        
        RRset[] answer = response.getSectionRRsets(Section.ANSWER);
        for (RRset rrSet : answer) {
            Iterator<Record> sigIterator = rrSet.sigs();
            
            while (sigIterator.hasNext()) {
                Record rrSig = sigIterator.next();
                if (rrSig instanceof RRSIGRecord) {
                    RRSIGRecord rr = (RRSIGRecord) rrSig;
//                    System.out.println("------------------------------------------");
                    verifyRRSIGRecord(rrSet, rr);
                } 
            }
        }
        
        
    }

	
}
