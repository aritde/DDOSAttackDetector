package phData;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class ddosAttackDetection {
	static private String inputFile = "E:/Transferred/Apps/GA/apache-access-log.txt";
	static Map<String,HitStructure> mapOfRecords = new HashMap<>();
	static Set<String> suspiciousIPs = new HashSet<>();
	public static void main(String[] args)throws IOException
	{
		FileReader reader = new FileReader(new File(inputFile));
    	BufferedReader bufferedReader = new BufferedReader(reader);
    	String line;
    	int minTimeFlag = 0;
    	Date minTimeData = null;
    	while((line = bufferedReader.readLine())!=null)
    	{
    		//parses desired data from records
    		Record r = splitFields(line);
    		String ipAddress = r.getIpAddress();
    		System.out.println("Currently Processsing IP :" + ipAddress);
    		Date currentTime = r.getTimestamp();
    		//checks for occurence of IP in map
			if(mapOfRecords.containsKey(ipAddress))
    		{
    			Date lastHitTime = mapOfRecords.get(ipAddress).getTimestamp();
    			//Calculates time difference
				long diff = currentTime.getTime()-lastHitTime.getTime();
    			long diffSeconds = diff /1000%60;
    			long diffMinutes = diff /(60*1000)%60;
    			long diffHours = diff /(60*60*1000);
    			if(diffHours==0 && diffMinutes<1)
    			{
    				int updateCount = mapOfRecords.get(ipAddress).getCount();
    				HitStructure h = new HitStructure(lastHitTime,updateCount+1);
    				mapOfRecords.put(ipAddress, h);
    				//Checks whether the current count exceeds the threshold or not
					if(updateCount+1 >=88)
    				{
    					// Adds the suspicious IP to the final result set
						if(!suspiciousIPs.contains(ipAddress))
    					{
	    					suspiciousIPs.add(ipAddress);
	    				}
    				}
    			}
    		}
    		else
    		{
    			//Resets the entry count to 1
				HitStructure h = new HitStructure(currentTime,1);
    			mapOfRecords.put(ipAddress, h);
    		}
    	}
    	System.out.println("Suspicious ID:" + suspiciousIPs.size());
    	//Writes the suspicious IP to the file.
		printSuspiciousIPs(suspiciousIPs);
	}
	// Core function for parsing desired data from records
	public static Record  splitFields(String line)
	{
		String[] fields = line.split(" ");
		String timeStamp = fields[3].substring(1,fields[3].length()).split(" ")[0];
		SimpleDateFormat df = new SimpleDateFormat("dd/MMM/yyyy:HH:mm:ss",Locale.US);
		Date d = null;
		try {
			d = df.parse(timeStamp);
		} catch (ParseException e) {
			e.printStackTrace();
		}
		Record r= new Record(fields[0],d);
		System.out.println(r.getIpAddress()+" "+r.getTimestamp());
		return r;
	}
	// Function for writing output to file
	public static void printSuspiciousIPs(Set<String> suspiciousIPs) throws IOException {
		try(FileWriter fw = new FileWriter("E:/Transferred/Apps/GA/suspiciousIP.txt", true);
			    BufferedWriter bw = new BufferedWriter(fw);
			    PrintWriter out = new PrintWriter(bw))
			{
			Iterator<String> ipIterator = suspiciousIPs.iterator();
			while(ipIterator.hasNext())
			{
				out.println("IP Address :" + ipIterator.next());
	        }
			
			} catch (IOException e) {
				e.printStackTrace();
			}
	    }
}

