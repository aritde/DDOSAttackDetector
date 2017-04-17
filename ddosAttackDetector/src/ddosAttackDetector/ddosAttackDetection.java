package ddosAttackDetector;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class ddosAttackDetection {
	static private String inputFile = "E:/Transferred/Apps/GA/apache-access-log.txt";
	static Map<String,HitStructure> map = new HashMap<>();
	static Set<String> set = new HashSet<>();
	public static void main(String[] args)throws IOException
	{
		FileReader reader = new FileReader(new File(inputFile));
    	BufferedReader bufferedReader = new BufferedReader(reader);
    	String line;
    	int minTimeFlag = 0;
    	Date minTimeData = null;
    	while((line = bufferedReader.readLine())!=null)
    	{
    		Record r = splitFields(line);
    		String ipAddress = r.getIpAddress();
    		System.out.println("Currently Processsing IP :" + ipAddress);
    		Date currentTime = r.getTimestamp();
    		if(minTimeFlag == 0)
    		{
    			minTimeFlag++;
    			minTimeData = currentTime; 
    		}
    		else
    		{
	    		long diff = currentTime.getTime()-minTimeData.getTime();
	    		long diffSeconds = diff /1000%60;
	    		long diffMinutes = diff /(60*1000)%60;
	    		long diffHours = diff /(60*60*1000);
	    		if(diffHours>=0 && diffMinutes>=1 && diffSeconds>=1)
				{
	    			minTimeData = currentTime;
					map.clear();
				}
    		}
    		if(map.containsKey(ipAddress))
    		{
    			Date lastHitTime = map.get(ipAddress).getTimestamp();
    			System.out.println("Last Hit Time " +lastHitTime );
    			System.out.println("Curr Hit Time " +currentTime );
    			long diff = currentTime.getTime()-lastHitTime.getTime();
    			long diffSeconds = diff /1000%60;
    			long diffMinutes = diff /(60*1000)%60;
    			long diffHours = diff /(60*60*1000);
    			if(diffHours==0 && diffMinutes<1)
    			{
    				int updateCount = map.get(ipAddress).getCount();
    				HitStructure h = new HitStructure(lastHitTime,updateCount+1);
    				map.put(ipAddress, h);
    				if(updateCount+1 >=88)
    				{
    					if(!set.contains(ipAddress))
    					{
	    					//System.out.println("Suspicious ID:" + ipAddress);
	    					set.add(ipAddress);
	    				}
    				}
    			}
    		}
    		else
    		{
    			HitStructure h = new HitStructure(currentTime,1);
    			map.put(ipAddress, h);
    		}
    	}
    	/*for(String ipa :set)
			System.out.println("Suspicious ID:" + ipa);*/
    	System.out.println("Suspicious ID:" + set.size());
	}
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

}

