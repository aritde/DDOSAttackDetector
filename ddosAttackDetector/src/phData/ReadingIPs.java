package ddosAttackDetector;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
public class ReadingIPs {
	static private String inputFile = "E:/Transferred/Apps/GA/apache-access-log.txt";
	static Map<String,Integer> map = new HashMap<>();
	public static void main(String[] args) throws IOException
	{
		loadInput();
		int total = 0;
		int totalUnique =0;
		int suspicious = 0;
		int twos =0;
		Set<Integer> set = new HashSet<>();
		Map<Integer,Integer> map2 = new HashMap<>();
		for(String s : map.keySet())
		{
			/*totalUnique++;
			total+=map.get(s);
			if(map.get(s)>1)
			{
				suspicious++;
				if(map.get(s)==2)
					twos++;
				System.out.println(s + " " +map.get(s));
			}*/
			if(map2.containsKey(map.get(s)))
			{
				map2.put(map.get(s),map2.get(map.get(s))+1);
			}
			else
				map2.put(map.get(s),1);
		}
		for(Map.Entry<Integer, Integer> i : map2.entrySet())
			System.out.println(i.getKey()+" " +i.getValue());
		System.out.println("total :" + total);
		System.out.println("twos :" + twos);
		System.out.println("totalUnique :" + totalUnique);
		System.out.println("suspicious :" + suspicious);
	}
	public static void loadInput() throws IOException {
    	FileReader reader = new FileReader(new File(inputFile));
    	BufferedReader bufferedReader = new BufferedReader(reader);
    	String line;
    	while((line = bufferedReader.readLine())!=null)
    	{
    		String[] columns = line.split(" ");
    		String ip = columns[0];
    		if(map.containsKey(ip))
    		{
    			int count = map.get(ip);
    			map.put(ip, count+ 1);
    		}
    		else
    		{
    			map.put(ip, 1);
    		}
    		
    	}
	}
}