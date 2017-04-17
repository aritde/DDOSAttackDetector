package ddosAttackDetector;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class parseDate {
	
	public static void main(String[] args)
	{
		String str = "[23/May/2015:23:31:15 +0000]";
	
	String str2 ="[25/May/2015:23:11:17 +0000]";
	str = str.substring(1,str.length()-1).split(" ")[0];
	str2 = str2.substring(1,str2.length()-1).split(" ")[0];
	System.out.println(str + " "+ str2);
	SimpleDateFormat df = new SimpleDateFormat("dd/MMM/yyyy:HH:mm:ss",Locale.US);
	Date d = null;
	Date d2 = null;
	try {
		d = df.parse(str);
		d2 = df.parse(str2);
	} catch (ParseException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	
	if(d.compareTo(d2) > 0)
		System.out.println("d is after d2");
	else
		System.out.println("d2 is after d1");
	long diff = d2.getTime()-d.getTime();
	System.out.println(d2.getTime());
	long diffSeconds = diff /1000%60;
	long diffMinutes = diff /(60*1000)%60;
	long diffHours = diff /(60*60*1000);
	System.out.println( diffHours + " " +diffMinutes + " "+ diffSeconds);
}
}