package ddosAttackDetector;

import java.util.Date;

public class HitStructure {
	Date timestamp;
	int count;
	HitStructure(Date timestamp,int count)
	{
		this.timestamp = timestamp;
		this.count = count;
	}
	public Date getTimestamp() {
		return timestamp;
	}
	public void setTimestamp(Date timestamp) {
		this.timestamp = timestamp;
	}
	public int getCount() {
		return count;
	}
	public void setCount(int count) {
		this.count = count;
	}
	
}