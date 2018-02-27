package program;

public class Function {
	long startAddr;
	long endAddr; 
	
	public Function() {
		
	}
	
	public void setStartAddr(long start) {
		this.startAddr = start;
	}
	
	public void setEndAddr(long end) {
		this.endAddr = end;
	}
	
	public long getStartAddr() {
		return this.startAddr;
	}
	
	public long getEndAddr() {
		return this.endAddr;
	}
}
