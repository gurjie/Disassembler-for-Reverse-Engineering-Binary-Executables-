package program;

public class Function {
	private long startAddr;
	private long endAddr; 
	private String name;
	
	public Function(String name) {
		this.name = name;
	}
	
	public String getName() {
		return this.name;
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
	
	@Override
	public String toString() {
		return this.name;
	}
}
