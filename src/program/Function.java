package program;

import java.util.HashSet;

public class Function {
	private long startAddr;
	private long endAddr; 
	private String name;
	private HashSet<Integer> associatedAddresses;	
	
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
	
	public int getStartAddr() {
		return (int) this.startAddr;
	}
	
	public int getEndAddr() {
		return (int) this.endAddr;
	}
	
	public void setAssociatedAddresses(HashSet<Integer> associated) {
		this.associatedAddresses = associated;
	}
	
	public HashSet<Integer> getAssociatedAddresses() {
		return this.associatedAddresses;
	}
	
	@Override
	public String toString() {
		return this.name;
	}
}
