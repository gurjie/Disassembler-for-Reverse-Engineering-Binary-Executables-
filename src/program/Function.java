package program;

import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;

public class Function {
	private long startAddr;
	private long endAddr; 
	private String name;
	//private HashSet<Integer> associatedAddresses;
	private HashSet<Integer> blockAddresses = new HashSet<Integer>();	

	
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
	
	/*
	public void setAssociatedAddresses(HashSet<Integer> associated) {
		this.associatedAddresses = associated;
	}*/
	
	public HashSet<Integer> getAssociatedAddresses() {
		return this.blockAddresses;
	}
	
	public HashSet<Integer> setAssociatedAddresses(Map<Integer,BasicBlock> blockList) {
		getFunctionReferences(blockList.get((int) this.startAddr),blockList);
		return blockAddresses;
	}
	
	private void getFunctionReferences(BasicBlock block, Map<Integer, BasicBlock> blockList){ 
	    for (int x : block.getAddressReferenceList()) {
	    	//if (findNearest(this.blockList,x).getAddressReferenceList().size()==0){
	    	//	System.out.println(x);
	    	//}
	    	if(!blockAddresses.contains(x)) {
	    		//System.out.print("associated addresses contains: ");
	    		//for (int y: blockAddresses) {
	    			//System.out.print(Integer.toHexString(y)+"; ");
	    		//}
	    		//System.out.println();
	    		//System.out.println("now adding "+Integer.toHexString(x));
	    		blockAddresses.add(x);
		    	getFunctionReferences(findNearest(blockList,x),blockList);
	    	}
	    	/*if(blockAddresses.add(x)) {
	    		System.out.println("added x");
	    		System.out.print("addociated addresses contains: ");
	    		for (int y: blockAddresses) {
	    			System.out.print(y+"; ");
	    		}
	    		System.out.println(x);
		    	getFunctionReferences(findNearest(this.blockList,x), blockAddresses);
	    	}*/
		}
	}
	
	private static BasicBlock findNearest(Map<Integer, BasicBlock> map, int value) {
	    Map.Entry<Integer, BasicBlock> previousEntry = null;
	    for (Entry<Integer, BasicBlock> e : map.entrySet()) {
	        if (e.getKey().compareTo(value) >= 0) {
	            if (previousEntry == null) {
	                return e.getValue();
	            } else {
	                if (e.getKey() - value >= value - previousEntry.getKey()) {
	                    return previousEntry.getValue();
	                } else {
	                    return e.getValue();
	                }
	            }
	        }
	        previousEntry = e;
	    }
	    return previousEntry.getValue();
	}
	
	
	@Override
	public String toString() {
		return this.name;
	}
}
