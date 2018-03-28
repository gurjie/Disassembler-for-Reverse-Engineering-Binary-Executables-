package program;

import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;

public class Function {
	private long startAddr;
	private long endAddr;
	private String name;
	private HashSet<Integer> blockAddresses = new HashSet<Integer>(); // addresses of blocks referenced by a function

	/**
	 * create a new function
	 * @param name of the function
	 */
	public Function(String name) {
		this.name = name;
	}

	/**
	 * @return name of function
	 */
	public String getName() {
		return this.name;
	}

	/**
	 * sets start address of a function
	 * @param start address to be set as start for a function
	 */
	public void setStartAddr(long start) {
		this.startAddr = start;
	}

	/**
	 * sets end adress of a function
	 * @param end address to be set as end of a function
	 */
	public void setEndAddr(long end) {
		this.endAddr = end;
	}

	/**
	 * 
	 * @return start address of a fuction
	 */
	public int getStartAddr() {
		return (int) this.startAddr;
	}

	/**
	 * 
	 * @return end address of a function
	 */
	public int getEndAddr() {
		return (int) this.endAddr;
	}
	
	/**
	 * Get addresses associated with a function
	 * @return set of addresses associated with function within its scope
	 */
	public HashSet<Integer> getAssociatedAddresses() {
		return this.blockAddresses;
	}

	/**
	 * set associated addresses of a function
	 * @param blockList containing basic blocks from disassembly
	 * @return block addresses of functions as a set
	 */
	public HashSet<Integer> setAssociatedAddresses(Map<Integer, BasicBlock> blockList) {
		getFunctionReferences(blockList.get((int) this.startAddr), blockList);
		return blockAddresses;
	}

	/**
	 * recursively finds out which addresses are associated with a function by analysing a function's children
	 * @param block current block being analysed
	 * @param blockList of all disassembled basic blocks
	 */
	private void getFunctionReferences(BasicBlock block, Map<Integer, BasicBlock> blockList) {
		for (int x : block.getAddressReferenceList()) {
			if (!blockAddresses.contains(x)) {
				blockAddresses.add(x);
				getFunctionReferences(findNearest(blockList, x), blockList);
			}
		}
	}

	/**
	 * get the nearest black in the blocklist to a specified block.
	 * Shouldn't be needed, but used anyway
	 * @param map to find nearest block in
	 * @param value start address of block which blocklist is being iterated to find
	 * @return
	 */
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
