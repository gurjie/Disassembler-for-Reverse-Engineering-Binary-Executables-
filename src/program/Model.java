package program;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

public class Model {

	private File file;
	private Disassemble instance;

	// Instantiated upon file -> load or loading a file
	public Model() {

	}
	
	public void setFile(File f) {
		this.file = f;
	}
	
	public File getFile() {
		return this.file;
	}
	
	public void disassemble() throws ReadException, ElfException, MainDiscoveryException {
			this.instance = new Disassemble(this.file);
	}
	
	public List<Section> getSections() {
		return this.instance.getSections();
	}
	
	public boolean symTabExists() {
		return this.instance.symTabExists();
	}
	
	public List<Function> getFunctions() {
		return this.instance.getFunctions();
	}
	
	public Map<Integer, BasicBlock> getBasicBlocks() {
		return this.instance.getBasicBlocks();
	}
	
	public boolean isKnownAddress(int address) {
		if(this.instance.getKnownAddresses().contains(address)) {
			return true;
		} else {
			return false;
		}
	}
	
	public String getHexRepresentationSpaces(int first, int last, boolean spaces) {
		return this.instance.getHexRepresentation(first-this.instance.getVtf(), last-this.instance.getVtf(), spaces);
	}
	
	public int getMain() {
		return this.instance.getMain();
	}
	
	public int getVtf() {
		return this.instance.getVtf();
	}

	public long getElapsed() {
		return this.instance.getElapsed();
	}
	
	/*
	public void disassembleFunction(Function f) {
		if(this.instance.getKnownAddresses().contains(address)) {
			return true;
		} else {
			return false;
		}
	}*/
	
	//public HashSet<Integer> getAssociatedBlockAddresses(int functionAddr) {
	//	return this.instance.getAssociatedAddresses(functionAddr);
	//}
	
}
