package program;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

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
	
	public ArrayList<BasicBlock> getBasicBlocks() {
		return this.instance.getBasicBlocks();
	}
	
}
