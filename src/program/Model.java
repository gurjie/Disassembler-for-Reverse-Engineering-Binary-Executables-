package program;

import java.io.File;
import java.io.IOException;
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
	
	public void disassemble() throws ReadException, ElfException {
			this.instance = new Disassemble(this.file);
	}
	
	public List<Section> getSections() {
		return this.instance.getSections();
	}
	
	public boolean symTabExists() {
		return this.instance.symTabExists();
	}
	
}
