package program;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

/**
 * invoked in run, providing an adapter to Disassembly class, such that disassembly data can be shown
 * @author gurjan
 *
 */
public class Model {

	private File file; // selected file to be disassembled
	private Disassemble instance; // current instance of disassemble

	// Instantiated upon file -> load or loading a file
	public Model() {

	}
	
	/**
	 * set the file to be disassembled
	 * @param f sleected file
	 */
	public void setFile(File f) {
		this.file = f;
	}
	
	/**
	 * 
	 * @return file being disasmd
	 */
	public File getFile() {
		return this.file;
	}
	
	/**
	 * Invoke an instance of disassembly, disassembling the selected file
	 * @throws ReadException if an error reading file into bytes
	 * @throws ElfException if file is not an ELF or associated issue
	 * @throws MainDiscoveryException if main cannot be determined heuristically
	 */
	public void disassemble() throws ReadException, ElfException, MainDiscoveryException {
			this.instance = new Disassemble(this.file);
	}
	
	/**
	 * 
	 * @return list of ELF sections
	 */
	public List<Section> getSections() {
		return this.instance.getSections();
	}
	
	/**
	 * 
	 * @return true if the ELF symtab exits
	 */
	public boolean symTabExists() {
		return this.instance.symTabExists();
	}
	
	/**
	 * 
	 * @return list of known functions to of the executable
	 */
	public List<Function> getFunctions() {
		return this.instance.getFunctions();
	}
	
	/**
	 * get list of disassembled basic blocks
	 * @return list of blocks
	 */
	public Map<Integer, BasicBlock> getBasicBlocks() {
		return this.instance.getBasicBlocks();
	}
	
	/**
	 * has the address passed in been disassembled?
	 * @param address addddres to be checked
	 * @return true if has been disassembled at
	 */
	public boolean isKnownAddress(int address) {
		if(this.instance.getKnownAddresses().contains(address)) {
			return true;
		} else {
			return false;
		}
	}
	
	/**
	 * get the hex representation of instructions between first and last addresses
	 * @param first address of a sequence of instructions
	 * @param last address of the sequence of instructions
	 * @param spaces if representation should include spaces between hex values
	 * @return
	 */
	public String getHexRepresentationSpaces(int first, int last, boolean spaces) {
		return this.instance.getHexRepresentation(first-this.instance.getVtf(), last-this.instance.getVtf(), spaces);
	}
	
	/**
	 * get main function location
	 * @return main address
	 */
	public int getMain() {
		return this.instance.getMain();
	}
	
	/**
	 * get converter required to convert from virtual address to physical
	 * @return integer converter
	 */
	public int getVtf() {
		return this.instance.getVtf();
	}

	/**
	 * get time elapsed for disassembly process
	 * @return time in milliseconds
	 */
	public long getElapsed() {
		return this.instance.getElapsed();
	}

	

	
}
