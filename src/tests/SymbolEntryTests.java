package tests;
import elf.Elf;
import elf.SectionHeader;
import first.SymbolEntry;

import static org.junit.Assert.assertEquals;
import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

import org.junit.Before;
import org.junit.jupiter.api.Test;

class SymbolEntryTests {

	private Elf elf; 
	private File f;
	private SectionHeader symtab;
	private byte[] symtab_bytes;
	private byte[] strtab_bytes;
	private byte[] slice_bytes;
	private String fileName = "maze";
	private SectionHeader strtab;
	private int symtab_size;
	private int symtab_offset;
	private int strtab_size;
	private int strtab_offset;
	
	@Before public void setUp() throws IOException {
		f = new File(fileName);
		try {
			elf = new Elf(f);
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
	    Path path = Paths.get(fileName);
	    byte[] data = Files.readAllBytes(path); //convert the executable to bytes
	    for(SectionHeader shrs : elf.sectionHeaders) {
	    	if(shrs.getName().equals(".strtab")) {
	    		this.strtab = shrs;
	    	}
	    }
		this.strtab_size = (int) this.strtab.size;
		this.strtab_offset = (int) this.strtab.fileOffset;
		for(SectionHeader shrs : elf.sectionHeaders) {
			if(shrs.getName().equals(".symtab")) {
				this.symtab = shrs;
				symtab_size = (int) symtab.size;
				symtab_offset = (int) symtab.fileOffset;
			}
		}
		symtab_bytes = Arrays.copyOfRange(data, symtab_offset, symtab_offset+symtab_size);
		strtab_bytes = Arrays.copyOfRange(data, strtab_offset, strtab_offset+strtab_size);
	}
	
	/*
	@Test // test 1, create constructor taking symbol table as argument...
	public void getMainSymtabSize() throws IOException {
		setUp();
		SymbolEntry symbol = new SymbolEntry(this.symtab_bytes, null);
		assertEquals("TEST 1: test the symboltable size is as expected", symbol.getSymTabSize(),this.symtab_size);
	}*/
	
	@Test // test 2, added to the constructer and the appropriate getter
	public void getMainStrtabSize() throws IOException {
		setUp();
		SymbolEntry symbol = new SymbolEntry(this.symtab_bytes,this.strtab_bytes);
		slice_bytes = Arrays.copyOfRange(symtab_bytes, 2208, 2208+24);
		assertEquals("TEST 2: test the symboltable size is as expected", symbol.getStrTabSize(),this.strtab_size);
	}
	
	@Test // test 3, added name getter, returns main hard coded
	public void getMainSymbolName() throws IOException {
		setUp();
		slice_bytes = Arrays.copyOfRange(symtab_bytes, 2208, 2208+24);
		SymbolEntry symbol = new SymbolEntry(this.slice_bytes,this.strtab_bytes);
		assertEquals("TEST 3: test get symbol name", symbol.getName(), "main");
	}
	
	@Test // getter for function type added, gets function
	public void getMainSymbolType() throws IOException {
		setUp();
		slice_bytes = Arrays.copyOfRange(symtab_bytes, 2208, 2208+24);
		SymbolEntry symbol = new SymbolEntry(this.slice_bytes,this.strtab_bytes);
		assertEquals("TEST 4: test get symbol type", symbol.getType(), "STT_FUNCT");
	}
	
	@Test // added getter for address return hard coded main address
	public void getMainAddress() throws IOException {
		setUp();
		slice_bytes = Arrays.copyOfRange(symtab_bytes, 2208, 2208+24);
		SymbolEntry symbol = new SymbolEntry(this.slice_bytes,this.strtab_bytes);
		assertEquals("TEST 5: test getter for address", symbol.getAddress(), 4203639);
	}
	
	/*@Test // added getter for 'other' field in symbol entries, hard coded return
	public void getMainOther() throws IOException {
		setUp();
		slice_bytes = Arrays.copyOfRange(symtab_bytes, 2208, 2208+24);
		SymbolEntry symbol = new SymbolEntry(this.slice_bytes,this.strtab_bytes);
		assertEquals("TEST 6: test getother method", symbol.getOther(), 0);
	}*/
	
	@Test // Added binding attributes getter
	public void getMainBindingAttributes() throws IOException {
		setUp();
		slice_bytes = Arrays.copyOfRange(symtab_bytes, 2208, 2208+24);
		SymbolEntry symbol = new SymbolEntry(this.slice_bytes,this.strtab_bytes);
		assertEquals("TEST 7: test get binding attributes", symbol.getBindingAttributes(), 1);
	}
	@Test // add hard coded getter for size
	public void MainSize() throws IOException {
		setUp();
		slice_bytes = Arrays.copyOfRange(symtab_bytes, 2208, 2208+24);
		SymbolEntry symbol = new SymbolEntry(this.slice_bytes,this.strtab_bytes);
		assertEquals("TEST 8: test get main symbol size", symbol.getSize(), 862);
	}
	
	@Test // implemented computations to get symbol size from slice of bytes, refactored
	public void startSize() throws IOException {
		setUp();
		slice_bytes = Arrays.copyOfRange(symtab_bytes, 2112, 2208+24);
		SymbolEntry symbol = new SymbolEntry(this.slice_bytes,this.strtab_bytes);
		assertEquals("TEST 9: test get start symbol size", 42, symbol.getSize());
	}
	
	@Test // implemented computations to get the symbol address, refactored
	public void startValue() throws IOException {
		setUp();
		slice_bytes = Arrays.copyOfRange(symtab_bytes, 2112, 2208+24);
		SymbolEntry symbol = new SymbolEntry(this.slice_bytes,this.strtab_bytes);
		assertEquals("TEST 10: test get start address", 4196784, symbol.getAddress());
	}
	
	@Test // implemented computations to get the binding attributes, refactored
	public void startBindingAttrs() throws IOException {
		setUp();
		slice_bytes = Arrays.copyOfRange(symtab_bytes, 2112, 2208+24);
		SymbolEntry symbol = new SymbolEntry(this.slice_bytes,this.strtab_bytes);
		assertEquals("TEST 11: test get start binding attrs", 1, symbol.getBindingAttributes());
	}
	
	@Test // computations to get symbol type added
	public void startSymbolType() throws IOException {
		setUp();
		slice_bytes = Arrays.copyOfRange(symtab_bytes, 2112, 2208+24);
		SymbolEntry symbol = new SymbolEntry(this.slice_bytes,this.strtab_bytes);
		assertEquals("TEST 12: test get start binding attrs", "STT_FUNCT", symbol.getType());
	}
	
	@Test // computations to get name 
	public void startName() throws IOException {
		setUp();
		slice_bytes = Arrays.copyOfRange(symtab_bytes, 2112, 2208+24);
		SymbolEntry symbol = new SymbolEntry(this.slice_bytes,this.strtab_bytes);
		assertEquals("TEST 13: test get start binding attrs", "_start", symbol.getName());
	}
}
