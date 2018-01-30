package first;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * This class is used to represent symbol entries in the ELF.
 * .symtab is outline in ELF specifications, and has a fixed representation.
 * Occupying 24 bytes, certain byte ranges represent different symbol attributes.
 * 
 * The setters in this class reflect this, parsing set amount of bytes to get
 * the information that they're setting.
 * 
 * Not all symtab information is read though, just the relevant!
 * 
 * @author Gurjan
 *
 */
public class SymbolEntry {

	private byte[] symtab_bytes; // symbol table byte representation
	private byte[] strtab_bytes; // string table byte representation
	private byte[] sizeBytes = new byte[8]; // bytes allocated  to hold 'size' value
	private long size; // concrete representation of the bytes
	private byte[] valueBytes = new byte[8]; // bytes allocated to hold 'address' value
	private long address; // address of this symbol entry
	private int bindingAttributes; // Binding attributes for this entry
	private int symbolType; // symbolType as per .symtab specification online
	private String type; // type as per .symtab specifications
	private byte[] nameOffsetBytes = new byte[4]; // offset into .strtab of this sym name
	private int nameOffset; // same as above, but an actual numerical representation
	private String name; // name of this symbol
	
	public SymbolEntry(byte[] symtab_bytes, byte[] strtab_bytes) {
		this.symtab_bytes = symtab_bytes;
		this.strtab_bytes = strtab_bytes;
		setSize();
		setAddress();
		setInfo();
		setName();
		// TODO Auto-generated constructor stub
	}

	public int getStrTabSize() {
		// TODO Auto-generated method stub
		return this.strtab_bytes.length;
	}

	/**
	 * get name of this symbol
	 * @return name of this symbol entry
	 */
	public String getName() {
		// TODO Auto-generated method stub
		return this.name;
	}

	/**
	 * get the type of symbol
	 * @return type of symbol
	 */
	public String getType() {
		// TODO Auto-generated method stub
		return this.type;
	}

	/**
	 * address of the symbol
	 * @return address of the symbol
	 */
	public long getAddress() {
		// TODO Auto-generated method stub
		return this.address;
	}

	/**
	 * returns symtab 'other'
	 * @return other, as per .symtab specification
	 */
	public int getOther() {
		// TODO Auto-generated method stub
		return 0;
	}

	/**
	 * get binding attributes
	 * @return numerical binding attribute
	 */
	public int getBindingAttributes() {
		// TODO Auto-generated method stub
		return this.bindingAttributes;
	}

	/**
	 * The size that this symbol occupies,
	 * @return size of the symbol's data
	 */
	public int getSize() {
		// TODO Auto-generated method stub
		return (int) this.size;
	}
	
	/**
	 * set the address, which is definted as the 8-16th byte in .symtab
	 */
	private void setAddress() {
		int start = 0;
		// value is 8 bytes into the symbol table, so start here
		for(int i = 8; i<16; i++) {
			this.valueBytes[i-8] = this.symtab_bytes[i];
		}
	    ByteBuffer value_bytes = ByteBuffer.wrap(this.valueBytes);
	    value_bytes.order(ByteOrder.LITTLE_ENDIAN); // or LITTLE_ENDIAN
	    this.address = value_bytes.getLong();
	}

	/**
	 * set size of the symbol, occupying 16th-24th bytes
	 */
	private void setSize() {
		for(int i = 16; i<24; i++) {
			this.sizeBytes[i-16] = this.symtab_bytes[i];
		}
	    ByteBuffer size_bytes = ByteBuffer.wrap(this.sizeBytes);
	    size_bytes.order(ByteOrder.LITTLE_ENDIAN); // or LITTLE_ENDIAN
	    this.size = size_bytes.getLong();
	}	
	
	/**
	 * set binding attribute and symbol types. Reads one byte to determine this
	 * Binding attributes are the most significant two bits.
	 * Symbol type is the least significant two bits
	 */
	private void setInfo() {
		int st_info = this.symtab_bytes[4]&0xff;
		this.bindingAttributes = st_info>>4;
		this.symbolType = st_info & 0x0f;
		setSymbolTypeString();
	}
	
	/**
	 * certain symbol types refer to different things. Really, we're just interesting in 
	 * functions though!
	 */
	public void setSymbolTypeString() {
		switch (this.symbolType) {
			case 0: this.type = "STT_NOTYPE";
					break;
			case 1: this.type = "STT_OBJECT";
					break;
			case 2: this.type = "STT_FUNCT";
					break;
			case 3: this.type = "STT_SECTION";
					break;
			case 4: this.type = "STT_FILE";
					break;
			case 5: this.type = "STT_COMMON";
					break;
			case 6: this.type = "STT_TLS";
					break;
			case 10:this.type = "STT_LOOS";
					break;
			case 12: this.type = "STT_HIOS";
					break;
			case 13: this.type = "STT_LOPROC/SPARC_REG";
					break;
			case 15: this.type = "STT_NOTYPE";
					break;
		}
	}
	
	/**
	 * head to the offset in .strtab to get the string representation of this symbol.
	 * strtab entry is terminated by the null byte, so read until it's reached
	 */
	private void setName() {
		setNameOffset();
	    byte start = 0;
	    String name = "";
	    while(this.strtab_bytes[this.nameOffset+start]!=0) {
	        String strAsciiTab = Character.toString((char) this.strtab_bytes[this.nameOffset+start]);
	        name = name.concat(strAsciiTab);
	    	start++;
	    }
    	this.name = name;
	}
	
	/**
	 * set the name offset, stored in symtab
	 */
	private void setNameOffset() {
		for (int i = 0; i<4; i++) {
			this.nameOffsetBytes [i] = this.symtab_bytes[i];
		}
		
	    ByteBuffer offset_bytes = ByteBuffer.wrap(this.nameOffsetBytes);
	    offset_bytes.order(ByteOrder.LITTLE_ENDIAN); // or LITTLE_ENDIAN
	    nameOffset = offset_bytes.getInt();
	}
	
	
}