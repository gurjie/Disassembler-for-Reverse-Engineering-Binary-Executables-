package first;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class SymbolEntry {

	private byte[] symtab_bytes;
	private byte[] strtab_bytes;
	private byte[] sizeBytes = new byte[8];
	private long size;
	private byte[] valueBytes = new byte[8];
	private long address;
	private int bindingAttributes;
	private int symbolType;
	private String type;
	private byte[] nameOffsetBytes = new byte[4];
	private int nameOffset;
	private String name;
	
	public SymbolEntry(byte[] symtab_bytes, byte[] strtab_bytes) {
		this.symtab_bytes = symtab_bytes;
		this.strtab_bytes = strtab_bytes;
		setSize();
		setAddress();
		setInfo();
		setName();
		// TODO Auto-generated constructor stub
	}

	public int getSymTabSize() {
		return 2640;
		// TODO Auto-generated method stub
		
	}

	public int getStrTabSize() {
		// TODO Auto-generated method stub
		return this.strtab_bytes.length;
	}

	public String getName() {
		// TODO Auto-generated method stub
		return this.name;
	}

	public String getType() {
		// TODO Auto-generated method stub
		return this.type;
	}

	public long getAddress() {
		// TODO Auto-generated method stub
		return this.address;
	}

	public int getOther() {
		// TODO Auto-generated method stub
		return 0;
	}

	public int getBindingAttributes() {
		// TODO Auto-generated method stub
		return this.bindingAttributes;
	}

	public int getSize() {
		// TODO Auto-generated method stub
		return (int) this.size;
	}
	
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
	

	private void setSize() {
		for(int i = 16; i<24; i++) {
			this.sizeBytes[i-16] = this.symtab_bytes[i];
		}
	    ByteBuffer size_bytes = ByteBuffer.wrap(this.sizeBytes);
	    size_bytes.order(ByteOrder.LITTLE_ENDIAN); // or LITTLE_ENDIAN
	    this.size = size_bytes.getLong();
	}	
	
	private void setInfo() {
		int st_info = this.symtab_bytes[4]&0xff;
		this.bindingAttributes = st_info>>4;
		this.symbolType = st_info & 0x0f;
		setSymbolTypeString();
	}
	
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
	
	private void setNameOffset() {
		for (int i = 0; i<4; i++) {
			this.nameOffsetBytes [i] = this.symtab_bytes[i];
		}
		
	    ByteBuffer offset_bytes = ByteBuffer.wrap(this.nameOffsetBytes);
	    offset_bytes.order(ByteOrder.LITTLE_ENDIAN); // or LITTLE_ENDIAN
	    nameOffset = offset_bytes.getInt();
	}
	
	
}