package program;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableModel;

import capstone.Capstone;

public class InstructionTableModel extends AbstractTableModel {

	private static final String[] columnNames = { "Function", "Address", "Mnemonic", "Opstring" };
	private ArrayList<Capstone.CsInsn> instructions;
	private List<Function> functions;
	private Map<Integer, BasicBlock> blocks;
	
	public InstructionTableModel() {
	
	}
	
	public void setModel(ArrayList<Capstone.CsInsn> instructions, List<Function> list, Map<Integer, BasicBlock> blocks) {
		this.instructions = instructions; 
		this.functions = list; 
		this.blocks = blocks;
	}
	
	@Override
	public int getRowCount() {
		// TODO Auto-generated method stub
		return this.instructions.size();
	}

	@Override
	public int getColumnCount() {
		// TODO Auto-generated method stub
		return 4;
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		Capstone.CsInsn instruction = this.instructions.get(rowIndex);
		switch(columnIndex) {
		case 0:
			for(Function ff:this.functions) {
				if(ff.getStartAddr()==instruction.address) {
					return ff.getName();
				}
			}			
			return "-";
		case 1: 
			return "0x"+Integer.toHexString((int) instruction.address);
		case 2:
			return instruction.mnemonic;
		case 3:
			return instruction.opStr;
		default:
			return "";
		}
	}
	
	public String getColumnName(int column) {
		return this.columnNames[column];
	}

}
