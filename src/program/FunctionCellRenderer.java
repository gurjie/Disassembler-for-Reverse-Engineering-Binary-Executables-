package program;

import java.awt.Color;
import java.awt.Component;

import javax.swing.DefaultListCellRenderer;
import javax.swing.JList;
import javax.swing.ListCellRenderer;

/**
 * Build a cell rendered for functions, so that functions not available to view for disassembly are displayed in red
 * @author gurjan
 *
 */
public class FunctionCellRenderer extends DefaultListCellRenderer {
	private static ListCellRenderer<? super Function> getCellRenderer() {
	    return new DefaultListCellRenderer(){
	        @Override
	        public Component getListCellRendererComponent(JList<?> list,Object value, int index, boolean isSelected,boolean cellHasFocus) {
	            Component listCellRendererComponent = super.getListCellRendererComponent(list, value, index, isSelected,cellHasFocus);
	            if(value instanceof Function){
	                listCellRendererComponent.setBackground(Color.RED);
	            } else {
	                listCellRendererComponent.setBackground(list.getBackground());
	            }
	            return listCellRendererComponent;
	        }
	    };
	}
 }