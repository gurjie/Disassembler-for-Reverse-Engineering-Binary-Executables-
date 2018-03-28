package program;

import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.LayoutManager;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

/**
 * view for the export dialogue box which appears when export selected instruction is selected
 * @author gurjan
 *
 */
public class ExportView {
	private JPanel panel;
	private FlowLayout flowLayout;
	private JLabel lblNewLabel_1;
	private JPanel panel_2;
	private JSplitPane splitPane;
	private JPanel panel_3;
	private JPanel panel_4;

	private JRadioButton rdbtnNewRadioButton1;
	private JRadioButton rdbtnNewRadioButton2;
	private JRadioButton rdbtnNewRadioButton3;
	private JRadioButton rdbtnNewRadioButton4;
	private JRadioButton rdbtnNewRadioButton5;
	private JLabel previewLabel;
	private JTextArea textField;
	private JTextField textField1;
	private JButton changeButton;
	private JButton cancelButton;
	private JButton exportButton;
	private JScrollPane scrollPane;


	public ExportView() {
		panel = new JPanel();
		lblNewLabel_1 = new JLabel("Select Export Format"); //
		panel_2 = new JPanel();//
		splitPane = new JSplitPane();
		panel_3 = new JPanel(); //
		rdbtnNewRadioButton1 = new JRadioButton("name, addr, mnemonic, opstr");
		rdbtnNewRadioButton2 = new JRadioButton("addr, mnemonic, opstr");
		rdbtnNewRadioButton3 = new JRadioButton("mnemonic, opstr");
		rdbtnNewRadioButton4 = new JRadioButton("Hex (spaces)");
		rdbtnNewRadioButton5 = new JRadioButton("Hex (no spaces)");
		previewLabel = new JLabel("Preview:");
		textField = new JTextArea();
		panel_4 = new JPanel(); //
		textField1 = new JTextField();
		changeButton = new JButton("Change Directory");
		cancelButton = new JButton("Cancel");
		exportButton = new JButton("Export");
		scrollPane = new JScrollPane(textField);


	}

	public JScrollPane getScrollPane() {
		return scrollPane;
	}
	
	public JButton getChangeButton() {
		return changeButton;
	}

	public JButton getCancelButton() {
		return cancelButton;
	}

	public JButton getExportButton() {
		return exportButton;
	}

	public JTextField getTextField1() {
		return this.textField1;
	}

	public JTextArea getTextField() {
		return this.textField;
	}

	public JLabel getPreviewLabel() {
		return previewLabel;
	}

	public JRadioButton getFromNameButton() {
		return rdbtnNewRadioButton1;
	}

	public JRadioButton getFromAddrButton() {
		return rdbtnNewRadioButton2;
	}

	public JRadioButton getFromMnemButton() {
		return rdbtnNewRadioButton3;
	}

	public JRadioButton getHexButton() {
		return rdbtnNewRadioButton4;
	}

	public JRadioButton getHexNoSpacesButton() {
		return rdbtnNewRadioButton5;
	}

	public JSplitPane getSplitPane() {
		return this.splitPane;
	}

	public JLabel getLabel1() {
		return this.lblNewLabel_1;
	}

	public JPanel getPanel() {
		return this.panel;
	}

	public JPanel getPanel2() {
		return this.panel_2;
	}

	public FlowLayout getFlowLayout() {
		return this.flowLayout;
	}

	public void setFlowLayout(LayoutManager m) {
		this.flowLayout = (FlowLayout) m;

	}

	public JPanel getPanel3() {
		// TODO Auto-generated method stub
		return this.panel_3;
	}

	public JPanel getPanel4() {
		return this.panel_4;
	}

}
