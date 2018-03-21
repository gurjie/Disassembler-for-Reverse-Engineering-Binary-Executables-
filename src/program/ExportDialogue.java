package program;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.Point;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;

public class ExportDialogue extends JDialog {
	private Model model;
	private ExportView view;
	private JTable instTable;
	public final int COPY_FROM_ADDR = 1;
	public final int COPY_FROM_MNEUMONIC = 2;
	public final int COPY_FROM_FUNCT_NAME = 3;
	// private JTextField textField;
	// private JTextField textField_1;

	public ExportDialogue(JFrame parent, ExportView view, String title, JTable instructionTable, Model model) {
		super(parent, title, true);
		this.model = model;
		this.view = view;
		this.instTable = instructionTable;
		if (parent != null) {
			Dimension parentSize = parent.getSize();
			Point p = parent.getLocation();
			setLocation(p.x + parentSize.width / 4, p.y + parentSize.height / 4);
		}
		setDefaultCloseOperation(DISPOSE_ON_CLOSE);
		pack();
		getContentPane().setLayout(new BorderLayout(150, 10));
		view.setFlowLayout(this.view.getPanel().getLayout());
		view.getFlowLayout().setHgap(0);
		getContentPane().add(this.view.getPanel(), BorderLayout.NORTH);
		view.getPanel().add(this.view.getLabel1());
		getContentPane().add(this.view.getPanel2(), BorderLayout.WEST);
		view.getPanel2().setLayout(new GridLayout(0, 1, 0, 0));
		view.getSplitPane().setBorder(BorderFactory.createEmptyBorder(1, 1, 1, 1));
		view.getSplitPane().setOrientation(JSplitPane.VERTICAL_SPLIT);
		view.getPanel2().add(this.view.getSplitPane());
		view.getSplitPane().setLeftComponent(this.view.getPanel3());
		view.getPanel3().setLayout(new GridLayout(0, 1, 0, 0));
		view.getPanel3().add(view.getFromNameButton());
		view.getPanel3().add(view.getFromAddrButton());
		view.getPanel3().add(view.getFromMnemButton());
		view.getPanel3().add(view.getHexNoSpacesButton());
		view.getPanel3().add(view.getHexButton());
		view.getPanel3().add(view.getPreviewLabel());
		view.getSplitPane().setRightComponent(view.getScrollPane());
		view.getScrollPane().setPreferredSize(new Dimension(450, 140));
		getContentPane().add(view.getPanel4(), BorderLayout.SOUTH);
		view.getPanel4().setLayout(new GridLayout(2, 2, 0, 0));
		view.getPanel4().add(view.getTextField1());
		view.getTextField1().setColumns(10);
		view.getPanel4().add(view.getChangeButton());
		view.getPanel4().add(view.getCancelButton());
		view.getPanel4().add(view.getExportButton());
		ButtonGroup group = new ButtonGroup();
		group.add(view.getFromNameButton());
		group.add(view.getFromAddrButton());
		group.add(view.getFromMnemButton());
		group.add(view.getHexButton());
		group.add(view.getHexNoSpacesButton());
		String exportLocation = "";
		String home = System.getProperty("user.home");
		exportLocation = exportLocation.concat(System.getProperty("user.home"));
		String exportDirName = this.model.getFile().getName() + "_exports";
		exportLocation = exportLocation.concat("/" + exportDirName);
		view.getTextField1().setText(exportLocation);
		// add allow listener
		
		view.getCancelButton().addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				setVisible(false);
				dispose();
			}
		});
		
		view.getFromNameButton().addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				String data = buildSelectionString(instTable.getSelectedRows(), COPY_FROM_FUNCT_NAME);
				view.getTextField().setText(data);
				view.getTextField().setCaretPosition(0);

			}
		});

		view.getFromAddrButton().addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				String data = buildSelectionString(instTable.getSelectedRows(), COPY_FROM_ADDR);
				view.getTextField().setText(data);
				view.getTextField().setCaretPosition(0);

			}
		});

		view.getFromMnemButton().addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				String data = buildSelectionString(instTable.getSelectedRows(), COPY_FROM_MNEUMONIC);
				view.getTextField().setText(data);
				view.getTextField().setCaretPosition(0);
			}
		});

		view.getHexButton().addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				int last = Integer.decode(instTable
						.getValueAt(instTable.getSelectedRows()[instTable.getSelectedRows().length - 1], 1).toString());
				int first = Integer.decode(instTable.getValueAt(instTable.getSelectedRows()[0], 1).toString());
				String selectedToHex = model.getHexRepresentationSpaces(first, last, true);
				view.getTextField().setText(selectedToHex);
				view.getTextField().setCaretPosition(0);

			}
		});

		view.getHexNoSpacesButton().addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				int last = Integer.decode(instTable
						.getValueAt(instTable.getSelectedRows()[instTable.getSelectedRows().length - 1], 1).toString());
				int first = Integer.decode(instTable.getValueAt(instTable.getSelectedRows()[0], 1).toString());
				String selectedToHex = model.getHexRepresentationSpaces(first, last, false);
				view.getTextField().setText(selectedToHex);
				view.getTextField().setCaretPosition(0);
			}
		});

		view.getChangeButton().addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				JFileChooser chooser = new JFileChooser();
				chooser.setCurrentDirectory(new java.io.File("."));
				chooser.setDialogTitle("Select Directory");
				chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
				chooser.setAcceptAllFileFilterUsed(false);
				if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
					view.getTextField1().setText(chooser.getSelectedFile().getPath());
				}
			}
		});

		view.getExportButton().addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				File exportDir = new File(view.getTextField1().getText());
				if (!exportDir.exists()) {
					System.out.println("creating directory: " + exportDir.getName());
					boolean result = false;
					try {
						exportDir.mkdir();
						result = true;
					} catch (SecurityException ex) {
						JOptionPane.showMessageDialog(new JFrame(), ex.getMessage(), "Security Exception",
								JOptionPane.ERROR_MESSAGE);
					}
					if (result) {
						System.out.println("DIR created");
					}
				}
				String exportName = model.getFile().getName() + ".txt";
				String exportFileName = model.getFile().getName();
				int exportNumber = 0;
				String exportSuffix = ".txt";
				while (new File(view.getTextField1().getText(), exportName).exists()) {
					exportNumber++;
					exportName = exportFileName.concat(Integer.toString(exportNumber)).concat(exportSuffix);
				}
				System.out.println(exportName);
				File newFile = new File(view.getTextField1().getText(), exportName);
				try {
					FileWriter fw = new FileWriter(newFile);
					fw.write(view.getTextField().getText());
					fw.close();
					JOptionPane.showMessageDialog(new JFrame(), newFile.getName()+" written to "+newFile.getPath(),
							"Success",
							JOptionPane.INFORMATION_MESSAGE);
				} catch (IOException iox) {
					JOptionPane.showMessageDialog(new JFrame(), iox.getMessage(), "File Write Exception",
							JOptionPane.ERROR_MESSAGE);
				}
			}
		});
	}

	public String buildSelectionString(int[] selectedRows, int id) {
		String allSelected = "", row = "";
		for (int x : selectedRows) {
			switch (id) {
			case COPY_FROM_ADDR:
				row = String.format("%s\t%s\t%s\n", this.instTable.getValueAt(x, 1), this.instTable.getValueAt(x, 2),
						this.instTable.getValueAt(x, 3));
				break;
			case COPY_FROM_MNEUMONIC:
				row = String.format("%s\t%s\n", this.instTable.getValueAt(x, 2), this.instTable.getValueAt(x, 3));
				break;
			case COPY_FROM_FUNCT_NAME:
				if (!this.instTable.getValueAt(x, 0).equals("-")) {
					allSelected = allSelected
							.concat("\n" + "----------" + this.instTable.getValueAt(x, 0) + "----------\n");
				}
				row = String.format("%s\t%s\t%s\n", this.instTable.getValueAt(x, 1), this.instTable.getValueAt(x, 2),
						this.instTable.getValueAt(x, 3));
				break;
			default:
			}
			allSelected = allSelected.concat(row);
		}
		System.out.println(allSelected);
		return allSelected;

	}
}