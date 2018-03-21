package program;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Rectangle;

import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JToolBar;

import com.mxgraph.swing.mxGraphComponent;

public class View {

	// View uses Swing framework to display UI to user

	private JFrame frame;
	private JMenuBar menuBar;
	private JMenu menuFile;
	private JMenuItem fileMenuLoad;
	private JMenuItem fileMenuExit;
	private JMenu menuEdit;
	private JMenu menuHelp;
	private JToolBar toolBar;
	private JButton loadButton;
	private JButton exportButton;
	private JButton cfgButton;
	private JButton zoomInButton;
	private JButton zoomOutButton;
	private JSplitPane encompassingPane;
	private JSplitPane functionsPane;
	private JPanel sectionsPanel;
	private JScrollPane sectionsScrollPane;
	private JList<String> sectionsList;
	private JLabel lblSections;
	private JScrollPane listScrollPane;
	private JList<Function> functionList;
	private JLabel lblFunctions;
	private JSplitPane mainPane; // The pane splitting graph and instruction panels
	private JScrollPane instScrollPane;
	private JPanel instPanel;
	private JTable instTable;
	// private JScrollPane graphScrollPane;
	// private JPanel graphPane;
	// private FlowLayout fl_graphPane;
	private DefaultListModel<String> sectionModel;
	private DefaultListModel<Function> functionModel;
	private JTabbedPane graphTabbedPane;
	private JPopupMenu popup;
	private JMenuItem exportSelected;
	private JMenuItem copy;
	private JMenuItem copyAll;
	private JMenuItem copyInstructions;
	private InstructionTableModel InstructionTableModel;
	

	public View(String title) {
		frame = new JFrame(title);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.setBounds(100, 100, 1261, 808);
		frame.setVisible(true);

		menuBar = new JMenuBar();
		menuFile = new JMenu("File");
		fileMenuLoad = new JMenuItem("Load Executable");
		fileMenuExit = new JMenuItem("Exit");
		menuEdit = new JMenu("Edit");
		menuHelp = new JMenu("Help");
		toolBar = new JToolBar();
		loadButton = new JButton("Load File");
		exportButton = new JButton("Export");
		cfgButton = new JButton("CFG");
		zoomInButton = new JButton("Zoom In");
		zoomOutButton = new JButton("Zoom Out");
		encompassingPane = new JSplitPane();
		functionsPane = new JSplitPane();
		sectionsPanel = new JPanel();
		sectionsScrollPane = new JScrollPane();
		sectionModel = new DefaultListModel<>();
		sectionsList = new JList<>(sectionModel);
		lblSections = new JLabel("ELF Sections");
		listScrollPane = new JScrollPane();
		functionModel = new DefaultListModel<Function>();
		functionList = new JList<>(functionModel);
		lblFunctions = new JLabel("Functions");
		mainPane = new JSplitPane();
		instScrollPane = new JScrollPane();
		instPanel = new JPanel();
		instTable = new JTable();
		// graphScrollPane = new JScrollPane();
		// graphPane = new JPanel();
		graphTabbedPane = new JTabbedPane(JTabbedPane.TOP);
		popup = new JPopupMenu();
		exportSelected = new JMenuItem("Export selected...");
		copy = new JMenuItem("Copy (addr, mneumonic, opstring)");
		copyAll = new JMenuItem("Copy (function, addr, mneumonic, opstring)");
		copyInstructions = new JMenuItem("Copy (mneumonic, opstring)");
		InstructionTableModel = new InstructionTableModel();
	}

	
	public JPopupMenu getPopup() {
		return popup;
	}
	
	public JMenuItem getExportSelected() {
		return exportSelected;
	}

	public JMenuItem getCopy() {
		return copy;
	}

	public JMenuItem getCopyAll() {
		return copyAll;
	}
	
	public JMenuItem getCopyInstructions() {
		return copyInstructions;
	}

	public InstructionTableModel getModel() {
		return InstructionTableModel;
	}

	
	public JTabbedPane getGraphTabbedPane() {
		return graphTabbedPane;
	}

	public JTable getInstTable() {
		return instTable;
	}

	public DefaultListModel<String> getSectionModel() {
		return sectionModel;
	}

	public DefaultListModel<Function> getFunctionModel() {
		return functionModel;
	}

	public JMenuBar getMenuBar() {
		return menuBar;
	}

	public JMenu getMenuFile() {
		return menuFile;
	}

	public JMenuItem getFileMenuLoad() {
		return fileMenuLoad;
	}

	public JMenuItem getFileMenuExit() {
		return fileMenuExit;
	}

	public JMenu getMenuEdit() {
		return menuEdit;
	}

	public JMenu getMenuHelp() {
		return menuHelp;
	}

	public JToolBar getToolBar() {
		return toolBar;
	}

	public JButton getLoadButton() {
		return loadButton;
	}

	public JButton getExportButton() {
		return exportButton;
	}

	public JButton getCfgButton() {
		return cfgButton;
	}

	public JButton getZoomInButton() {
		return zoomInButton;
	}

	public JButton getZoomOutButton() {
		return zoomOutButton;
	}

	public JSplitPane getEncompassingPane() {
		return encompassingPane;
	}

	public JSplitPane getFunctionsPane() {
		return functionsPane;
	}

	public JPanel getSectionsPanel() {
		return sectionsPanel;
	}

	public JScrollPane getSectionsScrollPane() {
		return sectionsScrollPane;
	}

	public JList<String> getSectionsList() {
		return sectionsList;
	}

	public JLabel getLblSections() {
		return lblSections;
	}

	public JScrollPane getListScrollPane() {
		return listScrollPane;
	}

	public JList<Function> getFunctionList() {
		return functionList;
	}

	public JLabel getFunctionLabel() {
		return lblFunctions;
	}

	public JSplitPane getMainPane() {
		return mainPane;
	}

	public JScrollPane getInstScrollPane() {
		return instScrollPane;
	}

	public JPanel getInstPanel() {
		return instPanel;
	}

	/*
	 * public JScrollPane getGraphScrollPane() { return graphScrollPane; }
	 * 
	 * public JPanel getGraphPane() { return graphPane; }
	 * 
	 * public void setFlGraphPane () { this.fl_graphPane = (FlowLayout)
	 * graphPane.getLayout(); }
	 * 
	 * public FlowLayout getFlGraphPane () { return fl_graphPane; }
	 */

	public JFrame getFrame() {
		return frame;
	}

	public void setFrame(JFrame frame) {
		this.frame = frame;
	}

	/*
	 * public void resetGraphPane() { this.graphPane = new JPanel(); }
	 * 
	 * public void resetGraphScrollPane() { this.graphScrollPane = new
	 * JScrollPane(); }
	 */

	public void addTab(String name, mxGraphComponent component) {
		if (this.graphTabbedPane.indexOfTab(name) == -1) {
			JScrollPane newScrollPane = new JScrollPane();
			JPanel graphPanel = new JPanel();
			FlowLayout fl_graphPanel = (FlowLayout) graphPanel.getLayout();
			fl_graphPanel.setHgap(150);
			newScrollPane.setViewportView(graphPanel);
			newScrollPane.removeMouseWheelListener(newScrollPane.getMouseWheelListeners()[0]);
			graphPanel.setLayout(new BorderLayout());
			graphPanel.add(component, BorderLayout.CENTER);
			graphPanel.validate();
			this.graphTabbedPane.addTab(name, component);
			this.graphTabbedPane.setSelectedComponent(component);
		} else {
			this.graphTabbedPane.setSelectedIndex(this.graphTabbedPane.indexOfTab(name));
		}
	}

}