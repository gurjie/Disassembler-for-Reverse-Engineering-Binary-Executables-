package first;

import java.awt.FlowLayout;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JToolBar;

public class View {

	// View uses Swing framework to display UI to user
	
	private JFrame frame;
	/*
	private JLabel firstnameLabel;
	private JLabel lastnameLabel;
	private JTextField firstnameTextfield;
	private JTextField lastnameTextfield;
	private JButton firstnameSaveButton;
	private JButton lastnameSaveButton;
	private JButton hello;
	private JButton bye;
	*/
	
	private JMenuBar menuBar;
	private JMenu menuFile;
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
	private JPanel minigraphPanel;
	private FlowLayout fl_minigraphPanel;
	private JScrollPane listScrollPane;
	private JList functionList;
	private JLabel lblFunctions;
	private JSplitPane mainPane; // The pane splitting graph and instruction panels
	private JScrollPane instScrollPane;
	private JPanel instPanel;
	private JScrollPane graphScrollPane;
	private JPanel graphPane;
	private FlowLayout fl_graphPane;
	
	public View(String title) {
		frame = new JFrame(title);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.setBounds(100,100,1261,808);
		frame.setVisible(true);

		// Create UI elements
		menuBar = new JMenuBar();
		menuFile = new JMenu("File");
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
		minigraphPanel = new JPanel();
		listScrollPane = new JScrollPane();
		functionList = new JList();
		lblFunctions = new JLabel("Functions");
		mainPane = new JSplitPane();
		instScrollPane = new JScrollPane();
		instPanel = new JPanel();
		graphScrollPane = new JScrollPane();
		graphPane = new JPanel();

		/*
		firstnameLabel = new JLabel("Firstname :");
		lastnameLabel = new JLabel("Lastname :");
		firstnameTextfield = new JTextField();
		lastnameTextfield = new JTextField();
		firstnameSaveButton = new JButton("Save firstname");
		lastnameSaveButton = new JButton("Save lastname");
		hello = new JButton("Hello!");
		bye = new JButton("Bye!");
		
		GroupLayout layout = new GroupLayout(frame.getContentPane());
		layout.setAutoCreateGaps(true);
		layout.setAutoCreateContainerGaps(true);
		layout.setHorizontalGroup(layout.createSequentialGroup()
				.addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(firstnameLabel)
						.addComponent(lastnameLabel))
				.addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(firstnameTextfield)
						.addComponent(lastnameTextfield))
				.addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(firstnameSaveButton)
						.addComponent(lastnameSaveButton))
				.addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING).addComponent(hello)
						.addComponent(bye)));
		layout.setVerticalGroup(layout.createSequentialGroup()
				.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(firstnameLabel)
						.addComponent(firstnameTextfield).addComponent(firstnameSaveButton).addComponent(hello))
				.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(lastnameLabel)
						.addComponent(lastnameTextfield).addComponent(lastnameSaveButton).addComponent(bye)));

		layout.linkSize(SwingConstants.HORIZONTAL, firstnameSaveButton, lastnameSaveButton);
		layout.linkSize(SwingConstants.HORIZONTAL, hello, bye);
		frame.getContentPane().setLayout(layout);*/
	}

	public JMenuBar getMenuBar() {
		return menuBar;
	}

	public JMenu getMenuFile() {
		return menuFile;
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

	public JPanel getMinigraphPanel() {
		return minigraphPanel;
	}
	
	public void setFlMinigraphPanel () {
		fl_minigraphPanel = (FlowLayout) this.minigraphPanel.getLayout();
	}
	
	public FlowLayout getFlMinigraphPanel () {
		return this.fl_minigraphPanel;
	}

	public JScrollPane getListScrollPane() {
		return listScrollPane;
	}

	public JList getFunctionList() {
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

	public JScrollPane getGraphScrollPane() {
		return graphScrollPane;
	}

	public JPanel getGraphPane() {
		return graphPane;
	}

	public void setFlGraphPane () {
		this.fl_graphPane = (FlowLayout) graphPane.getLayout();
	}
	
	public FlowLayout getFlGraphPane () {
		return fl_graphPane;
	}
	
	public JFrame getFrame() {
		return frame;
	}

	public void setFrame(JFrame frame) {
		this.frame = frame;
	}

	/*
	public JLabel getFirstnameLabel() {
		return firstnameLabel;
	}

	public void setFirstnameLabel(JLabel firstnameLabel) {
		this.firstnameLabel = firstnameLabel;
	}

	public JLabel getLastnameLabel() {
		return lastnameLabel;
	}

	public void setLastnameLabel(JLabel lastnameLabel) {
		this.lastnameLabel = lastnameLabel;
	}

	public JTextField getFirstnameTextfield() {
		return firstnameTextfield;
	}

	public void setFirstnameTextfield(JTextField firstnameTextfield) {
		this.firstnameTextfield = firstnameTextfield;
	}

	public JTextField getLastnameTextfield() {
		return lastnameTextfield;
	}

	public void setLastnameTextfield(JTextField lastnameTextfield) {
		this.lastnameTextfield = lastnameTextfield;
	}

	public JButton getFirstnameSaveButton() {
		return firstnameSaveButton;
	}

	public void setFirstnameSaveButton(JButton firstnameSaveButton) {
		this.firstnameSaveButton = firstnameSaveButton;
	}

	public JButton getLastnameSaveButton() {
		return lastnameSaveButton;
	}

	public void setLastnameSaveButton(JButton lastnameSaveButton) {
		this.lastnameSaveButton = lastnameSaveButton;
	}

	public JButton getHello() {
		return hello;
	}

	public void setHello(JButton hello) {
		this.hello = hello;
	}

	public JButton getBye() {
		return bye;
	}

	public void setBye(JButton bye) {
		this.bye = bye;
	}*/

}