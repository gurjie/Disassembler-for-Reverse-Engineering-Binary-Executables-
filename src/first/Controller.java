package first;

import java.awt.BorderLayout;
import java.awt.Color;
import javax.swing.JSplitPane;

public class Controller {

	private Model model;
	private View view;

	public Controller(Model m, View v) {
		model = m;
		view = v;
		initView();
	}

	public void initView() {
		view.getFrame().setJMenuBar(view.getMenuBar());
		view.getMenuBar().add(view.getMenuFile());
		view.getMenuBar().add(view.getMenuEdit());
		view.getMenuBar().add(view.getMenuHelp());
		view.getFrame().getContentPane().add(view.getToolBar(), BorderLayout.NORTH);
		view.getToolBar().add(view.getLoadButton());
		view.getToolBar().add(view.getExportButton());
		view.getToolBar().add(view.getCfgButton());
		view.getFrame().getContentPane().add(view.getEncompassingPane(), BorderLayout.CENTER);
		view.getFunctionsPane().setOrientation(JSplitPane.VERTICAL_SPLIT);
		view.getEncompassingPane().setLeftComponent(view.getFunctionsPane());
		view.getMinigraphPanel().setBackground(Color.LIGHT_GRAY);
		view.setFlMinigraphPanel();
		view.getFlMinigraphPanel().setVgap(40);
		view.getFlMinigraphPanel().setHgap(90);
		view.getFunctionsPane().setRightComponent(view.getMinigraphPanel());
		view.getFunctionsPane().setLeftComponent(view.getListScrollPane());
		view.getFunctionList().setVisibleRowCount(14);
		view.getListScrollPane().setViewportView(view.getFunctionList());
		view.getListScrollPane().setColumnHeaderView(view.getFunctionLabel());
		view.getEncompassingPane().setRightComponent(view.getMainPane());
		view.getMainPane().setRightComponent(view.getInstScrollPane());
		view.getInstScrollPane().setViewportView(view.getInstPanel());
		view.getMainPane().setLeftComponent(view.getGraphScrollPane());
		view.setFlGraphPane();
		view.getFlGraphPane().setHgap(150);
		view.getGraphScrollPane().setViewportView(view.getGraphPane());
		
		
		
		//view.getLastnameTextfield().setText(model.getLastname());
	}

	public void initController() {
		view.getLoadButton().addActionListener(e -> loadFile());
		view.getExportButton().addActionListener(e -> export());
		view.getCfgButton().addActionListener(e -> openCFG());

		//view.getLastnameSaveButton().addActionListener(e -> saveLastname());
		//view.getHello().addActionListener(e -> sayHello());
		//view.getBye().addActionListener(e -> sayBye());
	}
	
	private void loadFile() {
		System.out.println("Pressed");
	}
	
	private void export() {
		System.out.println("Pressed");
	}
	
	private void openCFG() {
		// initialise the control flow graph shower
		// start the popup CFG with model.showCfg as input, which returns a string 
		System.out.println("Pressed");
	}
	/*
	private void saveLastname() {
		model.setLastname(view.getLastnameTextfield().getText());
		JOptionPane.showMessageDialog(null, "Lastname saved : " + model.getLastname(), "Info",
				JOptionPane.INFORMATION_MESSAGE);
	}

	private void sayHello() {
		JOptionPane.showMessageDialog(null, "Hello " + model.getFirstname() + " " + model.getLastname(), "Info",
				JOptionPane.INFORMATION_MESSAGE);
	}

	private void sayBye() {
		System.exit(0);
	}*/

}