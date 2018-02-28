package program;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;

import javax.imageio.ImageIO;
import javax.swing.DefaultListCellRenderer;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JSplitPane;
import javax.swing.event.ListSelectionEvent;

import com.mxgraph.layout.mxIGraphLayout;
import com.mxgraph.layout.hierarchical.mxHierarchicalLayout;
import com.mxgraph.swing.mxGraphComponent;
import com.mxgraph.util.mxCellRenderer;
import com.mxgraph.view.mxGraph;

public class Controller {

	private Model model;
	private View view;
	private mxGraph graph;
	private boolean loaded;
	private Function selectedFunction;

	public Controller(Model m, View v) {
		model = m;
		view = v;
		initView();
	}

	public void initView() {
		view.getFrame().setJMenuBar(view.getMenuBar());
		view.getMenuBar().add(view.getMenuFile());
		view.getMenuFile().add(view.getFileMenuLoad());
		view.getMenuFile().add(view.getFileMenuExit());
		view.getMenuBar().add(view.getMenuEdit());
		view.getMenuBar().add(view.getMenuHelp());
		view.getFrame().getContentPane().add(view.getToolBar(), BorderLayout.NORTH);
		view.getToolBar().add(view.getLoadButton());
		view.getToolBar().add(view.getExportButton());
		view.getToolBar().add(view.getCfgButton());
		view.getToolBar().add(view.getZoomInButton());
		view.getToolBar().add(view.getZoomOutButton());
		view.getFrame().getContentPane().add(view.getEncompassingPane(), BorderLayout.CENTER);
		view.getFunctionsPane().setOrientation(JSplitPane.VERTICAL_SPLIT);
		view.getEncompassingPane().setLeftComponent(view.getFunctionsPane());
		// view.getSectionsPanel().setBackground(Color.LIGHT_GRAY);
		view.getSectionsList().setVisibleRowCount(14);
		view.getSectionsScrollPane().setViewportView(view.getSectionsList());
		view.getSectionsScrollPane().setColumnHeaderView(view.getLblSections());
		view.getFunctionsPane().setRightComponent(view.getSectionsScrollPane());
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
		view.getGraphScrollPane().removeMouseWheelListener(view.getGraphScrollPane().getMouseWheelListeners()[0]);

		// view.getLastnameTextfield().setText(model.getLastname());
	}

	public void initController() {
		view.getFileMenuLoad().addActionListener(e -> {
			loadFile();
		});
		view.getFileMenuExit().addActionListener(e -> {
			System.exit(0);
		});
		view.getLoadButton().addActionListener(e -> {
			loadFile();
		});
		view.getExportButton().addActionListener(e -> export());
		view.getCfgButton().addActionListener(e -> openCFG());
		// view.getLastnameSaveButton().addActionListener(e -> saveLastname());
		// view.getHello().addActionListener(e -> sayHello());
		// view.getBye().addActionListener(e -> sayBye());
	}

	public void initZoomListeners(mxGraphComponent graphComponent) {
		view.getZoomInButton().addActionListener(e -> zoomIn(graphComponent));
		view.getZoomOutButton().addActionListener(e -> zoomOut(graphComponent));
		// view.getLastnameSaveButton().addActionListener(e -> saveLastname());
		// view.getHello().addActionListener(e -> sayHello());
		// view.getBye().addActionListener(e -> sayBye());
	}

	public void initFunctionsListener() {
		view.getFunctionList().addMouseListener(new MouseAdapter() {
		    public void mouseClicked(MouseEvent evt) {
		        JList list = (JList)evt.getSource();
		        if (evt.getClickCount() == 2) {
		        	
		            // Double-click detected
		            int index = list.locationToIndex(evt.getPoint());
		            selectedFunction = view.getFunctionList().getSelectedValue();
		            System.out.println(selectedFunction.getName());
		        } 
		    }
		});
	}

	
	private void graphScroll() {
		System.out.println("Scrolled");
	}

	private void loadFile() {
		view.getFunctionModel().removeAllElements();
		view.getSectionModel().removeAllElements();
		JFileChooser fileChooser = new JFileChooser();
		int returnValue = fileChooser.showOpenDialog(null);
		if (returnValue == JFileChooser.APPROVE_OPTION) {
			File selectedFile = fileChooser.getSelectedFile();
			this.model.setFile(selectedFile);
			try {
				this.model.disassemble();
				loaded = true;
				for (Section s : this.model.getSections()) {
					view.getSectionModel().addElement(s.getName());
				}
				if (!this.model.symTabExists()) {
					JOptionPane.showMessageDialog(
							new JFrame(), "The symbol table could not be "
									+ "resolved. As a result, function names cannot be " + "displayed!",
							"Warning", JOptionPane.WARNING_MESSAGE);
				} else {
					for (Function func : this.model.getFunctions()) {
						view.getFunctionModel().addElement(func);
		                view.getFunctionList().setCellRenderer(new DefaultListCellRenderer() {

		                     @Override
		                     public Component getListCellRendererComponent(JList list, Object value, int index,
		                               boolean isSelected, boolean cellHasFocus) {
		                          Component c = super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
		                          if (value instanceof Function) {
		                               Function function = (Function) value;
		                               setText(function.getName());
		                               if (function.getStartAddr()==0) {
		                                    setForeground(Color.RED);
		                               } else {
		                                    setForeground(Color.BLUE);
		                               }
		                          } else {
		                               // do nothing
		                          }
		                          return c;
		                     }

		                });
					}
					initFunctionsListener();
				}

			} catch (ReadException e) {
				JOptionPane.showMessageDialog(new JFrame(), e.getMessage(), "Exception", JOptionPane.ERROR_MESSAGE);
			} catch (ElfException e) {
				JOptionPane.showMessageDialog(new JFrame(), e.getMessage(), "Not an ELF", JOptionPane.ERROR_MESSAGE);
			}
		}
	}

	private void export() {
		if (this.loaded == true) {
			try {
				String home = System.getProperty("user.home");
				String exportDirName = this.model.getFile().getName() + "_exports";
				File exportDir = new File(home, exportDirName);
				// if the directory does not exist, create it
				if (!exportDir.exists()) {
					System.out.println("creating directory: " + exportDir.getName());
					boolean result = false;
					try {
						exportDir.mkdir();
						result = true;
					} catch (SecurityException e) {
						JOptionPane.showMessageDialog(new JFrame(), e.getMessage(), "Security Exception",
								JOptionPane.ERROR_MESSAGE);
					}
					if (result) {
						System.out.println("DIR created");
					}
				}
				String exportName = "export.png";
				int exportNumber = 0;
				String exportFileName = "export";
				String exportSuffix = ".png";
				while (new File(home + "/" + exportDirName, exportName).exists()) {
					exportNumber++;
					exportName = exportFileName.concat(Integer.toString(exportNumber)).concat(exportSuffix);
				}
				System.out.println(exportName);

				File newFile = new File(home + "/" + exportDirName, exportName);
				BufferedImage image = mxCellRenderer.createBufferedImage(this.graph, null, 1, Color.WHITE, true, null);
				ImageIO.write(image, "PNG", newFile);
				JOptionPane.showMessageDialog(new JFrame(), "Exported CFG to " + newFile.getPath(), "Export Successful",
						JOptionPane.INFORMATION_MESSAGE);
			} catch (IOException e) {
				JOptionPane.showMessageDialog(new JFrame(), e.getMessage(), "Export error", JOptionPane.ERROR_MESSAGE);
			} catch (NullPointerException e) {
				JOptionPane.showMessageDialog(new JFrame(), "No CFG to export", "Graph error",
						JOptionPane.ERROR_MESSAGE);
			}
		}
	}

	private void openCFG() {
		view.getGraphPane().removeAll();
		// initialise the control flow graph shower
		// start the popup CFG with model.showCfg as input, which returns a string
		this.graph = new mxGraph();

		Object parent = graph.getDefaultParent();
		graph.getModel().beginUpdate();
		try {
			Object v1 = graph.insertVertex(parent, null, "asflfsaljiasflij\nflifjliadg", 20, 20, 80, 30);
			Object v2 = graph.insertVertex(parent, null,
					"Worl\nfaelijafijldgajil\nfailaf\nfkaafs\nfakjnfask\nfajkfsfas!", 240, 150, 80, 30);
			Object v3 = graph.insertVertex(parent, null,
					"Worl\nfaelijafijldgajil\nfailaf\nfkaafs\nfakjnfask\nfajkfsfas!", 320, 180, 80, 30);
			Object v4 = graph.insertVertex(parent, null, "1", 370, 250, 80, 30);
			Object v5 = graph.insertVertex(parent, null, "2", 370, 250, 80, 30);
			Object v6 = graph.insertVertex(parent, null, "3", 370, 250, 80, 30);
			Object v7 = graph.insertVertex(parent, null, "4", 370, 250, 80, 30);
			Object v8 = graph.insertVertex(parent, null, "5", 370, 250, 80, 30);
			Object v9 = graph.insertVertex(parent, null, "6", 370, 250, 80, 30);
			Object v10 = graph.insertVertex(parent, null, "7", 370, 250, 80, 30);
			Object v11 = graph.insertVertex(parent, null, "5", 370, 250, 80, 30);
			Object v12 = graph.insertVertex(parent, null, "6", 370, 250, 80, 30);
			Object v13 = graph.insertVertex(parent, null, "7", 370, 250, 80, 30);
			Object v14 = graph.insertVertex(parent, null, "5", 370, 250, 80, 30);
			Object v15 = graph.insertVertex(parent, null, "6", 370, 250, 80, 30);
			Object v16 = graph.insertVertex(parent, null, "7", 370, 250, 80, 30);
			Object v17 = graph.insertVertex(parent, null, "5", 370, 250, 80, 30);
			Object v18 = graph.insertVertex(parent, null, "6", 370, 250, 80, 30);
			Object v19 = graph.insertVertex(parent, null, "7", 370, 250, 80, 30);

			graph.setCellsResizable(true);
			graph.updateCellSize(v2);
			graph.insertEdge(parent, null, "", v1, v2);
			graph.insertEdge(parent, null, "", v2, v3);
			graph.insertEdge(parent, null, "", v1, v4);
			graph.insertEdge(parent, null, "", v8, v5);
			graph.insertEdge(parent, null, "", v5, v6);
			graph.insertEdge(parent, null, "", v7, v1);
			graph.insertEdge(parent, null, "", v9, v1);
			graph.insertEdge(parent, null, "", v1, v7);
			graph.insertEdge(parent, null, "", v4, v1);
			graph.insertEdge(parent, null, "", v7, v8);
			graph.insertEdge(parent, null, "", v1, v9);
			graph.insertEdge(parent, null, "", v4, v10);

			graph.setCellsDisconnectable(false);
			graph.setEdgeLabelsMovable(false);

			System.out.println("built!");
		} finally {
			graph.getModel().endUpdate();
		}
		mxGraphComponent graphComponent = new mxGraphComponent(graph);
		graphComponent.getGraphControl().addMouseListener(new MouseAdapter() {
			public void mouseReleased(MouseEvent e) {
				Object cell = graphComponent.getCellAt(e.getX(), e.getY());
				if (cell != null) {

					System.out.println("cell=" + graph.getLabel(cell));
				}
			}
		});
		mxIGraphLayout layout = new mxHierarchicalLayout(graph);
		layout.execute(graph.getDefaultParent());
		// graph.groupCells();
		graph.setCellsEditable(false);
		graphComponent.setConnectable(false);
		view.getGraphPane().setLayout(new BorderLayout());
		view.getGraphPane().add(graphComponent, BorderLayout.CENTER);
		view.getGraphPane().validate();
		initZoomListeners(graphComponent);
	}

	private void zoomIn(mxGraphComponent graphComponent) {
		graphComponent.zoomIn();
		graphComponent.validate();
	}

	private void zoomOut(mxGraphComponent graphComponent) {
		graphComponent.zoomOut();
		graphComponent.validate();
	}

	/*
	 * private void saveLastname() {
	 * model.setLastname(view.getLastnameTextfield().getText());
	 * JOptionPane.showMessageDialog(null, "Lastname saved : " +
	 * model.getLastname(), "Info", JOptionPane.INFORMATION_MESSAGE); }
	 * 
	 * private void sayHello() { JOptionPane.showMessageDialog(null, "Hello " +
	 * model.getFirstname() + " " + model.getLastname(), "Info",
	 * JOptionPane.INFORMATION_MESSAGE); }
	 * 
	 * private void sayBye() { System.exit(0); }
	 */

}