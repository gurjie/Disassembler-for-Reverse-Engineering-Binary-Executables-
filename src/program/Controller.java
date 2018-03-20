package program;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Point;
import java.awt.Rectangle;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;

import javax.imageio.ImageIO;
import javax.swing.DefaultListCellRenderer;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JViewport;
import javax.swing.event.ListSelectionEvent;
import javax.swing.table.DefaultTableModel;

import com.mxgraph.layout.mxCompactTreeLayout;
import com.mxgraph.layout.mxIGraphLayout;
import com.mxgraph.layout.hierarchical.mxHierarchicalLayout;
import com.mxgraph.model.mxCell;
import com.mxgraph.swing.mxGraphComponent;
import com.mxgraph.util.mxCellRenderer;
import com.mxgraph.util.mxConstants;
import com.mxgraph.view.mxGraph;
import com.mxgraph.view.mxStylesheet;

import capstone.Capstone;

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
		//view.getInstScrollPane().setLayout(new BorderLayout());
		//view.getInstScrollPane().setViewportView(view.getInstPanel());
		//view.getInstPanel().setLayout(new BorderLayout());
		view.getMainPane().setLeftComponent(view.getGraphTabbedPane());
		view.getMainPane().setDividerLocation(450);
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
	}

	public void initZoomListeners(mxGraphComponent graphComponent) {
		view.getZoomInButton().addActionListener(e -> zoomIn(graphComponent));
		view.getZoomOutButton().addActionListener(e -> zoomOut(graphComponent));
	}

	public ArrayList<Capstone.CsInsn> getInstructionList() {
		ArrayList<Capstone.CsInsn> instructions = new ArrayList<Capstone.CsInsn>();
		Iterator<BasicBlock> blockIterator = this.model.getBasicBlocks().values().iterator();
		while (blockIterator.hasNext()) {
			BasicBlock current = blockIterator.next();
			instructions.addAll(current.getInstructionList());
		}

		return instructions;
	}
	
	public void initFunctionsListener() {
		view.getFunctionList().addMouseListener(new MouseAdapter() {
			public void mouseClicked(MouseEvent evt) {
				JList list = (JList) evt.getSource();
				if (evt.getClickCount() == 2) {
					int index = list.locationToIndex(evt.getPoint());
					selectedFunction = view.getFunctionList().getSelectedValue();
					if (selectedFunction.getStartAddr() == 0) {
						System.out.println("x");
						JOptionPane.showMessageDialog(new JFrame(),
								selectedFunction.getName() + " is a shared library! Can't display disassembly.",
								"Shared library", JOptionPane.INFORMATION_MESSAGE);
					} else {
						try {
							showCFG(selectedFunction);
						} catch(NullPointerException e) {
							JOptionPane.showMessageDialog(new JFrame(),
									"This function was not disassembled!",
									"Critical", JOptionPane.ERROR_MESSAGE);
						}
					}

				}
			}
		});
	}

	private void graphScroll() {
		System.out.println("Scrolled");
	}

	private void loadFile() {
		view.getGraphTabbedPane().removeAll();
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
					JOptionPane.showMessageDialog(new JFrame(), "The symbol table could not be "
							+ "resolved. As a result, function names have been resolved by function prologue discovery.",
							"Warning", JOptionPane.WARNING_MESSAGE);
				}
				for (Function func : this.model.getFunctions()) {
					view.getFunctionModel().addElement(func);
					view.getFunctionList().setCellRenderer(new DefaultListCellRenderer() {

						@Override
						public Component getListCellRendererComponent(JList list, Object value, int index,
								boolean isSelected, boolean cellHasFocus) {
							Component c = super.getListCellRendererComponent(list, value, index, isSelected,
									cellHasFocus);
							if (value instanceof Function) {
								Function function = (Function) value;
								setText(function.getName());
								if (function.getStartAddr() == 0) {
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
				InstructionTableModel model = new InstructionTableModel(getInstructionList(),this.model.getFunctions(),this.model.getBasicBlocks());
				view.getInstTable().setModel(model);
				view.getInstScrollPane().getViewport().add(view.getInstTable());
				view.getInstTable().setShowGrid(false);
				//view.getInstTable().getModel().setValueAt(aValue, rowIndex, columnIndex);
				initFunctionsListener();

			} catch (ReadException e) {
				JOptionPane.showMessageDialog(new JFrame(), e.getMessage(), "Exception", JOptionPane.ERROR_MESSAGE);
			} catch (ElfException e) {
				JOptionPane.showMessageDialog(new JFrame(), e.getMessage(), "Not an ELF", JOptionPane.ERROR_MESSAGE);
			} catch (MainDiscoveryException e) {
				JOptionPane.showMessageDialog(new JFrame(), e.getMessage(), "Couldn't find main()",
						JOptionPane.ERROR_MESSAGE);
				e.printStackTrace();
			}
		}
	}

	private void export() {
		if (this.loaded == true) {
			try {
				String name = selectedFunction.getName();
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
				String exportName = name + ".png";
				int exportNumber = 0;
				String exportFileName = name;
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

	private static BasicBlock findNearest(Map<Integer, BasicBlock> map, int value) {
		Map.Entry<Integer, BasicBlock> previousEntry = null;
		for (Entry<Integer, BasicBlock> e : map.entrySet()) {
			if (e.getKey().compareTo(value) >= 0) {
				if (previousEntry == null) {
					return e.getValue();
				} else {
					if (e.getKey() - value >= value - previousEntry.getKey()) {
						return previousEntry.getValue();
					} else {
						return e.getValue();
					}
				}
			}
			previousEntry = e;
		}
		return previousEntry.getValue();
	}

	private void showCFG(Function f) {
		this.graph = new mxGraph();
		Object parent = graph.getDefaultParent();
		graph.getModel().beginUpdate();
		try {
			f.setAssociatedAddresses(this.model.getBasicBlocks());
			// store a mapping of basic blocks to vertices
			Map<BasicBlock, Object> blockToVertex = new LinkedHashMap<BasicBlock, Object>();
			BasicBlock first = findNearest(this.model.getBasicBlocks(), f.getStartAddr());
			Object root = graph.insertVertex(graph.getDefaultParent(), Integer.toHexString((first.getFirstAddress())),
					first.instructionsToString(), 240, 150, 80, 30);
			blockToVertex.put(first, root);
			graph.updateCellSize(root);
			int id = 0;
			for (int addr : f.getAssociatedAddresses()) {
				
					BasicBlock block = findNearest(this.model.getBasicBlocks(), addr);
					Object vertex = graph.insertVertex(graph.getDefaultParent(),
							Integer.toHexString((block.getFirstAddress())), block.instructionsToString(), 240, 150, 80, 30);
					blockToVertex.put(block, vertex);
					graph.updateCellSize(vertex);
			}

			// for every basic block connect its reference addresses
			for (int i : f.getAssociatedAddresses()) {
				BasicBlock block0 = findNearest(this.model.getBasicBlocks(), i);
				Object vertex0 = blockToVertex.get(block0);
				for (int x : block0.getAddressReferenceList()) {
					BasicBlock block1 = findNearest(this.model.getBasicBlocks(), x);
					;
					Object vertex1 = blockToVertex.get(block1);
					Object e1 = graph.insertEdge(graph.getDefaultParent(), null, "", vertex0, vertex1);
				}

				for (int x : block0.getLoopAddressReferences()) {
					BasicBlock block1 = findNearest(this.model.getBasicBlocks(), x);
					Object vertex1 = blockToVertex.get(block1);
					Object e1 = graph.insertEdge(graph.getDefaultParent(), null, "", vertex0, vertex1);
				}

			}

			Object vertex0 = blockToVertex.get(first);
			for (int x : first.getAddressReferenceList()) {
				BasicBlock block1 = this.model.getBasicBlocks().get(x);
				Object vertex1 = blockToVertex.get(block1);
				// System.out.println("added");
				Object e1 = graph.insertEdge(graph.getDefaultParent(), null, "", vertex0, vertex1);
			}

		} finally {
			graph.getModel().endUpdate();
		}
		graph.setCellsResizable(true);
		graph.setCellsDisconnectable(false);
		graph.setEdgeLabelsMovable(false);
		graph.alignCells(mxConstants.ALIGN_RIGHT);
		mxGraphComponent graphComponent = new mxGraphComponent(graph);
		graphComponent.getGraphControl().addMouseListener(new MouseAdapter() {
			public void mouseReleased(MouseEvent e) {
				Object cell = graphComponent.getCellAt(e.getX(), e.getY());
				if (cell != null) {
					mxCell selected = (mxCell) cell;
					System.out.println(selected.getId());
					for (int i = 0; i < view.getInstTable().getRowCount(); i++) {
						for (int j = 0; j < view.getInstTable().getColumnCount(); j++) {
							if(view.getInstTable().getValueAt(i, 1).equals("0x"+selected.getId())) {
								scrollToVisibleInstructionBlock(view.getInstTable(),i,
										model.getBasicBlocks().get(Integer.valueOf(selected.getId(), 16).intValue()).getBlockSize());
							}
						}
					}

				}
			}
		});
		mxIGraphLayout layout = new mxHierarchicalLayout(graph);
		layout.execute(graph.getDefaultParent());
		graph.setCellsEditable(false);
		graphComponent.setConnectable(false);

		// scroll to the root cell
		Object[] cells = graph.getChildVertices(graph.getDefaultParent());
		for (Object c : cells) {
			mxCell cell = (mxCell) c;
			if (cell.getId().equals(Integer.toHexString(f.getStartAddr()))) {
				graphComponent.scrollCellToVisible(cell);
			}
		}

		view.addTab(f.getName(), graphComponent);
		initZoomListeners(graphComponent);
		graphComponent.validate();

	}

	private void zoomIn(mxGraphComponent graphComponent) {
		graphComponent.zoomIn();
		graphComponent.validate();
	}

	private void zoomOut(mxGraphComponent graphComponent) {
		graphComponent.zoomOut();
		graphComponent.validate();
	}
	
	public void scrollToVisibleInstruction(JTable table, int rowIndex) {
	    if (!(table.getParent() instanceof JViewport)) return;
	    JViewport viewport = (JViewport)table.getParent();
	    Rectangle rect = table.getCellRect(rowIndex, 0, true);
	    Point pt = viewport.getViewPosition();
	    rect.setLocation(rect.x-pt.x, rect.y-pt.y);
	    viewport.scrollRectToVisible(rect);
	    table.setRowSelectionInterval(rowIndex, rowIndex);
	}
	
	public void scrollToVisibleInstructionBlock(JTable table, int rowIndex, int sizeOfBlock) {
	    if (!(table.getParent() instanceof JViewport)) return;
	    JViewport viewport = (JViewport)table.getParent();
	    Rectangle rect = table.getCellRect(rowIndex, 0, true);
	    Point pt = viewport.getViewPosition();
	    rect.setLocation(rect.x-pt.x, rect.y-pt.y);
	    viewport.scrollRectToVisible(rect);
	    table.setRowSelectionInterval(rowIndex, rowIndex+sizeOfBlock-1);
	}

}