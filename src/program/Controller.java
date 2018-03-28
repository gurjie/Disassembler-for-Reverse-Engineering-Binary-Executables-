package program;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Point;
import java.awt.Rectangle;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import javax.imageio.ImageIO;
import javax.swing.DefaultListCellRenderer;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JViewport;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;

import com.mxgraph.layout.mxIGraphLayout;
import com.mxgraph.layout.hierarchical.mxHierarchicalLayout;
import com.mxgraph.model.mxCell;
import com.mxgraph.swing.mxGraphComponent;
import com.mxgraph.util.mxCellRenderer;
import com.mxgraph.util.mxConstants;
import com.mxgraph.view.mxGraph;

import capstone.Capstone;

public class Controller {

	private Model model;
	private View view;
	private mxGraph graph;
	private boolean loaded;
	private boolean initialised = false;
	private Function selectedFunction;
	public final int COPY_FROM_ADDR = 1;
	public final int COPY_FROM_MNEUMONIC = 2;
	public final int COPY_FROM_FUNCT_NAME = 3;

	public Controller(Model m, View v) {
		model = m;
		view = v;
		initView();
	}

	/**
	 * Builds the UI components by letting components know eachotehr that they exist
	 * Layouts set and general parameters set
	 */
	private void initView() {
		view.getFrame().setJMenuBar(view.getMenuBar());
		view.getMenuBar().add(view.getMenuFile());
		view.getMenuFile().add(view.getFileMenuLoad());
		view.getMenuFile().add(view.getFileMenuExit());
		view.getMenuBar().add(view.getMenuEdit());
		view.getMenuBar().add(view.getMenuHelp());
		view.getMenuEdit().add(view.getEditMenuSelectAll());
		view.getMenuEdit().add(view.getEditMenuCopy());
		view.getMenuEdit().add(view.getEditMenuCopyAll());
		view.getMenuEdit().add(view.getEditMenuCopyInstructions());
		view.getMenuEdit().add(view.getEditMenuExport());
		view.getFrame().getContentPane().add(view.getToolBar(), BorderLayout.NORTH);
		view.getToolBar().add(view.getLoadButton());
		view.getToolBar().add(view.getExportButton());
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
		view.getInstScrollPane().getViewport().add(view.getInstTable());
		view.getInstTable().setShowGrid(false);
		view.getPopup().add(view.getExportSelected());
		view.getPopup().addSeparator();
		view.getPopup().add(view.getCopyInstructions());
		view.getPopup().add(view.getCopy());
		view.getPopup().add(view.getCopyAll());
		view.getMainPane().setLeftComponent(view.getGraphTabbedPane());
		view.getMainPane().setDividerLocation(450);
		view.getToolBar().add(view.getJbtFilter());

	}

	/**
	 * Opens a JFileChooser when called, letting the user choose a file from their
	 * file system
	 * 
	 * @return string path to the directory. "none selected" if no selection
	 */
	private String chooseDirectory() {
		JFileChooser chooser = new JFileChooser();
		chooser.setCurrentDirectory(new java.io.File("."));
		chooser.setDialogTitle("Select Directory");
		chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
		chooser.setAcceptAllFileFilterUsed(false);
		if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
			return chooser.getSelectedFile().getPath();
		}
		return "none selected";
	}

	/**
	 * Initialise the listeners, listening for changes in the view
	 */
	public void initController() {
		// listener for load button in the file option in the main menu
		view.getFileMenuLoad().addActionListener(e -> {
			loadFile();
		});
		// listener for exit button in the file option in the main menu
		view.getFileMenuExit().addActionListener(e -> {
			System.exit(0);
		});
		// listener for load button in the toolbar
		view.getLoadButton().addActionListener(e -> {
			loadFile();
		});
		// listener for the export button
		view.getExportButton().addActionListener(e -> {
			export();
		});
		// listener for export jmenuitem in the edit option of the main menu
		view.getExportSelected().addActionListener(e -> {
			exportSelected();
		});
		// right click popumenu item copy listener, copies formatted showing from addr onwards
		view.getCopy().addActionListener(e -> {
			selectedInstructionsToClipboard(this.COPY_FROM_ADDR);
		});
		// right click popumenu item copy listener, copies formatted showing from funct name onwards
		view.getCopyAll().addActionListener(e -> {
			selectedInstructionsToClipboard(this.COPY_FROM_FUNCT_NAME);

		});
		// right click popumenu item copy listener, copies formatted showing from menominic onwards
		view.getCopyInstructions().addActionListener(e -> {
			selectedInstructionsToClipboard(this.COPY_FROM_MNEUMONIC);
		});
		// mouse listener for the instruciton table right click
		view.getInstTable().addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent e) {
				showPopup(e);
			}
		});
		// listener for copy jmenuitem in the edit option of the main menu
		// this copy button copies from the funt address onwards
		view.getEditMenuCopy().addActionListener(e -> {
			if (view.getInstTable().getSelectedRow() != -1) {
				selectedInstructionsToClipboard(this.COPY_FROM_ADDR);
			} else {
				JOptionPane.showMessageDialog(new JFrame(), "Nothing selected to copy", "Nothing to copy",
						JOptionPane.INFORMATION_MESSAGE);
			}
		});
		// listener for copy jmenuitem in the edit option of the main menu
		// this copy button copies from the function name onwards
		view.getEditMenuCopyAll().addActionListener(e -> {
			if (view.getInstTable().getSelectedRow() != -1) {
				selectedInstructionsToClipboard(this.COPY_FROM_FUNCT_NAME);
			} else {
				JOptionPane.showMessageDialog(new JFrame(), "Nothing selected to copy", "Nothing to copy",
						JOptionPane.INFORMATION_MESSAGE);
			}
		});
		// listener for copy jmenuitem in the edit option of the main menu
		// this copy button copies from the menmonic onwards
		view.getEditMenuCopyInstructions().addActionListener(e -> {
			if (view.getInstTable().getSelectedRow() != -1) {
				selectedInstructionsToClipboard(this.COPY_FROM_MNEUMONIC);
			} else {
				JOptionPane.showMessageDialog(new JFrame(), "Nothing selected to copy", "Nothing to copy",
						JOptionPane.INFORMATION_MESSAGE);
			}
		});
		// Listener for the export button location in the edit menu
		view.getEditMenuExport().addActionListener(e -> {
			if (view.getInstTable().getSelectedRow() != -1) {
				exportSelected();
			} else {
				JOptionPane.showMessageDialog(new JFrame(), "Nothing selected to export", "Nothing to export",
						JOptionPane.INFORMATION_MESSAGE);
			}
		});
		// listener for select all menu item in the edit menu
		view.getEditMenuSelectAll().addActionListener(e -> {
			if (view.getInstTable().getSelectedRow() != -1) {
				view.getInstTable().selectAll();
			}
		});
	}

	/**
	 * Instantiate the dialogue box which appears whenever export is selected
	 * such that it is invoked with the model view controller patter
	 */
	private void exportSelected() {
		ExportView exportView = new ExportView();
		ExportDialogue instance = new ExportDialogue(this.view.getFrame(), exportView, "Export", view.getInstTable(),
				this.model);
		instance.pack();
		instance.setVisible(true);
	}

	/**
	 * Copies whatever is selected in the instruction table to clipboard
	 * @param id represents the format in which to present instructions when copied to the clipboard, 
	 * 			id can be COPY_FROM_ADDR, copies from the address column in the table onwards
	 * 			id can be COPY_FROM MNEMONIC copies from menmonic column in table onwards
	 * 			id can be COPY_FROM_FUNCT_NAME copies from name column in table onwards
	 * 
	 */
	private void selectedInstructionsToClipboard(int id) {
		StringSelection selection = new StringSelection(
				buildSelectionString(view.getInstTable().getSelectedRows(), id));
		Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
		clipboard.setContents(selection, selection);
	}
	
	/**
	 * Builds a string representing the selected rows in the instruction table
	 * @param selectedRows rows currently selected in the table
	 * @param id id of the selection type
	 * @return a string representing the isntructions selected int he table 
	 */
	private String buildSelectionString(int[] selectedRows, int id) {
		String allSelected = "", row = "";
		for (int x : selectedRows) {
			switch (id) {
			case COPY_FROM_ADDR:
				row = String.format("%s\t%s\t%s\n", view.getInstTable().getValueAt(x, 1),
						view.getInstTable().getValueAt(x, 2), view.getInstTable().getValueAt(x, 3));
				break;
			case COPY_FROM_MNEUMONIC:
				row = String.format("%s\t%s\n", view.getInstTable().getValueAt(x, 2),
						view.getInstTable().getValueAt(x, 3));
				break;
			case COPY_FROM_FUNCT_NAME:
				if (!view.getInstTable().getValueAt(x, 0).equals("-")) {
					allSelected = allSelected
							.concat("\n" + "----------" + view.getInstTable().getValueAt(x, 0) + "----------\n");
				}
				row = String.format("%s\t%s\t%s\n", view.getInstTable().getValueAt(x, 1),
						view.getInstTable().getValueAt(x, 2), view.getInstTable().getValueAt(x, 3));
				break;
			default:
			}
			allSelected = allSelected.concat(row);
		}
		return allSelected;

	}

	/**
	 * display the popup at (x,y) from view whenever right click selected 
	 * @param e MouseEvent which could be a right click
	 */
	private void showPopup(MouseEvent e) {
		if (SwingUtilities.isRightMouseButton(e) == true) {
			view.getPopup().show(e.getComponent(), e.getX(), e.getY());
		}

	}

	/** 
	 * Initialises the instruction table, filling the table by setting the table model
	 * Sets the row sorter so that table search can be implemented
	 */
	private void initInstTableModel() {
		view.getModel().setModel(getInstructionList(), this.model.getFunctions(), this.model.getBasicBlocks());
		view.getInstTable().setModel(view.getModel());
		// Code adapted from Paul Samsotha answer to
		// https://stackoverflow.com/questions/22066387/how-to-search-an-element-in-a-jtable-java
		TableRowSorter<InstructionTableModel> rowSorter = new TableRowSorter<>(view.getModel());
		view.getInstTable().setRowSorter(rowSorter);
		view.getJbtFilter().setVisible(false);
		TableSortFilter f = new TableSortFilter(view.getInstTable(), rowSorter, view.getJtfFilter(), view.getToolBar());

	}

	/**
	 * Initialises the listeners for zoom buttons in the view, such that when presses, the control flow
	 * graph zooms
	 * @param graphComponent related to the control flow graph
	 */
	public void initZoomListeners(mxGraphComponent graphComponent) {
		view.getZoomInButton().addActionListener(e -> zoomIn(graphComponent));
		view.getZoomOutButton().addActionListener(e -> zoomOut(graphComponent));
	}

	/**
	 * Build a list representing all instructions in the executable to be displayed in the instruction able
	 * @return list of all instructions in the executable to be displayed in instruction table
	 */
	public ArrayList<Capstone.CsInsn> getInstructionList() {
		ArrayList<Capstone.CsInsn> instructions = new ArrayList<Capstone.CsInsn>();
		Iterator<BasicBlock> blockIterator = this.model.getBasicBlocks().values().iterator();
		while (blockIterator.hasNext()) {
			BasicBlock current = blockIterator.next();
			instructions.addAll(current.getInstructionList());
		}

		return instructions;
	}

	/**
	 * Initialise the lister for when a function is pressed
	 * when a function is double clicked in the list, the function is shown in the CFG 
	 */
	public void initFunctionsListener() {
		view.getFunctionList().addMouseListener(new MouseAdapter() {
			// code adapted from Mohamed Saligh's response to the question at
			// https://stackoverflow.com/questions/4344682/double-click-event-on-jlist-element
			public void mouseClicked(MouseEvent evt) {
				JList list = (JList) evt.getSource();
				if (evt.getClickCount() == 2) { // if double click
					int index = list.locationToIndex(evt.getPoint()); 
					selectedFunction = view.getFunctionList().getSelectedValue();
					if (selectedFunction.getStartAddr() == 0) {
						JOptionPane.showMessageDialog(new JFrame(),
								selectedFunction.getName() + " is a shared library! Can't display disassembly.",
								"Shared library", JOptionPane.INFORMATION_MESSAGE);
					} else {
						try {
							showCFG(selectedFunction);
						} catch (NullPointerException e) {
							JOptionPane.showMessageDialog(new JFrame(), "This function was not disassembled!",
									"Critical", JOptionPane.ERROR_MESSAGE);
						}
					}

				}
			}
		});
	}


	/**
	 * Load an executable to be disassembled. Initialises all UI components required to be updated after loading
	 * the executable
	 */
	private void loadFile() {
		if (view.getInstTable().getRowCount() != 0) {
			int a = JOptionPane.showConfirmDialog(view.getFrame(),
					"You are about to load a new file. Doing so will "
							+ "close the current disassembly instance. Are you sure?",
					"Load new fil", JOptionPane.YES_NO_OPTION);
			if (a != JOptionPane.YES_OPTION) {
				return;
			}
		}
		view.getInstTable().setModel(new DefaultTableModel());
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
					view.getSectionModel().addElement(s.getName() + "   0x" + Long.toHexString(s.getAddress()));
				}
				if (!this.model.symTabExists()) {
					JOptionPane.showMessageDialog(new JFrame(), "The symbol table could not be "
							+ "resolved. As a result, only functions reachable from main \nhave been disassembled. "
							+ "Functions discovered are basic blocks with no parents.", "Warning",
							JOptionPane.WARNING_MESSAGE);
				}

				setFunctionsCellRenderer();
				displayInitialControlFlowGraph();
				
				initInstTableModel();
				if (this.initialised == false) {
					initFunctionsListener();
				}
	

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
	
	/**
	 * displays the control flow graph upon loading a disassembly instance
	 */
	private void displayInitialControlFlowGraph() {
		for (Function f : this.model.getFunctions()) {
			if (f.getStartAddr() - this.model.getVtf() == this.model.getMain()) {
				this.selectedFunction = f;
				showCFG(f);
			}
		}
	}
	
	private void setFunctionsCellRenderer() {
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
	}

	/**
	 * Export the control flow graph, rendering the graph a PNG, such that it 
	 * can be exported
	 */
	private void export() {
		if (this.loaded == true) {
			String chosenDir = chooseDirectory();
			if (chosenDir.equals("none selected")) {
				return;
			}
			File exportDir = new File(chosenDir);

			String exportName = model.getFile().getName() + ".png";
			String exportFileName = model.getFile().getName();
			int exportNumber = 0;
			String exportSuffix = ".png";
			while (new File(exportDir.getPath(), exportName).exists()) {
				exportNumber++;
				exportName = exportFileName.concat(Integer.toString(exportNumber)).concat(exportSuffix);
			}
			System.out.println(exportName);
			File newFile = new File(exportDir.getPath(), exportName);
			try {
				FileWriter fw = new FileWriter(newFile);
				fw.write(exportDir.getPath());
				fw.close();
				BufferedImage image = mxCellRenderer.createBufferedImage(this.graph, null, 1, Color.WHITE, true, null);
				ImageIO.write(image, "PNG", newFile);
				JOptionPane.showMessageDialog(new JFrame(), newFile.getName() + " exported to " + newFile.getPath(),
						"Success", JOptionPane.INFORMATION_MESSAGE);
			} catch (IOException iox) {
				JOptionPane.showMessageDialog(new JFrame(), iox.getMessage(), "File Write Exception",
						JOptionPane.ERROR_MESSAGE);
			}
		}
	}

	/**
	 * Find basic block nearest to a block. Pretty much deprecated but still used. 
	 * @param map Basic blocks disassembled
	 * @param value representing the block the find's beginning address
	 * @return the nearest block in the basic block list to the address input
	 */
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

	/**
	 * Display the control flow graph
	 * @param f function who's cfg to show
	 */
	private void showCFG(Function f) {
		// make a new graph
		this.graph = new mxGraph();
		Object parent = graph.getDefaultParent();
		graph.getModel().beginUpdate();
		// end create graph
		try {
			// let functions know all addresses associated with them; sets this information, as it is only
			// required for displaying the CFG, so it does this as and when required
			f.setAssociatedAddresses(this.model.getBasicBlocks());
			
			// Linked hashmap mapping basic blocks to mxgraph objects
			Map<BasicBlock, Object> blockToVertex = new LinkedHashMap<BasicBlock, Object>();
			BasicBlock first = findNearest(this.model.getBasicBlocks(), f.getStartAddr()); // set the first block
			Object root = graph.insertVertex(graph.getDefaultParent(), Integer.toHexString((first.getFirstAddress())), 
					first.instructionsToString(), 240, 150, 80, 30); // create a vertex representing the initial block
			blockToVertex.put(first, root); // map the first block to the root node
			graph.updateCellSize(root); // update size of the root node to its contained text
			// for every address associated with an instruction
			for (int addr : f.getAssociatedAddresses()) {
				// create a node in the graph representing the basic block at this address and store it in the mapping
				BasicBlock block = findNearest(this.model.getBasicBlocks(), addr);
				Object vertex = graph.insertVertex(graph.getDefaultParent(),
						Integer.toHexString((block.getFirstAddress())), block.instructionsToString(), 240, 150, 80, 30);
				blockToVertex.put(block, vertex);
				graph.updateCellSize(vertex);
			}

			// For every basic block associated with a function
			for (int i : f.getAssociatedAddresses()) {
				// connect the basic block to create a link from it to one of its children
				BasicBlock block0 = findNearest(this.model.getBasicBlocks(), i);
				Object vertex0 = blockToVertex.get(block0);
				for (int x : block0.getAddressReferenceList()) {
					BasicBlock block1 = findNearest(this.model.getBasicBlocks(), x);
					Object vertex1 = blockToVertex.get(block1);
					Object e1 = graph.insertEdge(graph.getDefaultParent(), null, "", vertex0, vertex1);
				}

				// blocks that reference themselves are have loop address references, and should be 
				// represented on the control flow graph as such
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
				Object e1 = graph.insertEdge(graph.getDefaultParent(), null, "", vertex0, vertex1);
			}

		} finally {
			graph.getModel().endUpdate();
		}
		graph.setCellsResizable(true); // cells can be resized
		graph.setCellsDisconnectable(false); // arrows can't be disconnected from cells
		graph.setEdgeLabelsMovable(false); // edge labels can't be moved
		graph.alignCells(mxConstants.ALIGN_RIGHT); // Align the content of the cells
		mxGraphComponent graphComponent = new mxGraphComponent(graph); 
		// listener for whenever a block is clicked added
		graphComponent.getGraphControl().addMouseListener(new MouseAdapter() {
			public void mouseReleased(MouseEvent e) {
				Object cell = graphComponent.getCellAt(e.getX(), e.getY());
				if (cell != null) {
					mxCell selected = (mxCell) cell;
					for (int i = 0; i < view.getInstTable().getRowCount(); i++) {
						for (int j = 0; j < view.getInstTable().getColumnCount(); j++) {
							if (view.getInstTable().getValueAt(i, 1).equals("0x" + selected.getId())) {
								scrollToVisibleInstructionBlock(view.getInstTable(), i, model.getBasicBlocks()
										.get(Integer.valueOf(selected.getId(), 16).intValue()).getBlockSize());
							}
						}
					}

				}

			}
		});
		// hierarchial graph layout defined 
		mxIGraphLayout layout = new mxHierarchicalLayout(graph);
		layout.execute(graph.getDefaultParent());
		graph.setCellsEditable(false); // nodes can't be modified 
		graphComponent.setConnectable(false);

		// scroll to the root cell whenever a control flow graph is loaded 
		Object[] cells = graph.getChildVertices(graph.getDefaultParent());
		for (Object c : cells) {
			mxCell cell = (mxCell) c;
			if (cell.getId().equals(Integer.toHexString(f.getStartAddr()))) {
				graphComponent.scrollCellToVisible(cell);
			}
		}

		// add a tab representing the selected function, representing an instance of a CFG
		view.addTab(f.getName(), graphComponent);
		initZoomListeners(graphComponent); // zoom listeners added 
		graphComponent.validate(); // update the graph by validating it

	}

	/**
	 * Zoom in
	 * @param graphComponent to zoom into
	 */
	private void zoomIn(mxGraphComponent graphComponent) {
		graphComponent.zoomIn();
		graphComponent.validate();
	}

	/**
	 * Zoom out
	 * @param graphComponent to zoom out of
	 */
	private void zoomOut(mxGraphComponent graphComponent) {
		graphComponent.zoomOut();
		graphComponent.validate();
	}

	/**
	 * scrolls to a block visible in the instruction table by taking into account the size of
	 * the instruction table so that the process in dynamic
	 * @param instructionTable to have a value in it scrolled to
	 * @param rowToScrollTo index of the row to scroll to
	 * @param sizeOfBlock number of instructions selected
	 */
	private void scrollToVisibleInstructionBlock(JTable instructionTable, int rowToScrollTo, int sizeOfBlock) {
		if (!(instructionTable.getParent() instanceof JViewport))
			return;
		JViewport instTableViewport = (JViewport) instructionTable.getParent();
		Rectangle rect = instructionTable.getCellRect(rowToScrollTo, 0, true);
		int exth = instTableViewport.getExtentSize().height;
		int currentViewH = instTableViewport.getViewSize().height;
		int point = Math.max(0, rect.y - ((exth - rect.height) / 2));
		point = Math.min(point, currentViewH - exth);
		instTableViewport.setViewPosition(new Point(0, point));
		instructionTable.setRowSelectionInterval(rowToScrollTo, rowToScrollTo + sizeOfBlock - 1);
	}

}