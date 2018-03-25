package program;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Point;
import java.awt.Rectangle;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
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
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JViewport;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;

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
	private Function selectedFunction;
	public final int COPY_FROM_ADDR = 1;
	public final int COPY_FROM_MNEUMONIC = 2;
	public final int COPY_FROM_FUNCT_NAME = 3;

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
	}

	public String chooseDirectory() {
		JFileChooser chooser = new JFileChooser();
		chooser.setCurrentDirectory(new java.io.File("."));
		chooser.setDialogTitle("Select Directory");
		chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
		chooser.setAcceptAllFileFilterUsed(false);
		if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
			return chooser.getSelectedFile().getPath();
		}
		return "";
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
		
		view.getExportButton().addActionListener(e -> {
				export();
			
		});

		view.getExportSelected().addActionListener(e -> {
			// do copy logic
			exportSelected();
			System.out.println("exporting selected...");
		});

		view.getCopy().addActionListener(e -> {
			// do copy logic
			selectedInstructionsToClipboard(this.COPY_FROM_ADDR);
		});

		view.getCopyAll().addActionListener(e -> {
			// do copy logic
			selectedInstructionsToClipboard(this.COPY_FROM_FUNCT_NAME);

		});

		view.getCopyInstructions().addActionListener(e -> {
			// do copy logic
			selectedInstructionsToClipboard(this.COPY_FROM_MNEUMONIC);

		});

		view.getInstTable().addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent e) {
				showPopup(e);
			}
		});

		view.getEditMenuCopy().addActionListener(e -> {
			if (view.getInstTable().getSelectedRow() != -1) {
				selectedInstructionsToClipboard(this.COPY_FROM_ADDR);
			} else {
				JOptionPane.showMessageDialog(new JFrame(), "Nothing selected to copy", "Nothing to copy",
						JOptionPane.INFORMATION_MESSAGE);
			}
		});

		view.getEditMenuCopyAll().addActionListener(e -> {
			if (view.getInstTable().getSelectedRow() != -1) {
				selectedInstructionsToClipboard(this.COPY_FROM_FUNCT_NAME);
			} else {
				JOptionPane.showMessageDialog(new JFrame(), "Nothing selected to copy", "Nothing to copy",
						JOptionPane.INFORMATION_MESSAGE);
			}
		});

		view.getEditMenuCopyInstructions().addActionListener(e -> {
			if (view.getInstTable().getSelectedRow() != -1) {
				selectedInstructionsToClipboard(this.COPY_FROM_MNEUMONIC);
			} else {
				JOptionPane.showMessageDialog(new JFrame(), "Nothing selected to copy", "Nothing to copy",
						JOptionPane.INFORMATION_MESSAGE);
			}
		});

		view.getEditMenuExport().addActionListener(e -> {
			if (view.getInstTable().getSelectedRow() != -1) {
				exportSelected();
			} else {
				JOptionPane.showMessageDialog(new JFrame(), "Nothing selected to export", "Nothing to export",
						JOptionPane.INFORMATION_MESSAGE);
			}
		});

		view.getEditMenuSelectAll().addActionListener(e -> {
			if (view.getInstTable().getSelectedRow() != -1) {
				view.getInstTable().selectAll();
			}
		});
	}

	public void exportSelected() {
		ExportView exportView = new ExportView();
		ExportDialogue instance = new ExportDialogue(this.view.getFrame(), exportView, "Export", view.getInstTable(),
				this.model);
		instance.pack();
		instance.setVisible(true);
		/*
		 * JFileChooser chooser = new JFileChooser(); chooser.setCurrentDirectory(new
		 * java.io.File(".")); chooser.setDialogTitle("choosertitle");
		 * chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
		 * chooser.setAcceptAllFileFilterUsed(false);
		 * 
		 * if (chooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
		 * System.out.println("getCurrentDirectory(): " +
		 * chooser.getCurrentDirectory()); } else { System.out.println("No Selection ");
		 * }
		 */
	}

	public void selectedInstructionsToClipboard(int id) {
		StringSelection selection = new StringSelection(
				buildSelectionString(view.getInstTable().getSelectedRows(), id));
		Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
		clipboard.setContents(selection, selection);
	}

	public String buildSelectionString(int[] selectedRows, int id) {
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

	public void selectedInstructionsWithFunctNameToClipboard() {
		String allSelected = "";
		int[] selectedRows = view.getInstTable().getSelectedRows();
		String row = "";
		for (int x : selectedRows) {
			row = String.format("%s\t%s\t%s\n", view.getInstTable().getValueAt(x, 1),
					view.getInstTable().getValueAt(x, 2), view.getInstTable().getValueAt(x, 3));
			allSelected = allSelected.concat(row);
		}
		StringSelection selection = new StringSelection(allSelected);
		Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
		clipboard.setContents(selection, selection);
	}

	public void showPopup(MouseEvent e) {
		if (SwingUtilities.isRightMouseButton(e) == true) {
			view.getPopup().show(e.getComponent(), e.getX(), e.getY());
		}

	}

	public void initInstTableModel() {
		view.getModel().setModel(getInstructionList(), this.model.getFunctions(), this.model.getBasicBlocks());
		view.getInstTable().setModel(view.getModel());

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

	private void graphScroll() {
		System.out.println("Scrolled");
	}

	private void loadFile() {
		if (view.getInstTable().getRowCount() != 0) {
			int a = JOptionPane.showConfirmDialog(view.getFrame(),
					"You are about to load a new file. Doing so will "
							+ "close the current disassembly instance. Are you sure?",
					"Load new fil", JOptionPane.YES_NO_OPTION);
			if (a == JOptionPane.YES_OPTION) {
				System.out.println("continue");
			} else {
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
					view.getSectionModel().addElement(s.getName());
				}
				if (!this.model.symTabExists()) {
					JOptionPane.showMessageDialog(new JFrame(), "The symbol table could not be "
							+ "resolved. As a result, only functions reachable from main \nhave been disassembled. "
							+ "Functions discovered are basic blocks with no parents.", "Warning",
							JOptionPane.WARNING_MESSAGE);
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
				for (Function f : this.model.getFunctions()) {
					if (f.getStartAddr() - this.model.getVtf() == this.model.getMain()) {
						this.selectedFunction = f;
						showCFG(f);
					}
				}
				initInstTableModel();
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
			File exportDir = new File(chooseDirectory());
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
				JOptionPane.showMessageDialog(new JFrame(), newFile.getName()+" exported to "+newFile.getPath(),
						"Success",
						JOptionPane.INFORMATION_MESSAGE);
			} catch (IOException iox) {
				JOptionPane.showMessageDialog(new JFrame(), iox.getMessage(), "File Write Exception",
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
		if (!(table.getParent() instanceof JViewport))
			return;
		JViewport viewport = (JViewport) table.getParent();
		Rectangle rect = table.getCellRect(rowIndex, 0, true);
		Point pt = viewport.getViewPosition();
		rect.setLocation(rect.x - pt.x, rect.y - pt.y);
		viewport.scrollRectToVisible(rect);
		table.setRowSelectionInterval(rowIndex, rowIndex);
	}

	public void scrollToVisibleInstructionBlock(JTable table, int rowIndex, int sizeOfBlock) {
		if (!(table.getParent() instanceof JViewport))
			return;
		JViewport viewport = (JViewport) table.getParent();
		// bottom of selection is 5 rows above bottom of scrollpane
		// Rectangle rect = table.getCellRect(rowIndex, 0, true);
		Rectangle r = table.getCellRect(rowIndex, 0, true);
		int extentHeight = viewport.getExtentSize().height;
		int viewHeight = viewport.getViewSize().height;

		int y = Math.max(0, r.y - ((extentHeight - r.height) / 2));
		y = Math.min(y, viewHeight - extentHeight);

		viewport.setViewPosition(new Point(0, y));
		// Point pt = viewport.getViewPosition();
		// rect.setLocation(rect.x - pt.x, rect.y - pt.y);
		// viewport.scrollRectToVisible(rect);
		table.setRowSelectionInterval(rowIndex, rowIndex + sizeOfBlock - 1);
	}

}