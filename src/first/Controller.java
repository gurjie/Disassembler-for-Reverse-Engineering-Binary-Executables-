package first;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import javax.swing.JSplitPane;

import com.mxgraph.layout.mxCircleLayout;
import com.mxgraph.layout.mxFastOrganicLayout;
import com.mxgraph.layout.mxGraphLayout;
import com.mxgraph.layout.mxIGraphLayout;
import com.mxgraph.layout.mxParallelEdgeLayout;
import com.mxgraph.layout.mxPartitionLayout;
import com.mxgraph.layout.hierarchical.mxHierarchicalLayout;
import com.mxgraph.model.mxCell;
import com.mxgraph.swing.mxGraphComponent;
import com.mxgraph.util.mxRectangle;
import com.mxgraph.view.mxGraph;
import com.mxgraph.view.mxGraphView;

public class Controller {

	private Model model;
	private View view;
	private mxGraphComponent graphComponent;

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
		view.getToolBar().add(view.getZoomInButton());
		view.getToolBar().add(view.getZoomOutButton());
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
		view.getGraphScrollPane().removeMouseWheelListener(view.getGraphScrollPane().getMouseWheelListeners()[0]);

		// view.getLastnameTextfield().setText(model.getLastname());
	}

	public void initController() {
		view.getLoadButton().addActionListener(e -> loadFile());
		view.getExportButton().addActionListener(e -> export());
		view.getCfgButton().addActionListener(e -> openCFG());

		// view.getLastnameSaveButton().addActionListener(e -> saveLastname());
		// view.getHello().addActionListener(e -> sayHello());
		// view.getBye().addActionListener(e -> sayBye());
	}

	private void graphScroll() {
		System.out.println("SCrolled");
	}

	private void loadFile() {
		System.out.println("Pressed");
		graphComponent.zoomIn();

	}

	private void export() {
		System.out.println("Pressed");
	}

	private void openCFG() {
		// initialise the control flow graph shower
		// start the popup CFG with model.showCfg as input, which returns a string
		mxGraph graph = new mxGraph();
		Object parent = graph.getDefaultParent();
		graph.getModel().beginUpdate();
		try {
			Object v1 = graph.insertVertex(parent, null, "asflfsaljiasflij\nflifjliadg", 20, 20, 80, 30);
			Object v2 = graph.insertVertex(parent, null,
					"Worl\nfaelijafijldgajil\nfailaf\nfkaafs\nfakjnfask\nfajkfsfas!", 240, 150, 80, 30);
			Object v3 = graph.insertVertex(parent, null,
					"Worl\nfaelijafijldgajil\nfailaf\nfkaafs\nfakjnfask\nfajkfsfas!", 320, 180, 80, 30);
			Object v4 = graph.insertVertex(parent, null, "Wogdagad", 370, 250, 80, 30);
			Object v5 = graph.insertVertex(parent, null, "Wogdagad", 370, 250, 80, 30);
			Object v6 = graph.insertVertex(parent, null, "Wogdagad", 370, 250, 80, 30);
			Object v7 = graph.insertVertex(parent, null, "Wogdagad", 370, 250, 80, 30);
			Object v8 = graph.insertVertex(parent, null, "Wogdagad", 370, 250, 80, 30);
			Object v9 = graph.insertVertex(parent, null, "Wogdagad", 370, 250, 80, 30);
			Object v10 = graph.insertVertex(parent, null, "Wogdagad", 370, 250, 80, 30);

			graph.setCellsResizable(true);
			graph.updateCellSize(v2);
			graph.selectNextCell();
			graph.insertEdge(parent, null, "Edge", v1, v2);
			graph.insertEdge(parent, null, "Edge", v2, v3);
			graph.insertEdge(parent, null, "Edge", v1, v4);
			graph.insertEdge(parent, null, "Edge", v8, v5);
			graph.insertEdge(parent, null, "Edge", v5, v6);
			graph.insertEdge(parent, null, "Edge", v7, v1);
			graph.insertEdge(parent, null, "Edge", v9, v1);
			graph.insertEdge(parent, null, "Edge", v1, v7);
			graph.insertEdge(parent, null, "Edge", v4, v1);
			graph.insertEdge(parent, null, "Edge", v7, v8);
			graph.insertEdge(parent, null, "Edge", v1, v9);
			graph.insertEdge(parent, null, "Edge", v4, v10);

			System.out.println("built!");
		} finally {
			graph.getModel().endUpdate();
		}
		graphComponent = new mxGraphComponent(graph);
		view.getZoomInButton().addActionListener(e -> zoomIn(graphComponent));
		view.getZoomOutButton().addActionListener(e-> zoomOut(graphComponent));
		graphComponent.getGraphControl().addMouseListener(new MouseAdapter()
		{
			public void mouseReleased(MouseEvent e)
			{
				Object cell = graphComponent.getCellAt(e.getX(), e.getY());
				if (cell != null)
				{
					
					System.out.println("cell="+graph.getLabel(cell));
				}
			}
		});
		mxIGraphLayout layout = new mxHierarchicalLayout(graph);
		layout.execute(graph.getDefaultParent());
		//graph.groupCells();
		view.getGraphPane().setLayout(new BorderLayout());
		view.getGraphPane().add(graphComponent, BorderLayout.CENTER);
		view.getGraphPane().validate();
		mxGraphView view = graphComponent.getGraph().getView();
	}

	private void zoomIn(mxGraphComponent graphComponent) {
		graphComponent.zoomIn();
	}
	
	private void zoomOut(mxGraphComponent graphComponent) {
		graphComponent.zoomOut();
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