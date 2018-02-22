package first;


import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import javax.swing.JFrame;

import com.mxgraph.swing.mxGraphComponent;
import com.mxgraph.view.mxGraph;

public class CFGExperiment {
	
	/**
	 * 
	 */
	JFrame frame;

	private static final long serialVersionUID = -2764911804288120883L;

	public JFrame getFrame() {
		return this.frame;
	}
	
	
	public CFGExperiment()
	{
		frame = new JFrame("yo");
		final mxGraph graph = new mxGraph();
		Object parent = graph.getDefaultParent();

		graph.getModel().beginUpdate();
		try
		{
		   Object v1 = graph.insertVertex(parent, null, "asflfsaljiasflij\nflifjliadg", 20, 20, 80,
		         30);
		   Object v2 = graph.insertVertex(parent, null, "Worl\nfaelijafijldgajil\nfailaf\nfkaafs\nfakjnfask\nfajkfsfas!",
		         240, 150, 80, 30);
		   graph.setCellsResizable(true);
		   graph.updateCellSize(v2);
		   graph.selectNextCell();
		   graph.insertEdge(parent, null, "Edge", v1, v2);
		}
		finally
		{
		   graph.getModel().endUpdate();
		}
		
		final mxGraphComponent graphComponent = new mxGraphComponent(graph);
		frame.getContentPane().add(graphComponent);
		
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
	}

	public static void main(String[] args)
	{
		CFGExperiment cfg = new CFGExperiment();
		cfg.getFrame().setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		cfg.getFrame().setBounds(100,100,1261,808);
		cfg.getFrame().setVisible(true);
	}

}