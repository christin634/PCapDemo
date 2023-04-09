package gui;

import java.awt.BorderLayout;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.border.EmptyBorder;

import org.jnetpcap.packet.PcapPacket;

import util.PacketProcessUtil;

public class DetailFrame extends JFrame {

	private static final long serialVersionUID = 1L;
	private JPanel contentPane;
	PcapPacket packet = null;
	
	/**
	 * Create the frame.
	 */
	public DetailFrame(String typeString,PcapPacket packet) {
		this.packet = packet;
		setTitle("Frame "+packet.getFrameNumber());
		setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		setBounds(100, 100, 1080, 760);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(new BorderLayout(0, 0));
		
		JSplitPane splitPane = new JSplitPane();
		splitPane.setDividerLocation(540);
		contentPane.add(splitPane, BorderLayout.CENTER);
		
		JScrollPane scrollPane_1 = new JScrollPane();
		splitPane.setRightComponent(scrollPane_1);
		
		//分析后的内容
		JTextArea processedArea = new JTextArea();
		processedArea.setEditable(false);
		processedArea.setText(PacketProcessUtil.packetProcess(typeString, packet));
		scrollPane_1.setViewportView(processedArea);
		
		JSplitPane splitPane_1 = new JSplitPane();
		splitPane_1.setOrientation(JSplitPane.VERTICAL_SPLIT);
		splitPane.setLeftComponent(splitPane_1);
		
		JScrollPane scrollPane = new JScrollPane();
		splitPane_1.setLeftComponent(scrollPane);
		
		JTextArea hexArea = new JTextArea();
		hexArea.setEditable(false);
		//十六进制
		hexArea.setText(packet.toHexdump());
		scrollPane.setViewportView(hexArea);
		
		JScrollPane scrollPane_2 = new JScrollPane();
		splitPane_1.setRightComponent(scrollPane_2);
		
		JTextArea packetArea = new JTextArea();
		packetArea.setEditable(false);
		//经内部处理后的结果
		packetArea.setText(packet.toString());
		scrollPane_2.setViewportView(packetArea);
		splitPane_1.setDividerLocation(380);
		setLocationRelativeTo(null);
	}
}
