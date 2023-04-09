package gui;

import java.awt.BorderLayout;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumnModel;

import com.formdev.flatlaf.FlatIntelliJLaf;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import com.jgoodies.forms.layout.ColumnSpec;
import com.jgoodies.forms.layout.FormLayout;
import com.jgoodies.forms.layout.FormSpecs;
import com.jgoodies.forms.layout.RowSpec;

import net.NetCap;
import util.AddressUtil;

public class MainFrame extends JFrame implements Runnable {

	private static final long serialVersionUID = 1L;
	
	NetCap netCap = new NetCap();
	List<PcapIf> allDevs = new ArrayList<PcapIf>();// 网卡列表
	List<String> descList = new ArrayList<>();// 网卡描述信息列表
	int netInterface = -1;// 选中网卡序号
	String filterExpre = "";// 协议字段
	Pcap pcap = null;
	List<PcapPacket> packets = new ArrayList<>();// 数据包list，便于分析
	List<String> types = new ArrayList<>();// 数据包类型list
	//String typeString = null;// 协议类型
	Thread thread = null;// 当前主线程
	int first = 0;// 是否第一次打开软件，网卡改变时是否弹窗
	// table列名
	String[] columns = new String[] { "\u5E8F\u53F7", "\u65F6\u95F4", "\u7C7B\u578B", "\u957F\u5EA6", "\u6E90MAC",
			"\u6E90IP", "\u6E90\u7AEF\u53E3", "\u76EE\u7684MAC", "\u76EE\u7684IP", "\u76EE\u7684\u7AEF\u53E3" };

	private JPanel contentPane;
	private JTable table;
	private JPanel panel;
	private JLabel lblNewLabel;
	private JComboBox<String> netInterfaceComb;
	private JLabel lblNewLabel_1;
	private JComboBox<String> filterComb;
	private JButton beginBtn;
	private JButton clearBtn;
	private JScrollPane scrollPane;
	DefaultTableModel tableModel;
	private JButton stopBtn;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		FlatIntelliJLaf.setup();
		MainFrame frame = new MainFrame();
		frame.setVisible(true);
	}

	/**
	 * Create the frame.
	 */
	public MainFrame() {
		setTitle("\u7F51\u7EDC\u6293\u5305");
		
		// 获取网卡即描述信息
		allDevs = netCap.getDevList();
		descList = this.netCap.getDescList();
		
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 920, 550);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(new BorderLayout(0, 0));

		panel = new JPanel();
		contentPane.add(panel, BorderLayout.NORTH);
		panel.setLayout(new FormLayout(new ColumnSpec[] { FormSpecs.LABEL_COMPONENT_GAP_COLSPEC,
				ColumnSpec.decode("45px"), ColumnSpec.decode("352px"), ColumnSpec.decode("59px"),
				ColumnSpec.decode("78px"), ColumnSpec.decode("95px"), FormSpecs.RELATED_GAP_COLSPEC,
				FormSpecs.DEFAULT_COLSPEC, FormSpecs.RELATED_GAP_COLSPEC, ColumnSpec.decode("max(7dlu;default)"),
				ColumnSpec.decode("64px"), }, new RowSpec[] { RowSpec.decode("23px"), }));

		lblNewLabel = new JLabel("\u7F51\u5361\uFF1A");
		panel.add(lblNewLabel, "2, 1, center, fill");
		//网卡下拉框
		netInterfaceComb = new JComboBox<String>();
		netInterfaceComb.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent e) {
				chooseNetInterface(e);
			}
		});
		for (String s : descList) {
			netInterfaceComb.addItem(s);
		}
		panel.add(netInterfaceComb, "3, 1, fill, fill");

		lblNewLabel_1 = new JLabel("\u8FC7\u6EE4\uFF1A");
		panel.add(lblNewLabel_1, "4, 1, center, center");
		//过滤协议下拉框
		filterComb = new JComboBox<>(new String[]{"---", "tcp", "udp", "arp", "icmp"});

		filterComb.addItemListener(e -> {
			if (!filterComb.getSelectedItem().equals("No filter"))
				filterExpre = (String) filterComb.getSelectedItem();
			else {
				filterExpre = "";
			}
		});
		panel.add(filterComb, "5, 1, default, fill");

		scrollPane = new JScrollPane();
		scrollPane.setAutoscrolls(true);
		//数据包表格
		table = new JTable(new Object[][] {}, columns);
		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {// 双击弹出详情
					int row = table.getSelectedRow();
					new DetailFrame(types.get(row), packets.get(row)).setVisible(true);
				}
			}
		});
		table.setModel(new DefaultTableModel(new Object[][] {}, columns) {
			private static final long serialVersionUID = 1L;
			// 设置单元格不可编辑
			public boolean isCellEditable(int rowIndex, int ColIndex) {
				return false;
			}
		});
		TableColumnModel columnModel = table.getColumnModel();
		columnModel.getColumn(6).setPreferredWidth(48);
		columnModel.getColumn(9).setPreferredWidth(59);
		columnModel.getColumn(0).setResizable(false);
		columnModel.getColumn(0).setPreferredWidth(38);
		columnModel.getColumn(0).setMinWidth(10);
		columnModel.getColumn(1).setPreferredWidth(62);
		columnModel.getColumn(2).setPreferredWidth(43);
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		scrollPane.setViewportView(table);

		tableModel = (DefaultTableModel) table.getModel();
		//开始按钮
		beginBtn = new JButton("\u5F00\u59CB");
		beginBtn.setFocusPainted(false);
		beginBtn.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				startCap();
			}
		});
		panel.add(beginBtn, "6, 1, center, center");
		// 清空按钮
		clearBtn = new JButton("\u6E05\u7A7A");
		clearBtn.setFocusPainted(false);
		clearBtn.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				// 清空列表内容
				packets.clear();
				tableModel.setRowCount(0);
				table.setModel(tableModel);
			}
		});
		// 停止按钮
		stopBtn = new JButton("\u505C\u6B62");
		stopBtn.setFocusPainted(false);
		stopBtn.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				stopCap();
			}
		});
		panel.add(stopBtn, "8, 1, default, center");
		panel.add(clearBtn, "11, 1, center, center");

		contentPane.add(scrollPane, BorderLayout.CENTER);
		setLocationRelativeTo(null);
	}

	public void chooseNetInterface(ItemEvent e) {// 选择网卡
		int index = netInterfaceComb.getSelectedIndex();
		netInterface = index;
		if (e.getStateChange() == ItemEvent.SELECTED && first != 0) {
			// 弹出选中的网卡信息
			JOptionPane.showMessageDialog(contentPane, "选中网卡：" + descList.get(index), "提示", JOptionPane.PLAIN_MESSAGE);
		}
		first++;// 避免第一次进入时弹出JOptionPane
	}

	public void startCap() {
		packets.clear();
		types.clear();
		pcap = netCap.startCap(contentPane, netInterface, filterExpre);
		thread = new Thread(this);
		thread.setPriority(Thread.MIN_PRIORITY);
		thread.start();
	}

	public void openCapture() {// 抓取数据包
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
			@Override
			public void nextPacket(PcapPacket packet, String user) {

				// 10列，对应columns
				Object[] objects = new Object[10];

				// TODO Auto-generated method stub
				objects[0] = packet.getFrameNumber();
				objects[1] = sdf.format(new Date(packet.getCaptureHeader().timestampInMillis()));
				objects[3] = packet.getCaptureHeader().caplen();

				// 根据协议类型，设置协议字段（objects[2]）
				if (packet.hasHeader(Ethernet.ID)) {// 分析Ethernet，获取MAC地址
					Ethernet ethernet = packet.getHeader(new Ethernet());
					objects[4] = AddressUtil.macBytesToString(ethernet.source());
					objects[7] = AddressUtil.macBytesToString(ethernet.destination());
				}
				if (packet.hasHeader(Ip4.ID)) {// 分析IP，获取IP地址
					Ip4 ip = packet.getHeader(new Ip4());
					objects[2] = "ip4";
					objects[5] = AddressUtil.ipBytesToString(ip.source());
					objects[8] = AddressUtil.ipBytesToString(ip.destination());
				}
				if (packet.hasHeader(Ip6.ID)) {// 分析IP，获取IP地址
					Ip6 ip = packet.getHeader(new Ip6());
					objects[2] = "ip6";
					objects[5] = AddressUtil.ipBytesToString(ip.source());
					objects[8] = AddressUtil.ipBytesToString(ip.destination());
				}
				if (packet.hasHeader(Tcp.ID)) {// 分析TCP，获取端口号
					Tcp tcp = packet.getHeader(new Tcp());
					objects[2] = "tcp";
					objects[6] = tcp.source();
					objects[9] = tcp.destination();
				}
				if (packet.hasHeader(Udp.ID)) {// 分析UDP，获取端口号
					Udp udp = packet.getHeader(new Udp());
					objects[2] = "udp";
					objects[6] = udp.source();
					objects[9] = udp.destination();
				}
				if (packet.hasHeader(new Arp())) {// 分析Arp，获取源ip和目的ip
					objects[2] = "arp";
					Arp arp = packet.getHeader(new Arp());
					objects[5] = AddressUtil.ipBytesToString(arp.spa());
					objects[8] = AddressUtil.ipBytesToString(arp.tpa());
				}
				if (packet.hasHeader(Icmp.ID)) {
					objects[2] = "icmp";
				}
				// 获取协议类型
				//typeString = (String) objects[2];
				// 数据包加入list
				packets.add(packet);
				types.add((String) objects[2]);
				// 表格添加一行
				tableModel.addRow(objects);
			}
		};
		// 无限次捕获
		pcap.loop(-1, jpacketHandler, "jNetPcap");
		// 关闭pcap
		pcap.close();
	}

	@Override
	public void run() {// 开始抓取并更新表格内容
		// TODO Auto-generated method stub
		openCapture();
		table.setModel(tableModel);
		table.validate();
	}

	@SuppressWarnings("deprecation")
	public void stopCap() {// 停止抓取
		if (thread == null) {
			JOptionPane.showMessageDialog(contentPane, "您未开始捕获数据！", "提示", JOptionPane.PLAIN_MESSAGE);
		} else {
			thread.stop();
		}
	}
}
