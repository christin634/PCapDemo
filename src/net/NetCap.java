package net;

import java.util.ArrayList;
import java.util.List;

import javax.swing.JOptionPane;
import javax.swing.JPanel;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;

public class NetCap {
	
	StringBuilder errbuf = new StringBuilder();
	private List<PcapIf> allDevs = new ArrayList<PcapIf>();
	private List<String> descList = new ArrayList<>();

	public NetCap() {
		// TODO Auto-generated constructor stub
		//获取全部网卡
        int r = Pcap.findAllDevs(allDevs, errbuf);
        if (r != Pcap.OK|| allDevs.isEmpty()) {
        	System.out.println("Error occured: " + errbuf.toString());
        }
        int i=0;
        for(PcapIf dev:allDevs) {//获取网卡描述，便于选择
        	if(!dev.getAddresses().isEmpty()) {
        		List<PcapAddr> addrs = dev.getAddresses();
        		descList.add("#"+i+" "+dev.getDescription()+" "+addrs.get(0).getAddr());
        	}else {
        		descList.add("#"+i+" "+dev.getDescription());
        	}
        	i++;
        }
	}
	
	public String setFilter(Pcap pcap,String expression) {
		// 过滤器
		PcapBpfProgram filter = new PcapBpfProgram();
		int res = pcap.compile(filter, expression.toLowerCase(), 1, 0);
		pcap.setFilter(filter);
		if (res != 0) {
			return "Filter error:" + pcap.getErr();
		}
		return "ok";
	}
	
	public Pcap startCap(JPanel contentPane,int netInterface,String filterExpre) {
		PcapIf devIf = allDevs.get(netInterface);
		// 截取长度不超过数据报max 65535
	    int snaplen = 64 * 1024; 
	    // 混杂模式，抓取所有数据包
	    int flags = Pcap.MODE_PROMISCUOUS; 
	    int timeout = 1 * 1000; // 超时
        Pcap pcap = Pcap.openLive(devIf.getName(), snaplen, flags, timeout,
                errbuf);
        if (pcap == null) {
        	JOptionPane.showMessageDialog(contentPane,"Error while opening device for capture: "+errbuf.toString(),"错误 ",0);
            return null;
        }
        String msgString;
        if(!filterExpre.equals(""))
        	msgString = this.setFilter(pcap, filterExpre);
        else {
        	msgString="ok";
        }
        if(msgString!="ok") {
        	JOptionPane.showMessageDialog(contentPane,msgString,"错误 ",0);
        }
        return pcap;
	}
	
	public List<String> getDescList(){
		return this.descList;
	}
	
	public List<PcapIf> getDevList(){
		return this.allDevs;
	}
	
	public StringBuilder getErrBuf() {
		return this.errbuf;
	}
}
