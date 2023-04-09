package util;

import java.text.SimpleDateFormat;
import java.util.Date;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

public class PacketProcessUtil {

	static PcapPacket packet;

	public static String packetProcess(String typeString, PcapPacket packet) {
		PacketProcessUtil.packet = packet;
		String s = "------------------Frame ";
		s = s + packet.getFrameNumber() + "------------------\n";
		s += "时间戳:" + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
				.format(new Date(packet.getCaptureHeader().timestampInMillis())) + "\n";
		s += "捕获长度:" + packet.getCaptureHeader().caplen() + " [ bytes ]\n\n";
		switch (typeString) {
		case "tcp":
			s += parseTcp();
			break;
		case "udp":
			s += parseUdp();
			break;
		case "arp":
			s += parseArp();
			break;
		case "icmp":
			s += parseIcmp();
			break;
		default:
			return packet.toString();
		}
		return s;
	}

	public static String parseIcmp() {
		StringBuilder builder = new StringBuilder();
		builder.append(parseEthernet());
		if(packet.hasHeader(Ip4.ID))
			builder.append(parseIp());
		else {
			builder.append(parseIp6());
		}
		Icmp icmp = packet.getHeader(new Icmp());
		builder.append("------------------Icmp------------------\n");
		builder.append("类型(8位):" + icmp.type() + " [ " + icmp.typeDescription() + "] \n");
		builder.append("代码(8位):" + icmp.code() + " \n");
		builder.append("检验和(16位):" + icmp.checksum() + " \n");
		builder.append("标识符(16位):" + icmp.getId() + "\n\n");
		return builder.toString();
	}

	
	public static String parseArp() {
		StringBuilder builder = new StringBuilder();
		builder.append(parseEthernet());
		Arp arp = packet.getHeader(new Arp());
		builder.append("------------------Arp------------------\n");
		builder.append("硬件类型(2字节):" + arp.hardwareType() + " [ " + arp.hardwareTypeDescription() + " ] \n");
		builder.append("协议类型(2字节):" + arp.protocolType() + " [ " + arp.protocolTypeDescription() + " ] \n");
		builder.append("硬件地址长度(1字节):" + arp.hlen() + " [ bytes ] \n");
		builder.append("协议长度(1字节):" + arp.plen() + " [ bytes ] \n");
		builder.append("操作类型op(2字节):" + arp.operation() + " [ " + arp.operationDescription() + " ] \n");
		builder.append("发送方MAC(6字节):" + AddressUtil.macBytesToString(arp.sha()) + "\n");
		builder.append("发送方Ip(4字节):" + AddressUtil.ipBytesToString(arp.spa()) + "\n");
		builder.append("接收方MAC(6字节):" + AddressUtil.macBytesToString(arp.tha()) + "\n");
		builder.append("接收方Ip(4字节):" + AddressUtil.ipBytesToString(arp.tpa()) + "\n\n");
		return builder.toString();
	}

	public static String parseUdp() {
		StringBuilder builder = new StringBuilder();
		builder.append(parseEthernet());
		if(packet.hasHeader(Ip4.ID))
			builder.append(parseIp());
		else {
			builder.append(parseIp6());
		}
		Udp udp = packet.getHeader(new Udp());
		builder.append("------------------Udp------------------\n");
		builder.append("源端口(2字节):" + udp.source() + "\n");
		builder.append("目的端口(2字节):" + udp.destination() + "\n");
		builder.append("长度(2字节)[整个UDP数据报长度]:" + udp.length() + "\n");
		builder.append("检验和(2字节):" + udp.checksum() + "\n\n");
		return builder.toString();
	}

	public static String parseTcp() {
		StringBuilder builder = new StringBuilder();
		builder.append(parseEthernet());
		if(packet.hasHeader(Ip4.ID))
			builder.append(parseIp());
		else {
			builder.append(parseIp6());
		}
		Tcp tcp = packet.getHeader(new Tcp());
		builder.append("------------------Tcp------------------\n");
		builder.append("源端口(2字节):" + tcp.source() + "\n");
		builder.append("目的端口(2字节):" + tcp.destination() + "\n");
		builder.append("序号(4字节):" + tcp.seq() + "\n");
		builder.append("确认号(4字节):" + tcp.ack() + "\n");
		builder.append("数据偏移(4位)[首部长度]:" + tcp.hlen() + " [ 4 bytes ]\n");
		builder.append("保留(6位):" + tcp.reserved() + "\n");
		builder.append("紧急URG(1位):" + boolToInt(tcp.flags_URG()) + "\n");
		builder.append("确认ACK(1位)[1-确认号有效]:" + boolToInt(tcp.flags_ACK()) + "\n");
		builder.append("推送PSH(1位):" + boolToInt(tcp.flags_PSH()) + "\n");
		builder.append("复位RST(1位):" + boolToInt(tcp.flags_RST()) + "\n");
		builder.append("同步SYN(1位):" + boolToInt(tcp.flags_SYN()) + "\n");
		builder.append("终止FIN(1位):" + boolToInt(tcp.flags_FIN()) + "\n");
		builder.append("窗口(2字节):" + tcp.window() + "\n");
		builder.append("检验和(2字节):" + tcp.checksum() + "\n");
		builder.append("紧急指针(2字节)[URG=1时有意义]:" + tcp.urgent() + "\n\n");
		return builder.toString();
	}

	public static String parseEthernet() {
		StringBuilder builder = new StringBuilder();
		Ethernet ethernet = packet.getHeader(new Ethernet());
		builder.append("------------------Ethernet------------------\n");
		builder.append("长度:" + ethernet.getLength() + " [ bytes ]\n");
		builder.append("目的地址(6字节):" + AddressUtil.macBytesToString(ethernet.destination()) + "\n");
		builder.append("源地址(6字节):" + AddressUtil.macBytesToString(ethernet.source()) + "\n");
		int typeCode = ethernet.type();
		String codeDesc = typeCode == 2054 ? "Arp" : ethernet.typeDescription();
		builder.append("类型(2字节)[ 标识上层协议 ]:" + typeCode + " [ " + codeDesc + " ]\n");
		return builder.toString();
	}

	public static String parseIp() {
		StringBuilder builder = new StringBuilder();
		Ip4 ip = packet.getHeader(new Ip4());
		builder.append("------------------Ip------------------\n");
		builder.append("版本(4位):" + ip.version() + "\n");
		builder.append("首部长度(4位):" + ip.hlen() + " [ 4 bytes ]\n");
		builder.append("区分服务(8位):" + ip.tos() + "\t[ code point:" + ip.tos_Codepoint() + " ECN:" + ip.tos_ECN() + " ECE:"
				+ ip.tos_ECE() + " ]\n");
		builder.append("总长度(16位):" + ip.length() + " [ bytes ]\n");
		builder.append("标识(16位):" + ip.id() + "\n");
		builder.append("标志(3位):" + ip.flags() + " [ MF:" + ip.flags_MF() + " DF:" + ip.flags_DF() + " ] \n");
		builder.append("片偏移(13位):" + ip.offset() + " [ 8 bytes ]\n");
		builder.append("生存时间(8位):" + ip.ttl() + "\n");
		builder.append("协议(8位)[数据报携带数据的协议]:" + ip.type() + "\n");
		builder.append("首部检验和(16位):" + ip.checksum() + "\n");
		builder.append("源地址(32位):" + AddressUtil.ipBytesToString(ip.source()) + "\n");
		builder.append("目的地址(32位):" + AddressUtil.ipBytesToString(ip.destination()) + "\n\n");
		return builder.toString();
	}
	
	public static String parseIp6() {
		StringBuilder builder = new StringBuilder();
		Ip6 ip = packet.getHeader(new Ip6());
		builder.append("------------------Ip------------------\n");
		builder.append("版本(4位):" + ip.version() + "\n");
		builder.append("通信量类(8位):" + ip.trafficClass() +" \n");
		builder.append("流标号(20位):" + ip.flowLabel() +" \n");
		builder.append("有效载荷长度(16位):" + ip.getPayloadLength() + " [ bytes ]\n");
		builder.append("下一个首部(8位):" + ip.getNextHeaderId() + "\n");
		builder.append("跳数限制(8位)[最大255跳]:" + ip.hopLimit() + " \n");
		builder.append("源地址(128位):" + AddressUtil.ipBytesToString(ip.source()) + "\n");
		builder.append("目的地址(128位):" + AddressUtil.ipBytesToString(ip.destination()) + "\n\n");
		return builder.toString();
	}
	
	public static int boolToInt(boolean b) {//根据bool值true/false获取1或0
		return b == true ? 1 : 0;
	}
}
