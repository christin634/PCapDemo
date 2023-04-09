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
		s += "ʱ���:" + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
				.format(new Date(packet.getCaptureHeader().timestampInMillis())) + "\n";
		s += "���񳤶�:" + packet.getCaptureHeader().caplen() + " [ bytes ]\n\n";
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
		builder.append("����(8λ):" + icmp.type() + " [ " + icmp.typeDescription() + "] \n");
		builder.append("����(8λ):" + icmp.code() + " \n");
		builder.append("�����(16λ):" + icmp.checksum() + " \n");
		builder.append("��ʶ��(16λ):" + icmp.getId() + "\n\n");
		return builder.toString();
	}

	
	public static String parseArp() {
		StringBuilder builder = new StringBuilder();
		builder.append(parseEthernet());
		Arp arp = packet.getHeader(new Arp());
		builder.append("------------------Arp------------------\n");
		builder.append("Ӳ������(2�ֽ�):" + arp.hardwareType() + " [ " + arp.hardwareTypeDescription() + " ] \n");
		builder.append("Э������(2�ֽ�):" + arp.protocolType() + " [ " + arp.protocolTypeDescription() + " ] \n");
		builder.append("Ӳ����ַ����(1�ֽ�):" + arp.hlen() + " [ bytes ] \n");
		builder.append("Э�鳤��(1�ֽ�):" + arp.plen() + " [ bytes ] \n");
		builder.append("��������op(2�ֽ�):" + arp.operation() + " [ " + arp.operationDescription() + " ] \n");
		builder.append("���ͷ�MAC(6�ֽ�):" + AddressUtil.macBytesToString(arp.sha()) + "\n");
		builder.append("���ͷ�Ip(4�ֽ�):" + AddressUtil.ipBytesToString(arp.spa()) + "\n");
		builder.append("���շ�MAC(6�ֽ�):" + AddressUtil.macBytesToString(arp.tha()) + "\n");
		builder.append("���շ�Ip(4�ֽ�):" + AddressUtil.ipBytesToString(arp.tpa()) + "\n\n");
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
		builder.append("Դ�˿�(2�ֽ�):" + udp.source() + "\n");
		builder.append("Ŀ�Ķ˿�(2�ֽ�):" + udp.destination() + "\n");
		builder.append("����(2�ֽ�)[����UDP���ݱ�����]:" + udp.length() + "\n");
		builder.append("�����(2�ֽ�):" + udp.checksum() + "\n\n");
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
		builder.append("Դ�˿�(2�ֽ�):" + tcp.source() + "\n");
		builder.append("Ŀ�Ķ˿�(2�ֽ�):" + tcp.destination() + "\n");
		builder.append("���(4�ֽ�):" + tcp.seq() + "\n");
		builder.append("ȷ�Ϻ�(4�ֽ�):" + tcp.ack() + "\n");
		builder.append("����ƫ��(4λ)[�ײ�����]:" + tcp.hlen() + " [ 4 bytes ]\n");
		builder.append("����(6λ):" + tcp.reserved() + "\n");
		builder.append("����URG(1λ):" + boolToInt(tcp.flags_URG()) + "\n");
		builder.append("ȷ��ACK(1λ)[1-ȷ�Ϻ���Ч]:" + boolToInt(tcp.flags_ACK()) + "\n");
		builder.append("����PSH(1λ):" + boolToInt(tcp.flags_PSH()) + "\n");
		builder.append("��λRST(1λ):" + boolToInt(tcp.flags_RST()) + "\n");
		builder.append("ͬ��SYN(1λ):" + boolToInt(tcp.flags_SYN()) + "\n");
		builder.append("��ֹFIN(1λ):" + boolToInt(tcp.flags_FIN()) + "\n");
		builder.append("����(2�ֽ�):" + tcp.window() + "\n");
		builder.append("�����(2�ֽ�):" + tcp.checksum() + "\n");
		builder.append("����ָ��(2�ֽ�)[URG=1ʱ������]:" + tcp.urgent() + "\n\n");
		return builder.toString();
	}

	public static String parseEthernet() {
		StringBuilder builder = new StringBuilder();
		Ethernet ethernet = packet.getHeader(new Ethernet());
		builder.append("------------------Ethernet------------------\n");
		builder.append("����:" + ethernet.getLength() + " [ bytes ]\n");
		builder.append("Ŀ�ĵ�ַ(6�ֽ�):" + AddressUtil.macBytesToString(ethernet.destination()) + "\n");
		builder.append("Դ��ַ(6�ֽ�):" + AddressUtil.macBytesToString(ethernet.source()) + "\n");
		int typeCode = ethernet.type();
		String codeDesc = typeCode == 2054 ? "Arp" : ethernet.typeDescription();
		builder.append("����(2�ֽ�)[ ��ʶ�ϲ�Э�� ]:" + typeCode + " [ " + codeDesc + " ]\n");
		return builder.toString();
	}

	public static String parseIp() {
		StringBuilder builder = new StringBuilder();
		Ip4 ip = packet.getHeader(new Ip4());
		builder.append("------------------Ip------------------\n");
		builder.append("�汾(4λ):" + ip.version() + "\n");
		builder.append("�ײ�����(4λ):" + ip.hlen() + " [ 4 bytes ]\n");
		builder.append("���ַ���(8λ):" + ip.tos() + "\t[ code point:" + ip.tos_Codepoint() + " ECN:" + ip.tos_ECN() + " ECE:"
				+ ip.tos_ECE() + " ]\n");
		builder.append("�ܳ���(16λ):" + ip.length() + " [ bytes ]\n");
		builder.append("��ʶ(16λ):" + ip.id() + "\n");
		builder.append("��־(3λ):" + ip.flags() + " [ MF:" + ip.flags_MF() + " DF:" + ip.flags_DF() + " ] \n");
		builder.append("Ƭƫ��(13λ):" + ip.offset() + " [ 8 bytes ]\n");
		builder.append("����ʱ��(8λ):" + ip.ttl() + "\n");
		builder.append("Э��(8λ)[���ݱ�Я�����ݵ�Э��]:" + ip.type() + "\n");
		builder.append("�ײ������(16λ):" + ip.checksum() + "\n");
		builder.append("Դ��ַ(32λ):" + AddressUtil.ipBytesToString(ip.source()) + "\n");
		builder.append("Ŀ�ĵ�ַ(32λ):" + AddressUtil.ipBytesToString(ip.destination()) + "\n\n");
		return builder.toString();
	}
	
	public static String parseIp6() {
		StringBuilder builder = new StringBuilder();
		Ip6 ip = packet.getHeader(new Ip6());
		builder.append("------------------Ip------------------\n");
		builder.append("�汾(4λ):" + ip.version() + "\n");
		builder.append("ͨ������(8λ):" + ip.trafficClass() +" \n");
		builder.append("�����(20λ):" + ip.flowLabel() +" \n");
		builder.append("��Ч�غɳ���(16λ):" + ip.getPayloadLength() + " [ bytes ]\n");
		builder.append("��һ���ײ�(8λ):" + ip.getNextHeaderId() + "\n");
		builder.append("��������(8λ)[���255��]:" + ip.hopLimit() + " \n");
		builder.append("Դ��ַ(128λ):" + AddressUtil.ipBytesToString(ip.source()) + "\n");
		builder.append("Ŀ�ĵ�ַ(128λ):" + AddressUtil.ipBytesToString(ip.destination()) + "\n\n");
		return builder.toString();
	}
	
	public static int boolToInt(boolean b) {//����boolֵtrue/false��ȡ1��0
		return b == true ? 1 : 0;
	}
}
