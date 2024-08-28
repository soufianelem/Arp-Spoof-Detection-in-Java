package edu.whs.nsa;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;

import java.io.EOFException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeoutException;

public class Main {
    public static void main(String[] args) throws PcapNativeException, NotOpenException, EOFException, TimeoutException {
        System.setProperty("org.pcap4j.core.pcapLibName", "C:\\Windows\\System32\\Npcap\\wpcap.dll");
        System.setProperty("org.pcap4j.core.packetLibName", "C:\\Windows\\System32\\Npcap\\Packet.dll");
        analyzePcapForARPPoisoning();
    }

    private static void analyzePcapForARPPoisoning() throws PcapNativeException, NotOpenException, EOFException, TimeoutException {
        String PCAP_FILE = "data\\arpspoof.pcap";
        PcapHandle handle;

        // Die Pcap Datei öffnen.
        try {
            handle = Pcaps.openOffline(PCAP_FILE, PcapHandle.TimestampPrecision.NANO);
        } catch (PcapNativeException e) {
            handle = Pcaps.openOffline(PCAP_FILE);
        }

        // Map zur Überprüfung von IP- und MAC-Adressen.
        Map<String, String> ipToMacMap = new HashMap<>();

        // Über alle Pakete in der Pcap Datei iterieren.
        while (true) {
            try {
                // Nächstes Packet auslesen.
                Packet packet = handle.getNextPacketEx();

                // Wenn es ein ARP Packet ist, analysieren wir dieses.
                if (packet.contains(ArpPacket.class)) {
                    ArpPacket arp = packet.get(ArpPacket.class);
                    String senderIp = arp.getHeader().getSrcProtocolAddr().toString();
                    String senderMac = arp.getHeader().getSrcHardwareAddr().toString();

                    // Überprüfen, ob die IP-Adresse bereits in der Map ist
                    if (ipToMacMap.containsKey(senderIp)) {
                        if (!ipToMacMap.get(senderIp).equals(senderMac)) {
                            System.out.println("ARP Spoofing erkannt!");
                            System.out.println("IP-Adresse: " + senderIp);
                            System.out.println("Vorherige MAC-Adresse: " + ipToMacMap.get(senderIp));
                            System.out.println("Aktuelle MAC-Adresse: " + senderMac);
                        }
                    } else {
                        ipToMacMap.put(senderIp, senderMac);
                    }
                }
            } catch (EOFException e) {
                handle.close();
                break;
            }
        }
    }
}