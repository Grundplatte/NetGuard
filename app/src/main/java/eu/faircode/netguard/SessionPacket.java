package eu.faircode.netguard;

/**
 * Created by Rainer on 15.01.2017.
 */

public class SessionPacket {
    public int uid;
    public long time;
    public int version;
    public int protocol;
    public String saddr;
    public int sport;
    public String daddr;
    public int dport;
    public int TLSversion;
    public int cipher;
    public int hash;
    public String data;
    public String flags;

    public SessionPacket() {

    }
}
