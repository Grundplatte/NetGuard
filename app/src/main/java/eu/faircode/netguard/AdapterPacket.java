package eu.faircode.netguard;

import android.content.Context;
import android.database.Cursor;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CursorAdapter;
import android.widget.ImageView;
import android.widget.TextView;

import java.text.SimpleDateFormat;

/**
 * Created by Rainer on 16.01.2017.
 */

public class AdapterPacket extends CursorAdapter {
    private static String TAG = "NetGuard.Log";

    private int colPacketTime;
    private int colPacketData;

    /*
    private int colPacketSessionId;
    private int colPacketUid;
    private int colPacketVersion;
    private int colPacketProtocol;
    private int colPacketDAddr;
    private int colPacketSAddr;
    private int colPacketDPort;
    private int colPacketSPort;
    private int colPacketDName;
    private int colPacketTLSversion;
    private int colPacketCipher;
    private int colPacketHash;
    private int colPacketFlags;
    */

    public AdapterPacket(Context context, Cursor cursorPacket) {
        super(context, cursorPacket, 0);

        colPacketTime = cursorPacket.getColumnIndex("time");
        colPacketData = cursorPacket.getColumnIndex("data");

        /*
        colPacketSessionId = cursorPacket.getColumnIndex("sessionId");
        colPacketUid = cursorPacket.getColumnIndex("uid");
        colPacketVersion = cursorPacket.getColumnIndex("version");
        colPacketProtocol = cursorPacket.getColumnIndex("protocol");
        colPacketDAddr = cursorPacket.getColumnIndex("daddr");
        colPacketSAddr = cursorPacket.getColumnIndex("saddr");
        colPacketDPort = cursorPacket.getColumnIndex("dport");
        colPacketSPort = cursorPacket.getColumnIndex("sport");
        colPacketDName = cursorPacket.getColumnIndex("dname");
        colPacketTLSversion = cursorPacket.getColumnIndex("TLSversion");
        colPacketCipher = cursorPacket.getColumnIndex("cipher");
        colPacketHash = cursorPacket.getColumnIndex("hash");
        colPacketFlags = cursorPacket.getColumnIndex("flags");
        */
    }

    @Override
    public View newView(Context context, Cursor cursor, ViewGroup parent) {
        return LayoutInflater.from(context).inflate(R.layout.packet, parent, false);
    }

    @Override
    public void bindView(final View view, final Context context, final Cursor cursor) {
        // Get values
        long time = cursor.getLong(colPacketTime);
        String payload = new String(cursor.getBlob(colPacketData));
        Log.d(TAG, "PAYLOAD");
        // Get views
        TextView tvTime = (TextView) view.findViewById(R.id.tvTime);
        TextView tvPayload = (TextView) view.findViewById(R.id.tvPayload);
        ImageView ivIcon = (ImageView) view.findViewById(R.id.ivIcon);


        // Show time
        tvTime.setText(new SimpleDateFormat("HH:mm:ss").format(time));
        tvPayload.setText(payload);
    }
    }
