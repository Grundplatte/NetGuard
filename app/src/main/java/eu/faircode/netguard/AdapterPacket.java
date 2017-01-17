package eu.faircode.netguard;

import android.content.Context;
import android.database.Cursor;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.support.v4.graphics.drawable.DrawableCompat;
import android.util.TypedValue;
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
    private int colPacketDirection;
    private int colPacketDPort;
    private int colPacketSPort;
    private int colPacketFlags;

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
    */

    public AdapterPacket(Context context, Cursor cursorPacket) {
        super(context, cursorPacket, 0);

        colPacketTime = cursorPacket.getColumnIndex("time");
        colPacketData = cursorPacket.getColumnIndex("data");
        colPacketFlags = cursorPacket.getColumnIndex("flags");
        colPacketDirection = cursorPacket.getColumnIndex("direction");
        colPacketDPort = cursorPacket.getColumnIndex("dport");
        colPacketSPort = cursorPacket.getColumnIndex("sport");

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
        String flags = cursor.getString(colPacketFlags);


        int direction = cursor.getInt(colPacketDirection);
        int dport = cursor.getInt(colPacketDPort);
        int sport = cursor.getInt(colPacketSPort);

        if(!payload.isEmpty() && (dport == 443 || sport == 443)) {
            payload = "Payload encrypted!";
        }

        // Get views
        TextView tvTime = (TextView) view.findViewById(R.id.tvTime);
        TextView tvPayload = (TextView) view.findViewById(R.id.tvPayload);
        ImageView ivIcon = (ImageView) view.findViewById(R.id.ivArrow);


        // Show time
        tvTime.setText(new SimpleDateFormat("HH:mm:ss").format(time));

        //show payload
        if(payload.isEmpty())
            tvPayload.setText(flags);
        else
            tvPayload.setText(payload);

        //show icon
        if(direction == 1) {
            ivIcon.setImageResource(R.drawable.packet_out);
            ivIcon.setScaleX(-1);
        }
        else
            ivIcon.setImageResource(R.drawable.packet_in);

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            TypedValue tv = new TypedValue();
            context.getTheme().resolveAttribute(R.attr.colorOn, tv, true);
            int colorOn = tv.data;
            context.getTheme().resolveAttribute(R.attr.colorOff, tv, true);
            int colorOff = tv.data;
            Drawable arrow = DrawableCompat.wrap(ivIcon.getDrawable());
            DrawableCompat.setTint(arrow, direction == 1 ? colorOn : colorOff);
        }
    }
}
