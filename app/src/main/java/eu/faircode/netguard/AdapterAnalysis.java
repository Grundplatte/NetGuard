package eu.faircode.netguard;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Build;
import android.preference.PreferenceManager;
import android.provider.ContactsContract;
import android.support.v4.graphics.drawable.DrawableCompat;
import android.support.v4.view.ViewCompat;
import android.support.v7.widget.LinearLayoutManager;
import android.support.v7.widget.RecyclerView;
import android.util.Log;
import android.util.TypedValue;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Filter;
import android.widget.Filterable;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;

import com.squareup.picasso.Picasso;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by Rainer on 13.12.2016.
 */

public class AdapterAnalysis extends CursorRecyclerViewAdapter<AdapterAnalysis.ViewHolder> implements Filterable{
    private static String TAG = "NetGuard.Analysis";

    private Context context;
    private RecyclerView rv;
    private PacketListLayout lvPayload;

    private boolean isHTTPS;

    private int colSessionId;
    private int colSessionUid;
    private int colSessionTime;
    private int colSessionVersion;
    private int colSessionProtocol;
    private int colSessionDAddr;
    private int colSessionSAddr;
    private int colSessionDPort;
    private int colSessionSPort;
    private int colSessionDName;
    private int colSessionTLSversion;
    private int colSessionCipher;
    private int colSessionPup;
    private int colSessionPdown;
    private int colSessionSecure;

    private int colorOn;
    private int colorOff;
    private int iconSize;
    private InetAddress dns1 = null;
    private InetAddress dns2 = null;
    private InetAddress vpn4 = null;
    private InetAddress vpn6 = null;

    // todo: problem when loading new packets and app expanded!
    private List<Boolean> listExpanded = new ArrayList<>();
    private int oldCount;


    public class ViewHolder extends RecyclerView.ViewHolder{
        public View view;

        public LinearLayout llAnalysis;
        public LinearLayout llAnalysisExpanded;
        public LinearLayout llHTTPS;

        public TextView tvTime;
        public TextView tvDaddr;
        public TextView tvDPort;
        public ImageView ivIcon;
        public ImageView ivLock;
        public ImageView ivStatus;
        public ImageView ivExpander;
        public ImageView ivPacketCount;

        //details
        public TextView tvAppName;
        public TextView tvAppVersion;
        public TextView tvProtocol;
        public TextView tvHTTP;
        public TextView tvTLSversion;
        public TextView tvCipherProtocol;
        public TextView tvKxAlgo;
        public TextView tvAuthAlgo;
        public TextView tvSymEncAlgo;
        public TextView tvHashAlgo;
        public TextView tvSymEncKeySize;
        public TextView tvIP;
        public TextView tvIPname;
        public TextView tvOrganization;
        public TextView tvPort;
        public TextView tvPacketsReceived;
        public TextView tvpacketsSent;
        public TextView tvPacketCount;


        public ViewHolder(View itemView) {
            super(itemView);
            view = itemView;

            lvPayload = (PacketListLayout) view.findViewById(R.id.lvPayload);

            llAnalysis = (LinearLayout) view.findViewById(R.id.llAnalysis);
            llAnalysisExpanded = (LinearLayout) view.findViewById(R.id.llAnalysisExpanded);
            llHTTPS = (LinearLayout) view.findViewById(R.id.llHTTPS);

            tvTime = (TextView) view.findViewById(R.id.tvTime);
            tvDaddr = (TextView) view.findViewById(R.id.tvDAddr);
            tvDPort = (TextView) view.findViewById(R.id.tvDPort);
            ivIcon = (ImageView) view.findViewById(R.id.ivIcon);
            ivLock = (ImageView) view.findViewById(R.id.ivLock);
            ivStatus = (ImageView) view.findViewById(R.id.ivStatus);
            ivExpander = (ImageView) view.findViewById(R.id.ivExpander);
            ivPacketCount = (ImageView) view.findViewById(R.id.ivPacketCount);

            tvAppName = (TextView) view.findViewById(R.id.tvName);
            tvAppVersion = (TextView) view.findViewById(R.id.tvAppVersion);
            tvProtocol = (TextView) view.findViewById(R.id.tvProtocol);
            tvHTTP = (TextView) view.findViewById(R.id.tvHTTP);
            tvTLSversion = (TextView) view.findViewById(R.id.tvTLSversion);
            tvCipherProtocol = (TextView) view.findViewById(R.id.tvCipherProtocol);
            tvKxAlgo = (TextView) view.findViewById(R.id.tvKxAlgo);
            tvAuthAlgo = (TextView) view.findViewById(R.id.tvAuthAlgo);
            tvSymEncAlgo = (TextView) view.findViewById(R.id.tvSymEncAlgo);
            tvHashAlgo = (TextView) view.findViewById(R.id.tvHashAlgo);

            tvSymEncKeySize = (TextView) view.findViewById(R.id.tvSymEncKeySize);
            tvIP = (TextView) view.findViewById(R.id.tvIP);
            tvIPname = (TextView) view.findViewById(R.id.tvIPname);
            tvOrganization = (TextView) view.findViewById(R.id.tvOrganization) ;
            tvPort = (TextView) view.findViewById(R.id.tvPort);
            tvPacketsReceived = (TextView) view.findViewById(R.id.tvPacketsReceived);
            tvpacketsSent = (TextView) view.findViewById(R.id.tvPacketsSent);
            tvPacketCount = (TextView) view.findViewById(R.id.tvPacketCount);
        }
    }

    @Override
    public void changeCursor(Cursor cursor) {
        super.changeCursor(cursor);
        int newCount = cursor.getCount();

        for (int i=oldCount; i < newCount; i++) {
            listExpanded.add(i, false);
        }
        oldCount = newCount;
    }

    public AdapterAnalysis(Context context, Cursor cursorSession){
        super(context, cursorSession);

        this.context = context;

        // Session Table
        colSessionId = cursorSession.getColumnIndex("ID");
        colSessionUid = cursorSession.getColumnIndex("uid");
        colSessionTime = cursorSession.getColumnIndex("time");
        colSessionVersion = cursorSession.getColumnIndex("version");
        colSessionProtocol = cursorSession.getColumnIndex("protocol");
        colSessionDAddr = cursorSession.getColumnIndex("daddr");
        colSessionSAddr = cursorSession.getColumnIndex("saddr");
        colSessionDPort = cursorSession.getColumnIndex("dport");
        colSessionSPort = cursorSession.getColumnIndex("sport");
        colSessionDName = cursorSession.getColumnIndex("dname");
        colSessionTLSversion = cursorSession.getColumnIndex("TLSversion");
        colSessionCipher = cursorSession.getColumnIndex("cipher");
        colSessionPup = cursorSession.getColumnIndex("pup");
        colSessionPdown = cursorSession.getColumnIndex("pdown");
        colSessionSecure = cursorSession.getColumnIndex("secure");

        TypedValue tv = new TypedValue();
        context.getTheme().resolveAttribute(R.attr.colorOn, tv, true);
        colorOn = tv.data;
        context.getTheme().resolveAttribute(R.attr.colorOff, tv, true);
        colorOff = tv.data;

        iconSize = Util.dips2pixels(24, context);

        try {
            List<InetAddress> lstDns = ServiceSinkhole.getDns(context);
            dns1 = (lstDns.size() > 0 ? lstDns.get(0) : null);
            dns2 = (lstDns.size() > 1 ? lstDns.get(1) : null);
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
            vpn4 = InetAddress.getByName(prefs.getString("vpn4", "10.1.10.1"));
            vpn6 = InetAddress.getByName(prefs.getString("vpn6", "fd00:1:fd00:1:fd00:1:fd00:1"));
        } catch (UnknownHostException ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }

        for(int i = 0; i < cursorSession.getCount(); i++)
            listExpanded.add(i, false);

        oldCount = cursorSession.getCount();
    }

    @Override
    public ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        View itemView = LayoutInflater.from(parent.getContext())
                .inflate(R.layout.analysis, parent, false);
        ViewHolder vh = new ViewHolder(itemView);
        return vh;
    }

    @Override
    public void onAttachedToRecyclerView(RecyclerView recyclerView) {
        super.onAttachedToRecyclerView(recyclerView);
        rv = recyclerView;
    }

    @Override
    public void onDetachedFromRecyclerView(RecyclerView recyclerView) {
        super.onDetachedFromRecyclerView(recyclerView);
        rv = null;
    }

    @Override
    public void onBindViewHolder(final ViewHolder viewHolder, final Cursor cursor) {

        final long pos = cursor.getPosition();

        viewHolder.llAnalysis.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                int pos_int = (int)pos;
                if (listExpanded.get(pos_int))
                    listExpanded.set(pos_int, false);
                else {
                    // to close all others
                    for(int i = 0; i < cursor.getCount(); i++) {
                        if (listExpanded.get(i) == true) {
                            listExpanded.set(i, false);
                            notifyItemChanged(i);
                            break;
                        }
                    }

                    listExpanded.set(pos_int, true);
                }
                notifyItemChanged(pos_int);
            }
        });

        // Show expand/collapse indicator
        viewHolder.ivExpander.setImageLevel((listExpanded.get((int)pos) == true) ? 1 : 0);

        // Get values
        long time = cursor.getLong(colSessionTime);
        String daddr = cursor.getString(colSessionDAddr);
        String saddr = cursor.getString(colSessionSAddr);
        String dname = (cursor.isNull(colSessionDName) ? null : cursor.getString(colSessionDName));
        int dport = (cursor.isNull(colSessionDPort) ? -1 : cursor.getInt(colSessionDPort));
        int sport = (cursor.isNull(colSessionSPort) ? -1 : cursor.getInt(colSessionSPort));
        int uid = (cursor.isNull(colSessionUid) ? -1 : cursor.getInt(colSessionUid));
        int secure = cursor.getInt(colSessionSecure);
        int pup = (cursor.isNull(colSessionPup) ? -1 : cursor.getInt(colSessionPup));
        int pdown = (cursor.isNull(colSessionPdown) ? -1 : cursor.getInt(colSessionPdown));
        int packetCount = pup + pdown;
        // Show time
        viewHolder.tvTime.setText(new SimpleDateFormat("HH:mm:ss").format(time));

        // Application icon, name & version
        ApplicationInfo info = null;
        PackageManager pm = context.getPackageManager();
        String[] pkg = pm.getPackagesForUid(uid);
        if (pkg != null && pkg.length > 0)
            try {
                info = pm.getApplicationInfo(pkg[0], 0);
            } catch (PackageManager.NameNotFoundException ignored) {
            }
        if (info == null) {
            viewHolder.ivIcon.setImageDrawable(null);
            viewHolder.tvAppName.setText("    Name: ----");
            viewHolder.tvAppVersion.setText("    Version: ----");
        }
        else if (info.icon == 0)
            Picasso.with(context).load(android.R.drawable.sym_def_app_icon).into(viewHolder.ivIcon);
        else {
            Uri uri = Uri.parse("android.resource://" + info.packageName + "/" + info.icon);
            Picasso.with(context).load(uri).resize(iconSize, iconSize).into(viewHolder.ivIcon);
            viewHolder.tvAppName.setText("    Name: " + info.loadLabel(pm).toString());
            String version = "    Version: ----";
            try {
                version = pm.getPackageInfo(info.packageName, 0).versionName;
            }
            catch (PackageManager.NameNotFoundException e) {
            }
            viewHolder.tvAppVersion.setText("    Version: " + version);
        }

        // show lock
        if(dport == 443 || sport == 443)
            isHTTPS = true;
        else
            isHTTPS = false;

        boolean gotTLSProperties = true;
        if (isHTTPS) {
            viewHolder.ivLock.setImageResource(R.drawable.lock_https);
            int TLSversion_ = (cursor.isNull(colSessionTLSversion) ? -1 : cursor.getInt(colSessionTLSversion));
            int cipher_ = (cursor.isNull(colSessionCipher) ? -1 : cursor.getInt(colSessionCipher));
            if(TLSversion_ == -1 || cipher_ == -1)
                gotTLSProperties = false;
        }
        else
            viewHolder.ivLock.setImageResource(R.drawable.lock_http);


        //show status icon
        if (secure != 0 || !gotTLSProperties)
            viewHolder.ivStatus.setImageResource(R.drawable.status_attention);
        else
            viewHolder.ivStatus.setImageResource(R.drawable.status_ok);

        //show packet Count icon
        viewHolder.ivPacketCount.setImageResource(R.drawable.packet_count);

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            Drawable wrap_lock = DrawableCompat.wrap(viewHolder.ivLock.getDrawable());
            Drawable wrap_status = DrawableCompat.wrap(viewHolder.ivStatus.getDrawable());
            DrawableCompat.setTint(wrap_lock, isHTTPS == true ? colorOn : colorOff);
            DrawableCompat.setTint(wrap_status, secure == 1 ? colorOn : colorOff);
        }

        // Show destination address
        viewHolder.tvDaddr.setText(daddr);

        // Show destination port
        viewHolder.tvDPort.setText(dport < 0 ? "" : Integer.toString(dport));

        // Show packet counter
        viewHolder.tvPacketCount.setText(Integer.toString(packetCount));


        // show details (expand)
        if(listExpanded.get((int)pos)) {

            viewHolder.llAnalysisExpanded.setVisibility(View.VISIBLE);

            long sessionId = (cursor.isNull(colSessionId) ? -1 : cursor.getLong(colSessionId));
            int version = (cursor.isNull(colSessionVersion) ? -1 : cursor.getInt(colSessionVersion));
            int protocol = (cursor.isNull(colSessionProtocol) ? -1 : cursor.getInt(colSessionProtocol));
            int TLSversion = (cursor.isNull(colSessionTLSversion) ? -1 : cursor.getInt(colSessionTLSversion));
            int cipher = (cursor.isNull(colSessionCipher) ? -1 : cursor.getInt(colSessionCipher));

            // show Protocol
            String protocol_name = Util.getProtocolName(protocol, version, false);
            String HTTP_name = isHTTPS ? "HTTPS" : "HTTP";
            viewHolder.tvProtocol.setText("    Transfer Protocol: " + protocol_name);
            viewHolder.tvHTTP.setText("    Application Protocol: " + HTTP_name);

            if(isHTTPS) {
                //show TLS properties
                int cipherIndex = CipherLookup.getCipherIndex(cipher);
                viewHolder.llHTTPS.setVisibility(View.VISIBLE);

                viewHolder.tvTLSversion.setText("    TLS Version: " + getTLSName(TLSversion));
                if(secure == 1)
                    viewHolder.tvTLSversion.setTextColor(Color.RED);

                // sometime we dont get the cipher suit (Facebook)
                if(getTLSName(TLSversion) == "undef") {
                    viewHolder.tvTLSversion.setTextColor(Color.RED);
                }

                viewHolder.tvCipherProtocol.setText("    Cipher Protocol: " + CipherLookup.getCipherProtocol(cipherIndex));
                viewHolder.tvKxAlgo.setText("    Key Exchange Algorithm: " + CipherLookup.getKxAlgo(cipherIndex));
                viewHolder.tvAuthAlgo.setText("    Authentication Algorithm: " + CipherLookup.getAuthAlgo(cipherIndex));
                viewHolder.tvHashAlgo.setText("    Hash Algorithm: " + CipherLookup.getHashAlgo(cipherIndex));

                viewHolder.tvSymEncAlgo.setText("    Symmetric Encryption Algorithm: " + CipherLookup.getSymEncAlgo(cipherIndex));
                if(secure == 2)
                    viewHolder.tvSymEncAlgo.setTextColor(Color.RED);

                viewHolder.tvSymEncKeySize.setText("    Symmetric Encryption Key Size: " + CipherLookup.getSymEncKeySize(cipherIndex));
                if(secure == 3)
                    viewHolder.tvSymEncKeySize.setTextColor(Color.RED);
            }
            else
                viewHolder.llHTTPS.setVisibility(View.GONE);

            // show destination informations
            viewHolder.tvIP.setText("    Destination Address: " + daddr);
            viewHolder.tvIPname.setText("    Destination Name: " + dname);
            viewHolder.tvPort.setText("    Destination Port: " + dport + " (" + getKnownPort(dport) + ")");

            // Show organization
            new AsyncTask<String, Object, String>() {
                @Override
                protected void onPreExecute() {
                    ViewCompat.setHasTransientState(viewHolder.tvOrganization, true);
                }

                @Override
                protected String doInBackground(String... args) {
                    try {
                        return Util.getOrganization(args[0]);
                    } catch (Throwable ex) {
                        Log.w(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                        return null;
                    }
                }

                @Override
                protected void onPostExecute(String organization) {
                    if (organization != null) {
                        viewHolder.tvOrganization.setText("    Organization: " + organization);
                    }
                    ViewCompat.setHasTransientState(viewHolder.tvOrganization, false);
                }
            }.execute(daddr);

            //packet counters
            viewHolder.tvPacketsReceived.setText("    Packets Received: " + Integer.toString(pdown));
            viewHolder.tvpacketsSent.setText("    Packets Sent: " + Integer.toString(pup));

            //lvPayload.removeAllViews();
            Cursor packetsCursor = DatabaseHelper.getInstance(context).getSessionPackets(sessionId);
            Log.d(TAG, "PACKETS: " + packetsCursor.getCount());
            AdapterPacket adapter = new AdapterPacket(context, packetsCursor);
            lvPayload.setList(adapter);

        }
        else {
            viewHolder.llAnalysisExpanded.setVisibility(View.GONE);
        }
    }

    public String getTLSName(int version) {

        switch (version) {
            case 0x0300:
                return "SSL 3.0";
            case 0x0301:
                return "TLS 1.0";
            case 0x0302:
                return "TLS 1.1";
            case 0x0303:
                return "TLS 1.2";
            default:
                return "undef";
        }
    }

    private String getKnownPort(int port) {
        // https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers#Well-known_ports
        switch (port) {
            case 7:
                return "echo";
            case 25:
                return "smtp";
            case 53:
                return "dns";
            case 80:
                return "http";
            case 110:
                return "pop3";
            case 143:
                return "imap";
            case 443:
                return "https";
            case 465:
                return "smtps";
            case 993:
                return "imaps";
            case 995:
                return "pop3s";
            default:
                return "undef";
        }
    }

    @Override
    public Filter getFilter() {
        return new Filter() {
            @Override
            protected FilterResults performFiltering(CharSequence query) {
                Cursor cursor;
                if (query == null) {
                    // change cursor to "normal"
                    SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
                    boolean udp = prefs.getBoolean("proto_udp", true);
                    boolean tcp = prefs.getBoolean("proto_tcp", true);
                    boolean dns = prefs.getBoolean("proto_dns", true);
                    boolean other = prefs.getBoolean("proto_other", true);
                    cursor = DatabaseHelper.getInstance(context).getSessions(udp, tcp, dns, other);
                }
                else {
                    // set the new cursor
                    cursor = DatabaseHelper.getInstance(context).searchSessions(query.toString());
                }

                FilterResults results = new FilterResults();
                if (cursor != null) {
                    results.count = cursor.getCount();
                    results.values = cursor;
                } else {
                    results.count = 0;
                    results.values = null;
                }
                return results;
            }

            @Override
            protected void publishResults(CharSequence constraint, FilterResults results) {
                Cursor oldCursor = getCursor();

                if (results.values != null && results.values != oldCursor) {
                    changeCursor((Cursor) results.values);
                }
            }
        };
    }

}
