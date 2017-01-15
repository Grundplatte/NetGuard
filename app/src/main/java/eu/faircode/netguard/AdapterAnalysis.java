package eu.faircode.netguard;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Build;
import android.preference.PreferenceManager;
import android.support.v4.graphics.drawable.DrawableCompat;
import android.support.v4.view.ViewCompat;
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

    private boolean isHTTPS;
    private boolean isGood;

    private int colTime;
    private int colVersion;
    private int colProtocol;
    private int colDAddr;
    private int colDPort;
    private int colDName;

    private int colTLSversion;
    private int colStr;
    private int colCipher;

    private int colUid;
    //private int colData;
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

        //details
        public TextView tvAppName;
        public TextView tvAppVersion;
        public TextView tvProtocol;
        public TextView tvHTTP;
        public TextView tvTLS;
        public TextView tvCipher;
        public TextView tvHash;
        public TextView tvKeyExchange;
        public TextView tvIP;
        public TextView tvIPname;
        public TextView tvOrganization;
        public TextView tvPort;
        public TextView tvPacketType;
        public TextView tvPayload;


        public ViewHolder(View itemView) {
            super(itemView);
            view = itemView;

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

            tvAppName = (TextView) view.findViewById(R.id.tvName);
            tvAppVersion = (TextView) view.findViewById(R.id.tvAppVersion);
            tvProtocol = (TextView) view.findViewById(R.id.tvProtocol);
            tvHTTP = (TextView) view.findViewById(R.id.tvHTTP);
            tvTLS = (TextView) view.findViewById(R.id.tvTLSversion);
            tvCipher = (TextView) view.findViewById(R.id.tvCipher);
            tvHash = (TextView) view.findViewById(R.id.tvHash);
            tvKeyExchange = (TextView) view.findViewById(R.id.tvKeyExchange);
            tvIP = (TextView) view.findViewById(R.id.tvIP);
            tvIPname = (TextView) view.findViewById(R.id.tvIPname);
            tvOrganization = (TextView) view.findViewById(R.id.tvOrganization) ;
            tvPort = (TextView) view.findViewById(R.id.tvPort);
            tvPacketType = (TextView) view.findViewById(R.id.tvPacketType);
            tvPayload = (TextView) view.findViewById(R.id.tvPayload);
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

    public AdapterAnalysis(Context context, Cursor cursor){
        super(context, cursor);

        this.context = context;

        //colTime = cursor.getColumnIndex("time");
        colVersion = cursor.getColumnIndex("version");
        colProtocol = cursor.getColumnIndex("protocol");
        colDAddr = cursor.getColumnIndex("daddr");
        colDPort = cursor.getColumnIndex("dport");
        colDName = cursor.getColumnIndex("dname");
        colUid = cursor.getColumnIndex("uid");
        //colData = cursor.getColumnIndex("data");
        colTLSversion = cursor.getColumnIndex("TLSversion");
        colCipher = cursor.getColumnIndex("cipher");
        colStr = cursor.getColumnIndex("str");

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

        for(int i = 0; i < cursor.getCount(); i++)
            listExpanded.add(i, false);

        oldCount = cursor.getCount();
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
        //long time = cursor.getLong(colTime);
        String daddr = cursor.getString(colDAddr);
        String dname = (cursor.isNull(colDName) ? null : cursor.getString(colDName));
        int dport = (cursor.isNull(colDPort) ? -1 : cursor.getInt(colDPort));
        int uid = (cursor.isNull(colUid) ? -1 : cursor.getInt(colUid));


        // Show time
        //viewHolder.tvTime.setText(new SimpleDateFormat("HH:mm:ss").format(time));
        viewHolder.tvTime.setText("ufo time");


        // TODO: i am ugly
        isGood = true;
        if(dport == 443)
            isHTTPS = true;
        else
            isHTTPS = false;

        if (isHTTPS)
            viewHolder.ivLock.setImageResource(R.drawable.lock_https);
        else
            viewHolder.ivLock.setImageResource(R.drawable.lock_http);

        if (isGood)
            viewHolder.ivStatus.setImageResource(R.drawable.status_ok);
        else
            viewHolder.ivStatus.setImageResource(R.drawable.status_attention);

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            Drawable wrap_lock = DrawableCompat.wrap(viewHolder.ivLock.getDrawable());
            Drawable wrap_status = DrawableCompat.wrap(viewHolder.ivStatus.getDrawable());
            DrawableCompat.setTint(wrap_lock, isHTTPS == true ? colorOn : colorOff);
            DrawableCompat.setTint(wrap_status, isGood == true ? colorOn : colorOff);
        }


        // Show destination port
        viewHolder.tvDPort.setText(dport < 0 ? "" : Integer.toString(dport));


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

        // Show destination address
        viewHolder.tvDaddr.setText(daddr);

        // show details (expand)
        if(listExpanded.get((int)pos)) {
            cursor.moveToPosition((int)pos);

            //String payload = (cursor.isNull(colData) ? "" : cursor.getString(colData));
            int version = (cursor.isNull(colVersion) ? -1 : cursor.getInt(colVersion));
            int protocol = (cursor.isNull(colProtocol) ? -1 : cursor.getInt(colProtocol));
            int SSLversion = (cursor.isNull(colTLSversion) ? -1 : cursor.getInt(colTLSversion));
            int cipher = (cursor.isNull(colCipher) ? -1 : cursor.getInt(colCipher));
            int str = (cursor.isNull(colStr) ? -1 : cursor.getInt(colStr));


            String protocol_name = Util.getProtocolName(protocol, version, false);
            String HTTP_name = isHTTPS ? "HTTPS" : "HTTP";
            viewHolder.llAnalysisExpanded.setVisibility(View.VISIBLE);

            viewHolder.tvProtocol.setText("    Transfer Protocol: " + protocol_name);
            viewHolder.tvHTTP.setText("    Application Protocol: " + HTTP_name);

            if(isHTTPS) {
                viewHolder.llHTTPS.setVisibility(View.VISIBLE);
                viewHolder.tvTLS.setText("    Version: " + SSLversion);
                viewHolder.tvCipher.setText("    Cipher: " + cipher);
                viewHolder.tvHash.setText("    Hash: " + str);
                viewHolder.tvKeyExchange.setText("    Key Exchange:");
            }
            else
                viewHolder.llHTTPS.setVisibility(View.GONE);

            viewHolder.tvIP.setText("    Destination Address: " + daddr);
            viewHolder.tvIPname.setText("    Destination Name: " + dname);
            viewHolder.tvPort.setText("    Destination Port: " + dport);
            viewHolder.tvPacketType.setText("    Type: " + getKnownPort(dport));

            viewHolder.tvPayload.setText("FAG");

            // Show organization
                if (!isKnownAddress(daddr))
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
        }
        else {
            viewHolder.llAnalysisExpanded.setVisibility(View.GONE);
        }

    }

    public boolean isKnownAddress(String addr) {
        try {
            InetAddress a = InetAddress.getByName(addr);
            if (a.equals(dns1) || a.equals(dns2) || a.equals(vpn4) || a.equals(vpn6))
                return true;
        } catch (UnknownHostException ignored) {
        }
        return false;
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
                    boolean other = prefs.getBoolean("proto_other", true);
                    cursor = DatabaseHelper.getInstance(context).getSessions(udp, tcp, other);
                }
                else {
                    // set the new cursor
                    //query = query.toString().toLowerCase().trim();
                    //todo: add udp, tcp, other to searchlog
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
