package eu.faircode.netguard;

import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.support.v4.app.NavUtils;
import android.support.v4.view.MenuItemCompat;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.SearchView;
import android.support.v7.widget.SwitchCompat;
import android.text.TextUtils;
import android.util.Log;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.CompoundButton;
import android.widget.FilterQueryProvider;
import android.widget.ListView;
import android.widget.PopupMenu;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.util.Date;

public class ActivityAnalysis extends AppCompatActivity implements SharedPreferences.OnSharedPreferenceChangeListener {
    private static final String TAG = "NetGuard.Analysis";

    private boolean running = false;
    private ListView lvAnalysis;
    private AdapterAnalysis adapter;
    private MenuItem menuSearch = null;

    private boolean live;
    private InetAddress vpn4 = null;
    private InetAddress vpn6 = null;

    private DatabaseHelper.LogChangedListener listener = new DatabaseHelper.LogChangedListener() {
        @Override
        public void onChanged() {
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    updateAdapter();
                }
            });
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        Util.setTheme(this);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.analysislist);
        running = true;

        // Action bar
        View actionView = getLayoutInflater().inflate(R.layout.actionanalysis, null, false);
        SwitchCompat swEnabled = (SwitchCompat) actionView.findViewById(R.id.swEnabled);

        getSupportActionBar().setDisplayShowCustomEnabled(true);
        getSupportActionBar().setCustomView(actionView);

        getSupportActionBar().setTitle(R.string.menu_analysis);
        getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        // Get settings
        final SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        boolean analysis = prefs.getBoolean("analysis", false);

        // Show disabled message
        TextView tvDisabled = (TextView) findViewById(R.id.tvDisabled);
        tvDisabled.setVisibility(analysis ? View.GONE : View.VISIBLE);

        // Set enabled switch
        swEnabled.setChecked(analysis);
        swEnabled.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                prefs.edit().putBoolean("analysis", isChecked).apply();
            }
        });

        // Listen for preference changes
        prefs.registerOnSharedPreferenceChangeListener(this);

        lvAnalysis = (ListView) findViewById(R.id.lvLog);

        boolean udp = prefs.getBoolean("proto_udp", true);
        boolean tcp = prefs.getBoolean("proto_tcp", true);
        boolean other = prefs.getBoolean("proto_other", true);
        boolean allowed = prefs.getBoolean("traffic_allowed", true);
        boolean blocked = prefs.getBoolean("traffic_blocked", true);

        adapter = new AdapterAnalysis(this, DatabaseHelper.getInstance(this).getLog(udp, tcp, other, allowed, blocked), true, true);
        adapter.setFilterQueryProvider(new FilterQueryProvider() {
            public Cursor runQuery(CharSequence constraint) {
                return DatabaseHelper.getInstance(ActivityAnalysis.this).searchLog(constraint.toString());
            }
        });

        lvAnalysis.setAdapter(adapter);

        try {
            vpn4 = InetAddress.getByName(prefs.getString("vpn4", "10.1.10.1"));
            vpn6 = InetAddress.getByName(prefs.getString("vpn6", "fd00:1:fd00:1:fd00:1:fd00:1"));
        } catch (UnknownHostException ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }

        lvAnalysis.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                PackageManager pm = getPackageManager();
                Cursor cursor = (Cursor) adapter.getItem(position);
                long time = cursor.getLong(cursor.getColumnIndex("time"));
                int version = cursor.getInt(cursor.getColumnIndex("version"));
                int protocol = cursor.getInt(cursor.getColumnIndex("protocol"));
                final String saddr = cursor.getString(cursor.getColumnIndex("saddr"));
                final int sport = (cursor.isNull(cursor.getColumnIndex("sport")) ? -1 : cursor.getInt(cursor.getColumnIndex("sport")));
                final String daddr = cursor.getString(cursor.getColumnIndex("daddr"));
                final int dport = (cursor.isNull(cursor.getColumnIndex("dport")) ? -1 : cursor.getInt(cursor.getColumnIndex("dport")));
                final String dname = cursor.getString(cursor.getColumnIndex("dname"));
                final int uid = (cursor.isNull(cursor.getColumnIndex("uid")) ? -1 : cursor.getInt(cursor.getColumnIndex("uid")));
                int allowed = (cursor.isNull(cursor.getColumnIndex("allowed")) ? -1 : cursor.getInt(cursor.getColumnIndex("allowed")));

                // Get external address
                InetAddress addr = null;
                try {
                    addr = InetAddress.getByName(daddr);
                } catch (UnknownHostException ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                }

                String ip;
                int port;
                if (addr.equals(vpn4) || addr.equals(vpn6)) {
                    ip = saddr;
                    port = sport;
                } else {
                    ip = daddr;
                    port = dport;
                }

                // Build popup menu
                PopupMenu popup = new PopupMenu(ActivityAnalysis.this, findViewById(R.id.vwPopupAnchor));
                popup.inflate(R.menu.analysispopup);

                // Application name
                if (uid >= 0)
                    popup.getMenu().findItem(R.id.menu_application).setTitle(TextUtils.join(", ", Util.getApplicationNames(uid, ActivityAnalysis.this)));
                else
                    popup.getMenu().removeItem(R.id.menu_application);

                // Destination IP
                popup.getMenu().findItem(R.id.menu_protocol).setTitle(Util.getProtocolName(protocol, version, false));

                // Whois
                final Intent lookupIP = new Intent(Intent.ACTION_VIEW, Uri.parse("http://www.tcpiputils.com/whois-lookup/" + ip));
                if (pm.resolveActivity(lookupIP, 0) == null)
                    popup.getMenu().removeItem(R.id.menu_whois);
                else
                    popup.getMenu().findItem(R.id.menu_whois).setTitle(getString(R.string.title_log_whois, ip));

                // Lookup port
                final Intent lookupPort = new Intent(Intent.ACTION_VIEW, Uri.parse("http://www.speedguide.net/port.php?port=" + port));
                if (port <= 0 || pm.resolveActivity(lookupPort, 0) == null)
                    popup.getMenu().removeItem(R.id.menu_port);
                else
                    popup.getMenu().findItem(R.id.menu_port).setTitle(getString(R.string.title_log_port, port));

                if (!prefs.getBoolean("filter", false)) {
                    popup.getMenu().removeItem(R.id.menu_allow);
                    popup.getMenu().removeItem(R.id.menu_block);
                }

                final Packet packet = new Packet();
                packet.version = version;
                packet.protocol = protocol;
                packet.daddr = daddr;
                packet.dport = dport;
                packet.time = time;
                packet.uid = uid;
                packet.allowed = (allowed > 0);

                // Time
                popup.getMenu().findItem(R.id.menu_time).setTitle(SimpleDateFormat.getDateTimeInstance().format(time));

                // Handle click
                popup.setOnMenuItemClickListener(new PopupMenu.OnMenuItemClickListener() {
                    @Override
                    public boolean onMenuItemClick(MenuItem menuItem) {
                        switch (menuItem.getItemId()) {
                            case R.id.menu_application: {
                                Intent main = new Intent(ActivityAnalysis.this, ActivityMain.class);
                                main.putExtra(ActivityMain.EXTRA_SEARCH, Integer.toString(uid));
                                startActivity(main);
                                return true;
                            }

                            case R.id.menu_whois:
                                startActivity(lookupIP);
                                return true;

                            case R.id.menu_port:
                                startActivity(lookupPort);
                                return true;

                            case R.id.menu_allow:
                                if (IAB.isPurchased(ActivityPro.SKU_FILTER, ActivityAnalysis.this)) {
                                    DatabaseHelper.getInstance(ActivityAnalysis.this).updateAccess(packet, dname, 0);
                                    ServiceSinkhole.reload("allow host", ActivityAnalysis.this);
                                    Intent main = new Intent(ActivityAnalysis.this, ActivityMain.class);
                                    main.putExtra(ActivityMain.EXTRA_SEARCH, Integer.toString(uid));
                                    startActivity(main);
                                } else
                                    startActivity(new Intent(ActivityAnalysis.this, ActivityPro.class));
                                return true;

                            case R.id.menu_block:
                                if (IAB.isPurchased(ActivityPro.SKU_FILTER, ActivityAnalysis.this)) {
                                    DatabaseHelper.getInstance(ActivityAnalysis.this).updateAccess(packet, dname, 1);
                                    ServiceSinkhole.reload("block host", ActivityAnalysis.this);
                                    Intent main = new Intent(ActivityAnalysis.this, ActivityMain.class);
                                    main.putExtra(ActivityMain.EXTRA_SEARCH, Integer.toString(uid));
                                    startActivity(main);
                                } else
                                    startActivity(new Intent(ActivityAnalysis.this, ActivityPro.class));
                                return true;

                            default:
                                return false;
                        }
                    }
                });

                // Show
                popup.show();
            }
        });

        live = true;
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (live) {
            DatabaseHelper.getInstance(this).addLogChangedListener(listener);
            updateAdapter();
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (live)
            DatabaseHelper.getInstance(this).removeLogChangedListener(listener);
    }

    @Override
    protected void onDestroy() {
        running = false;
        adapter = null;
        PreferenceManager.getDefaultSharedPreferences(this).unregisterOnSharedPreferenceChangeListener(this);
        super.onDestroy();
    }

    @Override
    public void onSharedPreferenceChanged(SharedPreferences prefs, String name) {
        Log.i(TAG, "Preference " + name + "=" + prefs.getAll().get(name));
        if ("analysis".equals(name)) {
            // Get enabled
            boolean analysis = prefs.getBoolean(name, false);

            // Display disabled warning
            TextView tvDisabled = (TextView) findViewById(R.id.tvDisabled);
            tvDisabled.setVisibility(analysis ? View.GONE : View.VISIBLE);

            // Check switch state
            SwitchCompat swEnabled = (SwitchCompat) getSupportActionBar().getCustomView().findViewById(R.id.swEnabled);
            if (swEnabled.isChecked() != analysis)
                swEnabled.setChecked(analysis);

            ServiceSinkhole.reload("changed " + name, ActivityAnalysis.this);
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.analysisoptions, menu);

        menuSearch = menu.findItem(R.id.menu_search);
        SearchView searchView = (SearchView) MenuItemCompat.getActionView(menuSearch);
        searchView.setOnQueryTextListener(new SearchView.OnQueryTextListener() {
            @Override
            public boolean onQueryTextSubmit(String query) {
                if (adapter != null)
                    adapter.getFilter().filter(query);
                return true;
            }

            @Override
            public boolean onQueryTextChange(String newText) {
                if (adapter != null)
                    adapter.getFilter().filter(newText);
                return true;
            }
        });
        searchView.setOnCloseListener(new SearchView.OnCloseListener() {
            @Override
            public boolean onClose() {
                if (adapter != null)
                    adapter.getFilter().filter(null);
                return true;
            }
        });

        return true;
    }

    @Override
    public boolean onPrepareOptionsMenu(Menu menu) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);

        menu.findItem(R.id.menu_protocol_udp).setChecked(prefs.getBoolean("proto_udp", true));
        menu.findItem(R.id.menu_protocol_tcp).setChecked(prefs.getBoolean("proto_tcp", true));
        menu.findItem(R.id.menu_protocol_other).setChecked(prefs.getBoolean("proto_other", true));
        menu.findItem(R.id.menu_traffic_allowed).setEnabled(prefs.getBoolean("filter", false));
        menu.findItem(R.id.menu_traffic_allowed).setChecked(prefs.getBoolean("traffic_allowed", true));
        menu.findItem(R.id.menu_traffic_blocked).setChecked(prefs.getBoolean("traffic_blocked", true));

        menu.findItem(R.id.menu_analysis_refresh).setEnabled(!menu.findItem(R.id.menu_anaysis_live).isChecked());

        return super.onPrepareOptionsMenu(menu);
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        final SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);

        switch (item.getItemId()) {
            case android.R.id.home:
                Log.i(TAG, "Up");
                NavUtils.navigateUpFromSameTask(this);
                return true;

            case R.id.menu_protocol_udp:
                item.setChecked(!item.isChecked());
                prefs.edit().putBoolean("proto_udp", item.isChecked()).apply();
                updateAdapter();
                return true;

            case R.id.menu_protocol_tcp:
                item.setChecked(!item.isChecked());
                prefs.edit().putBoolean("proto_tcp", item.isChecked()).apply();
                updateAdapter();
                return true;

            case R.id.menu_protocol_other:
                item.setChecked(!item.isChecked());
                prefs.edit().putBoolean("proto_other", item.isChecked()).apply();
                updateAdapter();
                return true;

            case R.id.menu_traffic_allowed:
                item.setChecked(!item.isChecked());
                prefs.edit().putBoolean("traffic_allowed", item.isChecked()).apply();
                updateAdapter();
                return true;

            case R.id.menu_traffic_blocked:
                item.setChecked(!item.isChecked());
                prefs.edit().putBoolean("traffic_blocked", item.isChecked()).apply();
                updateAdapter();
                return true;

            case R.id.menu_anaysis_live:
                item.setChecked(!item.isChecked());
                live = item.isChecked();
                if (live) {
                    DatabaseHelper.getInstance(this).addLogChangedListener(listener);
                    updateAdapter();
                } else
                    DatabaseHelper.getInstance(this).removeLogChangedListener(listener);
                return true;

            case R.id.menu_analysis_refresh:
                updateAdapter();
                return true;

            case R.id.menu_anaysis_alert:
                item.setChecked(!item.isChecked());
                prefs.edit().putBoolean("alert", item.isChecked()).apply();
                // TODO: maybe add ServiceSinkhole code?
                return true;

            case R.id.menu_analysis_clear:
                new AsyncTask<Object, Object, Object>() {
                    @Override
                    protected Object doInBackground(Object... objects) {
                        DatabaseHelper.getInstance(ActivityAnalysis.this).clearLog();
                        return null;
                    }

                    @Override
                    protected void onPostExecute(Object result) {
                        if (running)
                            updateAdapter();
                    }
                }.execute();
                return true;

            default:
                return super.onOptionsItemSelected(item);
        }
    }

    private void updateAdapter() {
        if (adapter != null) {
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
            boolean udp = prefs.getBoolean("proto_udp", true);
            boolean tcp = prefs.getBoolean("proto_tcp", true);
            boolean other = prefs.getBoolean("proto_other", true);
            boolean allowed = prefs.getBoolean("traffic_allowed", true);
            boolean blocked = prefs.getBoolean("traffic_blocked", true);
            adapter.changeCursor(DatabaseHelper.getInstance(this).getLog(udp, tcp, other, allowed, blocked));
            if (menuSearch != null && menuSearch.isActionViewExpanded()) {
                SearchView searchView = (SearchView) MenuItemCompat.getActionView(menuSearch);
                adapter.getFilter().filter(searchView.getQuery().toString());
            }
        }
    }

    private Intent getIntentPCAPDocument() {
        Intent intent;
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.KITKAT) {
            if (Util.isPackageInstalled("org.openintents.filemanager", this)) {
                intent = new Intent("org.openintents.action.PICK_DIRECTORY");
            } else {
                intent = new Intent(Intent.ACTION_VIEW);
                intent.setData(Uri.parse("https://play.google.com/store/apps/details?id=org.openintents.filemanager"));
            }
        } else {
            intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            intent.setType("application/octet-stream");
            intent.putExtra(Intent.EXTRA_TITLE, "netguard_" + new SimpleDateFormat("yyyyMMdd").format(new Date().getTime()) + ".pcap");
        }
        return intent;
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, final Intent data) {
        Log.i(TAG, "onActivityResult request=" + requestCode + " result=" + requestCode + " ok=" + (resultCode == RESULT_OK));

        Log.w(TAG, "Unknown activity result request=" + requestCode);
        super.onActivityResult(requestCode, resultCode, data);
    }
}
