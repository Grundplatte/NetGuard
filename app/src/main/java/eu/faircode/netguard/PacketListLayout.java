package eu.faircode.netguard;

import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.widget.Adapter;
import android.widget.LinearLayout;

public class PacketListLayout extends LinearLayout implements View.OnClickListener{

    private Adapter list;
    private View.OnClickListener mListener;

    public PacketListLayout(Context context) {
        super(context);
    }

    public PacketListLayout(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    public PacketListLayout(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
    }

    @Override
    public void onClick(View v) {
        if (mListener!=null)
            mListener.onClick(v);
    }

    public void setList(Adapter list) {
        this.list = list;

        //Popolute list
        if (this.list!=null){
            for (int i=0;i<this.list.getCount();i++){
                View item = list.getView(i, null,null);
                this.addView(item);
            }
        }

    }

    public void setmListener(View.OnClickListener mListener) {
        this.mListener = mListener;
    }
}
