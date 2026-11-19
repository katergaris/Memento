package io.github.katergaris.memento;

import android.app.PendingIntent;
import android.appwidget.AppWidgetManager;
import android.appwidget.AppWidgetProvider;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.widget.RemoteViews;

// Widget con tre tasti (Nuova nota, Carte, Ricevi con QR) che aprono l'app con
// un indirizzo memento://. Nessun dato dell'archivio esce dall'app.
public class MementoWidget extends AppWidgetProvider {

    private static PendingIntent open(Context context, String target, int code) {
        Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse("memento://" + target), context, MainActivity.class);
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        return PendingIntent.getActivity(context, code, intent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
    }

    @Override
    public void onUpdate(Context context, AppWidgetManager manager, int[] ids) {
        for (int id : ids) {
            RemoteViews views = new RemoteViews(context.getPackageName(), R.layout.memento_widget);
            views.setOnClickPendingIntent(R.id.w_note, open(context, "nota", 1));
            views.setOnClickPendingIntent(R.id.w_cards, open(context, "carte", 2));
            views.setOnClickPendingIntent(R.id.w_receive, open(context, "ricevi", 3));
            manager.updateAppWidget(id, views);
        }
    }
}
