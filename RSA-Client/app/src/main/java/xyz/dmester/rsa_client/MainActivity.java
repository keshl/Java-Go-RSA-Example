package xyz.dmester.rsa_client;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.widget.TextView;
import android.widget.Toast;

public class MainActivity extends AppCompatActivity {
	private TextView textView;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);

		textView = (TextView)findViewById(R.id.textView);
		registerReceiver(ErrorReceiver, new IntentFilter
						("xyz.dmester.rsa_client.error_report")
		);

		registerReceiver(changeText, new IntentFilter
				("xyz.dmester.rsa_client.change_text")
		);

		new Thread(new Runnable() {
			@Override
			public void run() {
				Intent broadcastError = new Intent("xyz.dmester.rsa_client.error_report");
				Intent changeText = new Intent("xyz.dmester.rsa_client.change_text");
				SocketManager socketManager = new SocketManager("YOUR HOST HERE", PORT);

				if ( socketManager.isConnected() ) {
					socketManager.encryptConnection();

					if ( socketManager.isEncrypted() ) {
						changeText.putExtra("text", socketManager.read());
						sendBroadcast(changeText);

						socketManager.send("Hello to everyone hehe");
					} else {
						broadcastError.putExtra("error", socketManager.getError());
						sendBroadcast(broadcastError);
					}
				} else {
					broadcastError.putExtra("error", socketManager.getError());
					sendBroadcast(broadcastError);
				}
			}
		}).start();
	}

	private BroadcastReceiver ErrorReceiver = new BroadcastReceiver() {
		@Override
		public void onReceive(Context context, Intent intent) {
			Toast.makeText(context, intent.getStringExtra("error"), Toast.LENGTH_SHORT).show();
		}
	};

	private BroadcastReceiver changeText = new BroadcastReceiver() {
		@Override
		public void onReceive(Context context, Intent intent) {
			String text = intent.getStringExtra("text");
			textView.setText(text);
		}
	};

	@Override
	public void onDestroy() {
		super.onDestroy();
		unregisterReceiver(ErrorReceiver);
		unregisterReceiver(changeText);
	}
}
