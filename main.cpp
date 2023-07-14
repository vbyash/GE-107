#include <WiFi.h>

#include <Wire.h>

#include "esp_wifi.h"

#include <SPI.h>

#include "SSD1306.h"

#include "SH1106.h"

#include <LiquidCrystal_I2C.h>

// set the LCD number of columns and rows

int lcdColumns = 16;

int lcdRows = 2;

// set LCD address, number of columns and rows

// if you don't know your display address, run an I2C scanner sketch

LiquidCrystal_I2C lcd(0x27, lcdColumns, lcdRows);

String maclist[64][3];

int listcount = 0;

String KnownMac[10][2] = { // Put devices you want to be reconized

    {"Xthpb_moto", "A0465A30904B"},

    {"NAME", "MACADDRESS"},

    {"NAME", "MACADDRESS"},

    {"NAME", "MACADDRESS"},

    {"NAME", "MACADDRESS"},

    {"NAME", "MACADDRESS"},

    {"NAME", "MACADDRESS"},

    {"NAME", "MACADDRESS"}

};

String defaultTTL = "60"; // Maximum time (Apx seconds) elapsed before device is consirded offline

const wifi_promiscuous_filter_t filt = {
    // This is the filter for the packets. This is where you can change what packets are sniffed.

    .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA // only sniff management packets and data packets

};

typedef struct
{ // or this

  uint8_t mac[6];

} __attribute__((packed)) MacAddr;

typedef struct
{ // still dont know much about this

  int16_t fctl;

  int16_t duration;

  MacAddr da;

  MacAddr sa;

  MacAddr bssid;

  int16_t seqctl;

  unsigned char payload[];

} __attribute__((packed)) WifiMgmtHdr;

#define maxCh 13 // max Channel -> US = 11, EU = 13, Japan = 14

int curChannel = 1; // current channel

void sniffer(void *buf, wifi_promiscuous_pkt_type_t type)
{ // This is where packets end up after they get sniffed

  wifi_promiscuous_pkt_t *p = (wifi_promiscuous_pkt_t *)buf;

  int len = p->rx_ctrl.sig_len;

  WifiMgmtHdr *wh = (WifiMgmtHdr *)p->payload;

  len -= sizeof(WifiMgmtHdr);

  if (len < 0)
  {

    Serial.println("Received 0");

    return;
  }

  String packet;

  String mac;

  int fctl = ntohs(wh->fctl);

  for (int i = 8; i <= 8 + 6 + 1; i++)
  { // This reads the first couple of bytes of the packet. This is where you can read the whole packet replacing the "8+6+1" with "p->rx_ctrl.sig_len"

    packet += String(p->payload[i], HEX);
  }

  for (int i = 4; i <= 15; i++)
  { // This removes the 'nibble' bits from the stat and end of the data we want. So we only get the mac address.

    mac += packet[i];
  }

  mac.toUpperCase();

  int added = 0;

  for (int i = 0; i <= listcount; i++)
  { // checks if the MAC address has been added before

    if (mac == maclist[i][0])
    {

      maclist[i][1] = defaultTTL;
      maclist[i][2] = "ONLINE";
      

      added = 1;
    }
  }

  if (added == 0)
  { // If its new. add it to the array.

    maclist[listcount][0] = mac;

    maclist[listcount][1] = defaultTTL;

    maclist[listcount][2] = "ONLINE";

    // Serial.println(mac);

    listcount++;

    // Serial.println(listcount);

    // Serial.println(mac);

    Serial.println();

    if (listcount >= 64)
    {

      Serial.println("Too many addresses");

      listcount = 0;
    }
  }

  int count = 0;

  for (int i = 0; i <= listcount; i++)
  {

    if (maclist[i][0] != "" && maclist[i][2] != "NO probe request detected!")
    {
      count++;
    }
  }

  lcd.setCursor(0, 0);

  lcd.print(count);

  // Serial.println(maclist[0].size());  //delay(2000);
}

/**/

//===== SETUP =====//

void setup()
{

  /* start Serial */

  Serial.begin(115200);

  // initialize LCD

  lcd.init();

  // turn on LCD backlight

  lcd.backlight();

  /* setup wifi */

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();

  esp_wifi_init(&cfg);

  esp_wifi_set_storage(WIFI_STORAGE_RAM);

  esp_wifi_set_mode(WIFI_MODE_NULL);

  esp_wifi_start();

  esp_wifi_set_promiscuous(true);

  esp_wifi_set_promiscuous_filter(&filt);

  esp_wifi_set_promiscuous_rx_cb(&sniffer);

  esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);

  Serial.println("starting!");
}

void purge()
{ // This manages the TTL

  for (int i = 0; i <= 63; i++)
  {

    if (!(maclist[i][0] == "") )
    {

      int ttl = (maclist[i][1].toInt());

      ttl--;

      if (ttl <= 0)
      {

        // Serial.println("OFFLINE: " + maclist[i][0]);

        maclist[i][2] = "NO probe request detected!";

        maclist[i][1] = defaultTTL;

        //maclist[i][0] = "";
      }
      else
      {

        maclist[i][1] = String(ttl);
      }
    }
  }
}

void showpeople()
{ // This checks if the MAC is in the recognized list and then displays it on the LcD and/or prints it to serial.

  String forScreen = "";

  for (int i = 0; i <= 63; i++)
  {

    String tmp1 = maclist[i][0];

    if (!(tmp1 == ""))
    {

      for (int j = 0; j <= 9; j++)
      {

        String tmp2 = KnownMac[j][1];

        if (tmp1 == tmp2)
        {

          forScreen += (KnownMac[j][0] + " : " + maclist[i][2] + "\n");

          Serial.print(KnownMac[j][0] + " : " + tmp1 + " : " + maclist[i][2] + "\n -- \n");
        }
      }
    }
  }

  // update_screen_text(forScreen);
}

//===== LOOP =====//

void loop()
{

  // Serial.println("Changed channel:" + String(curChannel));

  if (curChannel > maxCh)
  {

    curChannel = 1;
  }

  esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);

  delay(1000);

  //updatetime();

  purge();

  // showpeople();     //can be used to print known people's mac addresses

  // print message

  // so far its counting the same person multiple times

  // delay(100);

  curChannel++;
}
