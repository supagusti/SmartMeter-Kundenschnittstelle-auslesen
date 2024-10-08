// Programm zur Auslesung und Entschlüsselung der Kundenschnittstelle eines SmartMeters der EVN (NÖ)
// Bibliothek: https://github.com/rweather/arduinolibs/tree/master/libraries/Crypto
// Aus dem Ordner "libraries" die Bibliothek "Crypto" installieren!
// Prg. funktioniert für einen Atmega2560 (Arduino Mega), Man könnte aber auch die Bibliothek SoftwareSerial benutzen um 
// das Programm auf einem anderen Mikrocontroller zu realisieren.

#include <esp_task_wdt.h>
#include <Crypto.h>
#include <AES.h>
#include <GCM.h>

#include <WiFi.h>
#include <PubSubClient.h>


#define MAX_PLAINTEXT_LEN 300

//================================
bool  DEBUG_ENABLED = false;
//================================


bool ReceiveError = false;

// Replace the next variables with your SSID/Password combination
const char* ssid = "<ENTER YOU WLAN SSI>";
const char* password = "<ENTER YOUR WLAN PASSWORD>";

// Add your MQTT Broker IP address, example:
const char* mqtt_server = "192.168.0.150";

WiFiClient espClient;
PubSubClient client(espClient);

#define RX1 16
#define TX1 17
const int ledPin =LED_BUILTIN;
bool readyToSend=true;

int byteNumber = 0;
int eingelesendeBytes = 0;
unsigned long timeSinceLastData = 0;
bool processData = false;

struct Vector_GCM {
  const char *name;
  byte keysize;
  unsigned int datasize;
  byte authsize;
  byte ivsize;
  byte tagsize;
  uint8_t key[16];
  byte plaintext[MAX_PLAINTEXT_LEN];
  byte ciphertext[MAX_PLAINTEXT_LEN];
  byte authdata[17];
  byte iv[12];
  byte tag[12];
};

struct IncommingData {
  byte year, month, day, hour, minutes, seconds;
  unsigned long wirkenergiePlus, wirkenergieMinus, momentanleistungPlus, momentanleistungMinus;
  float uL1, uL2, uL3, iL1, iL2, iL3, powerF;
};

IncommingData aktuelleDaten;

Vector_GCM datenMbus = {   //static
  .name        = "AES-128 GCM",
  .keysize     = 16,
  .datasize    = 297,
  .authsize    = 17,
  .ivsize      = 12,
  .tagsize     = 12,
  .key         = {0x18, 0x81, 0x65, 0x47, 0xAD, 0x78, 0xC0, 0x4D, 0x64, 0xD9, 0x43, 0x94, 0x37, 0xCD, 0x4C, 0xCC},
  .plaintext   = {},
  .ciphertext  = {},
  .authdata    = {},
  .iv          = {},
  .tag         = {},  
};

bool firstOne=true;



void setup() {

  //----------------------------
  // WATCHDOG
  //----------------------------
     #define WDT_TIMEOUT 25
      // ESP32 Watchdog timer -    Note: esp32 board manager v3.x.x requires different code
        #if defined ESP32
          esp_task_wdt_deinit();                  // ensure a watchdog is not already configured
          #if defined(ESP_ARDUINO_VERSION_MAJOR) && ESP_ARDUINO_VERSION_MAJOR == 3  
            // v3 board manager detected
            // Create and initialize the watchdog timer(WDT) configuration structure
              esp_task_wdt_config_t wdt_config = {
                  .timeout_ms = WDT_TIMEOUT * 1000, // Convert seconds to milliseconds
                  .idle_core_mask = 1 << 0,         // Monitor core 1 only
                  .trigger_panic = true             // Enable panic
              };
            // Initialize the WDT with the configuration structure
              esp_task_wdt_init(&wdt_config);       // Pass the pointer to the configuration structure
              esp_task_wdt_add(NULL);               // Add current thread to WDT watch    
              esp_task_wdt_reset();                 // reset timer
          #else
            // pre v3 board manager assumed
              esp_task_wdt_init(WDT_TIMEOUT, true);                      //enable panic so ESP32 restarts
              esp_task_wdt_add(NULL);                                    //add current thread to WDT watch   
          #endif
        #endif
  //----------------------------

  
  for (int i = 0; i < MAX_PLAINTEXT_LEN; i++) {
    datenMbus.plaintext[i] = 0x00;
    datenMbus.ciphertext[i]=0x00;
  }
  Serial.begin(115200);
  Serial1.begin(2400, SERIAL_8N1, RX1, TX1);
  
  setup_wifi();
  client.setServer(mqtt_server, 1883);
  client.setCallback(callback);
  // initialize digital pin LED_BUILTIN as an output.
  pinMode(ledPin, OUTPUT);
 
}

void setup_wifi() {
  delay(10);
  // We start by connecting to a WiFi network
  Serial.println();
  Serial.print("Connecting to ");
  Serial.println(ssid);

  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("");
  Serial.println("WiFi connected");
  Serial.println("IP address: ");
  Serial.println(WiFi.localIP());
}

void reconnect() {
  // Loop until we're reconnected
  while (!client.connected()) {
    Serial.print("Attempting MQTT connection...");
    // Attempt to connect
    if (client.connect("ESP32Client_Smartmeter10")) {
      Serial.println("connected");
      // Subscribe
      client.subscribe("smartmeter10/esp32-reset");
    } else {
      Serial.print("failed, rc=");
      Serial.print(client.state());
      Serial.println(" try again in 5 seconds");
      // Wait 5 seconds before retrying
      delay(5000);
    }
  }
}

void callback(char* topic, byte* message, unsigned int length) {
  Serial.print("Message arrived on topic: ");
  Serial.print(topic);
  Serial.print(". Message: ");
  String messageTemp;
  
  for (int i = 0; i < length; i++) {
    Serial.print((char)message[i]);
    messageTemp += (char)message[i];
  }
  Serial.println();

  // Feel free to add more if statements to control more GPIOs with MQTT

  // If a message is received on the topic esp32/output, you check if the message is either "on" or "off". 
  // Changes the output state according to the message
  if (String(topic) == "smartmeter10/esp32-reset") {
    Serial.println("Reseting ESP32 via MQTT.. ");
    ESP.restart();
    }
  }


void loop() {

  delay(1);  //VERY VERY IMPORTANT for Watchdog Reset to apply. At least 1 ms
  esp_task_wdt_reset();
  
  if (!client.connected()) {
    reconnect();
  }
  client.loop();


  
  if (millis() > timeSinceLastData + 3000) {                // Das SmartMeter sendet alle 5Sek neue Daten-> 
      byteNumber = 0;                                       // Position im Speicher Array nach 3Sek wieder auf null setzen um neue Daten empfangen zu können
      ReceiveError = false;                                 // Fehlerindikator zurücksetzen
    }
  while (Serial1.available() > 0) {                         // Wenn Daten im Buffer der Ser. SChnittstelle sind....
    if (byteNumber < MAX_PLAINTEXT_LEN) {
      datenMbus.ciphertext[byteNumber] = Serial1.read();    // Daten speichern
      byteNumber++;                                         // Zählvariable erhöhen
    }
    timeSinceLastData = millis();
    //Serial.print("Bytenumber: ");      
    //Serial.println(byteNumber);        
    eingelesendeBytes=byteNumber;
  }
  if (millis() > timeSinceLastData + 3000) {                // Sind mehr als 3 Sekunden vergangen-> Daten entschlüsseln
    if (processData) {
      
    
      if (DEBUG_ENABLED) {
          //-------------------------------
          Serial.println("Daten vom Smart Meter: ");          // Ausgabe der eingelesenen Rohdaten(verschlüsselt)
          for (int i = 0; i < eingelesendeBytes; i++) {   //
            if (datenMbus.ciphertext[i] < 0x10)Serial.print("0");
            Serial.print(datenMbus.ciphertext[i], HEX);
            Serial.print(" ");
          }
          Serial.println(" ");
    
          
          //--------------------------------

        
          byte calculatedChecksum =0x00;
          int datacount = 26;
    //      for (int datacount = 0; datacount < eingelesendeBytes-250; datacount++)
    //      {
            for (int i = datacount; i < eingelesendeBytes-2; i++) {   //
              //calculatedChecksum = calculatedChecksum +datenMbus.ciphertext[i];
              //calculatedChecksum = byte(calculatedChecksum) ^ byte(datenMbus.ciphertext[i]);
              //calculatedChecksum = byte(calculatedChecksum) + byte(datenMbus.ciphertext[i]);
              calculatedChecksum = calculatedChecksum + datenMbus.ciphertext[i];
               if (datenMbus.ciphertext[i] < 0x10)Serial.print("0");
              Serial.print(datenMbus.ciphertext[i], HEX);
              Serial.print(" ");
      
            }
          int datalength = sizeof(datenMbus.ciphertext) / sizeof(datenMbus.ciphertext[0]);
          Serial.println(" ");
          Serial.print("DataLength= ");
          Serial.println(datalength);

          Serial.print("eingelesendeBytes= ");
          Serial.println(eingelesendeBytes);
          Serial.println(" ");
          Serial.print("Transmitted Checksum= ");
          Serial.print(datenMbus.ciphertext[eingelesendeBytes-2], HEX);
          Serial.println("h ");
          
          Serial.print("Calculated Checksum= ");
          Serial.print(calculatedChecksum, HEX);
          Serial.print("h      ");
          calculatedChecksum = ~ byte(calculatedChecksum);
          Serial.print("Inverted Checksum= ");
          Serial.print(calculatedChecksum, HEX);
          Serial.println("h ");
     //     }
    

          
          //Serial.print("datenMbus.plaintext=");
          //String numStr;
          //for (int i = 0; i < byteNumber; i++) {
          //  numStr=String(datenMbus.ciphertext[i],HEX);
          //  Serial.print(numStr);
          //}
          //Serial.println(" ");
          //Serial.println("=============================================");
          
      }

      digitalWrite(ledPin, HIGH);

      //EDIT this values to your needs
          
      if (datenMbus.ciphertext[0] != 0x68)ReceiveError = true;
      if (datenMbus.ciphertext[3] != 0x68)ReceiveError = true;
      if (datenMbus.ciphertext[11] != 0x53)ReceiveError = true;
      if (datenMbus.ciphertext[12] != 0x41)ReceiveError = true;
      if (datenMbus.ciphertext[13] != 0x47)ReceiveError = true;
      if (datenMbus.ciphertext[14] != 0x59)ReceiveError = true;
      if (datenMbus.ciphertext[15] != 0x05)ReceiveError = true;
      if (datenMbus.ciphertext[16] != 0xEB)ReceiveError = true;
      if (datenMbus.ciphertext[17] != 0xE4)ReceiveError = true;
      if (datenMbus.ciphertext[18] != 0x67)ReceiveError = true;
      if (datenMbus.ciphertext[281] != 0x16)ReceiveError = true;
      if (eingelesendeBytes != 282)ReceiveError = true;


      
      if (ReceiveError) {
          Serial.println("Receive Error occured");
      }
      else
      {

          for (int i = 0; i < 8; i++) {                          // Initialisation Vektor (IV) bilden (8Byte System Title + 4Byte Frame Counter) ...befinden sich immer an der selben stelle im Datensatz
            datenMbus.iv[i] = datenMbus.ciphertext[i + 11];
          }
          for (int i = 0; i < 4; i++) {
            datenMbus.iv[i + 8] = datenMbus.ciphertext[i + 22];  // FrameCounter anhängen...
          }
          
          for (unsigned int i = 0; i < datenMbus.datasize - 26; i++) { // Anfang der Nachricht "löschen", sodass nur mehr die verschlüsselten Daten in dem Array bleiben
            datenMbus.ciphertext[i] = datenMbus.ciphertext[i + 26];
          }
          for(int i = 256;i<MAX_PLAINTEXT_LEN;i++){
          datenMbus.ciphertext[i]=0x00;
          }
          decrypt_text(datenMbus);
          /*
          Serial.print("Iv: ");
          for (int i = 0; i < 12; i++) {
            if (datenMbus.iv[i] < 0x10)Serial.print("0");
            Serial.print(datenMbus.iv[i], HEX);
          }
          Serial.println();
          Serial.println("Entschluesselte Daten: ");
          for (unsigned int i = 0; i < datenMbus.datasize; i++) {
            if (datenMbus.plaintext[i] < 16)Serial.print("0");
            Serial.print(datenMbus.plaintext[i], HEX);
          }
          Serial.println(" ");*/
          aktuelleDaten.year = ((datenMbus.plaintext[6] << 8) | datenMbus.plaintext[7]) - 2000;
          aktuelleDaten.month = datenMbus.plaintext[8];
          aktuelleDaten.day = datenMbus.plaintext[9];
          aktuelleDaten.hour = datenMbus.plaintext[11];
          aktuelleDaten.minutes = datenMbus.plaintext[12];
          aktuelleDaten.seconds = datenMbus.plaintext[13];
          aktuelleDaten.wirkenergiePlus=((unsigned long)datenMbus.plaintext[43]<<24)|((unsigned long)datenMbus.plaintext[44]<<16)|((unsigned long)datenMbus.plaintext[45]<<8)|(unsigned long)datenMbus.plaintext[46];
          aktuelleDaten.wirkenergieMinus=((unsigned long)datenMbus.plaintext[62]<<24)|((unsigned long)datenMbus.plaintext[63]<<16)|((unsigned long)datenMbus.plaintext[64]<<8)|(unsigned long)datenMbus.plaintext[65];
          aktuelleDaten.momentanleistungPlus=((unsigned long)datenMbus.plaintext[81]<<24)|((unsigned long)datenMbus.plaintext[82]<<16)|((unsigned long)datenMbus.plaintext[83]<<8)|(unsigned long)datenMbus.plaintext[84];
          aktuelleDaten.momentanleistungMinus=((unsigned long)datenMbus.plaintext[100]<<24)|((unsigned long)datenMbus.plaintext[101]<<16)|((unsigned long)datenMbus.plaintext[102]<<8)|(unsigned long)datenMbus.plaintext[103];
          aktuelleDaten.uL1=float((datenMbus.plaintext[119]<<8)|datenMbus.plaintext[120])/10.0;
          aktuelleDaten.uL2=float((datenMbus.plaintext[136]<<8)|datenMbus.plaintext[137])/10.0;
          aktuelleDaten.uL3=float((datenMbus.plaintext[153]<<8)|datenMbus.plaintext[154])/10.0;
          aktuelleDaten.iL1=float((datenMbus.plaintext[170]<<8)|datenMbus.plaintext[171])/100.0;
          aktuelleDaten.iL2=float((datenMbus.plaintext[187]<<8)|datenMbus.plaintext[188])/100.0;
          aktuelleDaten.iL3=float((datenMbus.plaintext[204]<<8)|datenMbus.plaintext[205])/100.0;
          aktuelleDaten.powerF=float((datenMbus.plaintext[221]<<8)|datenMbus.plaintext[222])/1000.0;
          Serial.println("---------------------------------------------------------------------------");
          //Serial.print(aktuelleDaten.day);
          //Serial.print(".");
          //Serial.print(aktuelleDaten.month);
          //Serial.print(".");
          //Serial.print(aktuelleDaten.year);
          //Serial.print("  ");
          //Serial.print(aktuelleDaten.hour);
          //Serial.print(":");
          //Serial.print(aktuelleDaten.minutes);
          //Serial.print(":");
          //Serial.println(aktuelleDaten.seconds);
          Serial.print("A+: ");
          Serial.print(aktuelleDaten.wirkenergiePlus);
          Serial.print("Wh | A-: ");
          Serial.print(aktuelleDaten.wirkenergieMinus);
          Serial.println("Wh");
          Serial.print("P+: ");
          Serial.print(aktuelleDaten.momentanleistungPlus);
          Serial.print("W | P- (einsp.): ");
          Serial.print(aktuelleDaten.momentanleistungMinus);
          Serial.print("W  ");
          Serial.print("Saldo: ");
          int Momentanleistung = int(aktuelleDaten.momentanleistungPlus-aktuelleDaten.momentanleistungMinus);
          Serial.print(Momentanleistung);
          Serial.println(" W");
          Serial.println("U1: " + String(aktuelleDaten.uL1) + "V  U2: " + String(aktuelleDaten.uL2)+ "V  U3: " + String(aktuelleDaten.uL3)+"V");
          Serial.println("I1: " + String(aktuelleDaten.iL1) + "A  I2: " + String(aktuelleDaten.iL2)+ "A  I3: " + String(aktuelleDaten.iL3)+"A");
          Serial.print("PowerFactor: ");
          Serial.println(aktuelleDaten.powerF);
          //Serial.println("");
    
          if (!firstOne) 
          {
          //-----------------------------------------------------------------------
          //MQTT START
          //-----------------------------------------------------------------------
          
           //String wirkenergiePlusString = String(aktuelleDaten.wirkenergiePlus);
           //Serial.print("wirkenergiePlusString: ");
           //Serial.println(wirkenergiePlusString);
           //char const *wirkenergiePlus = wirkenergiePlusString.c_str();
           //Serial.print("wirkenergiePlus: ");
           //Serial.println(wirkenergiePlus);
           //client.publish("Smartmeter10/WirkenergieP",wirkenergiePlus);
           //client.publish("Smartmeter10/WirkenergieP","wirkenergiePlus");
           String Zeitstempel;
           String year, month, day, hour, minutes, seconds;
           year="20"+String (aktuelleDaten.year);
           month=String (aktuelleDaten.month);
           day=String (aktuelleDaten.day);
           hour=String (aktuelleDaten.hour);
           minutes=String (aktuelleDaten.minutes);
           seconds=String (aktuelleDaten.seconds);
           
           if (month.length() < 2) {month="0"+month;}
           if (day.length() < 2) {day="0"+day;}
           if (hour.length() < 2) {hour="0"+hour;}
           if (minutes.length() < 2) {minutes="0"+minutes;}
           if (seconds.length() < 2) {seconds="0"+seconds;}
           Zeitstempel = String (year)+"-"+String (month)+"-"+String(day)+" "+String(hour)+":"+String(minutes)+":"+String(seconds);
           //Zeitstempel = String (aktuelleDaten.year)+"-"+String (aktuelleDaten.month)+"-"+String(aktuelleDaten.day)+" "+String(aktuelleDaten.hour)+":"+String(aktuelleDaten.minutes)+":"+String(aktuelleDaten.seconds);
           Serial.print ("Zeitstempel: ");
           Serial.println(Zeitstempel);
          
           client.publish("Smartmeter10/WirkenergieP",(String(aktuelleDaten.wirkenergiePlus)).c_str() );
           client.publish("Smartmeter10/WirkenergieN",(String(aktuelleDaten.wirkenergieMinus)).c_str() );
           client.publish("Smartmeter10/MomentanleistungP",(String(aktuelleDaten.momentanleistungPlus)).c_str() );
           client.publish("Smartmeter10/MomentanleistungN",(String(aktuelleDaten.momentanleistungMinus)).c_str() );
           client.publish("Smartmeter10/Momentanleistung",(String(Momentanleistung)).c_str() );
           client.publish("Smartmeter10/SpannungL1",(String(aktuelleDaten.uL1)).c_str() );
           client.publish("Smartmeter10/SpannungL2",(String(aktuelleDaten.uL2)).c_str() );
           client.publish("Smartmeter10/SpannungL3",(String(aktuelleDaten.uL3)).c_str() );
           client.publish("Smartmeter10/StromL1",(String(aktuelleDaten.iL1)).c_str() );
           client.publish("Smartmeter10/StromL2",(String(aktuelleDaten.iL2)).c_str() );
           client.publish("Smartmeter10/StromL3",(String(aktuelleDaten.iL3)).c_str() );
           client.publish("Smartmeter10/Leistungsfaktor",(String(aktuelleDaten.powerF)).c_str() );
           client.publish("Smartmeter10/Zeitstempel",(String(Zeitstempel)).c_str() );
           client.publish("Smartmeter10/Alarm","false" );
           
    
          //-----------------------------------------------------------------------
          //MQTT END
          //-----------------------------------------------------------------------
          }
          else
          {
           firstOne=false;  
           client.publish("Smartmeter10/Boot","false" );
          }
      }
      
      for (int i = 0; i < MAX_PLAINTEXT_LEN; i++) {
        datenMbus.plaintext[i] = 0x00;
        datenMbus.ciphertext[i] = 0x00;
      }
      processData = false;
      digitalWrite(ledPin, LOW);
    }
  } else {
    processData = true;
  }
}

void decrypt_text(Vector_GCM &vect) {
  GCM<AES128> *gcmaes128 = 0;
  gcmaes128 = new GCM<AES128>();
  gcmaes128->setKey(vect.key, gcmaes128->keySize());
  gcmaes128->setIV(vect.iv, vect.ivsize);
  gcmaes128->decrypt(vect.plaintext, vect.ciphertext, vect.datasize);
  delete gcmaes128;
}
