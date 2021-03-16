var currentTabId = 0;
var currentTab = "";
var score = "";

//Prendo la tab attiva
chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    //Setto il nuovo currentTabId
    currentTabId = tabs[0].id;
    currentTab = tabs[0];
    console.log(currentTab);
});

//Se la finestra corrente cambia, prendo la tab attiva nella nuova finestra.
chrome.windows.onFocusChanged.addListener(function (data) {
    //Prendo la tab attiva
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        //Setto il nuovo currentTabId
        if (tabs.length > 0) {
            currentTabId = tabs[0].id;
            currentTab = tabs[0];
            console.log(currentTab);
        }
    });
});

//Se la tab attiva all'interno della finiestra corrente cambia prendo la nuova tab attiva nella finestra corrente.
chrome.tabs.onActivated.addListener(function(data){
    //Prendo la tab attiva
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        //Setto il nuovo currentTabId
        currentTabId = tabs[0].id;
        currentTab = tabs[0];
        console.log(currentTab);
    });
});

// Gestione arrivo richieste dagli script dell'esetnsione
chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
    // Richiesta della currentTab dal content-script features.js
    if (message.from == "features_js" && message.message == "get_current_tab") {
      sendResponse({ from:"background_js", requested: "get_current_tab", response: currentTab });
    }
    // Richiesta delle info sul certificato dal content-script features.js
    if (message.from == "features_js" && message.message == "get_cert_info") {
      var response = "";
      requestCertInfo(message.hostname, function(data){
          response = JSON.stringify(JSON.parse(data));
          console.log(response);
          sendResponse({ from:"background_js", requested: "get_cert_info", response: response });
      });
      return true; // Asincrona
    }
    // Richiesta delle info sul certificato dal popup-script
    if (message.from == "features_js" && message.message == "return_score") {
        score = message.score;
        chrome.tabs.sendMessage(currentTabId, {message: score});
        if (message.score >= 60){
            alert("WARNING: Phishing site");
        }
    }

});

// Necessario un recupero cross-orgin e il server non fornisce un "Access-Control-Allow-Origin response header"
// perciò le richieste cross-orgin vanno fatte nel background script
function requestCertInfo(hostname, callback) {
    // Crazione XHR
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function () {
      //Gestione dell'evento quando termina
      if (xhr.readyState !== 4) {
        return;
      }

      if (typeof this.responseText === 'undefined' || this.responseText.length === 0) {
        callback(null);
        return;
      }

      try {
        callback(this.responseText);
      } catch (e) {
        callback(null);
      }
    };

    // Richiesta
    xhr.open('GET', 'https://api.blupig.net/certificate-info/validate', true);
    xhr.setRequestHeader('x-validate-host', hostname);
    xhr.send();
}

chrome.runtime.onInstalled.addListener(() => {
   chrome.storage.sync.clear();
   chrome.storage.sync.set(
      // Suspicious keywords
      {
         keywords:
            [
               {
                  login:         25,
                  'log-in':      25,
                  'sign-in':     25,
                  signin:        25,
                  account:       25,
                  verification:  25,
                  verify:        25,
                  webscr:        25,
                  password:      25,
                  credential:    25,
                  support:       25,
                  activity:      25,
                  security:      25,
                  update:        25,
                  authentication: 25,
                  authenticate:  25,
                  authorize:     25,
                  wallet:        25,
                  alert:         25,
                  purchase:      25,
                  transaction:   25,
                  recover:       25,
                  unlock:        25,
                  confirm:       20,
                  live:          15,
                  office:        15,
                  service:       15,
                  manage:        15,
                  portal:        15,
                  invoice:       15,
                  secure:        10,
                  customer:      10,
                  client:        10,
                  bill:          10,
                  online:        10,
                  safe:          10,
                  form:          10,
                  appleid:       70,//
                  icloud:        60,
                  iforgot:       60,
                  itunes:        50,
                  apple:         30,
                  office365:     50,
                  microsoft:     60,
                  windows:       30,
                  protonmail:    70,//
                  tutanota:      60,
                  hotmail:       60,
                  gmail:         70,//
                  outlook:       60,
                  yahoo:         60,
                  google:        60,
                  yandex:        60,
                  twitter:       60,
                  facebook:      60,
                  tumblr:        60,
                  reddit:        60,
                  youtube:       40,
                  linkedin:      60,
                  instagram:     60,
                  flickr:        60,
                  whatsapp:      60,
                  localbitcoin:  70,//
                  poloniex:      60,
                  coinhive:      70,//
                  bithumb:       60,
                  kraken:        50,
                  bitstamp:      60,
                  bittrex:       60,
                  blockchain:    70,//
                  bitflyer:      60,
                  coinbase:      60,
                  hitbtc:        60,
                  lakebtc:       60,
                  bitfinex:      60,
                  bitconnect:    60,
                  coinsbank:     60,
                  paypal:        70,//
                  moneygram:     60,
                  westernunion:  60,
                  bankofamerica: 60,
                  wellsfargo:    60,
                  citigroup:     60,
                  santander:     60,
                  morganstanley: 60,
                  barclays:      50,
                  hsbc:          50,
                  scottrade:     60,
                  ameritrade:    60,
                  merilledge:    60,
                  bank:          15,
                  amazon:        60,
                  overstock:     60,
                  alibaba:       60,
                  aliexpress:    60,
                  leboncoin:     70,//
                  netflix:       70,//
                  skype:         60,
                  github:        60,
                  onedrive:      60,
                  dropbox:       60,
                  'cgi-bin':     50,
                  '-com.':       20,
                  '.net-':       20,
                  '.org-':       20,
                  '.com-':       20,
                  '.net.':       20,
                  '.org.':       20,
                  '.com.':       20,
                  '.gov-':       30,
                  '.gov.':       30,
                  '.gouv-':      40,
                  '-gouv-':      40,
                  '.gouv.':      40,
                  suivi:         50,
                  laposte:       50
               }
            ],
         validDomain:
            [
               //Microsoft
               'microsoft.com',
               'office.com',
               'microsoftonline.com',
               'microsoft365.com',
               'skype.com',
               'onedrive.com',
               'live.com',

               //Apple
               'www.itunes.com',
               'apple.com',
               'icloud.com',

               //Protonmail
               'protonmail.com',
               'protonmail.ch',
               'protonvpn.com',
               'pm.me',

               //Google
               'google.com',
               'android.com',
               'google-analytics.com',
               'google.ca',
               'google.cl',
               'google.co.in',
               'google.co.jp',
               'google.co.uk',
               'google.com.ar',
               'google.com.au',
               'google.com.br',
               'google.com.co',
               'google.com.mx',
               'google.com.tr',
               'google.com.vn',
               'google.de',
               'google.es',
               'google.fr',
               'google.hu',
               'google.it',
               'google.nl',
               'google.pl',
               'google.pt',
               'googlevideo.com',
               'youtube.com',
               'youtubekids.com',
               'yt.be',
               'g.co',
               'goo.gl',
               'urchin.com',
               'youtu.be',
               'youtubeeducation.com',

               //Yahoo
               'www.yahoo.com',
               'yahoo.com',
               'yahoo.net',

               //Yandex
               'xn--d1acpjx3f.xn--p1ai',
               'yandex.ru',
               'yandex.com',

               //Twitter
               'twitter.com',

               //Facebook
               'facebook.com',
               'facebook.net',
               'messenger.com',

               //Tumblr
               'tumblr.com',

               //Reddit
               'reddit.com',
               'reddithelp.com',

               //Linkedin
               'us.linkedin.com',
               'linkedin.com',

               //Instagram
               'instagram.com',
               'www.instagram.com',

               //Flickr
               'flickr.com',

               //Whatsapp
               'whatsapp.net',
               'whatsappbrand.com',

               //Bitcoin
               'localbitcoins.com',
               'poloniex.com',
               'bithumb.com',
               'kraken.com',
               'bitstamp.com',
               'bitstamp.net',
               'blockchain.com',
               'bitflyer.com',
               'coinbase.com',
               'hitbtc.com',
               'lakebtc.com',
               'bitcoin.org',
               'bitfinex.com',
               'coinsbank.com',

               //Paypal
               'paypal.com',
               'www.paypal.com',

               //Bank
               'moneygram.com',
               'westernunion.com',
               'bankofamerica.com',
               'wellsfargo.com',
               'citi.com',
               'santanderconsumer.it',
               'morganstanley.com',
               'barclays.com',
               'barclays.co.uk',
               'hsbc.com',
               'tdameritrade.com',
               'merrilledge.com',
               'unipol.it',
               'intesasanpaolo.com',

               //Amazon
               'amazon.com',
               'amazon.it',
               'www.amazon.it',
               'www.amazon.com',

               //Alibaba
               'air.alibaba.com',
               'aliexpress.com',

               //Netlix
               'netflix.com',
               'www.netflix.com',

               //Github
               'www.github.com',
               'github.com',
               'github.blog',

               //Dropbox
               'dropbox.com'
            ]
      }

    );

});
