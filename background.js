var cachedData = {};
var domTrie = getDomTrie();

//Svuota cache ogni 10 minuti
setInterval(function(){
   cachedData = {};
}, 1000*60*10);


//Gestisce richieste dagli script di contenuto
chrome.runtime.onMessage.addListener(function(message, sender, sendResponse){
   if (message.request == 'check_domain'){
      domTrie.then(trie => {
         resp = trie.search(message.dom);
         sendResponse({message: resp});
      });
   }
   return true;
});

//Prendo la tab attiva
chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
   update(tabs[0]);
});

//Se la finestra corrente cambia, prendo la tab attiva nella nuova finestra.
chrome.windows.onFocusChanged.addListener(function(data) {
   //Prendo la tab attiva
   chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
      if (tabs.length > 0) {
         update(tabs[0]);
      }
   });
});

//Se la tab attiva all'interno della finiestra corrente cambia prendo la nuova tab attiva nella finestra corrente.
chrome.tabs.onActivated.addListener(function(data) {
   //Prendo la tab attiva
   chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
      update(tabs[0]);
   });
});
//Se una tab viene caricata o ricaricata
chrome.tabs.onUpdated.addListener(function (tabId, changeInfo, tab) {
   if ('status' in changeInfo && changeInfo['status'] === 'complete') {
      update(tab, true);
   }
});

function update(tab, reload=false){
   if (typeof tab === 'undefined') return;
   var url = tab.url;
   var tabId = tab.id;
   if (typeof url === 'undefined' || typeof tabId === 'undefined') return;
  
   var protocol = getPageProtocol(url)

   if (protocol === 'http' || protocol === 'https'){
      var certInfo = '';
      var hostname = getHostname(url);

      if (hostname in cachedData){
         if (cachedData[hostname] == 1 && reload)
            alert("Warning: Phishing detected!!");
         return;
      }

      if (protocol === 'https'){
         getCertInfo(hostname, function(data){
            certInfo = JSON.stringify(JSON.parse(data));
            chrome.tabs.sendMessage(tabId, {
               request: 'get_score', 
               host: hostname,
               cert_info: certInfo,
               protocol: protocol,
               url: url
            }, 
            function(response){
               var lastError = chrome.runtime.lastError;
               if (lastError){
                  console.log(lastError.message);
                  return;
               }
               if (typeof response !== 'undefined'){
                  cachedData[hostname] = response.mess;
                  if (response.mess == 1){
                     console.log("Phishing");
                     alert("Warning: Phishing detected!!");
                  }
               }
            });
         });
      } else {
         chrome.tabs.sendMessage(tabId, {
            request: 'get_score', 
            host: hostname,
            cert_info: certInfo,
            protocol: protocol,
            url: url
         }, 
         function(response){
            var lastError = chrome.runtime.lastError;
            if (lastError){
               console.log(lastError.message);
               return;
            }
            if (typeof response !== 'undefined'){
               cachedData[hostname] = response.mess;
               if (response.mess == 1){
                  console.log("Phishing");
                  alert("Warning: Phishing detected!!");
               }
            }
         });
      }
   }
}

function getPageProtocol(url) {
   if (url.substring(0, 7) === 'http://')
      return 'http';
   else if (url.substring(0, 8) === 'https://')
      return 'https';
   else
      return '';
}

function getHostname(url) {
   var hostname = url.substr(8, url.length - 1 - 8);
   for (var i = 8, len = url.length; i < len; i++) {
      if (url[i] === '/') {
         hostname = url.substr(8, i - 8);
         break;
      }
   }
   return hostname;
}

// Necessario un recupero cross-orgin e il server non fornisce un "Access-Control-Allow-Origin response header"
// perciò le richieste cross-orgin vanno fatte nel background script
function getCertInfo(hostname, callback) {
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

   xhr.open('GET', 'https://api.blupig.net/certificate-info/validate', true);
   xhr.setRequestHeader('x-validate-host', hostname);
   xhr.send();
}

async function getFile(file){
   var resp = await fetch(file);
   resp = await resp.text();
   return resp;
}

function initTrie(file){
   if (file === null) return null;
   var domTrie = new Trie();
   var domains = file.split('\n');
   domains = domains.filter(str => { return !str.startsWith('='); });
   domains.forEach(d => {domTrie.insert(d.slice(0, (d.length)-1))});
   return domTrie;
}

async function getDomTrie(){
   var f = await getFile(chrome.extension.getURL('data/SAN.txt'));
   var domTrie = initTrie(f);
   return domTrie;
}