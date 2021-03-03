window.onload = function(){

  var currentTab;
  var certInfo;
  var susKeywords;
  var validDomains;
  var susTlds = [".ga",".gq",".ml",".cf",".tk",".xyz",".pw",".cc",".club",".work",".top",".support",".bank",".info",".study",".click",".country",".stream",".gdn",".mom",".xin",".kim",".men",".loan",".download",".racing",".online",".center",".ren",".gb",".win",".review",".vip",".party",".tech",".science",".business"]

  var validDomain = [];

  chrome.runtime.sendMessage({ from:"features_js", message:"get_current_tab" }, function(data){
      currentTab = data.response;
      chrome.storage.sync.get(function(data){
        susKeywords = data.keywords[0];
        validDomains = data.validDomain;
        getCertInfo(currentTab);
      });
  });

  chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
    if (message.from == "background_js" && message.message == "get_cert_info") {
        sendResponse({ from:"features_js", requested: "get_cert_info", response: certInfo });
    }
   });

  function detect(){
      var score = 0;

      //Se la pagina ha protocollo sicuro
      if (hasSecureProtocol()){
        
          for (var domain of validDomains) {
              if (certInfo.subject_common_name == domain) {
                  chrome.runtime.sendMessage({ from:"features_js", message:"return_score", score:0});
                  console.log("SCORE: "+score);
                  return false;
              }
          }

          console.log(certInfo);

          if (isIssuedFromFreeCA()){
              score += 10;
              console.log("Issued from free CA: "+isIssuedFromFreeCA()+" (+10)");
          }
          if (isDVCertificate()){
              score += 10;
              console.log("DV Certificate: "+isDVCertificate()+" (+10)");
          }
          if (domainEndWithSusTLD()){
              score += 20;
              console.log("Domain end with sus TLD: "+domainEndWithSusTLD()+" (+20)");
          }

          score += Math.round(domainEntropy())*10;
          console.log("Domain entropy: "+Math.round(domainEntropy())+" (*10)");

          if (domainHasFakeTLDNested()){
              score += 10;
              console.log("Domain has fake TLD nested: "+domainHasFakeTLDNested()+" (+10)");
          }

          var res = domainHasSusKeywords();
          if (res.length > 0){
              res.forEach((key) => {
                  score += susKeywords[key];
                  console.log("Domain has sus keywords: "+key+" (+"+susKeywords[key]+")");
              });
          }
          score += levenshteinDistance()*70;
          score += domainLotOfDash()*3;
          score += nestedSubdomains()*3;

          console.log("Levenshtein distance for word in domain: "+levenshteinDistance()+" (*70)");
          console.log("Occ of \'-\' in domain: "+domainLotOfDash()+" (*3)");
          console.log("Nested subdomain: "+nestedSubdomains()+" (*3)");

      } else {
          score += 20;
          console.log("Has secure protocol: "+hasSecureProtocol()+" (+20)");
      }

      if (isLongURL()){
          score += 8;
          console.log("Is long URL: "+isLongURL()+" (+8)");
      }
      if (isIPInURL()){
          score += 8;
          console.log("Is IP URL: "+isIPInURL()+" (+8)");
      }
      if (isMultiDomainURL()){
          score += 8;
          console.log("Is Multidomain URL: "+isMultiDomainURL()+" (+8)");
      }
      if (isHypenURL()){
          score += 13;
          console.log("Is hyphen URL: "+isHypenURL()+" (+13)");
      }
      if (lotOfSlashesInURL()){
          score += 8;
          console.log("Lot of slashes in URL: "+lotOfSlashesInURL()+" (+8)");
      }
      if (isImgFromDifferentDomain()){
          score += 8;
          console.log("Is img from different domain: "+isImgFromDifferentDomain()+" (+8)");
      }
      if (isFaviconDomainUnidentical()){
          score += 8;
          console.log("Is favicon domain unidentical: "+isFaviconDomainUnidentical()+" (+8)");
      }
      if (isAnchorFromDifferentDomain()){
          score += 13;
          console.log("Is anchor from different domain: "+isAnchorFromDifferentDomain()+" (+13)");
      }
      if (isScLnkFromDifferentDomain()){
          score += 13;
          console.log("Is script link from different domain: "+isScLnkFromDifferentDomain()+" (+13)");
      }
      if (isFormActionInvalid()){
          score += 13;
          console.log("Is form action invalid: "+isFormActionInvalid()+" (+13)");
      }

      console.log("SCORE: "+score);

      //console.log(URLHasSusKeywords());

      chrome.runtime.sendMessage({ from:"features_js", message:"return_score", score:score});

  }
  /**********************DOMAIN&CERT-BASED FEATURES****************************/

  // Features e dati estratti da: -"Phish-Hook: Detecting Phishing Certificates"
  //                              -"https://github.com/x0rz/phishing_catcher"

  function isIssuedFromFreeCA(){
      if (certInfo.issuer_organization == "Let's Encrypt")
          return true;
      else
          return false;
  }

  function isDVCertificate(){
      if (certInfo.validation_result_short == "DV")
          return true;
      else
          return false;
  }

  function domainEndWithSusTLD(){
      var domain = certInfo.subject_common_name;
      susTlds.forEach((tld, i) => {
          if (domain.endsWith(tld)) return true;
      });
      return false;
  }

  function domainEntropy(){
    var str = certInfo.subject_common_name;

    if (str.startsWith("*."))
        str = str.slice(2);

    var words = str.split(".");
    words = words.slice(0, words.length-1);
    str = words.join(".");

    return [...new Set(str)]
        .map(chr => {
            return str.match(new RegExp(chr, 'g')).length;
        })
        .reduce((sum, frequency) => {
            let p = frequency / str.length;
            return sum + p * Math.log2(1 / p);
        }, 0);
  }

  function domainHasFakeTLDNested(){
      var str = certInfo.subject_common_name;

      if (str.startsWith("*."))
          str = str.slice(2);

      var words = str.split(".");
      words = words.slice(0, words.length-1);
      str = words.join(".");

      var words = str.split(/\W+/);

      words.forEach(word => {
          if (word == "com" || word == "org" || word == "net")
              return true;
      });
      return false;
  }

  function domainHasSusKeywords(){
    var str = certInfo.subject_common_name;

    if (str.startsWith("*."))
        str = str.slice(2);

    var words = str.split(".");
    words = words.slice(0, words.length-1);
    str = words.join(".");

    var keywords = Object.keys(susKeywords);
    var keywordsContained = [];

    keywords.forEach((keyword) => {
        if(str.includes(keyword)) {
            keywordsContained.push(keyword);
        }
    });
    return keywordsContained;
  }

  function levenshteinDistance(){
      var str = certInfo.subject_common_name;
      var keywords = Object.keys(susKeywords);
      var strongKeywords = keywords.filter(k => susKeywords[k] >= 70);
      //Rimuove l'eventuale *. iniziale
      if (str.startsWith("*."))
          str = str.slice(2);

      //Rimuove il tld
      var words = str.split(".");
      words = words.slice(0, words.length-1);
      str = words.join(".");
      //Parole nel dominio
      var words = str.split(/\W+/);
      //Rimuove parole generiche
      words = words.filter(w => (w !== "email" || w !== "mail" || w !== "cloud"));
      var occ = 0;
      for (var k in strongKeywords) {
          for (var w in words) {
              if (distance(strongKeywords[k],words[w]) == 1)
                  occ++;
          }
      }
      return occ;
  }

  function domainLotOfDash(){
      var str = certInfo.subject_common_name;

      if (str.startsWith("*."))
          str = str.slice(2);

      var words = str.split(".");
      words = words.slice(0, words.length-1);
      str = words.join(".");

      if ((str.match(/\-/g) || []).length >= 4)
          return (str.match(/\-/g) || []).length;
      else
          return 0;
  }

  function nestedSubdomains(){
      var str = certInfo.subject_common_name;

      if (str.startsWith("*."))
          str = str.slice(2);

      var words = str.split(".");
      words = words.slice(0, words.length-1);
      str = words.join(".");

      if ((str.match(/\./g) || []).length >= 3)
          return (str.match(/\./g) || []).length;
      else
          return 0;
  }

  function hasSecureProtocol(){
      return (pageProtocol(currentTab.url) == "https") ? true : false;
  }


  /************************CONTENT-BASED FEATURES******************************/

  // Features e dati estratti da: -"Machine Learning Approach to Phishing Detection"
  //                              -"Intelligent phishing url detection using association rule mining"
  //                              -"Intelligent Rule based Phishing Websites Classification"

  //Lenght of the host URL
  function isLongURL(){
      if (currentTab.url.length >= 75)
          return true;
      else
          return false;
  }

  function isIPInURL(){
      var reg =/\d{1,3}[\.]{1}\d{1,3}[\.]{1}\d{1,3}[\.]{1}\d{1,3}/;
      var url = currentTab.url;
      if(reg.exec(url) == null)
          return false;
      else
          return true;
  }

  function isHypenURL(){
      var reg = /[a-zA-Z]\//;
      var srch ="-";
      var url = currentTab.url;
      if(((url.substring(0, url.search(reg) + 1)).match(srch)) == null)
          return false;
      else
          return true;
}

  function isMultiDomainURL(){
      var reg = /[a-zA-Z]\//;
      var url = currentTab.url;
      if ((url.substring(0, url.search(reg) + 1)).split('.').length < 5)
          return false;
      else
          return true;
  }

  //>=5
  function lotOfSlashesInURL(){
    var str = currentTab.url;
    if ((str.match(/\//g) || []).length-2 >= 5)
        return true;
    else
        return false;
  }

  function isImgFromDifferentDomain(){
      var totalCount = document.querySelectorAll("img").length
      var identicalCount = getIdenticalDomainCount("img");
      if (((totalCount-identicalCount)/totalCount) > 0.61)
          return true;
      else
          return false;
  }

  function isFaviconDomainUnidentical(){
      if(currentTab.favIconUrl === "undefined"){
          var favIconUrl = currentTab.favIconUrl;
          var url = currentTab.url;
          var reg = /[a-zA-Z]\//;
          if ((url.substring(0, url.search(reg) + 1)) == (favIconUrl.substring(0, favIconUrl.search(reg) + 1))){
              return false;
          }
          else {
              return true;
          }
      }
      return "none";
  }

  function isAnchorFromDifferentDomain(){
      var totalCount = document.querySelectorAll("a").length
      var identicalCount = getIdenticalDomainCount("a");
      if (((totalCount-identicalCount)/totalCount) > 0.67)
          return true;
      else
          return false;
  }

  function isScLnkFromDifferentDomain(){
      var totalCount = document.querySelectorAll("script").length + document.querySelectorAll("link").length
      var identicalCount = getIdenticalDomainCount("script") + getIdenticalDomainCount("link");
      if (((totalCount - identicalCount) / totalCount) > 0.81)
          return true;
      else
          return false;
  }

  function isFormActionInvalid(){
      if (document.querySelectorAll('form[action]').length <= 0)
          return false;
      else
          return true;
  }

  function URLHasSusKeywords(){
      var hostname = extractHostname(currentTab.url);

      var keywords = Object.keys(susKeywords);
      var keywordsContained = [];

      keywords.forEach((keyword) => {
          if(hostname.includes(keyword)) {
              keywordsContained.push(keyword);
          }
      });
      return keywordsContained;
  }

  /***************************SUPPORT FUNCTION*********************************/

  function getIdenticalDomainCount(tag){
      var i, identicalCount = 0;
      var reg = /[a-zA-Z]\//;
      var url = currentTab.url;
      var mainDomain = url.substring(0, url.search(reg) + 1);
      var nodeList = document.querySelectorAll(tag);
      if (tag == "img" || tag == "script"){
          nodeList.forEach(function(element,index) {
              i = nodeList[index].src
              if (mainDomain == (i.substring(0, i.search(reg) + 1))){
                  identicalCount++;
              }
          });
      }
      else if (tag == "form"){
          nodeList.forEach(function(element,index) {
              i = nodeList[index].action
              if (mainDomain == (i.substring(0, i.search(reg) + 1))){
                  identicalCount++;
              }
          });
      }
      else if (tag == "a"){
          nodeList.forEach(function(element,index) {
              i = nodeList[index].href
              if ((mainDomain == (i.substring(0, i.search(reg) + 1))) && ((i.substring(0, i.search(reg) + 1)) != null) && ((i.substring(0, i.search(reg) + 1)) != "")){
                  identicalCount++;
              }
          });
      }
      else {
          nodeList.forEach(function(element,index) {
              i = nodeList[index].href
              if (mainDomain == (i.substring(0, i.search(reg) + 1))){
                  identicalCount++;
              }
          });
      }
      return identicalCount;
  }

  function distance(str1, str2){
      var track = Array(str2.length + 1).fill(null).map(() => Array(str1.length + 1).fill(null));
      for (let i = 0; i <= str1.length; i += 1) {
          track[0][i] = i;
      }
      for (let j = 0; j <= str2.length; j += 1) {
          track[j][0] = j;
      }
      for (let j = 1; j <= str2.length; j += 1) {
          for (let i = 1; i <= str1.length; i += 1) {
              var indicator = str1[i - 1] === str2[j - 1] ? 0 : 1;
              track[j][i] = Math.min(
                  track[j][i - 1] + 1, // deletion
                  track[j - 1][i] + 1, // insertion
                  track[j - 1][i - 1] + indicator, // substitution
              );
          }
      }
      return track[str2.length][str1.length];
  }

  function pageProtocol(url) {
      if (url.substring(0, 7) === 'http://')
          return 'http';
      else if (url.substring(0, 8) === 'https://')
          return 'https';
      else
          return '';
  }

  function extractHostname(url) {
      var hostname = url.substr(8, url.length - 1 - 8);
      for (var i = 8, len = url.length; i < len; i++) {
          if (url[i] === '/') {
              hostname = url.substr(8, i - 8);
              break;
          }
      }
      return hostname;
  }

  function getCertInfo(tab){
      if (typeof tab === 'undefined') return;

      var tabUrl = tab.url;
      var tabId = tab.id;

      if (typeof tabUrl === 'undefined' || typeof tabId === 'undefined') return;

      var protocol = pageProtocol(tabUrl);
      if (protocol === "https"){
          var hostname = extractHostname(tabUrl);
          chrome.runtime.sendMessage({ from: "features_js", message: "get_cert_info", hostname: hostname }, function(data){
              certInfo = JSON.parse(data.response);
              detect();
          });
      } else {
          return "None";
      }
  }

}
