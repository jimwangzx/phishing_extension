window.onload = function(){

   var currentTab;
   var certInfo;
   var susKeywords;
   var validDomains;
   var susTlds = [".ga",".gq",".ml",".cf",".tk",".xyz",".pw",".cc",".club",".work",".top",".support",".bank",".info",".study",".click",".country",".stream",".gdn",".mom",".xin",".kim",".men",".loan",".download",".racing",".online",".center",".ren",".gb",".win",".review",".vip",".party",".tech",".science",".business"]

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

//###DETECTION

function detect(){
   var score = 0;

   for (var domain of validDomains) {
      var d = certInfo.subject_common_name;
      if (d.startsWith("*."))
         d = d.slice(2);
      if (d == domain) {
            chrome.runtime.sendMessage({ from:"features_js", message:"return_score", score:0});
            console.log("SCORE: "+score);
            return false;
      }
   }

   if(hasSecureProtocol()){
      score += scoreCert();
      score += scoreDomain();
      score += scoreUrl();
      score += scoreHtml();
   } else {
      score += scoreDomain();
      score += scoreUrl();
      score += scoreHtml();
   }

   score = Math.round(score);

   console.log("Score Tot: "+score);
   chrome.runtime.sendMessage({ from:"features_js", message:"return_score", score:score});

}

//###SCORE

function scoreCert(){
   var score = 0;

   score += isIssuedFromFreeCA()*10;
   score += isDVCertificate()*10;
   console.log("Score cert: "+score);

   return score;
}

function scoreDomain(){
   var score = 0;

   score += domainEndWithSusTLD()*20;
   score += Math.round(domainEntropy())*10;
   score += domainHasFakeTLDNested()*10;

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
   console.log("Score domain: "+score);

   return score;
}

function scoreUrl(){
   var score = 0;

   score += isIPInURL()*(3.333);
   score += isLongURL()*(-1.112);
   score += isTinyURL()*(-7.778);
   score += containsAt()*(1.110);
   score += isRedirectingURL()*(3.894);
   score += isIllegalHttpsURL()*(-0.0006);
   score += isMultiDomainURL()*(4.443);
   console.log("Score URL: "+score);

   return score;
}

function scoreHtml(){
   var score = 0;

   score += isMailToAvailable()*(0.557);
   score += isIframePresent()*(-1.666);
   score += isImgFromDifferentDomain()*(3.332);
   score += isFaviconDomainUnidentical()*(-2.779);
   score += isAnchorFromDifferentDomain()*(26.664);
   score += isScriptAndLinkDifferentDomain()*(6.667);
   score += isFormActionInvalid()*(5.554);
   console.log("Score HTML: "+score);

   return score;
}


//###CERT

   function isIssuedFromFreeCA(){
      if (certInfo.issuer_organization == "Let's Encrypt")
         return 1;
      else
         return 0;
   }

   function isDVCertificate(){
      if (certInfo.validation_result_short == "DV")
         return 1;
      else
         return 0;
   }

//###DOMAIN

   function domainEndWithSusTLD(){
      var domain = certInfo.subject_common_name;
      susTlds.forEach((tld, i) => {
         if (domain.endsWith(tld)) 
            return 1;
      });
      return 0;
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

      if (words[0] == 'com' || words[0] == 'net' || words[0] == 'org')
         return 1;
      return 0;
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

//###URL

   function isLongURL(){
      if (currentTab.url.length < 54)
         return -1;
      else if (currentTab.url.length >= 54 && currentTab.url.length <= 75)
         return 0;
      else
         return 1;
   }

   function isIPInURL(){
      var reg =/\d{1,3}[\.]{1}\d{1,3}[\.]{1}\d{1,3}[\.]{1}\d{1,3}/;
      var url = currentTab.url;
      if (reg.exec(url) == null)
         return -1;
      else
         return 1;
   }

   function isTinyURL(){
      var url = currentTab.url;
      if (url.length > 20)
         return -1;
      else
         return 1;
   }

   function containsAt(){
      var search ="@";
      var url = currentTab.url; 
      if (url.match(search) == null)
         return -1;
      else
         return 1;
   }

   function isRedirectingURL(){
      var reg1 = /^http:/
      var reg2 = /^https:/
      var srch ="//";
      var url = currentTab.url; 
      if(url.search(srch)==5 && reg1.exec(url) != null && (url.substring(7)).match(srch) == null)
          return -1;
      else if (url.search(srch) == 6 && reg2.exec(url) != null && (url.substring(8)).match(srch) == null)
         return -1;
      else
         return 1;
  }

   function isIllegalHttpsURL(){
      var srch1 ="//";   
      var srch2 = "https";   
      var url = currentTab.url; 
      if (((url.substring(url.search(srch1))).match(srch2)) == null)
         return -1;   
      else
         return 1;
  }

   function isMultiDomainURL(){
      var reg = /[a-zA-Z]\//;
      var url = currentTab.url; 
      if((url.substring(0, url.search(reg)+1)).split('.').length < 5)
         return -1;  
      else
         return 1;
   }

//###CONTENT

   function isImgFromDifferentDomain(){
      var totalCount = document.querySelectorAll("img").length
      var identicalCount = getIdenticalDomainCount("img");
      if (((totalCount-identicalCount)/totalCount) < 0.22)
         return -1;
      else if (((totalCount-identicalCount)/totalCount) >= 0.22 && ((totalCount-identicalCount)/totalCount) <= 0.61)
         return 0;
      else
         return 1;
   }

   function isFaviconDomainUnidentical(){
      if(currentTab.favIconUrl === "undefined"){
         var favIconUrl = currentTab.favIconUrl;
         var url = currentTab.url;
         var reg = /[a-zA-Z]\//;
         if ((url.substring(0, url.search(reg) + 1)) == (favIconUrl.substring(0, favIconUrl.search(reg) + 1)))
            return -1;
         else
            return 1;
      }
      return -1;
   }

   function isAnchorFromDifferentDomain(){
      var totalCount = document.querySelectorAll("a").length
      var identicalCount = getIdenticalDomainCount("a");
      if (((totalCount-identicalCount)/totalCount) < 0.31)
         return -1;
      else if (((totalCount-identicalCount)/totalCount) >= 0.31 && ((totalCount-identicalCount)/totalCount) <= 0.67)
         return 0;
      else
         return 1;
   }

   function isScriptAndLinkDifferentDomain(){
      var totalCount = document.querySelectorAll("script").length + document.querySelectorAll("link").length
      var identicalCount = getIdenticalDomainCount("script") + getIdenticalDomainCount("link");
      if (((totalCount - identicalCount) / totalCount) < 0.17)
         return -1;
      else if (((totalCount - identicalCount) / totalCount) >= 0.17 && ((totalCount - identicalCount) / totalCount) <= 0.81)
         return 0;
      else
         return 1;
   }

   function isFormActionInvalid(){
      var totalCount = document.querySelectorAll("form").length
	   var identicalCount = getIdenticalDomainCount("form");
      if (document.querySelectorAll('form[action]').length <= 0)
         return -1;
      else if (identicalCount!=totalCount)
         return 0;
      else if (document.querySelectorAll('form[action*=""]').length>0)
         return 1;
      else
         return -1;
   }

   function isMailToAvailable(){
      if(document.querySelectorAll('a[href^=mailto]').length<=0)
         return -1;
      else
         return 1;
   }

   function isIframePresent(){
      if(document.querySelectorAll('iframe').length<=0)
         return -1;
      else
         return 1;
   }


//###AUX

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
         detect();
         certInfo = "";
      }
   }

}
