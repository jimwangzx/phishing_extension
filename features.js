
chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
   aux(message).then(value => {sendResponse({mess: value})});
   return true;
});

async function aux(message){
   if (message.request == "get_score") {
      var score = await detect(message.host, message.cert_info, message.protocol, message.url);
      return score;
   }
}

//###DETECTION

async function detect(host, certInfo, protocol, url){
   var score = 0;
   var scoreH = scoreHtml(url);
   var scoreU = scoreUrl(url);
   var scoreD = await scoreDomain(host);
   console.log(scoreH);
   console.log(scoreU);
   console.log(scoreD);

   if (protocol === 'https'){
      score += scoreCert(certInfo);
      if (await isValidDomain(certInfo, url)){
         return -1;
      }
   } else {
      score += 10;
   }

   if (scoreH+scoreU > 0 && scoreD+score >= 65)
      return 1;
   else if (scoreH+scoreU <= 0 && scoreD+score < 65)
      return -1;
   else if (scoreH+scoreU+scoreD+score > 0)
      return 1;
   else
      return -1;
}

//###SCORE

function scoreCert(certInfo){
   score = 0
   certInfo = JSON.parse(certInfo);
   score += isIssuedFromFreeCA(certInfo)*10;
   score += isDVCertificate(certInfo)*10;
   
   return score;
}

async function scoreDomain(host){
   var score = 0;
   var res = await fetch(chrome.extension.getURL('data/sus.json'));
   var obj = await res.json();

   score += await domainEndWithSusTLD(host, obj)*20;

   host = removeWildcard(host);
   host = removeTld(host);

   score += Math.round(domainEntropy(host))*10;

   host = await unconfuse(host);
   console.log(host);

   score += domainHasFakeTLD(host)*10;

   var res = domainHasSusKeywords(host, obj);
   if (res.length > 0){
      for (let keyword of res){
         score += obj.keywords[keyword];
      }
   }
   score += levenshteinDistance(host, obj)*70;
   score += domainLotOfDash(host)*3;
   score += nestedSubdomains(host)*3;
   
   return score;
}

function scoreUrl(url){
   score = 0;

   score += isIPInURL(url)*(0.333);
   score += isLongURL(url)*(-1.112);
   score += isTinyURL(url)*(-7.778);
   score += containsAt(url)*(1.110);
   score += isRedirectingURL(url)*(3.894);
   score += isHypenURL(url)*(19.999);
   score += isIllegalHttpsURL(url)*(-0.0006);
   score += isMultiDomainURL(url)*(4.443);

   return score;
}

function scoreHtml(url){
   score = 0

   score += isMailToAvailable()*(0.557);
   score += isIframePresent()*(-1.666);
   score += isImgFromDifferentDomain(url)*(3.332);
   score += isFaviconDomainUnidentical(url)*(-2.779);
   score += isAnchorFromDifferentDomain(url)*(26.664);
   score += isScriptAndLinkDifferentDomain(url)*(6.667);
   score += isFormActionInvalid(url)*(5.554);

   return score;
}


//###CERT

function isIssuedFromFreeCA(certInfo){
   if (certInfo.issuer_organization == "Let's Encrypt")
      return 1;
   else
      return 0;
}

function isDVCertificate(certInfo){
   if (certInfo.validation_result_short == "DV")
      return 1;
   else
      return 0;
}


//###DOMAIN

async function domainEndWithSusTLD(host, obj){
   var susTlds = Object.keys(obj.tlds);
   for (let tld of susTlds){
      if (host.endsWith(tld))
         return 1;
   }
   return 0;
}

function domainEntropy(host){
   var str = host;
   return [...new Set(str)]
      .map(chr => {
         return str.match(new RegExp(chr, 'g')).length;
      })
      .reduce((sum, frequency) => {
         let p = frequency / str.length;
         return sum + p * Math.log2(1 / p);
      }, 0);
}

function domainHasFakeTLD(host){
   var str = host;
   var words = str.split(/\W+/);

   if (words[0] == 'com' || words[0] == 'net' || words[0] == 'org')
      return 1;
   return 0;
}

function domainHasSusKeywords(host, obj){
   var str = host;
   var keywordsContained = [];

   keywords = Object.keys(obj.keywords);

   for (let keyword of keywords){
      if (str.includes(keyword)){
         keywordsContained.push(keyword);
      }
   }
   return keywordsContained;
}

function levenshteinDistance(host, obj){
   var str = host;
   var keywords = Object.keys(obj.keywords);
   var strongKeywords = keywords.filter(k => obj.keywords[k] >= 70);
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

function domainLotOfDash(host){
   var str = host;
   if (!str.includes('xn--') && (str.match(/\-/g) || []).length >= 4)
      return (str.match(/\-/g) || []).length;
   else
      return 0;
}

function nestedSubdomains(host){
   var str = host;
   if ((str.match(/\./g) || []).length >= 3)
      return (str.match(/\./g) || []).length;
   else
      return 0;
}

//###URL

function isLongURL(url){
   if (url.length < 54)
      return -1;
   else if (url.length >= 54 && url.length <= 75)
      return 0;
   else
      return 1;
}

function isIPInURL(url){
   var reg =/\d{1,3}[\.]{1}\d{1,3}[\.]{1}\d{1,3}[\.]{1}\d{1,3}/;
   if (reg.exec(url) == null)
      return -1;
   else
      return 1;
}

function isTinyURL(url){
   if (url.length > 20)
      return -1;
   else
      return 1;
}

function containsAt(url){
   var search ="@";
   if (url.match(search) == null)
      return -1;
   else
      return 1;
}

function isRedirectingURL(url){
   var reg1 = /^http:/
   var reg2 = /^https:/
   var srch ="//";
   if(url.search(srch)==5 && reg1.exec(url) != null && (url.substring(7)).match(srch) == null)
       return -1;
   else if (url.search(srch) == 6 && reg2.exec(url) != null && (url.substring(8)).match(srch) == null)
      return -1;
   else
      return 1;
}

function isHypenURL(url){
   var reg = /[a-zA-Z]\//;
   var srch ="-";
   if(((url.substring(0,url.search(reg)+1)).match(srch)) == null)
      return -1;  
   else
     return 1;
}

function isIllegalHttpsURL(url){
   var srch1 ="//";   
   var srch2 = "https";    
   if (((url.substring(url.search(srch1))).match(srch2)) == null)
      return -1;   
   else
      return 1;
}

function isMultiDomainURL(url){
   var reg = /[a-zA-Z]\//; 
   if((url.substring(0, url.search(reg)+1)).split('.').length < 5)
      return -1;  
   else
      return 1;
}

//###CONTENT

function isImgFromDifferentDomain(url){
   var totalCount = document.querySelectorAll("img").length
   var identicalCount = getIdenticalDomainCount("img", url);
   if (((totalCount-identicalCount)/totalCount) < 0.22)
      return -1;
   else if (((totalCount-identicalCount)/totalCount) >= 0.22 && ((totalCount-identicalCount)/totalCount) <= 0.61)
      return 0;
   else
      return 1;
}

function isFaviconDomainUnidentical(url){
   var reg = /[a-zA-Z]\//;
   if(document.querySelectorAll("link[rel*='shortcut icon']").length > 0){            
      var faviconurl = document.querySelectorAll("link[rel*='shortcut icon']")[0].href;
      if((url.substring(0, url.search(reg) + 1)) == (faviconurl.substring(0, faviconurl.search(reg) + 1)))
         return -1;  
      else
         return 1;
   }
   else
      return -1;
}

function isAnchorFromDifferentDomain(url){
   var totalCount = document.querySelectorAll("a").length
   var identicalCount = getIdenticalDomainCount("a", url);
   if (((totalCount-identicalCount)/totalCount) < 0.31)
      return -1;
   else if (((totalCount-identicalCount)/totalCount) >= 0.31 && ((totalCount-identicalCount)/totalCount) <= 0.67)
      return 0;
   else
      return 1;
}

function isScriptAndLinkDifferentDomain(url){
   var totalCount = document.querySelectorAll("script").length + document.querySelectorAll("link").length
   var identicalCount = getIdenticalDomainCount("script", url) + getIdenticalDomainCount("link", url);
   if (((totalCount - identicalCount) / totalCount) < 0.17)
      return -1;
   else if (((totalCount - identicalCount) / totalCount) >= 0.17 && ((totalCount - identicalCount) / totalCount) <= 0.81)
      return 0;
   else
      return 1;
}

function isFormActionInvalid(url){
   var totalCount = document.querySelectorAll("form").length
   var identicalCount = getIdenticalDomainCount("form", url);
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

function getIdenticalDomainCount(tag, url){
   var i, identicalCount = 0;
   var reg = /[a-zA-Z]\//;
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

function removeWildcard(host){
   if (host.startsWith("*."))
      host = host.slice(2);
   return host;
}

function removeTld(host){
   var words = host.split(".");
   words = words.slice(0, words.length-1);
   host = words.join(".");
   return host;
}

function checkDomain(domain){
   return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({request: 'check_domain', dom: domain}, function(response){
         if (typeof response.message !== 'undefined')
            resolve(response);
         else
            reject();
      });
   });
}

async function isValidDomain(certInfo, url){
   certInfo = JSON.parse(certInfo);
   var certDomain = certInfo.subject_common_name;
   var response = await checkDomain(certDomain).then(value => {return value;});
   checkResponse = response.message;
   console.log(certDomain);
   console.log(checkResponse);

   if (checkResponse && isRedirectingURL(url) == -1)
      return true;
   else
      return false;
}

async function unconfuse(host){
   if (host.startsWith('xn--'))
      host = punycode.ToUnicode(host);
   var uncofused = '';

   var res = await fetch(chrome.extension.getURL('data/confusables.json'));
   var obj = await res.json();

   for (var i = 0; i < host.length; i++){
      if (host[i] in obj){
         uncofused += obj[host[i]];
      } else {
         uncofused += host[i];
      }
   }
   return uncofused;
}
//Thanks to "Some"(https://stackoverflow.com/users/36866/some). !!!!FREE USE!!!!!
//Javascript Punycode converter derived from example in RFC3492.
//This implementation is created by some@domain.name and released into public domain
var punycode = new function Punycode() {
   // This object converts to and from puny-code used in IDN
   //
   // punycode.ToASCII ( domain )
   // 
   // Returns a puny coded representation of "domain".
   // It only converts the part of the domain name that
   // has non ASCII characters. I.e. it dosent matter if
   // you call it with a domain that already is in ASCII.
   //
   // punycode.ToUnicode (domain)
   //
   // Converts a puny-coded domain name to unicode.
   // It only converts the puny-coded parts of the domain name.
   // I.e. it dosent matter if you call it on a string
   // that already has been converted to unicode.
   //
   //
   this.utf16 = {
      // The utf16-class is necessary to convert from javascripts internal character representation to unicode and back.
      decode:function(input){
         var output = [], i=0, len=input.length,value,extra;
         while (i < len) {
            value = input.charCodeAt(i++);
            if ((value & 0xF800) === 0xD800) {
               extra = input.charCodeAt(i++);
               if ( ((value & 0xFC00) !== 0xD800) || ((extra & 0xFC00) !== 0xDC00) ) {
                  throw new RangeError("UTF-16(decode): Illegal UTF-16 sequence");
               }
               value = ((value & 0x3FF) << 10) + (extra & 0x3FF) + 0x10000;
            }
            output.push(value);
         }
         return output;
      },
      encode:function(input){
         var output = [], i=0, len=input.length,value;
         while (i < len) {
            value = input[i++];
            if ( (value & 0xF800) === 0xD800 ) {
               throw new RangeError("UTF-16(encode): Illegal UTF-16 value");
            }
            if (value > 0xFFFF) {
               value -= 0x10000;
               output.push(String.fromCharCode(((value >>>10) & 0x3FF) | 0xD800));
               value = 0xDC00 | (value & 0x3FF);
            }
            output.push(String.fromCharCode(value));
         }
         return output.join("");
      }
   }

   //Default parameters
   var initial_n = 0x80;
   var initial_bias = 72;
   var delimiter = "\x2D";
   var base = 36;
   var damp = 700;
   var tmin=1;
   var tmax=26;
   var skew=38;
   var maxint = 0x7FFFFFFF;

   // decode_digit(cp) returns the numeric value of a basic code 
   // point (for use in representing integers) in the range 0 to
   // base-1, or base if cp is does not represent a value.

   function decode_digit(cp) {
      return cp - 48 < 10 ? cp - 22 : cp - 65 < 26 ? cp - 65 : cp - 97 < 26 ? cp - 97 : base;
   }

   // encode_digit(d,flag) returns the basic code point whose value
   // (when used for representing integers) is d, which needs to be in
   // the range 0 to base-1. The lowercase form is used unless flag is
   // nonzero, in which case the uppercase form is used. The behavior
   // is undefined if flag is nonzero and digit d has no uppercase form. 

   function encode_digit(d, flag) {
      return d + 22 + 75 * (d < 26) - ((flag != 0) << 5);
      //  0..25 map to ASCII a..z or A..Z 
      // 26..35 map to ASCII 0..9
   }
   //** Bias adaptation function **
   function adapt(delta, numpoints, firsttime ) {
      var k;
      delta = firsttime ? Math.floor(delta / damp) : (delta >> 1);
      delta += Math.floor(delta / numpoints);

      for (k = 0; delta > (((base - tmin) * tmax) >> 1); k += base) {
         delta = Math.floor(delta / ( base - tmin ));
      }
      return Math.floor(k + (base - tmin + 1) * delta / (delta + skew));
   }

   // encode_basic(bcp,flag) forces a basic code point to lowercase if flag is zero,
   // uppercase if flag is nonzero, and returns the resulting code point.
   // The code point is unchanged if it is caseless.
   // The behavior is undefined if bcp is not a basic code point.

   function encode_basic(bcp, flag) {
      bcp -= (bcp - 97 < 26) << 5;
      return bcp + ((!flag && (bcp - 65 < 26)) << 5);
   }

   // Main decode
   this.decode=function(input,preserveCase) {
      // Dont use utf16
      var output=[];
      var case_flags=[];
      var input_length = input.length;

      var n, out, i, bias, basic, j, ic, oldi, w, k, digit, t, len;

      // Initialize the state: 

      n = initial_n;
      i = 0;
      bias = initial_bias;

      // Handle the basic code points: Let basic be the number of input code 
      // points before the last delimiter, or 0 if there is none, then
      // copy the first basic code points to the output.

      basic = input.lastIndexOf(delimiter);
      if (basic < 0) basic = 0;

      for (j = 0; j < basic; ++j) {
         if(preserveCase) case_flags[output.length] = ( input.charCodeAt(j) -65 < 26);
         if ( input.charCodeAt(j) >= 0x80) {
            throw new RangeError("Illegal input >= 0x80");
         }
         output.push( input.charCodeAt(j) );
      }

      // Main decoding loop: Start just after the last delimiter if any
      // basic code points were copied; start at the beginning otherwise. 

      for (ic = basic > 0 ? basic + 1 : 0; ic < input_length; ) {

         // ic is the index of the next character to be consumed,

         // Decode a generalized variable-length integer into delta,
         // which gets added to i. The overflow checking is easier
         // if we increase i as we go, then subtract off its starting 
         // value at the end to obtain delta.
         for (oldi = i, w = 1, k = base; ; k += base) {
            if (ic >= input_length) {
               throw RangeError ("punycode_bad_input(1)");
            }
            digit = decode_digit(input.charCodeAt(ic++));

            if (digit >= base) {
               throw RangeError("punycode_bad_input(2)");
            }
            if (digit > Math.floor((maxint - i) / w)) {
               throw RangeError ("punycode_overflow(1)");
            }
            i += digit * w;
            t = k <= bias ? tmin : k >= bias + tmax ? tmax : k - bias;
            if (digit < t) { break; }
            if (w > Math.floor(maxint / (base - t))) {
               throw RangeError("punycode_overflow(2)");
            }
            w *= (base - t);
         }

         out = output.length + 1;
         bias = adapt(i - oldi, out, oldi === 0);

         // i was supposed to wrap around from out to 0,
         // incrementing n each time, so we'll fix that now: 
         if ( Math.floor(i / out) > maxint - n) {
            throw RangeError("punycode_overflow(3)");
         }
         n += Math.floor( i / out ) ;
         i %= out;

         // Insert n at position i of the output: 
         // Case of last character determines uppercase flag: 
         if (preserveCase) { case_flags.splice(i, 0, input.charCodeAt(ic -1) -65 < 26);}

         output.splice(i, 0, n);
         i++;
      }
      if (preserveCase) {
         for (i = 0, len = output.length; i < len; i++) {
            if (case_flags[i]) {
               output[i] = (String.fromCharCode(output[i]).toUpperCase()).charCodeAt(0);
            }
         }
      }
      return this.utf16.encode(output);
  };

  //** Main encode function **

   this.encode = function (input,preserveCase) {
      //** Bias adaptation function **

      var n, delta, h, b, bias, j, m, q, k, t, ijv, case_flags;

      if (preserveCase) {
         // Preserve case, step1 of 2: Get a list of the unaltered string
         case_flags = this.utf16.decode(input);
      }
      // Converts the input in UTF-16 to Unicode
      input = this.utf16.decode(input.toLowerCase());

      var input_length = input.length; // Cache the length

      if (preserveCase) {
         // Preserve case, step2 of 2: Modify the list to true/false
         for (j=0; j < input_length; j++) {
            case_flags[j] = input[j] != case_flags[j];
         }
      }

      var output=[];

      // Initialize the state: 
      n = initial_n;
      delta = 0;
      bias = initial_bias;

      // Handle the basic code points: 
      for (j = 0; j < input_length; ++j) {
         if ( input[j] < 0x80) {
            output.push(
               String.fromCharCode(
                  case_flags ? encode_basic(input[j], case_flags[j]) : input[j]
               )
            );
         }
      }

      h = b = output.length;

      // h is the number of code points that have been handled, b is the
      // number of basic code points 

      if (b > 0) output.push(delimiter);

      // Main encoding loop: 
      //
      while (h < input_length) {
         // All non-basic code points < n have been
         // handled already. Find the next larger one: 

         for (m = maxint, j = 0; j < input_length; ++j) {
            ijv = input[j];
            if (ijv >= n && ijv < m) m = ijv;
         }

         // Increase delta enough to advance the decoder's
         // <n,i> state to <m,0>, but guard against overflow: 

         if (m - n > Math.floor((maxint - delta) / (h + 1))) {
            throw RangeError("punycode_overflow (1)");
         }
         delta += (m - n) * (h + 1);
         n = m;

         for (j = 0; j < input_length; ++j) {
            ijv = input[j];

            if (ijv < n ) {
               if (++delta > maxint) return Error("punycode_overflow(2)");
            }

            if (ijv == n) {
               // Represent delta as a generalized variable-length integer: 
               for (q = delta, k = base; ; k += base) {
                  t = k <= bias ? tmin : k >= bias + tmax ? tmax : k - bias;
                  if (q < t) break;
                  output.push( String.fromCharCode(encode_digit(t + (q - t) % (base - t), 0)) );
                  q = Math.floor( (q - t) / (base - t) );
               }
               output.push( String.fromCharCode(encode_digit(q, preserveCase && case_flags[j] ? 1:0 )));
               bias = adapt(delta, h + 1, h == b);
               delta = 0;
               ++h;
            }
         }

         ++delta, ++n;
      }
      return output.join("");
   }

   this.ToASCII = function ( domain ) {
      var domain_array = domain.split(".");
      var out = [];
      for (var i=0; i < domain_array.length; ++i) {
         var s = domain_array[i];
         out.push(
            s.match(/[^A-Za-z0-9-]/) ?
            "xn--" + punycode.encode(s) :
            s
         );
      }
      return out.join(".");
  }
  this.ToUnicode = function ( domain ) {
      var domain_array = domain.split(".");
      var out = [];
      for (var i=0; i < domain_array.length; ++i) {
         var s = domain_array[i];
         out.push(
            s.match(/^xn--/) ?
            punycode.decode(s.slice(4)) :
            s
         );
      }
      return out.join(".");
   }
}();