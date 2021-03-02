
window.onload = function(){

    var ext = chrome.extension.getBackgroundPage();
    var currentTabId = ext.currentTabId;
    var certInfo = "";

    /*chrome.runtime.sendMessage({from: "popup_js", message: "get_cert_info"}, function(data){
        certInfo = data.response;
    });*/

    document.getElementById("idCurrentTab").innerHTML = currentTabId;
    document.getElementById("certInfo").innerHTML = certInfo;

}
