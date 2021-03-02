
window.onload = function(){

    var ext = chrome.extension.getBackgroundPage();
    var currentTabId = ext.currentTabId;
    var score = ext.score;

    document.getElementById("idCurrentTab").innerHTML = currentTabId;
    document.getElementById("certInfo").innerHTML = score;


}
