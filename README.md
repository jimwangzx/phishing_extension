# Anti-Phishing Extension
Chrome extension to detect potential phishing sites. Based on domain and content features.

The purpose of the project is to create an anti-phishing extension that can combine content-based and domain-based features to detect phishing sites.

Domain-based features developed within the extension are extracted from the tool [**Phishing Catcher**](https://github.com/x0rz/phishing_catcher) by [**x0rz**](https://github.com/x0rz/).
They consist of analysis: 
  * if the communication protocol is secure
  * if any SSL certificate is issued by a free CA
  * the type of certificate (DV)
  * if it contains suspicious Tlds or suspicious keywords
  * domain entropy
  * levenshtein distance
  * number of dash and sub domains

The following articles deal with the detection of phishing sites through machine learning algorithms, which classify a site according to the presence of certain characteristics. The chrome extension uses features extracted from these algorithms to analyze a site.
  * "Machine Learning Approach to Phishing Detection"
  * "Intelligent phishing url detection using association rule mining"
  * "Intelligent Rule based Phishing Websites Classification"
  
When we connect to a site the extension verifies the presence of features and assigns a score whether each of them occurs or not. When a particular web page reaches or exceeds the score of 100, an alert will appear by reporting the page as potentially phishing.



# License

GNU GPLv3
