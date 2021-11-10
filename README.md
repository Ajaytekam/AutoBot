# Autobot 

Check for vulnerabilities on Passivelly collected URLs from tools [gau](https://github.com/lc/gau) and [waybackurls](https://github.com/tomnomnom/waybackurls) and send the result files and notofocatiosn messages to telegram Bot.  

![](sc.png)

### How It Works   

* Collect the urls, sort them.  
* Check the urls if they are alive or not. 
* Test for XSS vulnerability using dalfox.   
* Test for sql injection vulnerability using sqlmap.  
* Test for Open Redirect.   
* Test for Server side request forgery.   
* Test for IDOR.   

__Tools Used :__  gau, waybackurls, gf, dalfox, sqlmap, httpx, qsreplace, kxss, ffuf.  

### Usage   

* Start [interactsh](https://github.com/projectdiscovery/interactsh) client instance and copy the url. 
* Run the application 

```  
python3 autobot -d testphp.vulnweb.com -i c65rgt1ufkgit27hcvq0cgf5o7eyyyyyn.interact.sh
```  

* for Blind XSS use [xsshunter]() url  

```    
python3 autobot -d testphp.vulnweb.com -b yoursubdomain.xss.ht -i c65rgt1ufkgit27hcvq0cgf5o7eyyyyyn.interact.sh
```     

