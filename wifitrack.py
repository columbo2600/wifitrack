#!/usr/bin/env python2
# -*- coding: utf-8 -*-

#For best results, run as root in a safe enviornment.
#This is experimental software.  Use at your own risk.
#This requires the scapy python library, the aircrack-ng suite, gpsd, and the gps python library.
#Read the original article for further documentation.

from scapy.all import *
import os, sys, time, datetime
from gps import *
#Insert some threading to run multiple functions at the same time.
from threading import Thread
#Some variables to use globally later.
menu = ""
interface = ""
hwaddress = ""
#Optional vender list to view the names of the hardware venders.
venderlist = []
#Our output file's name.
file_name = ""
#Lattitude/Longitude global variables.
lat = 0.0
lon = 0.0
#Menu display.  Title font uses a figlet font named Bloody.  Requires utf coding.
def displaymenu():
    global menu 
    menu = raw_input("\n\
 █     █░ ██▓  █████▒██▓▄▄▄█████▓ ██▀███   ▄▄▄       ▄████▄   ██ ▄█▀\n\
▓█░ █ ░█░▓██▒▓██   ▒▓██▒▓  ██▒ ▓▒▓██ ▒ ██▒▒████▄    ▒██▀ ▀█   ██▄█▒ \n\
▒█░ █ ░█ ▒██▒▒████ ░▒██▒▒ ▓██░ ▒░▓██ ░▄█ ▒▒██  ▀█▄  ▒▓█    ▄ ▓███▄░ \n\
░█░ █ ░█ ░██░░▓█▒  ░░██░░ ▓██▓ ░ ▒██▀▀█▄  ░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄ \n\
░░██▒██▓ ░██░░▒█░   ░██░  ▒██▒ ░ ░██▓ ▒██▒ ▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄\n\
░ ▓░▒ ▒  ░▓   ▒ ░   ░▓    ▒ ░░   ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒\n\
  ▒ ░ ░   ▒ ░ ░      ▒ ░    ░      ░▒ ░ ▒░  ▒   ▒▒ ░  ░  ▒   ░ ░▒ ▒░\n\
  ░   ░   ▒ ░ ░ ░    ▒ ░  ░        ░░   ░   ░   ▒   ░        ░ ░░ ░ \n\
    ░     ░          ░              ░           ░  ░░ ░      ░  ░   \n\
                                                    ░               \n\
To continue, type a number and then press enter:\n\
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *\n\
Choose an option:\n\
1. Change into monitor mode with airmon-ng.\n\
2. Start gpsd and specify your gps device.\n\
3. Scan for all hardware addresses and write to file. ctrl-z to exit.\n\
4. Match hardware addresses from different file outputs.\n\
5. Scan for one or more specific hardware addresses from a file.\n\
6. Find probes and associated devices from a hw address.  This scans through your airodump-ng database.\n\
7. Create or update hardware vender file to identify most devices scanned.\n\
8. Stop monitor mode and return wifi to normal. \n\
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *\n\
")


#---------------------definitions-----------------------    
def AddressScan(pkt) :
    global file_name
    global lat
    global lon
    splitstring = []
    f = open(file_name, "a")
    venderfound  = 0
    thetimeis = datetime.datetime.now()
    #This section looks for valid harddware addresses.  The length will be 17.  Then it looks through your hardware vender file
    #to figure out which type of device the address belongs to.  It also takes note of the date/time and gps coordinates.
    if pkt.addr1 not in clients and len(str(pkt.addr1)) == 17:
        clients.append(pkt.addr1)
        for line in venderlist:
            if len(line) > 2 and line[2] == ":":
                splitstring = line.split(',')
                if str(pkt.addr1)[:len(splitstring[0])] == splitstring[0].lower() and venderfound == 0:
                    f.write(str(pkt.addr1) + "," + splitstring[1].rstrip() + "," + str(lat) + "," + str(lon) + "," + str(thetimeis) + "\n")
                    print "Device Found: %s - %s,%s,%s,%s" % ((pkt.addr1), splitstring[1].rstrip(), str(lat), str(lon),str(thetimeis))
                    venderfound = 1
        if venderfound == 1:
            venderfound = 0
        else:
            f.write(str(pkt.addr1) + ",unknown," + str(lat) + "," + str(lon) + "," + str(thetimeis) + "\n")
            print "Device Found: %s,unknown,%s,%s,%s" % ((pkt.addr1), str(lat), str(lon), str(thetimeis))

    if pkt.addr2 not in clients and len(str(pkt.addr2)) == 17:
        clients.append(pkt.addr2)
        for line in venderlist:
            if len(line) > 2 and line[2] == ":":
                splitstring = line.split(',')
                if str(pkt.addr2)[:len(splitstring[0])] == splitstring[0].lower() and venderfound == 0:
                    f.write(str(pkt.addr2) + "," + splitstring[1].rstrip() + "," + str(lat) + "," + str(lon) + "," + str(thetimeis) + "\n")
                    print "Device Found: %s - %s,%s,%s,%s" % ((pkt.addr2), splitstring[1].rstrip(), str(lat), str(lon), str(thetimeis))
                    venderfound = 1
        if venderfound == 1:
            venderfound = 0
        else:
            f.write(str(pkt.addr2) + ",unknown," + str(lat) + "," + str(lon) + "," + str(thetimeis) + "\n")
            print "Device Found: %s,unknown,%s,%s,%s" % ((pkt.addr2), str(lat), str(lon), str(thetimeis))

    if pkt.addr3 not in clients and len(str(pkt.addr3)) == 17:
        clients.append(pkt.addr3)
        for line in venderlist:
            if len(line) > 2 and line[2] == ":":
                splitstring = line.split(',')
                if str(pkt.addr3)[:len(splitstring[0])] == splitstring[0].lower() and venderfound == 0:
                    f.write(str(pkt.addr3) + "," + splitstring[1].rstrip() + "," + str(lat) + "," + str(lon) + "," + str(thetimeis) + "\n")
                    print "Device Found: %s - %s,%s,%s,%s" % ((pkt.addr3), splitstring[1].rstrip(), str(lat), str(lon), str(thetimeis))
                    venderfound = 1
        if venderfound == 1:
            venderfound = 0
        else:
            f.write(str(pkt.addr3) + ",unknown," + str(lat) + "," + str(lon) + "," + str(thetimeis) + "\n")
            print "Device Found: %s,unknown,%s,%s,%s" % ((pkt.addr3), str(lat), str(lon), str(thetimeis))

def scancommand(pkt) :
    global file_name
    global hwaddressfile
    global lat
    global lon
    global systemcommand
    f = open(file_name, "a")
    if pkt.addr1 in clients:
        thetimeis = datetime.datetime.now()
        print "Device Detected: %s, %s, %s, %s, %s" % ((pkt.addr1), clients[pkt.addr1], str(lat), str(lon), str(thetimeis))
        f.write(str(pkt.addr1) + "," + clients[pkt.addr1] + "," + str(lat) + "," + str(lon) + "," + str(thetimeis) + "\n")
        if systemcommand != "":
            os.system(systemcommand)
    if pkt.addr2 in clients:
        thetimeis = datetime.datetime.now()
        print "Device Detected: %s, %s, %s, %s, %s" % ((pkt.addr2), clients[pkt.addr2], str(lat), str(lon), str(thetimeis))    
        f.write(str(pkt.addr2) + "," + clients[pkt.addr2] + "," + str(lat) + "," + str(lon) + "," + str(thetimeis) + "\n")
        if systemcommand != "":
            os.system(systemcommand)

    if pkt.addr3 in clients:
        thetimeis = datetime.datetime.now()
        print "Device Detected: %s, %s, %s, %s, %s" % ((pkt.addr3), clients[pkt.addr3], str(lat), str(lon), str(thetimeis))
        f.write(str(pkt.addr3) + "," + clients[pkt.addr3] + "," + str(lat) + "," + str(lon) + "," + str(thetimeis) + "\n")
        if systemcommand != "":
            os.system(systemcommand)
    f.close()

def channelhop():
    channel = 1
    while channel < 14:
        os.system("iw dev %s set channel %d" % (interface, channel))
        time.sleep(.01)
        channel = channel + 1
            
        if channel == 13:
            channel = 1

#This feature requires you to set up gpsd on your system.  Also requires the python module gps.
def gpsfunct():
    global lat
    global lon
    gpsd = gps(mode=WATCH_ENABLE|WATCH_NEWSTYLE)
    while True:
        report = gpsd.next()
        if report['class'] == 'TPV':
            lat = getattr(report,'lat',0.0)
            lon = getattr(report,'lon',0.0)

def airodumpdatabase():
        #Run airodump and save all the data. we can refer to this data later.  This line uses the -K 1 option to run airodump-ng in the
        #background.  If this option isn't used airodump-ng seems to override the output.  This will keep on running even after the
        #python script is closed.  You may want to close it manually when you're finished.
        os.system('airodump-ng -K 1 -w' + "aird-db/" + str(datetime.datetime.now()).replace(" ","") + ' --output-format csv ' + interface)
#---------------------menu------------------------------ 
while True:
    displaymenu()
    if menu == "1":
        os.system("clear")
        #Assumes the user has iwconfig.  Shows available interfaces.
        os.system("iwconfig")
        #User inputs preferred wireless interface
        interface = raw_input("Please enter your wireless interface: (ex. wlan0)\n")
        #Device is turned off and then put into monitor mode
        os.system("ip link set dev " + interface + " down")
        os.system("airmon-ng start " + interface)
        #If you type in your interface name incorrectly you should restart.  The other options will assume you succesfully entered monitor mode.
        interface = interface + "mon"
    if menu == "2":
        gpsdevice = raw_input("Please enter your gps device. (ex. /dev/ttyUSB0)\n")
        os.system("gpsd " + gpsdevice + " -F /var/run/gpsd.sock")
    if menu == "3":
        #Start GPS function so that can load while prompts are entered.
        Thread(target = gpsfunct).start()
        clients = []
        clients.append("ff:ff:ff:ff:ff:ff")
        #User inputs interface if string is empty.
        if interface == "":
            os.system("clear")
            os.system("iwconfig")
            interface = raw_input("Please enter your wireless interface: (ex. wlan0mon)\n")
        if os.path.exists("hwvenderlist"):
            venderfile = "hwvenderlist"
        else:
            venderfile = raw_input("Please enter the name of the file with hardware venders, or leave this blank.\n")
        if venderfile != "":
            vf = open(venderfile,"r")
            for line in vf:
                venderlist.append(line)
            vf.close()
        blacklistfile = raw_input("Enter the name of your blacklist file or leave this blank and press enter.\n")
        if blacklistfile != "":
            bl = open(blacklistfile,"r")
            for line in bl:
                #Truncate the line to 17 characters.
                clients.append(line[:17])
            bl.close()
        file_name = raw_input("Please name the output file.\n")
        if file_name == "":
            file_name = "wt-option3-default-output-" + str(datetime.datetime.now())
        #Checks for airodump-database directory.  Creates it if it doesn't exist.  We can use these files later.
        if os.path.exists("aird-db") == False:
            os.system("mkdir aird-db")
        
        #Press ctrl c OR ctrl Z to stop scripts
        #Runs our channel hopper, address scanner, and airodump-ng database.
        Thread(target = airodumpdatabase).start()
        Thread(target = channelhop).start()
        Thread(target = sniff(iface=interface, prn = AddressScan)).start()
    if menu == "4":
        list1 = []
        list2 = []
        file1 = raw_input("Enter the name of your first output file.\n")
        file2 = raw_input("Enter the name of your second output file.\n")
        savedfile = raw_input("If you would like to save the matches to a file enter a file name.\n")
        f1 = open(file1,"r")
        f2 = open(file2,"r")
        #Check to see if the user wants to save a file.  Otherwise you'll get an error.
        if savedfile != "":
            nf = open(savedfile,"a")
        for line in f1:
            list1.append(line.lower()[:17])
        f1.close()
        for line in f2:
            list2.append(line.lower()[:17])
        f2.close()
        for line in set(list1).intersection(list2):
            print line
            if savedfile != "":
                nf.write(line)
        raw_input("Press enter to return to menu.")
        os.system("clear")
    if menu == "5":
        Thread(target = gpsfunct).start()
        if interface == "":
            os.system("clear")
            os.system("iwconfig")
            interface = raw_input("Please enter your wireless interface: (ex. wlan0mon)\n")
        clients = {}
        hwaddressfile = raw_input("Please enter the filename that contains the addresses you would like to scan for\n")
        file_name = raw_input("Enter the name of the file to output successful scan info.  (date/time GPS)\n")
        if file_name == "":
            file_name = "wt-option5-default-output-" + str(datetime.datetime.now())
        systemcommand = raw_input("Enter a shell command to run on a successful scan. (ex. vlc ring.wav)\n")
        hwf = open(hwaddressfile,"r")
        splitstring = []
        for line in hwf:
            splitstring = line.split(",")
            if len(splitstring) > 1:
                clients.update({splitstring[0][:17].lower() : splitstring[1].rstrip()})
            else:
                clients.update({splitstring[0][:17].lower() : "no name"})
        Thread(target = channelhop).start()
        Thread(target = sniff(iface=interface, prn = scancommand)).start()
        hwf.close()
    if menu == "6":
        splitstring = []
        airdfile = []
        airddb = os.listdir("aird-db")
        clientmac = raw_input("Please enter the mac address of the client.\n")
        clientmac = clientmac.upper()
        for line in airddb:
            ad = open("aird-db/" + line,"r")
            #We start scanning from the bottom.  The first line we need is len(airdfile)-2.
            linenum = 2
            for line in ad:
                airdfile.append(line)
            #Checks for a colon on the 3rd character of the line.  If it's there it should be a client.
            while airdfile[len(airdfile)-linenum][2] == ":":
                splitstring = airdfile[len(airdfile)-linenum].split(',')
                #Prints out the associated client.
                if splitstring[0] == clientmac:
                    print "Associated AP:"
                    print splitstring[5]
                if splitstring[0] == clientmac and len(splitstring[6]) != 2:
                    for probe in range(len(splitstring) - 6):
                        print "Probe:"
                        print splitstring[6 + probe]
                linenum = linenum + 1
            ad.close()
        raw_input("Press enter to return to menu.")
        os.system("clear")
    
    if menu == "7":
        #We start out with the wireshark manuf file.  That has all the info we need.  It just has to be modified.
        os.system("wget -O hwvenderlist-tempfile-delete https://raw.githubusercontent.com/wireshark/wireshark/master/manuf")
        #Get rid of all the commas.  We need to turn this into a csv file of sorts.
        os.system("sed -i 's/,//g' hwvenderlist-tempfile-delete")
        #Replace the first tab on each line with a comma.  This should separate all the hardware addresses.
        os.system("sed -i 's/\\t/,/' hwvenderlist-tempfile-delete")
        #Truncate the "netmasks" after the specified number of bits.
        os.system("sed -i 's/0:00\\/36//' hwvenderlist-tempfile-delete")
        os.system("sed -i 's/0:00:00\\/28//' hwvenderlist-tempfile-delete")
        splitstring = []
        ieeereg = ""
        #We need to move all the IeeeRegi addresses to the bottom.  Some are redundant after modifying the netmasks.
        with open("hwvenderlist-tempfile-delete", "r") as fdownload:
            with open("hwvenderlist", "w") as output:
                output.write("# This file has been modified for use with wifitrack.  Sorry for any confusion.\n")
                for line in fdownload:
                    splitstring = line.split(",")
                    if len(splitstring) > 1 and splitstring[1][:8] == "IeeeRegi":
                        ieeereg = ieeereg + line
                    else:
                        output.write(line)
                output.write(ieeereg)
        fdownload.close()
        output.close()
        os.system("rm hwvenderlist-tempfile-delete")
        
    if menu == "8":
        #User inputs preferred wireless interface.
        if interface == "":
            os.system("iwconfig")
            interface = raw_input("Please enter your wireless interface: (ex. wlan0mon)\n")
        #Device is turned off and then put into monitor mode.
        os.system("airmon-ng stop " + interface)


