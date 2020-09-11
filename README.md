Columbo2600 Wifitrack Readme
Date: September 11th 2020

Note: A few things have changed since I wrote the article (I finished it a year and one day ago).
Python 2 was officially deprecated in January so the dependencies are slightly different as you 
have to install scapy through pip. I may go ahead and convert the program to Python 3 in the near
future. For now I've included the instructions to get it to work in the new Kali Linux.

Installation Instructions for Kali 2020.3 Live Media:
1. Connect to the internet.
2. Obtain wifitrack.py from the Columbo2600 github.
3. Open the terminal and log in to root.  type "sudo su"
4. Install some dependencies with the following command "apt install python-pip gpsd"
5. Install the rest of the dependencies with the dependencies with the following command "pip install gps scapy"
6. Navigate to the folder with wifitrack.  (ex. "cd /home/kali/Downloads")
7. Run wifitrack "python2 wifitrack.py"
