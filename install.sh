#Exec this script to automatically install the dependencies
# chmod +x install.sh
# ./install.sh

# Install Scapy
cd /tmp
wget scapy.net
unzip scapy-latest.zip
cd scapy-2.*
sudo python setup.py install
cd ..


# Install pyaes
wget https://github.com/ricmoo/pyaes/archive/master.zip
unzip *master.zip
cd pyaes*
sudo python setup.py install

echo "Finished installing Scapy and pyaes!!\nNow run ICMPme"
