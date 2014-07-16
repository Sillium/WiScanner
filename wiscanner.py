#!/usr/bin/env python3

import os
import sys
import nmap
import time
import pickle
import configparser
from datetime import datetime
from twython import Twython
from pushover import Pushover

# ==========================================================
class Device:
	allDevices = set()
	devicesInHouse = set()

	# ======================================================
	def __init__(self, macAddress, name, thresholdSeconds):
		self.inHouse = None
		self.lastJoinTime = self.lastLeaveTime = self.lastVisibleTime = datetime.now()
		self.macAddress = macAddress
		self.name = name
		self.thresholdSeconds = thresholdSeconds
		Device.allDevices.add(self)
			  
	# ======================================================
	def __reportJoin(self):
		self.lastJoinTime = datetime.now()
		self.inHouse = True
		timePrefix = '{0}: '.format(self.lastJoinTime.strftime("%d.%m.%Y %H:%M"))
		message = '{0} entered {1}.'.format(self.name, LOCATION)
		if len(Device.devicesInHouse) > 0:
			message += ' Already there: {0}.'.format(Device.joinDeviceNames(Device.devicesInHouse))
		else:
			message += ' He is alone.'
		Device.__sendMessage(timePrefix + message)
		Device.devicesInHouse.add(self)

	# ======================================================
	def __reportLeave(self):
		self.lastLeaveTime = datetime.now()
		self.inHouse = False
		Device.devicesInHouse.remove(self)
		timePrefix = '{0}: '.format(self.lastLeaveTime.strftime("%d.%m.%Y %H:%M"))
		message = '{0} left {1} '.format(self.name, LOCATION)
		message += '(last seen {0}).'.format(self.lastVisibleTime.strftime("%d.%m.%Y %H:%M"))
		if len(Device.devicesInHouse) > 0:
			message += ' Still there: {0}'.format(Device.joinDeviceNames(Device.devicesInHouse))
		else:
			message += ' He was alone.'
		Device.__sendMessage(timePrefix + message)

	# ======================================================
	def __reportInvisible(self):
		# If device is invisible, is regarded to be here currently and was not visible during the threshold amount of seconds, it probably left. Oh noez!
		if (self.inHouse == True and self.secondsSinceLastVisible() > self.thresholdSeconds):
			self.__reportLeave()

	# ======================================================
	def __reportVisible(self):
		self.lastVisibleTime = datetime.now()
		
		# If device is visible but is not known to be here currently, then it just joined. Woohoo!
		if (self.inHouse is None or self.inHouse == False):
			self.__reportJoin()

	# ======================================================
	def secondsSinceLastJoin(self):
		return Device.__secondsSince(self.lastJoinTime)

	# ======================================================
	def secondsSinceLastLeave(self):
		return Device.__secondsSince(self.lastLeaveTime)

	# ======================================================
	def secondsSinceLastVisible(self):
		return Device.__secondsSince(self.lastVisibleTime)
	
	# ======================================================
	@staticmethod
	def __secondsSince(time):
		tdelta = datetime.now() - time
		s = tdelta.total_seconds()
		return s

	# ======================================================
	def scanNetwork(self, ipRange):
		try:
			nm = nmap.PortScanner()
		except nmap.PortScannerError:
			print('Nmap not found', sys.exc_info()[0])
			sys.exit(0)
		except:
			print("Unexpected error:", sys.exc_info()[0])
			sys.exit(0)

		nm.scan(hosts= ipRange + '/24', arguments='-n -sP -PE -T5')
		hosts_list = [(nm[x]['addresses']) for x in nm.all_hosts()]
		for host in hosts_list:
			if 'mac' in host and host['mac'] == self.macAddress:
				self.__reportVisible()
				return
		self.__reportInvisible()

	# ======================================================
	@staticmethod
	def __sendToTwitter(text):
		twitter = Twython(TWITTER_APP_KEY, TWITTER_APP_SECRET, TWITTER_OAUTH_TOKEN, TWITTER_OAUTH_TOKEN_SECRET)
		twitter.update_status(status=text)

	# ======================================================
	@staticmethod
	def __sendToPushover(text):
		po = Pushover(PUSHOVER_TOKEN)
		po.user(PUSHOVER_USER)
		msg = po.msg(text)
		msg.set("title", PUSHOVER_TITLE)
		po.send(msg) 

	# ======================================================
	@staticmethod
	def __sendToConsole(text):
		print(text)

	# ======================================================
	@staticmethod
	def __sendMessage(text):
		Device.__sendToConsole(text)
		Device.__sendToTwitter(text)
		#Device.__sendToPushover(text)

	# ======================================================
	@staticmethod
	def joinDeviceNames(deviceList):
		deviceNamesList = [(x.name) for x in deviceList]
		return ", ".join(deviceNamesList)

	# ======================================================
	def __str__(self):
		return '{0} | {1} | {2} | {3} | {4} | {5}'.format(self.name, self.macAddress, self.inHouse, self.lastVisibleTime, self.lastJoinTime, self.lastLeaveTime)

	# ==========================================================
	def pickle(self):
		try:
			device_file = open(self.name + '.pkl', 'wb')
			pickle.dump(self, device_file)
			device_file.close()
		except:
			print("Pickling for {0} went wrong!".format(self.name))

	# ==========================================================
	def unpickle(self):
		try:
			device_file = open(self.name + '.pkl', 'rb')
			tempDevice = pickle.load(device_file)
			self.inHouse = tempDevice.inHouse
			self.lastVisibleTime = tempDevice.lastVisibleTime
			self.lastLeaveTime = tempDevice.lastLeaveTime
			self.lastJoinTime = tempDevice.lastJoinTime
			device_file.close()
			if self.inHouse:
				Device.devicesInHouse.add(self)
		except:
			print("No unpickling for {0}.".format(self.name))

# === End Class Device =====================================



# ==========================================================
if __name__ == '__main__':
	config = configparser.ConfigParser()
	config.read('config.ini')

	LOCATION = config['General']['Location']
	IP_RANGE = config['General']['IpRange']
	INTERVAL = int(config['General']['ScanInterval'])

	TWITTER_APP_KEY = config['Twitter']['AppKey']
	TWITTER_APP_SECRET = config['Twitter']['AppSecret']
	TWITTER_OAUTH_TOKEN = config['Twitter']['OAuthToken']
	TWITTER_OAUTH_TOKEN_SECRET = config['Twitter']['OAuthTokenSecret']
	
	PUSHOVER_TOKEN = config['Pushover']['Token']
	PUSHOVER_USER = config['Pushover']['User']
	PUSHOVER_TITLE = config['Pushover']['Title']

	for section in config.sections():
		if (section[:7] == 'Device_'):	
			print(section[7:])
			newDevice = Device(config[section]['MacAddress'], section[7:], int(config[section]['Threshold']))
	
	while True:
		for device in Device.allDevices:
			# unpickle
			device.unpickle()

			# visible in network?
			device.scanNetwork(IP_RANGE)

			# pickle
			device.pickle()

		#print('all devices: {0} | in house: {1}'.format(Device.joinDeviceNames(Device.allDevices), Device.joinDeviceNames(Device.devicesInHouse)))
		time.sleep(INTERVAL)