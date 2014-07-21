#!/usr/bin/env python3

import os
import sys
import nmap
import time
import pickle
import configparser
import glob
import logging
import logging.handlers
from datetime import datetime
from twython import Twython
from pushover import Pushover

# ==========================================================
try:
	nm = nmap.PortScanner()
except nmap.PortScannerError:
	print('Nmap not found', sys.exc_info()[0])
	sys.exit(0)
except:
	print("Unexpected error:", sys.exc_info()[0])
	sys.exit(0)

# ==========================================================
class Device:
	allDevices = set()
	devicesInHouse = set()

	# ======================================================
	def __init__(self, macAddress, name, thresholdSeconds, notifyTwitter, notifyPushover):
		self.inHouse = None
		self.lastJoinTime = self.lastLeaveTime = self.lastVisibleTime = datetime.now()
		self.macAddress = macAddress
		self.name = name
		self.thresholdSeconds = thresholdSeconds
		self.notifyTwitter = notifyTwitter
		self.notifyPushover = notifyPushover
		self.visible = False
		Device.allDevices.add(self)
			  
	# ======================================================
	def __reportJoin(self):
		self.lastJoinTime = datetime.now()
		self.inHouse = True
		timePrefix = '{0}: '.format(self.lastJoinTime.strftime("%d.%m.%Y %H:%M"))
		message = '{0} entered {1}.'.format(self.name, LOCATION)
		if len(Device.devicesInHouse) > 0:
			message += ' Already here: {0}.'.format(Device.joinDeviceNames(Device.devicesInHouse))
		else:
			message += ' No one else is currently here.'.format(self.name)
		self.__sendMessage(timePrefix + message)
		Device.devicesInHouse.add(self)
		self.writeStatusFile()

	# ======================================================
	def __reportLeave(self):
		self.lastLeaveTime = datetime.now()
		self.inHouse = False
		Device.devicesInHouse.remove(self)
		timePrefix = '{0}: '.format(self.lastLeaveTime.strftime("%d.%m.%Y %H:%M"))
		message = '{0} left {1} '.format(self.name, LOCATION)
		message += '(last seen {0}).'.format(self.lastVisibleTime.strftime("%d.%m.%Y %H:%M"))
		if len(Device.devicesInHouse) > 0:
			message += ' Still here: {0}.'.format(Device.joinDeviceNames(Device.devicesInHouse))
		else:
			message += ' No one else was here.'.format(self.name)
		self.__sendMessage(timePrefix + message)
		self.writeStatusFile()

	# ======================================================
	def writeStatusFile(self):
		statusDir = 'status/'
		outFile = statusDir + self.name + '.out'
		inFile = statusDir + self.name + '.in'

		if (self.inHouse):
			deleteFile = outFile
			touchFile = inFile
		else:
			deleteFile = inFile
			touchFile = outFile			

		open(touchFile, 'a').close()
		try:
			os.remove(deleteFile)
		except OSError:
			pass

	# ======================================================
	def reportInvisible(self):
		self.visible = False

		# If device is invisible, is regarded to be here currently and was not visible during the threshold amount of seconds, it probably left. Oh noez!
		if (self.inHouse == True and self.secondsSinceLastVisible() > self.thresholdSeconds):
			self.__reportLeave()

	# ======================================================
	def reportVisible(self):
		self.visible = True
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
	@staticmethod
	def __sendToTwitter(text):
		try:
			twitter = Twython(TWITTER_APP_KEY, TWITTER_APP_SECRET, TWITTER_OAUTH_TOKEN, TWITTER_OAUTH_TOKEN_SECRET)
			twitter.update_status(status=text)
			log.debug('Sent message to Twitter.')
		except:
			log.error('Twitter exception!')

	# ======================================================
	@staticmethod
	def __sendToPushover(text):
		try:
			po = Pushover(PUSHOVER_TOKEN)
			po.user(PUSHOVER_USER)
			msg = po.msg(text)
			msg.set("title", PUSHOVER_TITLE)
			po.send(msg)
			log.debug('Sent message to Pushover.')
		except:
			log.error('Pushover exception!')

	# ======================================================
	@staticmethod
	def __sendToConsole(text):
		log.info(text)

	# ======================================================
	def __sendMessage(self, text):
		Device.__sendToConsole(text)
		if (self.notifyTwitter):
			Device.__sendToTwitter(text)
		if (self.notifyPushover):
			Device.__sendToPushover(text)

	# ======================================================
	@staticmethod
	def joinDeviceNames(deviceList):
		deviceNamesList = [(x.name) for x in deviceList]
		return ", ".join(deviceNamesList)

	# ======================================================
	@staticmethod
	def joinStrings(deviceList):
		devicesList = [(str(x)) for x in deviceList]
		return ", ".join(devicesList)

	# ======================================================
	def __str__(self):
		visible = '+' if self.visible else '-'
		inHouse = 'i' if self.inHouse else 'o'
		return '{0}({1}|{2})'.format(self.name, visible, inHouse)

	# ==========================================================
	def pickle(self):
		try:
			device_file = open('pickle/' + self.name + '.pkl', 'wb')
			pickle.dump(self, device_file)
			device_file.close()
		except:
			log.error("Pickling for {0} went wrong!".format(self.name))

	# ==========================================================
	def unpickle(self):
		try:
			device_file = open('pickle/' + self.name + '.pkl', 'rb')
			tempDevice = pickle.load(device_file)
			self.inHouse = tempDevice.inHouse
			self.lastVisibleTime = tempDevice.lastVisibleTime
			self.lastLeaveTime = tempDevice.lastLeaveTime
			self.lastJoinTime = tempDevice.lastJoinTime
			device_file.close()
			if self.inHouse:
				Device.devicesInHouse.add(self)
		except:
			log.info("No unpickling for {0}.".format(self.name))

# === End Class Device =====================================

# ==========================================================
if __name__ == '__main__':
	# get configuration from config file
	config = configparser.ConfigParser()
	config.read('config/config.ini')

	LOCATION = config['General']['Location']
	IP_RANGE = config['General']['IpRange']
	INTERVAL = int(config['General']['ScanInterval'])
	LOG_FILE = config['General']['LogFile']
	LOG_LEVEL = config['General']['LogLevel']

	TWITTER_APP_KEY = config['Twitter']['AppKey']
	TWITTER_APP_SECRET = config['Twitter']['AppSecret']
	TWITTER_OAUTH_TOKEN = config['Twitter']['OAuthToken']
	TWITTER_OAUTH_TOKEN_SECRET = config['Twitter']['OAuthTokenSecret']
	
	PUSHOVER_TOKEN = config['Pushover']['Token']
	PUSHOVER_USER = config['Pushover']['User']
	PUSHOVER_TITLE = config['Pushover']['Title']

	# configure logging
	numericLogLevel = getattr(logging, LOG_LEVEL.upper(), None)
	if not isinstance(numericLogLevel, int):
		raise ValueError('Invalid log level: {0}'.format(LOG_LEVEL))
		
	log = logging.getLogger(__name__)
	log.setLevel(numericLogLevel)

	formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

	handler = logging.handlers.TimedRotatingFileHandler(LOG_FILE, when="midnight", backupCount=1)
	handler.setLevel(numericLogLevel)
	handler.setFormatter(formatter)
	log.addHandler(handler)

	log.info('Starting up...')
	
	# iterate over configured devices in config file
	for section in config.sections():
		if (section[:7] == 'Device_'):
			newDevice = Device(config[section]['MacAddress'], section[7:], int(config[section]['Threshold']), config[section].getboolean('Twitter'), config[section].getboolean('Pushover'))
			log.info('Device configured: {0}'.format(newDevice.name))
	
	while True:
		nm.scan(hosts= IP_RANGE + '/24', arguments='-n -sP -PE -T5')
		hostsList = [(nm[x]['addresses']) for x in nm.all_hosts()]
		log.debug(hostsList)

		for device in Device.allDevices:
			# unpickle
			device.unpickle()

			# visible in network?
			visible = False
			for host in hostsList:
				if 'mac' in host and host['mac'] == device.macAddress:
					visible = True
					continue
			
			if visible:
				device.reportVisible()
			else:
				device.reportInvisible()

			# pickle
			device.pickle()

		log.debug(Device.joinStrings(Device.allDevices))

		lastRunFile = open('last.run', 'w')
		lastRunFile.write(Device.joinStrings(Device.allDevices))
		lastRunFile.close()
		
		log.debug('Going to sleep for {0} seconds...'.format(INTERVAL))
		time.sleep(INTERVAL)
