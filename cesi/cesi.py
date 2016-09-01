import xmlrpclib
import yaml
from datetime import datetime, timedelta
from flask import jsonify
import logging
import os

CONFIG_FILE = "cesi.yaml"

class Config:
    
    def __init__(self, config_file=CONFIG_FILE):
        self.def_home_dir = os.environ.get("CESI_HOME_DIR", os.getcwd())
        default_file = os.path.join(self.def_home_dir, "conf", config_file)
        self.config_file = default_file
        self.dataMap = yaml.load(open(self.config_file))

        self.cesi_config = self.dataMap.get("cesi", {})
        self.nodes_config = self.dataMap.get("nodes", {})
        
        # list of all unique node's name
        self.node_list = self.nodes_config.keys()

        #map of all node's based on enviroment (to remove)
        self.environment_list = []
        
        # to remove
        self.group_list = []

    def getNodeConfig(self, node_name):
        node_name = node_name
        node_config = self.nodes_config.get(node_name, {})
        host = node_config.get("host")
        port = node_config.get("port")
        username =  node_config.get("username")
        password = node_config.get("password")
        environment = node_config.get("environment", "production")
        return NodeConfig(node_name, host, port, username, password, environment)

    # to remove
    def getMemberNames(self, environment_name):
        self.environment_name = "environment:%s" % (environment_name)
        self.member_list = self.cfg.get(self.environment_name, 'members')
        self.member_list = self.member_list.split(', ')
        return self.member_list

    def getDatabase(self):
        return str(self.cesi_config.get("database", "/opt/local/cesi/database.db"))

    def getActivityLog(self):
        return str(self.cesi_config.get("activity_log", "/opt/local/cesi/activity_log"))

    def getHost(self):
        return str(self.cesi_config.get("host", "0.0.0.0"))

    def getPort(self):
        return int(self.cesi_config.get("port", 9002))
    
    def getCoolOffTime(self):
        return int(self.cesi_config.get("cool_off_time", 5))

    def getRefreshTime(self):
        return int(self.cesi_config.get("refresh_time", 60))

class NodeConfig:

    def __init__(self, node_name, host, port, username, password, environment):
        self.node_name = node_name
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.environment = environment
            

class Node:

    def __init__(self, node_config):
        self.name = node_config.node_name
        self.connection = Connection(node_config).getConnection()
        self.process_list=[]
        self.process_dict2={}
        self.process_dict = self.connection.supervisor.getAllProcessInfo()
        for p in self.process_dict:
            process_info = ProcessInfo(p)
            self.process_list.append(process_info)
            self.process_dict2[p['group']+':'+p['name']] = process_info

class Connection:

    def __init__(self, node_config):
        self.node_name = node_config.node_name
        self.host = node_config.host
        self.port = node_config.port
        self.username = node_config.username
        self.password = node_config.password
        if self.username and self.password:
            self.address = "http://%s:%s@%s:%s/RPC2" % (self.username, self.password, self.host, self.port)
        elif self.username or self.password:
            logging.error("Only one username/password given. Please check your inputs for node_name:%s host:%s port:%s", self.node_name, self.host, self.port)
            self.address = None
        else:
            logging.info("Conntecting with supervisord node without any authentication for node_name:%s host:%s port:%s", self.node_name, self.host, self.port)
            self.address = "http://%s:%s/RPC2" % (self.host, self.port) 

    def getConnection(self):
        if self.address:
            return xmlrpclib.Server(self.address)
        return None

class ProcessInfo:

    def __init__(self, dictionary):
        self.dictionary = dictionary
        self.name = self.dictionary['name']
        self.group = self.dictionary['group']
        self.start = self.dictionary['start']
        self.start_hr = datetime.fromtimestamp(self.dictionary['start']).strftime('%Y-%m-%d %H:%M:%S')[11:]
        self.stop_hr = datetime.fromtimestamp(self.dictionary['stop']).strftime('%Y-%m-%d %H:%M:%S')[11:]
        self.now_hr = datetime.fromtimestamp(self.dictionary['now']).strftime('%Y-%m-%d %H:%M:%S')[11:]
        self.stop = self.dictionary['stop']
        self.now = self.dictionary['now']
        self.state = self.dictionary['state']
        self.statename = self.dictionary['statename']
        self.spawnerr = self.dictionary['spawnerr']
        self.exitstatus = self.dictionary['exitstatus']
        self.stdout_logfile = self.dictionary['stdout_logfile']
        self.stderr_logfile = self.dictionary['stderr_logfile']
        self.pid = self.dictionary['pid']
        self.seconds = self.now - self.start
        self.uptime = str(timedelta(seconds=self.seconds))

class JsonValue:
    
    def __init__(self, process_name, node_name, event):
        self.process_name = process_name
        self.event = event
        self.node_name = node_name
        self.node_config = Config().getNodeConfig(self.node_name)
        self.node = Node(self.node_config)

    def success(self):
        return jsonify(status = "Success",
                       code = 80,
                       message = "%s %s %s event succesfully" %(self.node_name, self.process_name, self.event),
                       nodename = self.node_name,
                       data = self.node.connection.supervisor.getProcessInfo(self.process_name))

    def error(self, code, payload):     
        self.code = code
        self.payload = payload
        return jsonify(status = "Error",
                       code = self.code,
                       message = "%s %s %s event unsuccesful" %(self.node_name, self.process_name, self.event),
                       nodename = self.node_name,
                       payload = self.payload)
 