import yaml
import os

CONFIG_FILE = "cesi.yaml"

class Config:
    
    def __init__(self, config_file=CONFIG_FILE):
        self.def_home_dir = os.environ.get("CESI_HOME_DIR", os.getcwd())
        default_file = os.path.join(self.def_home_dir, "conf", config_file)
        self.config_file = default_file
        self.dataMap = yaml.load(open(self.config_file))
        self.cesi_config = self.dataMap.get("cesi", {})

    def getDatabase(self):
        return str(self.cesi_config.get("database", "/opt/local/cesi/database.db"))

    def getLoggingLevel(self):
        return str(self.cesi_config.get("logging_level", "debug"))

    def getHost(self):
        return str(self.cesi_config.get("host", "0.0.0.0"))

    def getPort(self):
        return int(self.cesi_config.get("port", 9002))
    
    def getCoolOffTime(self):
        return int(self.cesi_config.get("cool_off_time", 5))

    def getRefreshTime(self):
        return int(self.cesi_config.get("refresh_time", 60))