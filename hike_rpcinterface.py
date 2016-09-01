import os
import time
import datetime
import subprocess

API_VERSION  = '1.0'

class SupervisorNamespaceRPCInterface:
    def __init__(self, supervisord):
        self.supervisord = supervisord

    # RPC API methods
    def getAPIVersion(self):
        """ Return the version of the RPC API used by supervisord

        @return string version version id
        """
        return API_VERSION

    # this can be used to run any shell command on supervisord host server using RPC
    # Helpful when you want to see that there is any local changes made on source code repo etc.
    """
    def _run_command(shell_command):
        p = subprocess.Popen(shell_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        body = ""
        for line in p.stdout.readlines():
            body += str(line)
            retval = p.wait()
        return body
    """

    def _get_process_configs(self, group_name, process_name):
        group = self.supervisord.process_groups.get(group_name)
        if not group:
            return None
        process_configs = group.config.process_configs
        for process_config in process_configs:
            if process_config.name == process_name:
                return process_config
        return None

    def listMethods(self):
        return [ "getAPIVersion", "getProcessInfo", "getSourceCodeInfo", "getWorkingDirectory", "getEnvironmenVariables"]

    def getProcessInfo(self, group_name, process_name):
        result = dict()
        result['working_dir'] = self.getWorkingDirectory(group_name, process_name)
        result['source_code_info'] = self.getSourceCodeInfo(group_name, process_name)
        result['environment_variables'] = self.getEnvironmenVariables(group_name, process_name)
        return result

    def getSourceCodeInfo(self, group_name, process_name):
        result = dict()
        process_config = self._get_process_configs(group_name, process_name)
        if not process_config:
            return result
        working_dir = self.getWorkingDirectory(group_name, process_name)
        try:
            counter = 0
            with open(working_dir+"/build/info", 'r') as build_info_file:
                for line in build_info_file:
                    if not line:
                        continue
                    line = line.strip()
                    if counter == 0:
                        result["author"] = line
                    elif counter == 1:
                        result["timestamp"] = line
                    elif counter == 2:
                        result["branch"] = line
                    elif counter == 3:
                        result["commit_id"] = line
                    elif counter == 4:
                        result["source_repo"] = line
                    else:
                        break
                    counter += 1
        except Exception as err:
            result["error"] = "build info file not found"
        return result

    def getWorkingDirectory(self, group_name, process_name):
        process_config = self._get_process_configs(group_name, process_name)
        if not process_config:
            return ""
        return process_config.directory

    def getEnvironmenVariables(self, group_name, process_name):
        process_config = self._get_process_configs(group_name, process_name)
        if not process_config:
            return {}
        return process_config.environment

# this is not used in code but referenced via an entry point in the conf file
def make_main_rpcinterface(supervisord):
    return SupervisorNamespaceRPCInterface(supervisord)

