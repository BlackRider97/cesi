from flask import Flask, render_template, url_for, redirect, jsonify, request, g, session, flash
from cesi import Config
from datetime import datetime, timedelta
import xmlrpclib
import sqlite3
import logging
import time

def getLogger(log_level="debug"):
    logger = logging.getLogger('web')
    log_level_number = getattr(logging, log_level.upper())
    logger.setLevel(log_level_number)
    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(levelname)s %(message)s', '%d/%m/%Y %I:%M:%S %p')
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    return logger

app = Flask(__name__)
app.config.from_object(__name__)
app.secret_key= '42'
myconfig = Config()
 
def enum(*sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    enums['reverse_mapping'] = dict((value, key) for key, value in enums.iteritems())
    return type('Enum', (), enums)

USER_TYPES = enum(ADMIN=0, STANDARD=1, LOG_ONLY=2, READ_ONLY=3, TEAM_ONLY=4)
NODE_ENVIRONMENTS = enum(PRODUCTION=0, PRE_PRODUCTION=1, STAGING=2, DEVELOPMENT=3, MIXED=4)
PROCESS_STATES = enum(STOPPED=0, RUNNING=20, FATAL=200, STARTING=10, BACKOFF=30, STOPPING=40, EXITED=100, UNKNOWN=1000)
COMPARE_OPERATIONS = enum(NOTHING=0, EQUAL=1, NOT_EQUAL=2, LESS_THAN_OR_EQAUL=3, GREATER_THAN=4)

def get_user_type_code(user_type):
    for code, value in USER_TYPES.reverse_mapping.iteritems():
        if user_type == value:
            return code
    return None

def get_user_type(user_type_code):
    for code, value in USER_TYPES.reverse_mapping.iteritems():
        if code == user_type_code:
            return value.strip().title()
    return "unknown"

def get_node_env_code(node_env):
    for code, value in NODE_ENVIRONMENTS.reverse_mapping.iteritems():
        if node_env == value:
            return code
    return None

def get_node_env(node_env_code):
    for code, value in NODE_ENVIRONMENTS.reverse_mapping.iteritems():
        if code == node_env_code:
            return value.strip().title()
    return None

def get_process_state_code(process_state):
    for code, value in PROCESS_STATES.reverse_mapping.iteritems():
        if process_state == value:
            return code
    return None

def get_process_state(process_state_code):
    for code, value in PROCESS_STATES.reverse_mapping.iteritems():
        if code == process_state_code:
            return value.strip().title()
    return None

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
            logger.error("Only one username/password given. Please check your inputs for node_name:%s host:%s port:%s", self.node_name, self.host, self.port)
            self.address = None
        else:
            logger.info("Conntecting with supervisord node without any authentication for node_name:%s host:%s port:%s", self.node_name, self.host, self.port)
            self.address = "http://%s:%s/RPC2" % (self.host, self.port) 

    def getConnection(self):
        if self.address:
            return xmlrpclib.Server(self.address)
        return None

class NodeConfig:
    def __init__(self, node_name, host, port, username, password, environment):
        self.node_name = node_name
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.environment = environment

class Team:
    def __init__(self, id, name, desc):
        self.id = int(id)
        self.name = name
        self.desc = desc

class ProcessInfo:
    def __init__(self, dictionary):                
        # supervisor specific
        self.name = dictionary['name']
        self.group = dictionary['group']
        self.supervisor_name = self.group + ":" + self.name        
        self.start = dictionary['start']
        self.start_hr = datetime.fromtimestamp(dictionary['start']).strftime('%Y-%m-%d %H:%M:%S')[11:]
        self.stop_hr = datetime.fromtimestamp(dictionary['stop']).strftime('%Y-%m-%d %H:%M:%S')[11:]
        self.now_hr = datetime.fromtimestamp(dictionary['now']).strftime('%Y-%m-%d %H:%M:%S')[11:]
        self.stop = dictionary['stop']
        self.now = dictionary['now']
        self.state = dictionary['state']
        self.statename = dictionary['statename']
        self.spawnerr = dictionary['spawnerr']
        self.exitstatus = dictionary['exitstatus']
        self.stdout_logfile = dictionary['stdout_logfile']
        self.stderr_logfile = dictionary['stderr_logfile']
        self.stderr_logfile = self.stdout_logfile if not self.stderr_logfile else self.stderr_logfile
        self.pid = dictionary['pid']
        self.seconds = self.now - self.start
        self.uptime = str(timedelta(seconds=self.seconds)) 
         
        # hike specific
        self.working_dir = dictionary.get('working_dir')
        self.source_code_info =  dictionary.get('source_code_info')
        self.environment_variables = dictionary.get('environment_variables')

    def get_dictionary(self):
        return self.__dict__

    def get_process_owner_team(self):
        return int(self.environment_variables.get("team", -1))
    def get_process_environment(self):
        return self.environment_variables.get("environment", NODE_ENVIRONMENTS.PRODUCTION)

    def get_author_name(self):
        return self.source_code_info.get("author", "unknown")
    def get_deployment_ts(self):
        return self.source_code_info.get("timestamp", 0) 
    def get_branch_name(self):
        return self.source_code_info.get("branch", "unknown")  
    def get_commit_id(self):
        return self.source_code_info.get("commit_id", "unknown") 
    def get_source_repo(self):
        return self.source_code_info.get("source_repo", "unknown")   

class Node:
    def __init__(self, node_config):
        self.name = node_config.node_name
        self.host = node_config.host
        self.connection = Connection(node_config).getConnection()
        self.process_list=[]
        process_dict = self.connection.supervisor.getAllProcessInfo()
        for p in process_dict:
            process_group, process_name  =  p['group'], p['name']
            process_info = self.get_process_info(process_group, process_name)
            self.process_list.append(process_info)

    def get_process_info(self, process_group, process_name):
        supervisor_info = self.connection.supervisor.getProcessInfo(process_group+":"+process_name)
        hike_info = self.connection.hike.getProcessInfo(process_group, process_name)
        process_info_dict = dict(hike_info.items()+supervisor_info.items())
        logger.debug("process_group:%s process_name:%s process_info_dict:%s", process_group, process_name, process_info_dict)
        process_info = ProcessInfo(process_info_dict)
        return process_info


teams = []
def get_all_teams():
    global teams
    if not teams:
        cur = get_db().cursor()
        cur.execute("select * from teams")
        for node in cur.fetchall():
            name = node[1]
            team  = Team(node[0], name, node[2])
            teams.append(team)
    return teams 

def invalidate_teams():
    global teams
    teams = []

def does_user_belong_to_process(process_info, user_team_id):
    process_team_id = process_info.get_process_owner_team()
    user_team_id  = int(user_team_id)
    if user_team_id == -1:
        return True
    for team in get_all_teams():
        if user_team_id == team.id and process_team_id == team.id:
            return True
    return False

    
# Internal function to get node information
node_configs = {}
def get_all_nodes_configs():
    global node_configs
    if not node_configs:
        cur = get_db().cursor()
        cur.execute("select * from nodes")
        for node in cur.fetchall():
            node_name = node[0]
            node_config  = NodeConfig(node_name, node[1], int(node[2]), node[3], node[4], int(node[5]))
            node_configs[node_name] = node_config
    return node_configs

nodes = {}
last_node_update_ts = 0
def get_all_nodes():
    global last_node_update_ts, nodes 
    node_configs = get_all_nodes_configs()
    current_ts = int(time.time())
    if current_ts - last_node_update_ts > myconfig.getRefreshTime():
        last_node_update_ts = current_ts
        for node_name, node_config in node_configs.iteritems():
            node = Node(node_config)
            nodes[node_name] = node
    return nodes

def invalidate_all_nodes():
    global nodes, node_configs 
    nodes = {}
    node_configs = {}
   
def get_node(node_name):
    return get_all_nodes().get(node_name)
    
def get_process_info_and_node(node_name, process_name):
    node = get_node(node_name)
    my_process = None
    if node:
        for process in node.process_list:
            if process.supervisor_name == process_name:
                my_process = process
                break
    return node, my_process

class JsonValue:
    def __init__(self, process_name, node_name, event):
        self.process_name = process_name
        self.node_name = node_name
        self.event = event
        self.node = get_node(self.node_name)
    def success(self):
        group , name = self.process_name.split(":")
        return jsonify(status = "Success",
                       code = 80,
                       message = "node_name:%s process_name:%s %s event is successful" % (self.node_name, self.process_name, self.event),
                       nodename = self.node_name,
                       data = self.node.get_process_info(group, name).get_dictionary())

    def error(self, code, payload):
        return jsonify(status = "Error",
                       code = code,
                       message = "node_name:%s process_name:%s %s event is unsuccessful" % (self.node_name, self.process_name, self.event),
                       nodename = self.node_name,
                       payload = payload)

# Database connection
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(myconfig.getDatabase())
    return db

# Close database connection
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# Username and password control
@app.route('/login/control', methods = ['POST'])
def login_control():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        cur = get_db().cursor()
        cur.execute("select * from users where username=?",(username,))
        #if query returns an empty list
        if not cur.fetchall():
            session.clear()
            logger.warn("Given username:%s is not valid", username)
            return jsonify(status = "warning",
                           message = "Username is not  avaible ")
        else:
            cur.execute("select * from users where username=?",(username,))
            result = cur.fetchall()[0]
            if password == result[1]:
                session['username'] = username
                session['logged_in'] = True
                session['user_type'] = result[2]
                session['team_id'] = result[3]
                logger.info("Given username:%s user_type:%s team_id:%s is valid and logged in successfully", username, session['user_type'], session['team_id'])
                return jsonify(status = "success", type = session['user_type'], type_text = get_user_type(session['user_type']), team = session['team_id'], username = username)
            else:
                session.clear()
                logger.warn("Given username:%s password:%s combination is not valid", username, password)
                return jsonify(status = "warning",
                               message = "Invalid password")

# Render login page
@app.route('/login', methods = ['GET', 'POST'])
def login():
    return render_template('login.html')

# Logout action
@app.route('/logout', methods = ['GET', 'POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))

# Dashboard
@app.route('/')
def showMain():
# get user type
    if session.get('logged_in'):
        return render_template('index.html',
                                node_count =10,
                                environment_states = {},
                                process_states = {})
    else:   
        return redirect(url_for('login'))


# Get criteria to apply filter on process
@app.route('/criteria', methods = ['GET'])
def get_criteria():
    result = {}
    result["team"] = [{"name": team.name, "id": team.id} for team in get_all_teams()]
    result["environment"]  = [ {"name": name, "id": id} for id, name in NODE_ENVIRONMENTS.reverse_mapping.iteritems()]
    result["state"]  = [ {"name": name, "id": id} for id, name in PROCESS_STATES.reverse_mapping.iteritems()]
    result["operations"]  = [ {"name": name, "id": id} for id, name in COMPARE_OPERATIONS.reverse_mapping.iteritems()]
    nodes = get_all_nodes()
    nodes_list = set()
    groups_list = set()
    author_name_list = set()
    source_repo_list = set()
    if nodes:
        for node_name, node in nodes.iteritems():
            nodes_list.add(node_name)
            for process_info in node.process_list:
                groups_list.add(process_info.group)
                author_name_list.add(process_info.get_author_name())
                source_repo_list.add(process_info.get_source_repo())
    result["node"] = [{"name": name, "id": name} for name in nodes_list]
    result["group"] = [{"name": name, "id": name} for name in groups_list]
    result["last_author"] = [{"name": name, "id": name} for name in author_name_list]
    result["source_repo"] = [{"name": name, "id": name} for name in source_repo_list]
    return jsonify(status = "success", result = result)

def __perform_operation(a, b, operation):
    if operation == COMPARE_OPERATIONS.EQUAL:
        return a == b
    elif operation == COMPARE_OPERATIONS.NOT_EQUAL:
        return a != b
    elif operation == COMPARE_OPERATIONS.LESS_THAN_OR_EQAUL:
        return a <= b
    elif operation == COMPARE_OPERATIONS.GREATER_THAN:
        return a > b
    else:
        return True
         
# Get info about all processes running on all node
@app.route('/nodes', methods = ['POST'])
def get_nodes_info():
    nodes = get_all_nodes()
    if nodes:
        # node specific
        node_id = request.form.get('node', None)
        host = request.form.get('host', None)
        
        # process specific
        team_id = request.form.get('team', None)
        state_id = request.form.get('state', None)
        group_id = request.form.get('group', None)
        env_id = request.form.get('environment', None)
        source_repo_id = request.form.get('source_repo', None)
        last_author_id = request.form.get('last_author', None)
        name_contains = request.form.get('name', None)
        commit_id = request.form.get('commit_id', None)
        commit_id_op = int(request.form.get('commit_id_op', COMPARE_OPERATIONS.NOTHING))
        code_deploy_ts = request.form.get('deploy_ts', None)
        code_deploy_ts_op = int(request.form.get('deploy_ts_op', COMPARE_OPERATIONS.NOTHING))
        process_start_ts = request.form.get('start_ts', None)
        process_start_ts_op = int(request.form.get('start_ts_op', COMPARE_OPERATIONS.NOTHING))
        process_uptime_seconds = request.form.get('uptime', None)
        process_uptime_seconds_op = int(request.form.get('uptime_op', COMPARE_OPERATIONS.NOTHING))
        result = {}
        for node_name, node in nodes.iteritems():
            if node_id and not node_id == node_name:
                continue
            if host and not host == node.host:
                continue
            nodes_process_list = []
            for process_info in node.process_list:
                if team_id and not does_user_belong_to_process(process_info, team_id):
                    continue
                if state_id and not int(state_id) == int(process_info.state):
                    continue
                if group_id and not group_id == process_info.group:
                    continue
                if env_id and not int(env_id) == int(process_info.get_process_environment()):
                    continue
                if source_repo_id and not source_repo_id == process_info.get_source_repo():
                    continue
                if last_author_id and not last_author_id == process_info.get_author_name():
                    continue
                if name_contains and not name_contains in process_info.name:
                    continue
                if commit_id and not __perform_operation(commit_id, process_info.get_commit_id(), commit_id_op):
                    continue
                if code_deploy_ts and not __perform_operation(long(code_deploy_ts), long(process_info.get_deployment_ts()), code_deploy_ts_op):
                    continue
                if process_start_ts and not __perform_operation(long(process_start_ts), long(process_info.start), process_start_ts_op):
                    continue
                if process_uptime_seconds and not __perform_operation(long(process_uptime_seconds), long(process_info.seconds), process_uptime_seconds_op):
                    continue
                nodes_process_list.append(process_info.get_dictionary())
            result[node_name] = nodes_process_list
        return jsonify(status = "success", 
                       result = result)
    else:
        return jsonify(status = "warning",
                           message = "No nodes found") 


# forcefully reload info about nodes
last_reload_ts = 0
@app.route('/reload', methods = ['GET','POST'])
def reload_app():
    global last_reload_ts
    current_ts = int(time.time())
    if current_ts - last_reload_ts > myconfig.getCoolOffTime():
        invalidate_all_nodes()
        invalidate_teams()
        last_reload_ts = last_reload_ts
    return jsonify(status = "success")

# Get info about all processes running on node
@app.route('/node/<node_name>', methods = ['GET','POST'])
def get_node_info(node_name):
    node = get_node(node_name)    
    if node:
        return jsonify(status = "success", 
                       result = { node_name : [ process_info.get_dictionary() for process_info in node.process_list ] })
    else:
        return jsonify(status = "warning",
                           message = "No node found with given name")        

def action_on_process(node_name, process_name, event):
    if session.get('logged_in'):
        user_type_code = session['user_type']
        user_team_id = session['team_id']
        node, process = get_process_info_and_node(node_name, process_name)
        if not node or not process:
            return jsonify(status = "error", message = "No process exits for given node name and process name")       
        if (user_type_code == USER_TYPES.ADMIN or user_type_code == USER_TYPES.STANDARD) or (user_type_code == USER_TYPES.TEAM_ONLY and does_user_belong_to_process(process, user_team_id)):
            try:
                if event == "start":
                    action = node.connection.supervisor.startProcess(process_name)
                elif event == "stop":
                    action = node.connection.supervisor.stopProcess(process_name)
                elif event == "restart":
                    pre_action = node.connection.supervisor.stopProcess(process_name)
                    if pre_action:
                        action = node.connection.supervisor.startProcess(process_name)                   
                if action:
                    logger.info("username:%s user_team_id:%s taken action: %s on node: %s process: %s", session['username'], user_team_id, event, node_name, process_name)
                    return JsonValue(process_name, node_name, event).success()
            except xmlrpclib.Fault as err:
                logger.warn("username: %s got unsuccess during action: %s on node: %s process: %s", session['username'], event, node_name, process_name )
                return JsonValue(process_name, node_name, event).error(err.faultCode, err.faultString)
        else:
            logger.warn("%s is unauthorized user request for perform action: %s on node: %s process: %s", session['username'], event, node_name, process_name)
            return jsonify(status = "error2",
                           message = "You are not authorized this action" )
    else:
        logger.warn("Illegal request for action:%s on node: %s process: %s by user:%s", event, node_name, process_name, session['username'])
        return redirect(url_for('login'))

# Process restart
@app.route('/node/<node_name>/process/<process_name>/restart', methods = ['GET'])
def json_restart(node_name, process_name):
    return action_on_process(node_name, process_name, "restart")

# Process start
@app.route('/node/<node_name>/process/<process_name>/start', methods = ['GET'])
def json_start(node_name, process_name):
    return action_on_process(node_name, process_name, "start")

# Process stop
@app.route('/node/<node_name>/process/<process_name>/stop', methods = ['GET'])
def json_stop(node_name, process_name):
    return action_on_process(node_name, process_name, "stop")

# Show log for a process
@app.route('/node/<node_name>/process/<process_name>/readlog', methods = ['GET'])
def readlog(node_name, process_name):
    if session.get('logged_in'):
        user_type_code = session['user_type']
        if user_type_code != USER_TYPES.READ_ONLY:
            node, process = get_process_info_and_node(node_name, process_name)
            if not process:
                return jsonify( status = "warning", 
                                message= "No process found with given name")

            log = node.connection.supervisor.tailProcessStdoutLog(process_name, 0, 2000)[0]
            logger.info("User with username:%s user_type_code:%s is reading logs for node:%s process_name:%s", session['username'], session['user_type'], node_name, process_name)
            return jsonify( status = "success", url="node/"+node_name+"/process/"+process_name+"/readlog", log=log)
        else:
            logger.warn("username:%s is unauthorized user request for read log for %s node's %s process_name:%s", session['username'], node_name, process_name)
            return jsonify( status = "error", message= "You are not authorized for this action")
    else:
        logger.warn("Illegal request for read log to %s node's %s process %s", node_name, process_name)
        return jsonify( status = "error", message= "First login please")

# Writes new node information to database
@app.route('/node', methods = ['POST'])
def add_node_handler():
    if session.get('logged_in'):
        if session['user_type'] == 0:
            name = request.form.get('name')
            host = request.form.get('host')
            port = request.form.get('port', 9001)
            username = request.form.get('username', "")
            password = request.form.get('password', "")
            environment = request.form.get('environment', NODE_ENVIRONMENTS.PRODUCTION)
            if not host or not port or not environment:
                return jsonify( status = "null",
                                message = "Please enter values")
            name = name if name else "ip-"+host.strip().replace(".", "-")
            cur = get_db().cursor()
            cur.execute("select * from nodes where name=?",(name,))
            if cur.fetchall():
                logger.warn("Node name already exists where given name:%s", name)
                return jsonify(status = "warning",
                                   message ="Node name already exists. Please select different name")
            cur = get_db().cursor()
            cur.execute("insert into nodes values(?, ?, ?, ?, ?, ?)", (name, host, port, username, password, environment, ))
            get_db().commit()
            invalidate_all_nodes()
            logger.info("New node with name:%s host:%s port:%s added successfully", name, host, port)
            return jsonify(status = "success",
                           message ="Node added successfully")
        else:
            logger.warn("username:%s user_type_code:%s is unauthorized user for request to add node",session['username'],session['user_type'])  
            return jsonify(status = "error",
                           message = "Only Admin can add a node")
    else:
        logger.warn("Please first login then try to add a node")
        return jsonify(status = "error",
                       message = "First login please")

# delete node information from database
@app.route('/node/<node_name>', methods = ['DELETE'])
def delete_node_handler(node_name):
    if session.get('logged_in'):
        if session['user_type'] == 0:
            cur = get_db().cursor()
            cur.execute("delete from nodes where name=?",(node_name,))
            get_db().commit()
            invalidate_all_nodes()
            logger.info("Node with name:%s deleted successfully", node_name)
            return jsonify(status = "success",
                           message ="Node deleted successfully")
        else:
            logger.warn("username:%s user_type_code:%s is unauthorized user for request to delete a node",session['username'],session['user_type'])  
            return jsonify(status = "error",
                           message = "Only Admin can delete a node")
    else:
        logger.warn("Please first login then try to delete a node")
        return jsonify(status = "error",
                       message = "First login please")

# Writes new team information to database
@app.route('/team', methods = ['POST'])
def add_team_handler():
    if session.get('logged_in'):
        if session['user_type'] == 0:
            name = request.form.get('name')
            description = request.form.get('description', "")
            if not name:
                return jsonify( status = "null",
                                message = "Please enter values")
            name = name.strip().title()
            cur = get_db().cursor()
            cur.execute("select * from teams where name=?",(name,))
            if cur.fetchall():
                logger.warn("Team name already exists where given name:%s", name)
                return jsonify(status = "warning",
                                   message ="Team name already exists. Please select different name")
            cur = get_db().cursor()
            cur.execute("insert into teams(name, desc) values(?, ?)", (name, description,))
            get_db().commit()
            logger.info("New team with name:%s description:%s added successfully", name, description)
            invalidate_teams()
            return jsonify(status = "success",
                           message ="Team added successfully")
        else:
            logger.warn("username:%s user_type_code:%s is unauthorized user for request to add team",session['username'],session['user_type'])  
            return jsonify(status = "error",
                           message = "Only Admin can add a team")
    else:
        logger.warn("Please first login then try to add a team")
        return jsonify(status = "error",
                       message = "First login please")

# Writes new team information to database
@app.route('/team/<team_name>', methods = ['DELETE'])
def delete_team_handler(team_name):
    if session.get('logged_in'):
        if session['user_type'] == 0:
            cur = get_db().cursor()
            team_name = team_name.strip().title()
            cur.execute("delete from teams where name=?",(team_name,))
            get_db().commit()
            logger.info("Team with name:%s deleted successfully", team_name)
            invalidate_teams()
            return jsonify(status = "success",
                           message ="Team deleted successfully")
        else:
            logger.warn("username:%s user_type_code:%s is unauthorized user for request to delete a team",session['username'],session['user_type'])  
            return jsonify(status = "error",
                           message = "Only Admin can delete a team")
    else:
        logger.warn("Please first login then try to delete a team")
        return jsonify(status = "error",
                       message = "First login please")

# Writes new user information to database
@app.route('/user', methods = ['POST'])
def add_user_handler():
    if session.get('logged_in'):
        if session['user_type'] == 0:
            username = request.form.get('username')
            password = request.form.get('password')
            team = request.form.get('team', -1)
            confirmpassword = request.form.get('confirmpassword')
            user_type_code = get_user_type_code(request.form.get('user_type'))
            if not username or not password or not confirmpassword or user_type_code == None:
                return jsonify( status = "null",
                                message = "Please enter values")
            else:
                cur = get_db().cursor()
                cur.execute("select * from users where username=?",(username,))
                if not cur.fetchall():
                    if password == confirmpassword:
                        cur.execute("insert into users values(?, ?, ?, ?)", (username, password, user_type_code, team,))
                        get_db().commit()
                        logger.info("New user with username:%s user_type_code:%s team:%s added successfully", username, user_type_code, team)
                        return jsonify(status = "success",
                                       message ="User added successfully")
                    else:
                        logger.warn("Passwords didn't match at add user event with username:%s user_type_code:%s", username, user_type_code)
                        return jsonify(status = "warning",
                                       message ="Passwords didn't match")
                else:
                    logger.warn("Username already exists where given username:%s user_type_code:%s", username, user_type_code)
                    return jsonify(status = "warning",
                                   message ="Username already exists. Please select different username")
        else:
            logger.warn("username:%s user_type_code:%s is unauthorized user for request to add user event.",session['username'],session['user_type'])  
            return jsonify(status = "error",
                           message = "Only Admin can add a user")
    else:
        logger.warn("Please first login then try to add user")
        return jsonify(status = "error",
                       message = "First login please")


# Update existing user information to database
@app.route('/user/<old_username>', methods = ['PUT'])
def update_user_handler(old_username):
    if session.get('logged_in'):
        if session['user_type'] == 0:
            username = request.form.get('username')
            password = request.form.get('password')
            confirmpassword = request.form.get('confirmpassword')
            team = request.form.get('team', -1)
            user_type_code = get_user_type_code(request.form.get('user_type'))
            if not username or not password or not confirmpassword or user_type_code == None:
                return jsonify( status = "null",
                                message = "Please enter values")
            else:
                cur = get_db().cursor()
                cur.execute("delete from users where username=?",(old_username,))
                get_db().commit()
                cur.execute("select * from users where username=?",(username,))
                if cur.fetchall():
                    logger.warn("Username already exists where given username:%s user_type_code:%s", username, user_type_code)
                    return jsonify(status = "warning",
                                    message ="Username already exists. Please select different username")                    
                if password == confirmpassword:
                    
                    cur.execute("insert into users values(?, ?, ?, ?)", (username, password, user_type_code, team, ))
                    get_db().commit()
                    logger.info("User with old username:%s new username:%s user_type_code:%s updated successfully", old_username, username, user_type_code)
                    return jsonify(status = "success",
                                       message ="User updated successfully")
                else:
                    logger.warn("Passwords didn't match at update user event with username:%s user_type_code:%s", username, user_type_code)
                    return jsonify(status = "warning",
                                       message ="Passwords didn't match")
        else:
            logger.warn("username:%s user_type_code:%s is unauthorized user for request to update user event.",session['username'],session['user_type'])  
            return jsonify(status = "error",
                           message = "Only Admin can update a user")
    else:
        logger.warn("Please first login then try to update a user")
        return jsonify(status = "error",
                       message = "First login please")

# Delete user information from database
@app.route('/user/<username>', methods = ['DELETE'])
def delete_user_handler(username):
    if session.get('logged_in'):
        if session['user_type'] == 0:
            cur = get_db().cursor()
            cur.execute("delete from users where username=?",(username,))
            get_db().commit()
            logger.info("User with username:%s deleted successfully", username)
            return jsonify(status = "success",
                                       message ="User deleted successfully")   
        else:
            logger.warn("username:%s user_type_code:%s is unauthorized user for request to delete user event.",session['username'],session['user_type'])  
            return jsonify(status = "error",
                           message = "Only Admin can delete a user")
    else:
        logger.warn("Please first login then try to delete a user")
        return jsonify(status = "error",
                       message = "First login please")

@app.errorhandler(404)
def page_not_found(error):
    return render_template('page_not_found.html'), 404

try:
    if __name__ == '__main__':
        logger = getLogger()
        app.run(debug=True, use_reloader=True, host=myconfig.getHost(), port=myconfig.getPort())
except xmlrpclib.Fault as err:
    print "A fault occurred"
    print "Fault code: %d" % err.faultCode
    print "Fault string: %s" % err.faultString