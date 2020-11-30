"""ISNG / vStream POC configurator

This script allows the user to configure either a NetScout Infinistream (ISNG) or
a virtual Infinistream (vStream) with all the typical settings that would be needed
to conduct a Proof of Concept (POC).

It is assumed that this utility will be installed directly on the nGeniusONE CentOS-REL
operating system, although it can be installed on Windows, MAC or other Linux OSes.

A remote SSH connection is made to an ISNG/vStream (the probe) and the current configuration is queried
by using the localconsole script command line and menu functions. Then modifications are made
to better match what is needed in the case of a POC with SPAN traffic sources.

The probe agent is then restarted. The probe should be relearned by nGeniusONE, but that is out of
scope for this program.

"""
import time
import os
import sys
import subprocess
import pathlib
import requests
from datetime import datetime
import logging
from cryptography.fernet import Fernet
import paramiko
import scp
import pprint
import re
import string
import json

class Credentials:
    """
        A class to hold user credentials and pass into other functions.
        ...
        Attributes
        ----------
        probehostname : str
            The hostname of the probe
        probeport : str
            The port to use for the SSH connection
        probeusername : str
            The SSH username
        probepassword : str
            The SSH password
        use_ssh_keyfile : bool
            Use a keyfile or not for the SSH connection
        probe_ssh_keyfile : str
            The filename of the SSH key file.
        probekey : str
            The key contents of the probe_ssh_keyfile.
        time_of_exp : str
            The number of seconds before the encrypted password expires.
        """
    def __init__(self):
        self.probehostname = ''
        self.probeport = 22
        self.probeusername = ''
        self.probepassword = ''
        self.use_ssh_keyfile = False
        self.probe_ssh_keyfile = ''
        self.probekey_file = ''
        self.pkey = ''
        self.time_of_exp = ''


def create_logging_function(log_filename):
    """Creates the logging function and specifies a log file to write to.
    Use this option to log to stdout and stderr using systemd (import os):
    logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
    :param log_filename: A string that is the name of the logfile to write to in the same directory.
    :return: The logger instance if successfully completed, false if not successful.
    """
    now = datetime.now()
    date_time = now.strftime("%Y_%m_%d_%H%M%S")

    try:
        # Call the basicConfig module and pass in the log file filename.
        logging.basicConfig(filename=log_filename, format='%(asctime)s %(message)s', filemode='a+')
        # Call the logging class and create a logger object.
        logger = logging.getLogger()
        # Set the logging level to the lowest setting so that all logging messages get logged.
        logger.setLevel(logging.INFO) # Allowable options include DEBUG, INFO, WARNING, ERROR, and CRITICAL.
        # Write the current date and time to the log file to at least show when the program was executed.
        logger.info(f"*** Start of logs {date_time} ***")
        return logger
    except:
        print(f'[CRITICAL] Unable to create log file function for: {log_filename}.')
        return False

def get_decrypted_credentials(cred_filename, probekey_file, logger):
    """Read in the encrypted user or user-token credentials from an ini file.
    Decrypt the credentials and place all the user credentials attributes into a user_creds object.
    :param cred_filename: A string that is the name of the cred_filename to read in.
    :param probekey_file: A string that is the name of the ng1 key file to read in.
    :return: If successful return the user_creds as a class instance that contains all the params needed to
    log into nG1.
    """
    # Create a user_creds instance to hold our user credentials.
    user_creds = Credentials()

    # Retrieve the decrypted credentials that we will use to open a session to nG1.
    try:
        with open(cred_filename, 'r') as cred_in:
            lines = cred_in.readlines()
            probe_ssh_keyfile = lines[2].partition('=')[2].rstrip("\n")
            #Check to see if we are expected to use an SSH key file or Username:Password.
            if len(probe_ssh_keyfile) > 1: # Yes use an SSH key file rather than username/password.
                user_creds.use_ssh_keyfile = True
                user_creds.probe_ssh_keyfile = probe_ssh_keyfile
                user_creds.probeusername = lines[3].partition('=')[2].rstrip("\n")
                try:
                    user_creds.pkey = paramiko.RSAKey.from_private_key_file(user_creds.probe_ssh_keyfile)
                    logger.info(f'Found SSH key: {user_creds.probe_ssh_keyfile}')
                    print(f'[INFO] Using SSH key file: {user_creds.probe_ssh_keyfile} for connection')
                except SSHException as error:
                    logger.error(f'An SSHException has occurred {error}')
                    print(f'[ERROR] An SSHException has occurred {error}')
                    return False
            else: # no don't use an SSH key file but rather a username/password.
                try: # Open the keyfile containing the key needed to decrypt the password.
                    with open(probekey_file, 'r') as probekey_in:
                        probekey = probekey_in.read().encode()
                        fng1 = Fernet(probekey)
                except:
                    print(f'[CRITICAL] Unable to open probekey_file: {probekey_file}.')
                    logger.critical(f'[CRITICAL] Unable to open probekey_file: {probekey_file}.')
                    return False
                user_creds.use_ssh_keyfile = False
                user_creds.probeusername = lines[3].partition('=')[2].rstrip("\n")
                user_creds.probepassword = lines[4].partition('=')[2].rstrip("\n")
                user_creds.probepassword_pl = fng1.decrypt(user_creds.probepassword.encode()).decode()
            user_creds.probehostname = lines[5].partition('=')[2].rstrip("\n")
            user_creds.probePort = lines[6].partition('=')[2].rstrip("\n")
    except:
        print(f'[CRITICAL] Unable to open cred_filename: {cred_filename}.')
        logger.critical(f'[CRITICAL] Unable to open cred_filename: {cred_filename}.')
        return False
    return user_creds

def open_ssh_session(user_creds, logger):
    """
    Opens an SSH session to the probe using paramiko.
    :param user_creds: A class instance that contains all the necessary connection parameters.
    :param logger: A class instance of logger so we can log messages.
    :return: The SSH client instance if successful, False if unsuccessful.
    """
    hostname = user_creds.probehostname
    port = user_creds.probeport
    username = user_creds.probeusername
    probeport = user_creds.probePort
    if user_creds.use_ssh_keyfile == False: # Use a password for the SSH connection
        key_filename = None
        pkey = None
        password = user_creds.probepassword_pl
    else: # Use an SSH keyfile for the SSH connection rather than a password.
        password = None
        key_filename = user_creds.probe_ssh_keyfile
        pkey = user_creds.pkey
    timeout = 20 # Number of seconds to wait before timing out
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        #client.connect(hostname=hostname, port=port, username=username, password=password, pkey=pkey,
        # key_filename=key_filename, timeout=timeout, allow_agent=True, look_for_keys=True,
        # compress=False, sock=None, gss_auth=False, gss_kex=False, gss_deleg_creds=True,
         #gss_host=None, banner_timeout=None, auth_timeout=None, gss_trust_dns=True, passphrase=None,
        # disabled_algorithms=None)
        print(f'[INFO] Attempting SSH connection to hostname: {hostname} with username: {username} on port: {probeport}')
        client.connect(hostname=hostname, username=username, password=password, pkey=pkey, timeout=timeout)
        print(f'[INFO] Open SSH connection to: {hostname} Successful.')
        logger.info(f'[INFO] Open SSH connection to: {hostname} Successful.')
        #client.connect(hostname,username,pkey=none,key_filename='id_rsa',look_for_keys=True)
        return client
    except:
        print(f'[CRITICAL] Unable to open SSH connection to: {hostname}.')
        logger.critical(f'[CRITICAL] Unable to open SSH connection to: {hostname}.')
        return False

def execute_single_command_on_remote(command, rem_con):
    """
    Sends a single console command to the probe and returns the result.
    :command: A string that contains the command with an new line char at the end to simulate
    hitting the enter key.
    :rem_con: A class instance of invoke_shell that opens a remote console shell over SSH.
    :return: The output string that was returned from the console as a result of the command.
    """
    while not rem_con.send_ready():
        time.sleep(0.5)
    rem_con.send(command) # Send the command string to the remote console shell.
    while not rem_con.recv_ready():
        time.sleep(0.5)
    time.sleep(3)
    output = rem_con.recv(2048) # Pull down the receive buffer from the remote console.
    output = output.decode("utf-8") # Output comes back as a file-like binary object. Decode to a string.

    return output

def init_probe_console(logger, client):
    """
    Sends commands to the SSH client to establish a console object and set the user to su.
    :param client: The SSH client instance established with the probe.
    :param logger: An instance of logger so we can log messages.
    :return: rem_con, A class instance of invoke_shell that opens a remote console shell over SSH.
    """

    rem_con = client.invoke_shell()
    # turn off paging
    rem_con.send('terminal length 0\n')
    while rem_con.recv_ready() != True:
        time.sleep(0.25)
    time.sleep(1)
    output = rem_con.recv(1000)
    output = output.decode("utf-8") #Output comes back as a file-like object. Decode to a string.
    if 'Last login:' not in output:
        print('[ERROR] SSH command invoke_shell failed')
        logger.error('[ERROR] SSH command invoke_shell failed.')
        return False

    command = "sudo su -\n"
    output = execute_single_command_on_remote(command, rem_con)
    if "su:" in output or "sudo:" in output: # The sudo command has failed.
        print(f'[ERROR] Console command: {command[:-1]} failed')
        logger.error(f'[ERROR] Console command: {command} failed')
        return False
    #stty -echo
    return rem_con

def get_probe_options(config_attributes_list, index_counter, rem_con, probe_configs_dict, options_type):
    """
    Sends a command the probe to get a whole options list and read in the response for processing.
    The list of options returned by the probe will be used to fill in the attributes for the probe_configs_dict.
    :config_attributes_list: A list of attribute names to be entered into the probe_configs_dict.
    :interface_list: A list of probe monitor interface numbers that are available.
    :index_counter: An integer counter used to access each config element as we loop through the interfaces.
    :rem_con: An instance of the remote console shell session to the probe.
    :probe_configs_dict: A dictionary of all the probe configurations.
    :options_type: The name of the probe options that we want to fetch from the probe.
    :return: False if any command fails, The filled in probe_configs_dict if all commands pass.
    """
    formatted_options_configs = [] # create an empty list to hold the options settings returned by the probe.

    formatted_configs = []
    if options_type == 'agent_configs':
        command = "get agent\n"
    else:
        command = "get " + options_type + "\n"
    output = execute_single_command_on_remote(command, rem_con)
    options_configs = output.splitlines()
    for options_config in options_configs:
        options_config_split = options_config.split()
        options_config_new = " ".join(options_config_split)
        formatted_options_configs.append(options_config_new)

    print(f'\nformatted_options_configs is: {formatted_options_configs}')
    for config_attribute in config_attributes_list:
        # print(f'config_attribute is: {config_attribute}')
        if options_type == 'http' and index_counter > 3: # Another inconsistency in the attribute string names. Include ' =' for http type.
            probe_configs_dict[options_type][0][config_attribute] = formatted_options_configs[index_counter].partition(config_attribute + ' = ')[2]
        else:
            probe_configs_dict[options_type][0][config_attribute] = formatted_options_configs[index_counter].partition(config_attribute + ' ')[2]
        index_counter += 1

    return probe_configs_dict

def get_probe_options_interface_specific(config_attributes_list, interface_list, index_counter, rem_con, probe_configs_dict, options_type):
    """
    For each monitor interface, send a command the probe to get the specific settings passed in as config_attributes_list.
    The setting for each config attribute will be used to fill in the attributes for the probe_configs_dict.
    :config_attributes_list: A list of attribute names to be entered into the probe_configs_dict.
    :interface_list: A list of probe monitor interface numbers that are available.
    :index_counter: An integer counter used to access each config element as we loop through the interfaces.
    :rem_con: An instance of the remote console shell session to the probe.
    :probe_configs_dict: A dictionary of all the probe configurations.
    :options_type: In this case, interface_specific to indicate that we need send the query with the interface number included in the command.
    :return: False if any command fails, The filled in probe_configs_dict if all commands pass.
    """

    formatted_options_configs = [] # create an empty list to hold the options settings returned by the probe.
    loop_counter = index_counter # The index_counter is our starting point for the elements returned by get 'options_type'.
    interface_loop_counter = 0 # Needed to send get asi for the first interface, 'y' for each subsequent interface.
    la_burst_is_on = True # A flag to use when the config options change due to a setting being 'on'.
    for interface in interface_list:
        probe_configs_dict[options_type][0]['interface '+ interface] = [{}]
    for config_attribute in config_attributes_list:
        formatted_options_configs = [] # Reset the list each time we loop to the next config_attribute.
        for interface in interface_list:
            formatted_options_configs = [] # For each interface, reset formatted_options_configs to an empty list
            command = "get " + config_attribute + " " + interface + "\n"
            #print(f'\ncommand is: {command}')
            output = execute_single_command_on_remote(command, rem_con)
            options_configs = output.splitlines()

            for options_config in options_configs:
                #print(f'\noptions_config is: {options_config}')
                options_config_split = options_config.split()
                #print(f'\noptions_config_split is: {options_config_split}')
                options_config_new = " ".join(options_config_split)
                #print(f'\noptions_config_new is: {options_config_new}')
                formatted_options_configs.append(options_config_new)
            #print(f'\nformatted_options_configs is: {formatted_options_configs}')
            config_attribute_verbose = formatted_options_configs[2].partition(config_attribute + ' ')[2].lower()
            if 'is on ' in config_attribute_verbose or 'is enabled ' in config_attribute_verbose or 'on on ' in config_attribute_verbose: # Some settins use on, some enabled.
                probe_configs_dict[options_type][0]['interface '+ interface][0][config_attribute] = 'on'
            else:
                probe_configs_dict[options_type][0]['interface '+ interface][0][config_attribute] = 'off'
    return probe_configs_dict

def get_probe_options_per_interface(config_attributes_list, interface_list, index_counter, rem_con, probe_configs_dict, options_type):
    """
    For each monitor interface, send a command the probe to get the whole options list.
    The list of options returned by the probe will be used to fill in the attributes for the probe_configs_dict.
    :config_attributes_list: A list of attribute names to be entered into the probe_configs_dict.
    :interface_list: A list of probe monitor interface numbers that are available.
    :index_counter: An integer counter used to access each config element as we loop through the interfaces.
    :rem_con: An instance of the remote console shell session to the probe.
    :probe_configs_dict: A dictionary of all the probe configurations.
    :options_type: The name of the probe options that we want to fetch from the probe.
    :return: False if any command fails, The filled in probe_configs_dict if all commands pass.
    """

    formatted_options_configs = [] # create an empty list to hold the options settings returned by the probe.
    loop_counter = index_counter # The index_counter is our starting point for the elements returned by get 'options_type'.
    interface_loop_counter = 0 # Needed to send get asi for the first interface, 'y' for each subsequent interface.
    la_burst_is_on = True # A flag to use when the config options change due to a setting being 'on'.
    for interface in interface_list:
        probe_configs_dict[options_type][0]['interface '+ interface] = [{}]

    for interface in interface_list:
        config_counter = index_counter# Reset the index to what was passed into the function.
        if options_type != 'asi': # Get asi does not use set curr_interface, you must hit enter to advance.
            command = "set curr_interface " + interface +" \n"
            output = execute_single_command_on_remote(command, rem_con)

        formatted_options_configs = []
        #print(f'\noptions_type is: {options_type}')
        #print(f'\ninterface_loop_counter is: {interface_loop_counter}')
        if options_type == 'asi' and interface_loop_counter > 0:
            command = "\n" # Send the yes response to get asi on the next interface
        else:
            command = "get " + options_type + "\n"
        output = execute_single_command_on_remote(command, rem_con)
        options_configs = output.splitlines()
        for options_config in options_configs:
            options_config_split = options_config.split()
            options_config_new = " ".join(options_config_split)
            formatted_options_configs.append(options_config_new)
        print(f'\nformatted_options_configs is: {formatted_options_configs}')
        for config_attribute in config_attributes_list:
            #print(f'loop_counter is: {loop_counter}')
            #print(f'\nconfig_attribute is: {config_attribute}')
            if la_burst_is_on == False: # The menu is dynamic. If la_burst is on, there will be an extra element la_type.
                if config_attribute == 'la_type':
                    la_burst_is_on = True # Reset the la_burst_is_on flag to True in case the next interface has it set to on.
                    continue # If the la_burst is off, and this loop config_attribute is is 'la_type, skip to the next valid attribute.
                else:
                    continue # If the la_burst is off, then skip the next config_attribute 'la_type'.
            probe_configs_dict[options_type][0]['interface '+ interface][0][config_attribute] = formatted_options_configs[loop_counter].partition(config_attribute + ' ')[2]
            if config_attribute == 'la_burst': # Check the setting for 'la_burst' for this interface that we just set.
                if probe_configs_dict[options_type][0]['interface '+ interface][0][config_attribute] == 'off':
                    la_burst_is_on = False # If la_burst is off for this interface, then set the flag to False.

            loop_counter += 1 # Increment the formatted_options_configs index number we use for each config_attribute loop.
        if options_type == 'asi': # The menu for the first interface on get asi has two extra elements.
            loop_counter = 2 # The subsequent interface menus have valid data starting at the third element.
        else:
            loop_counter = index_counter # Reset the counter to the right formatted_options_configs index number starting point that was passed in.
        interface_loop_counter += 1 # Increment the interface loop counter to account for 'get asi' interactive menu.

    if options_type == 'asi': # The final menu page prints out the V4 and V6 community masks.
        command = "\n" # Send the yes <enter> response to 'get asi' to end the menu and return to the command line prompt.
        output = execute_single_command_on_remote(command, rem_con)
        command = "\n" # Send the yes <enter> response to 'get asi' to end the menu and return to the command line prompt.
        output = execute_single_command_on_remote(command, rem_con)

    return probe_configs_dict

def get_probe_options_non_interface_specific(config_attributes_list, index_counter, rem_con, probe_configs_dict, options_type):
    """
    For each config attribute, send a command the probe to get the specific probe-wide non-interface specific settings.
    The setting for each config attribute will be used to fill in the attributes for the probe_configs_dict.
    :config_attributes_list: A list of attribute names to be entered into the probe_configs_dict.
    :index_counter: An integer counter used to access each config element as we loop through the interfaces.
    :rem_con: An instance of the remote console shell session to the probe.
    :probe_configs_dict: A dictionary of all the probe configurations.
    :options_type: In this case, interface_non_specific to indicate that we need send one command for each config attribute.
    :return: False if any command fails, The filled in probe_configs_dict if all commands pass.
    """
    for config_attribute in config_attributes_list:
        formatted_options_configs = [] # Reset the list each time we loop to the next config_attribute.
        command = "get " + config_attribute + "\n"
        #print(f'\ncommand is: {command}')
        output = execute_single_command_on_remote(command, rem_con)
        options_configs = output.splitlines()

        for options_config in options_configs:
            #print(f'\noptions_config is: {options_config}')
            options_config_split = options_config.split()
            #print(f'\noptions_config_split is: {options_config_split}')
            options_config_new = " ".join(options_config_split)
            #print(f'\noptions_config_new is: {options_config_new}')
            formatted_options_configs.append(options_config_new)
        print(f'\nformatted_options_configs is: {formatted_options_configs}')
        if config_attribute == 'config_download':
            config_attribute_verbose = formatted_options_configs[index_counter].partition('config_download : ')[2].lower()
        elif config_attribute == 'probe_mode':
            config_attribute_verbose = formatted_options_configs[index_counter].partition('Probe Mode : ')[2].lower()
        elif config_attribute == 'vq payload':
            config_attribute_verbose = formatted_options_configs[index_counter].partition('vq payload: ')[2].lower()
        elif config_attribute == 'asi_mode':
            config_attribute_verbose = formatted_options_configs[index_counter].partition('asi_mode is currently set to ')[2].lower()
        #print(f'\nconfig_attribute_verbose is: {config_attribute_verbose}')
        probe_configs_dict[options_type][0][config_attribute] = config_attribute_verbose
    return probe_configs_dict

def get_probe_options_single_command_multi_interface(config_attributes_list, interface_list, index_counter, rem_con, probe_configs_dict, options_type):
    """
    This is another example of how get <setting> returns a wildly different format from other get commands.
    In this case a single get command returns a list of each setting for each interface.
    The list of options returned by the probe will be used to fill in the attributes for the probe_configs_dict.
    :config_attributes_list: A list of attribute names to be entered into the probe_configs_dict.
    :interface_list: A list of probe monitor interface numbers that are available.
    :index_counter: An integer counter used to access each config element as we loop through the interfaces.
    :rem_con: An instance of the remote console shell session to the probe.
    :probe_configs_dict: A dictionary of all the probe configurations.
    :options_type: The name of the probe options that we want to fetch from the probe.
    :return: False if any command fails, The filled in probe_configs_dict if all commands pass.
    """
    for config_attribute in config_attributes_list:
        formatted_options_configs = [] # Start with an empty list.
        loop_counter = index_counter # This is the starting point for reading elements from the formatted_options_configs.
        command = "get " + config_attribute + "\n" # One command returns a list of interface settings to parse through.
        #print(f'\ncommand is: {command}')
        output = execute_single_command_on_remote(command, rem_con)
        options_configs = output.splitlines()
        for options_config in options_configs:
            options_config_split = options_config.split()
            options_config_new = " ".join(options_config_split)
            formatted_options_configs.append(options_config_new)
        print(f'\nformatted_options_configs is: {formatted_options_configs}')
        for interface in interface_list: # In this case, loop through each line returned for each interface.
            probe_configs_dict[options_type][0]['interface '+ interface][0][config_attribute] = formatted_options_configs[loop_counter].partition(interface + ' ')[2]
            loop_counter += 1 # Increment the formatted_options_configs index number we use for each config_attribute loop.

    return probe_configs_dict


def gather_probe_configs(logger, rem_con):
    """
    Sends a series of commands to the remote console and gathers the responses for processing.
    The responses will be used to fill in the attributes for the probe_configs_dict.
    :rem_con: An instance of the remote console shell session to the probe.
    :return: False if any command fails, The filled in probe_configs_dict if all commands pass.
    """

    print('[INFO] Gathering current probe configurations...')
    logger.info('[INFO] Gathering current probe configurations...')

    #try:
    # Initialize an empty dictionary to hold our probe config params.
    probe_configs_dict = {'interface_options': [{}], 'agent_configs': [{}], 'agent_options': [{}], 'software_options': [{}],
                            'protocol_options': [{}], 'http': [{}], 'asi': [{}], 'interface_specific': [{}],
                            'non_interface_specific': [{}]}

    command = "localconsole\n"
    output = execute_single_command_on_remote(command, rem_con)
    #print(output)
    output = ""
    command = "7\n" # We need to know what interfaces exist on this probe.
    output = execute_single_command_on_remote(command, rem_con)
    interface_list = []
    interface_configs = output.splitlines()
    for interface_config in interface_configs:
        #print(f'\ninterface_config is: {interface_config}')
        interface_config_split = interface_config.split()
        #print(f'\ninterface_config_split is: {interface_config_split}')
        interface_config_new = " ".join(interface_config_split)
        #print(f'\ninterface_config_new is: {interface_config_new}')
        if '[99] Go Back to Main Menu' in interface_config_new: # We are at the end of the page. Break.
            break
        if '-ETHERNET' in interface_config_new:
            interface_list.append(interface_config_new[1:3].strip())

    print(f'\ninterface_list is: {interface_list}')

    command = "99\n" # We need to know what interfaces exist on this probe.
    output = execute_single_command_on_remote(command, rem_con)

    command = "11\n"
    output = execute_single_command_on_remote(command, rem_con)

    # Difficult not to hard code these lists of attribute names as it is not consistent in...
    # the probe if there are underscores or spaces or how many words are in the attribute name.
    config_attributes_list = ['power_alarm_util', 'power_alarm_resp', 'admin_shutdown', 'Data w/o Control Tcm',
                            'jumboframe_support', 'interface_speed', 'mib2_ifspeed', 'vifn_enable',
                            'vifn_discovery', 'vifn_mode', 'reverse_ports', 'HTTP Mode', 'M3UA Table',
                            'enable xDR', 'Tunnel Parsing', 'interface type', 'auxiliary interfaces', 'Data w/o Control',
                            'Interface Mode', 'Configure Tunnel Termination']

    index_counter = 4 # The starting index of the first valid element in formatted_interface_configs.
    options_type = 'interface_options'
    probe_configs_dict = get_probe_options_per_interface(config_attributes_list, interface_list, index_counter, rem_con, probe_configs_dict, options_type)

    config_attributes_list = ['model_number', 'software_version', 'link time', 'memory size', 'nvram_version',
                            'nvram size', 'agent_location', 'agent_contact', 'agent_name', 'read_community',
                            'write_community', 'Probe Communication Mode', 'IP V4 address', 'MAC Address',
                            'config_server', 'serial_number', 'nsprobe_type', 'kernel']

    index_counter = 2 # The starting index of the first valid element in formatted_interface_configs.
    options_type = 'agent_configs'
    probe_configs_dict = get_probe_options(config_attributes_list, index_counter, rem_con, probe_configs_dict, options_type)

    config_attributes_list = ['watchdog', 'auto_reboot', 'timestamp_ns', 'burst_advisor_peak',
                            'Infinistream Console Support', 'Traffic Violations', 'nGeniusONE Managed',
                            'Health Monitoring', 'Eth0 GRE Monitoring', 'Network Analyzer Support']

    index_counter = 4 # The starting index of the first valid element in formatted_interface_configs.
    options_type = 'agent_options'
    probe_configs_dict = get_probe_options(config_attributes_list, index_counter, rem_con, probe_configs_dict, options_type)

    config_attributes_list = ['Response Time Monitor', 'NL and AL Host', 'NL and AL Conversation',
                            'SBA Priority']

    index_counter = 2 # The starting index of the first valid element in formatted_interface_configs.
    options_type = 'software_options'
    probe_configs_dict = get_probe_options(config_attributes_list, index_counter, rem_con, probe_configs_dict, options_type)

    config_attributes_list = ['Pattern Matching', 'CORBA', 'Conversation Port Discovery',
                            'Skype Pattern Matching', 'Extended FIS', 'Voice and Video Quality']

    index_counter = 2 # The starting index of the first valid element in formatted_interface_configs.
    options_type = 'protocol_options'
    probe_configs_dict = get_probe_options(config_attributes_list, index_counter, rem_con, probe_configs_dict, options_type)

    config_attributes_list = ['http web_classify', 'http db_type', 'http proxy_server_uri_search', 'http hsts',
                            'http my_nw_url_discovery', 'http parse_xcap', 'http parse_stir', 'http ssl_quic_subscr_info',
                            'http use_xff', 'http use_xff_multiple_clients', 'http use_client_ip_field',
                            'http use_x_true_client_ip', 'http use_x_real_ip_field']

    index_counter = 2 # The starting index of the first valid element in formatted_interface_configs.
    options_type = 'http'
    probe_configs_dict = get_probe_options(config_attributes_list, index_counter, rem_con, probe_configs_dict, options_type)

    config_attributes_list = ['kti_peak_type', 'kti_peak_interval', 'ksi_mtu_size', 'uc_conv',
                            'server_table', 'disc_table', 'vital_table', 'tcp_monitor', 'conv',
                            'conv ports', 'conv qos', 'la_burst', 'la_type', 'host_activity',
                            'htt', 'ksi 1min', 'ksi client_ip', 'subscriber', '1-min', '15-sec',
                            'url_disc_table']

    index_counter = 3 # The starting index of the first valid element in formatted_interface_configs.
    options_type = 'asi'
    probe_configs_dict = get_probe_options_per_interface(config_attributes_list, interface_list, index_counter, rem_con, probe_configs_dict, options_type)

    config_attributes_list = ['skt_vlan_enable', 'span_duplicate', 'ssl_sni']

    index_counter = 2 # The starting index of the first valid element in formatted_interface_configs.
    options_type = 'interface_specific'
    probe_configs_dict = get_probe_options_interface_specific(config_attributes_list, interface_list, index_counter, rem_con, probe_configs_dict, options_type)

    config_attributes_list = ['config_download', 'probe_mode', 'vq payload', 'asi_mode']

    index_counter = 2 # The starting index of the first valid element in formatted_interface_configs.
    options_type = 'non_interface_specific'
    probe_configs_dict = get_probe_options_non_interface_specific(config_attributes_list, index_counter, rem_con, probe_configs_dict, options_type)

    config_attributes_list = ['community_type']

    index_counter = 3 # The starting index of the first valid element in formatted_interface_configs.
    options_type = 'interface_specific'
    probe_configs_dict = get_probe_options_single_command_multi_interface(config_attributes_list, interface_list, index_counter, rem_con, probe_configs_dict, options_type)

    command = "quit\n"
    output = execute_single_command_on_remote(command, rem_con)

    command = "exit\n"
    output = execute_single_command_on_remote(command, rem_con)

    #except:
        #print(f'[ERROR] Error occurred while gathering the current probe configuration')
        #logger.error(f'[ERROR] Error occurred while gathering the current probe configuration')
        #return False
    return probe_configs_dict

def write_config_to_json(config_filename, probe_configs_dict, logger):
    """
    Serialize the probe_configs_dict and write it out to a json file.
    :config_filename: The name of the json file that we want to save the probe configs to.
    :probe_configs_dict: The probe config dictionary that contains all the probe config settings.
    :return: False if any command fails, True if the config is successfully written to the json file.
    """

    # write the probe_configs_dict to a json file.
    try:
        with open(config_filename,"w") as f:
            json.dump(probe_configs_dict, f)
            print(f'[INFO] Writing probe config to JSON file: {config_filename}')
            logger.info(f'[INFO] Writing probe config to JSON file: {config_filename}')
            return True
    except IOError as e: # Handle file I/O errors.
        print(f'[ERROR] Unable to write to the JSON config file: {config_filename}')
        logger.error(f'[ERROR] Unable to write to the JSON config file: {config_filename}')
        print("I/O error({0}): {1}".format(e.errno, e.strerror))
        logger.error(f'[ERROR] I/O error: {e.errno}:  {e.strerror}.')
        return False
    except: # Handle other exceptions such as attribute errors.
        print(f'[ERROR] Unable to write to the JSON config file: {config_filename}')
        logger.error(f'[ERROR] Unable to write to the JSON config file: {config_filename}')
        print(f'Unexpected error: {sys.exc_info()[0]}')
        logger.error(f'[ERROR] Unexpected error: {sys.exc_info()[0]}.')
        return False


def close_ssh_session(user_creds, client, rem_con, logger):
    """
    Close the remote console shell session to the probe.
    Close an SSH session to the probe using paramiko.
    :param user_creds: A class instance that contains all the necessary connection parameters.
    :param client: The SSH client instance.
    :param rem_con: The remote console shell session instance.
    :param logger: An instance of logger so we can log messages.
    :return: True if successful, False if unsuccessful.
    """
    hostname = user_creds.probehostname
    try:
        rem_con.close()
        client.close()
        print(f'[INFO] SSH connection to: {hostname} successfully closed.')
        logger.critical(f'[INFO] SSH connection to: {hostname} successfully closed.')
        return True
    except:
        print(f'[CRITICAL] Unable to close SSH connection to: {hostname}.')
        logger.critical(f'[CRITICAL] Unable to close SSH connection to: {hostname}.')
        return False


def main():

    log_filename = 'isng_vstream_poc_config.log'

    # Hardcoding the filenames for encrypted credentials and the key file needed to decrypt the credentials.
    cred_filename = 'ProbeCredFile.ini'
    probekey_file = 'probekey.key'
    # Create a logger instance and write the date_time to a log file.
    logger = create_logging_function(log_filename)
    if logger == False: # Creating the logger instance has failed. Exit.
        print('Exiting...')
        exit()
    # Get the user's credentials from a file and decrypt them.
    user_creds = get_decrypted_credentials(cred_filename, probekey_file, logger)
    if user_creds == False: # Creating the user_creds instance has failed. Exit.
        print('Exiting...')
        exit()

    # Open an SSH session to the probe.
    client = open_ssh_session(user_creds, logger)
    if client == False: # Opening the SSH session to the probe has failed. Exit.
        print('Exiting...')
        exit()

    # Open a remote shell console session over the SSH connection and become the root user.
    rem_con = init_probe_console(logger, client)
    if rem_con == False: # Establishing the remote console session has failed. Exit.
        print('Exiting...')
        exit()

    # Run the localconsole menu on the remote probe and gather it's current settings.
    probe_configs_dict = gather_probe_configs(logger, rem_con)
    if probe_configs_dict == False:
        print('Closing the connection...')
        close_status = close_ssh_session(user_creds, client, rem_con, logger)
        if close_status == False: # Closing the SSH session to the probe has failed. Exit.
            print('Exiting...')
            exit()
        else:
            # We cannot continue. Exit anyway.
            exit()

    #pprint.pprint(f'\nprobe_configs_dict is {probe_configs_dict}', indent=4)
    # Create the config filename as 'probe IP' + 'probe_config_backup_' + a date-time string.
    now = datetime.now()
    date_time = now.strftime("%Y_%m_%d_%H%M%S")
    probe_ipv4 = str(probe_configs_dict['agent_configs'][0]['IP V4 address']) # Get the IP addr of the probe.
    probe_ipv4 = probe_ipv4.replace('.', '_') # Replace dots with underscores so we have a valid filename.
    config_filename = probe_ipv4 + '_' 'probe_config_backup_' + str(date_time) + '.json'
    # Backup the finished configs dictionary to a json file.
    write_status = write_config_to_json(config_filename, probe_configs_dict, logger)
    if write_status == False: # Writing the probe config to a json file has failed. Exit.
        print('Exiting...')
        exit()

    # Close the SSH session to the probe.
    close_status = close_ssh_session(user_creds, client, rem_con, logger)
    if close_status == False: # Closing the SSH session to the probe has failed. Exit.
        print('Exiting...')
        exit()
    else:
        # We are done. Exit anyway.
        exit()

if __name__ == "__main__":
    main()
