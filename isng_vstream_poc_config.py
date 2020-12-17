"""ISNG / vStream POC configurator

This script allows the user to configure either a NetScout Infinistream (ISNG) or
a virtual Infinistream (vStream) with all the typical settings that would be needed
to conduct a Proof of Concept (POC).

It is assumed that this utility will be installed directly on the nGeniusONE CentOS-REL
operating system, although it can be installed on Windows, MAC or other Linux OSes.

A remote SSH connection is made to an ISNG/vStream (the probe) and the current configuration is queried
by using the localconsole script command line and menu functions. The current configuration is backed up
to a .json file in the local directory. Then modifications are made to the probe's configuration to
better match what is needed in the case of a POC with SPAN traffic sources. It is presumed that UC is
also desired to be switched on.

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
            The hostname of the probe.
        probeport : str
            The port to use for the SSH connection.
        probeusername : str
            The SSH username.
        probepassword : str
            The SSH password.
        use_ssh_keyfile : bool
            Use a keyfile or not for the SSH connection.
        probe_ssh_keyfile : str
            The filename (include the path) of the SSH key file.
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

def spinning_cursor():
    """Rotates through spinning cursor characters to print to stdout.
    :yield: Then next cursor character to print.
    """
    while True:
        for cursor in '|/-\\':
            yield cursor

def display_spinner(spinner, timer):
    """Show that we are making progress during a long wait time versus appearing as if we are locked up.
    :spinner: An object that holds the spinning cursor characters.
    """

    while timer > 0:
        sys.stdout.write(next(spinner)) # Display a spinning cursor so they know we are not locked up.
        sys.stdout.flush()
        time.sleep(1)
        sys.stdout.write('\b')
        sys.stdout.flush()
        timer -= 1

def create_logging_function(log_filename):
    """Creates the logging function and specifies a log file to write to.
    Use this option to log to stdout and stderr using systemd (import os):
    logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
    :param log_filename: A string that is the name of the logfile to write to in the same directory.
    :return: The logger instance if successfully completed, false if not successful.
    """
    now = datetime.now()
    date_time = now.strftime("%Y_%m_%d_%H%M%S") # Used for timestamping filenames.

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
    """Read in the encrypted user or user-token credentials from a local CredFile.ini file.
    Decrypt the credentials and place all the user credentials attributes into a user_creds instance.
    :param cred_filename: A string that is the name of the cred_filename to read in.
    :param probekey_file: A string that is the name of the probe's key file to read in.
    :return: If successful, return the user_creds as a class instance that contains all the params needed to
    log into the probe via SSH.
    """
    # Create a user_creds instance to hold our user credentials.
    user_creds = Credentials()
    # Retrieve the decrypted credentials that we will use to open a session to the probe.
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
    Opens an SSH session to the probe using the paramiko module.
    :param user_creds: A class instance that contains all the necessary SSH connection parameters.
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
        client.connect(hostname=hostname, username=username, password=password, pkey=pkey, timeout=timeout, port=port)
        print(f'[INFO] Open SSH connection to: {hostname} Successful.')
        logger.info(f'[INFO] Open SSH connection to: {hostname} Successful.')
        #client.connect(hostname,username,pkey=none,key_filename='id_rsa',look_for_keys=True)
        return client
    except:
        print(f'[CRITICAL] Unable to open SSH connection to: {hostname}.')
        logger.critical(f'[CRITICAL] Unable to open SSH connection to: {hostname}.')
        return False

def execute_single_command_on_remote(command, rem_con, logger):
    """
    Sends a single console command to the probe and returns the result.
    :command: A string that contains the command with an new line char at the end to simulate
    hitting the enter key.
    :rem_con: A class instance of invoke_shell that opens a remote console shell over SSH.
    :return: The output string that was returned from the console as a result of the command.
    """
    print(f'[INFO] Executing command: {command}')
    logger.info(f'[INFO] Executing command: {command}')
    try:
        while not rem_con.send_ready(): # Wait for send ready status before sending a command.
            time.sleep(0.5)
        rem_con.send(command) # Send the command string to the remote console shell.
        while not rem_con.recv_ready(): # Wait for the first byte to come into the buffer before starting the sleep timer.
            time.sleep(0.5)
        time.sleep(2)
        output = rem_con.recv(2048) # Pull down the receive buffer from the remote console to a limit of 2048 bytes.
        output = output.decode("utf-8") # Output comes back as a file-like binary object. Decode to a string.
    except:
        print(f'[ERROR] Execute single command: {command} over the SSH shell has failed')
        logger.error(f'[ERROR] Execute single command: {command} over the SSH shell has failed')
        return False
    return output

def init_probe_console(logger, client):
    """
    Sends commands to the SSH client to establish a console object and set the user to su.
    :param client: The SSH client instance established with the probe.
    :param logger: An instance of logger so we can log messages.
    :return: rem_con, A class instance of invoke_shell that opens a remote console shell over SSH.
    """
    # Create the SSH shell instance.
    rem_con = client.invoke_shell()
    # turn off paging to supress echos.
    rem_con.send('terminal length 0\n')
    while rem_con.recv_ready() != True:
        time.sleep(0.25)
    time.sleep(1)
    output = rem_con.recv(1000) # Pass in the buffer size in bytes
    output = output.decode("utf-8") # Output comes back as a file-like object. Decode to a string.
    if 'Last login:' not in output:
        print('[ERROR] SSH command invoke_shell failed')
        logger.error('[ERROR] SSH command invoke_shell failed.')
        return False

    command = "sudo su -\n"
    output = execute_single_command_on_remote(command, rem_con, logger)
    if "su:" in output or "sudo:" in output: # The sudo command has failed.
        print(f'[ERROR] Console command: {command[:-1]} failed')
        logger.error(f'[ERROR] Console command: {command} failed')
        return False
    elif output == False:
        print('Exiting...')
        sys.exit()

    return rem_con

def get_probe_options(config_attributes_list, index_counter, rem_con, old_probe_configs_dict, options_type, logger):
    """
    Query the probe for the current config parameters of a set of related options.
    The list of options returned by the probe will be used to fill in the attributes for the old_probe_configs_dict.
    :config_attributes_list: A list of attribute names to be entered into the old_probe_configs_dict.
    :interface_list: A list of probe monitor interface numbers that are available.
    :index_counter: An integer counter used to access each config element as we loop through the interfaces.
    :rem_con: An instance of the remote console shell session to the probe.
    :old_probe_configs_dict: A dictionary of all the probe configurations.
    :options_type: The name of the probe options that we want to fetch from the probe.
    :return: False if any command fails, The filled in old_probe_configs_dict if all commands pass.
    """
    formatted_options_configs = [] # create an empty list to hold the options settings returned by the probe.

    formatted_configs = [] # Initialize an empty list to hold the formatted configs prior to adding them to the dict.
    if options_type == 'agent_configs':
        command = "get agent\n"
    else:
        command = "get " + options_type + "\n"
    output = execute_single_command_on_remote(command, rem_con, logger)
    if output == False:
        print('Exiting...')
        sys.exit()
    options_configs = output.splitlines()
    for options_config in options_configs:
        options_config_split = options_config.split()
        options_config_new = " ".join(options_config_split)
        formatted_options_configs.append(options_config_new)

    #print(f'\nformatted_options_configs is: {formatted_options_configs}')
    for config_attribute in config_attributes_list:
        #print(f'config_attribute is: {config_attribute}')
        #print(f'old_probe_configs_dict is: {old_probe_configs_dict}')
        if options_type == 'http' and index_counter > 3: # Another inconsistency in the attribute string names. Include ' =' for http type.
            old_probe_configs_dict[options_type][0][config_attribute] = formatted_options_configs[index_counter].partition(config_attribute + ' = ')[2]
        else:
            old_probe_configs_dict[options_type][0][config_attribute] = formatted_options_configs[index_counter].partition(config_attribute + ' ')[2]
        index_counter += 1

    return old_probe_configs_dict

def get_probe_options_interface_specific(config_attributes_list, interface_list, index_counter, rem_con, old_probe_configs_dict, options_type, logger):
    """
    For each monitor interface, send a command the probe to get the specific settings passed in as config_attributes_list.
    The setting for each config attribute will be used to fill in the attributes for the old_probe_configs_dict.
    :config_attributes_list: A list of attribute names to be entered into the old_probe_configs_dict.
    :interface_list: A list of probe monitor interface numbers that are available.
    :index_counter: An integer counter used to access each config element as we loop through the interfaces.
    :rem_con: An instance of the remote console shell session to the probe.
    :old_probe_configs_dict: A dictionary of all the probe configurations.
    :options_type: In this case, interface_specific to indicate that we need send the query with the interface number included in the command.
    :return: False if any command fails, The filled in old_probe_configs_dict if all commands pass.
    """

    formatted_options_configs = [] # create an empty list to hold the options settings returned by the probe.
    loop_counter = index_counter # The index_counter is our starting point for the elements returned by get 'options_type'.
    interface_loop_counter = 0 # Needed to send get asi for the first interface, 'y' for each subsequent interface.
    la_burst_is_on = True # A flag to use when the config options change due to a setting being 'on'.
    for interface in interface_list:
        old_probe_configs_dict[options_type][0]['interface '+ interface] = [{}]
    for config_attribute in config_attributes_list:
        formatted_options_configs = [] # Reset the list each time we loop to the next config_attribute.
        for interface in interface_list:
            formatted_options_configs = [] # For each interface, reset formatted_options_configs to an empty list
            command = "get " + config_attribute + " " + interface + "\n"
            #print(f'\ncommand is: {command}')
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                print('Exiting...')
                sys.exit()
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
                old_probe_configs_dict[options_type][0]['interface '+ interface][0][config_attribute] = 'on'
            else:
                old_probe_configs_dict[options_type][0]['interface '+ interface][0][config_attribute] = 'off'
    return old_probe_configs_dict

def get_probe_options_per_interface(config_attributes_list, interface_list, index_counter, rem_con, old_probe_configs_dict, options_type, logger):
    """
    For each monitor interface, send a command the probe to get the whole options list.
    The list of options returned by the probe will be used to fill in the attributes for the old_probe_configs_dict.
    :config_attributes_list: A list of attribute names to be entered into the old_probe_configs_dict.
    :interface_list: A list of probe monitor interface numbers that are available.
    :index_counter: An integer counter used to access each config element as we loop through the interfaces.
    :rem_con: An instance of the remote console shell session to the probe.
    :old_probe_configs_dict: A dictionary of all the probe configurations.
    :options_type: The name of the probe options that we want to fetch from the probe.
    :return: False if any command fails, The filled in old_probe_configs_dict if all commands pass.
    """

    formatted_options_configs = [] # create an empty list to hold the options settings returned by the probe.
    loop_counter = index_counter # The index_counter is our starting point for the elements returned by get 'options_type'.
    interface_loop_counter = 0 # Needed to send get asi for the first interface, 'y' for each subsequent interface.
    la_burst_is_on = True # A flag to use when the config options change due to a setting being 'on'.
    for interface in interface_list:
        old_probe_configs_dict[options_type][0]['interface '+ interface] = [{}]

    for interface in interface_list:
        config_counter = index_counter# Reset the index to what was passed into the function.
        if options_type != 'asi': # Get asi does not use set curr_interface, you must hit enter to advance.
            command = "set curr_interface " + interface +" \n"
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                print('Exiting...')
                sys.exit()

        formatted_options_configs = []
        #print(f'\noptions_type is: {options_type}')
        #print(f'\ninterface_loop_counter is: {interface_loop_counter}')
        if options_type == 'asi' and interface_loop_counter > 0:
            command = "\n" # Send the yes response to get asi on the next interface
        else:
            command = "get " + options_type + "\n"
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            print('Exiting...')
            sys.exit()
        options_configs = output.splitlines()
        for options_config in options_configs:
            options_config_split = options_config.split()
            options_config_new = " ".join(options_config_split)
            formatted_options_configs.append(options_config_new)
        # print(f'\nformatted_options_configs is: {formatted_options_configs}')
        for config_attribute in config_attributes_list:
            #print(f'loop_counter is: {loop_counter}')
            #print(f'\nconfig_attribute is: {config_attribute}')
            if la_burst_is_on == False: # The menu is dynamic. If la_burst is on, there will be an extra element la_type.
                if config_attribute == 'la_type':
                    la_burst_is_on = True # Reset the la_burst_is_on flag to True in case the next interface has it set to on.
                    continue # If the la_burst is off, and this loop config_attribute is is 'la_type, skip to the next valid attribute.
                else:
                    continue # If the la_burst is off, then skip the next config_attribute 'la_type'.
            old_probe_configs_dict[options_type][0]['interface '+ interface][0][config_attribute] = formatted_options_configs[loop_counter].partition(config_attribute + ' ')[2]
            if config_attribute == 'la_burst': # Check the setting for 'la_burst' for this interface that we just set.
                if old_probe_configs_dict[options_type][0]['interface '+ interface][0][config_attribute] == 'off':
                    la_burst_is_on = False # If la_burst is off for this interface, then set the flag to False.

            loop_counter += 1 # Increment the formatted_options_configs index number we use for each config_attribute loop.
        if options_type == 'asi': # The menu for the first interface on get asi has two extra elements.
            loop_counter = 2 # The subsequent interface menus have valid data starting at the third element.
        else:
            loop_counter = index_counter # Reset the counter to the right formatted_options_configs index number starting point that was passed in.
        interface_loop_counter += 1 # Increment the interface loop counter to account for 'get asi' interactive menu.

    if options_type == 'asi': # The final menu page prints out the V4 and V6 community masks.
        command = "\n" # Send the yes <enter> response to 'get asi' to end the menu and return to the command line prompt.
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            print('Exiting...')
            sys.exit()
        command = "\n" # Send the yes <enter> response to 'get asi' to end the menu and return to the command line prompt.
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            print('Exiting...')
            sys.exit()

    return old_probe_configs_dict

def get_probe_options_non_interface_specific(config_attributes_list, index_counter, rem_con, old_probe_configs_dict, options_type, logger):
    """
    For each config attribute, send a command the probe to get the specific probe-wide non-interface specific settings.
    The setting for each config attribute will be used to fill in the attributes for the old_probe_configs_dict.
    :config_attributes_list: A list of attribute names to be entered into the old_probe_configs_dict.
    :index_counter: An integer counter used to access each config element as we loop through the interfaces.
    :rem_con: An instance of the remote console shell session to the probe.
    :old_probe_configs_dict: A dictionary of all the probe configurations.
    :options_type: In this case, interface_non_specific to indicate that we need send one command for each config attribute.
    :return: False if any command fails, The filled in old_probe_configs_dict if all commands pass.
    """
    for config_attribute in config_attributes_list:
        formatted_options_configs = [] # Reset the list each time we loop to the next config_attribute.
        command = "get " + config_attribute + "\n"
        #print(f'\ncommand is: {command}')
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            print('Exiting...')
            sys.exit()
        options_configs = output.splitlines()

        for options_config in options_configs:
            #print(f'\noptions_config is: {options_config}')
            options_config_split = options_config.split()
            #print(f'\noptions_config_split is: {options_config_split}')
            options_config_new = " ".join(options_config_split)
            #print(f'\noptions_config_new is: {options_config_new}')
            formatted_options_configs.append(options_config_new)
        # print(f'\nformatted_options_configs is: {formatted_options_configs}')
        if config_attribute == 'config_download':
            config_attribute_verbose = formatted_options_configs[index_counter].partition('config_download : ')[2].lower()
        elif config_attribute == 'probe_mode':
            config_attribute_verbose = formatted_options_configs[index_counter].partition('Probe Mode : ')[2].lower()
        elif config_attribute == 'vq payload':
            config_attribute_verbose = formatted_options_configs[index_counter].partition('vq payload: ')[2].lower()
        elif config_attribute == 'asi_mode':
            config_attribute_verbose = formatted_options_configs[index_counter].partition('asi_mode is currently set to ')[2].lower()
        #print(f'\nconfig_attribute_verbose is: {config_attribute_verbose}')
        old_probe_configs_dict[options_type][0][config_attribute] = config_attribute_verbose
    return old_probe_configs_dict

def get_probe_options_single_command_multi_interface(config_attributes_list, interface_list, index_counter, rem_con, old_probe_configs_dict, options_type, logger):
    """
    This is another example of how get <setting> returns a wildly different format from other get commands.
    In this case a single get command returns a list of each setting for each interface.
    The list of options returned by the probe will be used to fill in the attributes for the old_probe_configs_dict.
    :config_attributes_list: A list of attribute names to be entered into the old_probe_configs_dict.
    :interface_list: A list of probe monitor interface numbers that are available.
    :index_counter: An integer counter used to access each config element as we loop through the interfaces.
    :rem_con: An instance of the remote console shell session to the probe.
    :old_probe_configs_dict: A dictionary of all the probe configurations.
    :options_type: The name of the probe options that we want to fetch from the probe.
    :return: False if any command fails, The filled in old_probe_configs_dict if all commands pass.
    """
    for config_attribute in config_attributes_list:
        formatted_options_configs = [] # Start with an empty list.
        loop_counter = index_counter # This is the starting point for reading elements from the formatted_options_configs.
        command = "get " + config_attribute + "\n" # One command returns a list of interface settings to parse through.
        #print(f'\ncommand is: {command}')
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            print('Exiting...')
            sys.exit()
        options_configs = output.splitlines()
        for options_config in options_configs:
            options_config_split = options_config.split()
            options_config_new = " ".join(options_config_split)
            formatted_options_configs.append(options_config_new)
        #print(f'\nformatted_options_configs is: {formatted_options_configs}')
        for interface in interface_list: # In this case, loop through each line returned for each interface.
            old_probe_configs_dict[options_type][0]['interface '+ interface][0][config_attribute] = formatted_options_configs[loop_counter].partition(interface + ' ')[2]
            loop_counter += 1 # Increment the formatted_options_configs index number we use for each config_attribute loop.

    return old_probe_configs_dict

def do_agent_reset(command, rem_con, logger):
    """
    Sends to the remote console either a 'y' yes to respond to a reset agent confirmation message from
    the localconsole menu, or a 'do reset' command if not responding to a reset agent prompt from localconsole.
    :command: Either 'y\n' if responding to a prompt or 'do reset\n' if not responding to a prompt.
    :rem_con: An instance of the remote console shell session to the probe.
    :return: False if any command fails, True if the agent resets and we get the localconsole menu back.
    """
    spinner = spinning_cursor() # Initialize a spinner object for long wait times.

    print(f'[INFO] Resetting the probe agent, please wait...')

    if command == "y\n": # We are responding to a prompt, check for the expected output
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            return False
        if 'Rebooting after 5 secs' not in output:
            return False
    if command == 'do reset\n': # You have to enter a confirmation after sending a 'do reset' command.
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            return False
        if 'WARNING : agent will be reset, confirm' not in output:
            return False
        command = "y\n"
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            return False
        if 'Rebooting after 5 secs' not in output:
            return False
    timer = 60 # We will wait 60 seconds for the probe agent to reset.
    display_spinner(spinner, timer)

    while True:
        print('\nWe are trying to get back into localconsole following an agent reset')
        command = "localconsole\n" # Following an agent reset, you have to launch localconsole again.
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            return False
        elif 'Error connecting to server:: Connection refused' in output:
            timer = 30 # We will wait 30 seconds for the localconsole to become available.
            display_spinner(spinner, timer) # Wait a little longer and try again.
            print('\r ', end="") # Erase the last spinner character and return the cursor to home.
            continue
        elif 'History file:' in output and 'Error connecting to server:: Connection refused' not in output:
            break # We successfully entered the localconsole menu. Break.
        else:
            return False

    while True:
        print('\nWe are trying to get back into localconsole command line mode following an agent reset')
        command = "11\n" # Enter the command line mode in localconsole.
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            return False
        elif 'Enter "quit" to exit command-line mode' in output: # We successfully entered command line mode. Break.
            break
        elif 'Please wait while the agent is coming up' in output:
            command = "\n" # Press enter to continue.
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                return False
            timer = 60 # We will wait 30 seconds for the probe agent to finish its reset.
            display_spinner(spinner, timer) # Wait a little longer and try again.
            print('\r ', end="") # Erase the last spinner character and return the cursor to home.
            continue # Wait a little longer and try again.
        else:
            return false # We did not get the expected response

    return True

def set_probe_options_interface_specific(config_attributes_list, old_probe_configs_dict, interface_list, rem_con, logger):
    """
    For each monitor interface, set the asi config parameters to match the desired POC settings.
    :interface_list: A list of probe monitor interface numbers that are available.
    :rem_con: An instance of the remote console shell session to the probe.
    :old_probe_configs_dict: A dictionary of all the probe configurations.
    :return: False if any command fails, True if all commands pass.
    """

    # We should already be in the command line entry mode within the localconsole menu.
    for interface in interface_list:
        for config_attribute in config_attributes_list:
            if config_attribute == 'kti_peak_type':
                if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['kti_peak_type'] != 'octet':
                    command = 'set asi ' + interface + ' kti_peak_type octet' + "\n"
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if '%' not in output: # The response to the set asi command is not the expected '%'.
                        return False
            elif config_attribute == 'kti_peak_interval':
                if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['kti_peak_interval'] != '100000':
                    command = 'set asi ' + interface + ' kti_peak_interval 100000' + "\n"
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if '%' not in output: # The response to the set asi command is not the expected '%'.
                        return False
            elif config_attribute == 'ksi_mtu_size':
                if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['ksi_mtu_size'] != '1518':
                    command = 'set asi ' + interface + ' ksi_mtu_size 1518' + "\n"
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if '%' not in output: # The response to the set asi command is not the expected '%'.
                        return False
            elif config_attribute == 'uc_conv':
                if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['uc_conv'] != 'on':
                    command = 'set asi ' + interface + ' uc_conv on' + "\n"
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if '%' not in output: # The response to the set asi command is not the expected '%'.
                        return False
            elif config_attribute == 'server_table':
                if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['server_table'] != 'on':
                    command = 'set asi ' + interface + ' server_table on' + "\n"
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if '%' not in output: # The response to the set asi command is not the expected '%'.
                        return False
            elif config_attribute == 'disc_table':
                if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['disc_table'] != 'on':
                    command = 'set asi ' + interface + ' disc_table on' + "\n"
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if '%' not in output: # The response to the set asi command is not the expected '%'.
                        return False
            elif config_attribute == 'vital_table':
                if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['vital_table'] != 'on':
                    command = 'set asi ' + interface + ' vital_table on' + "\n"
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if '%' not in output: # The response to the set asi command is not the expected '%'.
                        return False
            elif config_attribute == 'tcp_monitor':
                if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['tcp_monitor'] != 'on':
                    command = 'set asi ' + interface + ' tcp_monitor on' + "\n"
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if '%' not in output: # The response to the set asi command is not the expected '%'.
                        return False
            elif config_attribute == 'conv':
                if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['conv'] != 'off':
                    command = 'set asi ' + interface + ' conv off' + "\n"
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if '%' not in output: # The response to the set asi command is not the expected '%'.
                        return False
            elif config_attribute == 'conv ports':
                if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['conv ports'] != 'off':
                    command = 'set asi ' + interface + ' conv ports off' + "\n"
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if '%' not in output: # The response to the set asi command is not the expected '%'.
                        return False
            elif config_attribute == 'conv qos':
                if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['conv qos'] != 'off':
                    command = 'set asi ' + interface + ' conv qos off' + "\n"
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if '%' not in output: # The response to the set asi command is not the expected '%'.
                        return False
            elif config_attribute == 'la_burst':
                if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['la_burst'] != 'on':
                    command = 'set asi ' + interface + ' la_burst site' + "\n"
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if '%' not in output: # The response to the set asi command is not the expected '%'.
                        return False
            elif config_attribute == 'host_activity':
                if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['host_activity'] != 'off':
                    command = 'set asi ' + interface + ' host_activity off' + "\n"
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if '%' not in output: # The response to the set asi command is not the expected '%'.
                        return False
            elif config_attribute == 'htt':
                if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['htt'] != 'off':
                    command = 'set asi ' + interface + ' htt off' + "\n"
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if '%' not in output: # The response to the set asi command is not the expected '%'.
                        return False
            elif config_attribute == 'ksi 1min':
                if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['ksi 1min'] != 'on':
                    command = 'set asi ' + interface + ' ksi 1min on' + "\n"
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if '%' not in output: # The response to the set asi command is not the expected '%'.
                        return False
            elif config_attribute == 'ksi client_ip':
                if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['ksi client_ip'] != 'on':
                    command = 'set asi ' + interface + ' ksi client_ip on' + "\n"
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if 'WARNING: client_ip on will disable ASI_CONV and HOST_ACTIVITY' not in output: # The response to the set asi command is not the expected '%'.
                        return False
            elif config_attribute == 'subscriber':
                if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['subscriber'] != 'off':
                    command = 'set asi ' + interface + ' subscriber off' + "\n"
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if '%' not in output: # The response to the set asi command is not the expected '%'.
                        return False
            elif config_attribute == '1-min':
                if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['1-min'] != 'on':
                    command = 'set asi ' + interface + ' 1-min on' + "\n"
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if '%' not in output: # The response to the set asi command is not the expected '%'.
                        return False
            elif config_attribute == '15-sec':
                if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['15-sec'] != 'on':
                    command = 'set asi ' + interface + ' 15-sec on' + "\n"
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if '%' not in output: # The response to the set asi command is not the expected '%'.
                        return False
            elif config_attribute == 'url_disc_table':
                if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['url_disc_table'] != 'on':
                    command = 'set asi ' + interface + ' url_disc_table on' + "\n"
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if '%' not in output: # The response to the set asi command is not the expected '%'.
                        return False

    return True

def set_probe_options_per_interface(config_attributes_list, old_probe_configs_dict, interface_list, rem_con, logger):
    """
    For each monitor interface, set the interface options config parameters to match the desired POC settings.
    :interface_list: A list of probe monitor interface numbers that are available.
    :rem_con: An instance of the remote console shell session to the probe.
    :old_probe_configs_dict: A dictionary of all the probe configurations.
    :return: False if any command fails, True if all commands pass.
    """

    command = "quit\n" # Exit the command line menu to the main menu
    output = execute_single_command_on_remote(command, rem_con, logger)
    #print(f'\noutput is: {output}')
    if output == False:
        return False
    if 'Probe IP V4 address' not in output: # We did not enter the localconsole menu correctly.
        return False

    command = "7\n" # We need to get to the list of interfaces menu.
    output = execute_single_command_on_remote(command, rem_con, logger) # Send option 7 to the localconsole menu.
    #print(f'\noutput is: {output}')
    if output == False:
        return False
    if 'Select Interface :' not in output: # We did not enter the interface menu correctly.
        return False

    for interface in interface_list:
        command = str(interface + '\n') # Select the interface to configure by sending the interface number.
        output = execute_single_command_on_remote(command, rem_con, logger) # Send option 7 to the localconsole menu.
        #print(f'\noutput is: {output}')
        if output == False:
            return False
        if 'Interface Options Menu:' not in output: # We did not enter the interface options menu correctly.
            return False
        for config_attribute in config_attributes_list:

            if config_attribute == 'power_alarm_util':
                if old_probe_configs_dict['interface_options'][0]['interface ' + str(interface)][0]['power_alarm_util'] != 'off':
                    command = "2\n" # Toggle the power_alarm_util setting.
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if 'Interface Options Menu:' not in output:
                        return False
            elif config_attribute == 'power_alarm_resp':
                if old_probe_configs_dict['interface_options'][0]['interface ' + str(interface)][0]['power_alarm_resp'] != 'off':
                    command = "3\n" # Toggle the power_alarm_resp setting.
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if 'Interface Options Menu:' not in output:
                        return False
            elif config_attribute == 'admin_shutdown':
                if old_probe_configs_dict['interface_options'][0]['interface ' + str(interface)][0]['admin_shutdown'] != 'off':
                    command = "5\n" # Toggle the admin_shutdown setting.
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if 'Interface Options Menu:' not in output:
                        return False
            elif config_attribute == 'Data w/o Control Tcm':
                if old_probe_configs_dict['interface_options'][0]['interface ' + str(interface)][0]['Data w/o Control Tcm'] != 'off':
                    command = "10\n" # Toggle the Data w/o Control Tcm setting.
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if 'Interface Options Menu:' not in output:
                        return False
            elif config_attribute == 'vifn_enable':
                if old_probe_configs_dict['interface_options'][0]['interface ' + str(interface)][0]['vifn_enable'] != 'on':
                    command = "34\n" # Toggle the vifn_enable setting.
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if 'Interface Options Menu:' not in output:
                        return False
            elif config_attribute == 'vifn_mode':
                if old_probe_configs_dict['interface_options'][0]['interface ' + str(interface)][0]['vifn_mode'] != 'vlan-site-qos':
                    command = "36\n" # Enter the vifn_mode menu.
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if 'Select vifn_mode:' not in output:
                        return False
                    command = "38\n" # Enter the vlan-site-qos as the vifn_mode.
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if 'Interface Options Menu:' not in output: # localconsole returns us to the interface options menu.
                        return False
            elif config_attribute == 'HTTP Mode':
                if old_probe_configs_dict['interface_options'][0]['interface ' + str(interface)][0]['HTTP Mode'] != 'Monitor URL Only':
                    command = "45\n" # Enter the HTTP Mode menu.
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if 'Select HTTP Mode:' not in output:
                        return False
                    command = "1\n" # Select Monitor URL Only.
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if 'Interface Options Menu:' not in output:
                        return False
            elif config_attribute == 'M3UA Table':
                if old_probe_configs_dict['interface_options'][0]['interface ' + str(interface)][0]['M3UA Table'] != 'off':
                    command = "52\n" # Toggle the M3UA Table setting.
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if 'Interface Options Menu:' not in output:
                        return False
            elif config_attribute == 'enable xDR':
                if old_probe_configs_dict['interface_options'][0]['interface ' + str(interface)][0]['enable xDR'] != 'on':
                    command = "53\n" # Toggle the enable xDR setting.
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if 'Interface Options Menu:' not in output:
                        return False
            elif config_attribute == 'Tunnel Parsing':
                if old_probe_configs_dict['interface_options'][0]['interface ' + str(interface)][0]['Tunnel Parsing'] != 'off':
                    command = "54\n" # Toggle the Tunnel Parsing setting.
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if 'Interface Options Menu:' not in output:
                        return False
            elif config_attribute == 'interface type':
                if old_probe_configs_dict['interface_options'][0]['interface ' + str(interface)][0]['interface type'] != 'Enterprise':
                    command = "55\n" # Enter the interface type menu.
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if 'Select interface type:' not in output:
                        return False
                    command = "1\n" # Select Enterprise type.
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if 'Interface Options Menu:' not in output:
                        return False
            elif config_attribute == 'Data w/o Control':
                if old_probe_configs_dict['interface_options'][0]['interface ' + str(interface)][0]['Data w/o Control'] != 'off':
                    command = "54\n" # Toggle the Data w/o Control setting.
                    output = execute_single_command_on_remote(command, rem_con, logger)
                    #print(f'\noutput is: {output}')
                    if output == False:
                        return False
                    if 'Interface Options Menu:' not in output:
                        return False
        command = "99\n" # We need to get back to the list of interfaces menu.
        output = execute_single_command_on_remote(command, rem_con, logger) # Send option 7 to the localconsole menu.
        #print(f'\noutput is: {output}')
        if output == False:
            return False
        if 'Select Interface :' not in output: # We did not enter the interface list menu correctly.
            return False

    command = "99\n" # Exit the interfaces list menu back up to the main menu
    output = execute_single_command_on_remote(command, rem_con, logger)
    #print(f'\noutput is: {output}')
    if output == False:
        return False
    if 'Probe IP V4 address' not in output: # We did not enter the localconsole menu correctly.
        return False

    command = "11\n" # Enter the command line mode in localconsole.
    output = execute_single_command_on_remote(command, rem_con, logger)
    if output == False:
        return False
    if 'Enter "quit" to exit command-line mode' not in output: # We did not enter command line mode.
        return False

    return True

def set_probe_options_non_interface_specific(old_probe_configs_dict, rem_con, logger):
    """
    Set the major, probe-wide non-interface specific settings. Do agent resets as needed.
    :rem_con: An instance of the remote console shell session to the probe.
    :old_probe_configs_dict: A dictionary of all the probe configurations.
    :return: False if any command fails, True if all commands pass.
    """

    reset_agent_command = ''
    if old_probe_configs_dict['non_interface_specific'][0]['vq payload'] != 'on':
        command = "set vq payload on\n"
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            return False
        if 'vq payload will be updated on next reset' not in output:
            return False
        reset_agent_command = 'do reset\n' # Not a prompt to reset agent, so we will do it after table size allocation.

    if old_probe_configs_dict['non_interface_specific'][0]['config_download'] != 'off':
        command = "set config_download off\n"
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            return False

    if old_probe_configs_dict['non_interface_specific'][0]['asi_mode'] != 'asi':
        command = "set asi_mode ASI\n"
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            return False
        if "Please rerun 'set table_size_allocation commit' to ensure correct table sizes" not in output:
            return False
        reset_agent_command = 'do reset\n' # Need to reallocate interface table sizes before reset.

    if old_probe_configs_dict['non_interface_specific'][0]['probe_mode'] != 'half-duplex':
        command = "set probe_mode hdx\n"
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            return False
        if 'Warning: This will delete all existing flows and reboot the probe!!' not in output:
            return False
        command = "y\n"
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            return False
        if 'Warning: The table size allocation has been committed' not in output:
            return False
        reset_agent_command = 'y\n' # In this case you are prompted to reset the agent before coninuing.

    if reset_agent_command != '': # Skip the reset if none of the major settings needs to be modified.
        reset_status = do_agent_reset(reset_agent_command, rem_con, logger)
        if output == False:
            return False

    #command = "set tsa auto\n"
    #output = execute_single_command_on_remote(command, rem_con, logger)
    #if output == False:
        #return False
    #if "A commit and reset will be required before this setting takes effect" not in output:
        #return False
    #command = "set tsa commit\n"
    #output = execute_single_command_on_remote(command, rem_con, logger)
    #if output == False:
        #return False
    #if "Committed new table sizes" not in output:
        #return False
    #reset_agent_command = 'y\n' # In this case you are prompted to reset the agent before coninuing.
    #reset_status = do_agent_reset(reset_agent_command, rem_con, logger)
    #if output == False:
        #return False

    return True

def set_probe_software_options(config_attributes_list, old_probe_configs_dict, rem_con, logger):
    """
    Set the probe software options settings.
    :rem_con: An instance of the remote console shell session to the probe.
    :old_probe_configs_dict: A dictionary of all the probe configurations.
    :return: False if any command fails, True if all commands pass.
    """

    command = "8\n" # We need to get into the agent options menu.
    output = execute_single_command_on_remote(command, rem_con, logger) # Send option 8 to the localconsole menu.
    if output == False:
        return False
    if 'Software Options Menu:' not in output: # We did not enter the interface menu correctly.
        return False

    if old_probe_configs_dict['software_options'][0]['Response Time Monitor'] != 'on':
        command = "2\n" # Toggle the Response Time Monitor setting
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            return False
        if 'Software Options Menu:' not in output:
            return False

    if old_probe_configs_dict['software_options'][0]['NL and AL Host'] != 'on':
        command = "3\n" # Toggle the NL and AL Host setting
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            return False
        if 'Software Options Menu:' not in output:
            return False

    if old_probe_configs_dict['software_options'][0]['NL and AL Conversation'] != 'on':
        command = "4\n" # Toggle the NL and AL Conversation setting
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            return False
        if 'Software Options Menu:' not in output:
            return False

    if old_probe_configs_dict['software_options'][0]['SBA Priority'] != 'on':
        command = "13\n" # Toggle the NL and AL Conversation setting
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            return False
        if 'Software Options Menu:' not in output:
            return False

    command = "99\n" # Return to the main menu
    output = execute_single_command_on_remote(command, rem_con, logger)
    if output == False:
        return False
    if 'Probe IP V4 address' not in output: # We did not enter the localconsole menu correctly.
        return False

    return True

def set_probe_protocol_options(config_attributes_list, old_probe_configs_dict, rem_con, logger):
    """
    Set the probe protocol options settings.
    :rem_con: An instance of the remote console shell session to the probe.
    :old_probe_configs_dict: A dictionary of all the probe configurations.
    :return: False if any command fails, True if all commands pass.
    """

    command = "15\n" # We need to get into the protocol options menu.
    output = execute_single_command_on_remote(command, rem_con, logger) # Send option 15 to the localconsole menu.
    if output == False:
        return False
    if 'Protocol Options Menu:' not in output: # We did not enter the interface menu correctly.
        return False

    if old_probe_configs_dict['protocol_options'][0]['Pattern Matching'] != 'off':
        command = "2\n" # Toggle the Pattern Matching setting
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            return False
        if 'Protocol Options Menu:' not in output:
            return False

    if old_probe_configs_dict['protocol_options'][0]['CORBA'] != 'off':
        command = "3\n" # Toggle the CORBA setting
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            return False
        if 'Protocol Options Menu:' not in output:
            return False

    if old_probe_configs_dict['protocol_options'][0]['Conversation Port Discovery'] != 'on':
        command = "5\n" # Toggle the Conversation Port Discovery setting
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            return False
        if 'Protocol Options Menu:' not in output:
            return False

    if old_probe_configs_dict['protocol_options'][0]['Skype Pattern Matching'] != 'off':
        command = "8\n" # Toggle the Conversation Port Discovery setting
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            return False
        if 'Protocol Options Menu:' not in output:
            return False

    if old_probe_configs_dict['protocol_options'][0]['Extended FIS'] != 'off':
        command = "14\n" # Toggle the Extended FIS setting
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            return False
        if 'Protocol Options Menu:' not in output:
            return False

    if old_probe_configs_dict['protocol_options'][0]['Voice and Video Quality'] != 'on':
        command = "15\n" # Toggle the Extended FIS setting
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            return False
        if 'Protocol Options Menu:' not in output:
            return False

    command = "99\n" # Return to the main menu
    output = execute_single_command_on_remote(command, rem_con, logger)
    if output == False:
        return False
    if 'Probe IP V4 address' not in output: # We did not enter the localconsole menu correctly.
        return False

    return True

def set_probe_http_options(config_attributes_list, old_probe_configs_dict, rem_con, logger):
    """
    Set the probe protocol options settings.
    :rem_con: An instance of the remote console shell session to the probe.
    :old_probe_configs_dict: A dictionary of all the probe configurations.
    :return: False if any command fails, True if all commands pass.
    """

config_attributes_list = ['http web_classify', 'http db_type', 'http proxy_server_uri_search', 'http hsts',
                        'http my_nw_url_discovery', 'http parse_xcap', 'http parse_stir', 'http ssl_quic_subscr_info',
                        'http use_xff', 'http use_xff_multiple_clients', 'http use_client_ip_field',
                        'http use_x_true_client_ip', 'http use_x_real_ip_field']

    command = "11\n" # Enter the command line mode in localconsole.
    output = execute_single_command_on_remote(command, rem_con, logger)
    if output == False:
        return False
    if 'Enter "quit" to exit command-line mode' not in output: # We did not enter command line mode.
        return False

    if old_probe_configs_dict['http'][0]['http web_classify'] != 'off':
        command = "set http web_classify off\n" # Change the http web_classify setting
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            return False
        if '%:' not in output:
            return False


    command = "99\n" # Return to the main menu
    output = execute_single_command_on_remote(command, rem_con, logger)
    if output == False:
        return False
    if 'Probe IP V4 address' not in output: # We did not enter the localconsole menu correctly.
        return False

    return True


def set_probe_agent_options(config_attributes_list, old_probe_configs_dict, rem_con, logger):
    """
    Set the probe agent (not related to interfaces) specific settings.
    :rem_con: An instance of the remote console shell session to the probe.
    :old_probe_configs_dict: A dictionary of all the probe configurations.
    :return: False if any command fails, True if all commands pass.
    """

    command = "quit\n" # Exit the command line menu to the main menu
    output = execute_single_command_on_remote(command, rem_con, logger)
    if output == False:
        return False
    if 'Probe IP V4 address' not in output: # We did not enter the localconsole menu correctly.
        return False

    command = "9\n" # We need to get into the agent options menu.
    output = execute_single_command_on_remote(command, rem_con, logger) # Send option 7 to the localconsole menu.
    if output == False:
        return False
    if 'Agent Options Menu:' not in output: # We did not enter the interface menu correctly.
        return False

    if old_probe_configs_dict['agent_options'][0]['watchdog'] != 'on':
        command = "1\n" # Toggle the watchdog setting
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            return False
        if 'Agent Options Menu:' not in output:
            return False

    if old_probe_configs_dict['agent_options'][0]['auto_reboot'] != 'on':
        command = "6\n" # Toggle the auto_reboot setting
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            return False
        if 'Agent Options Menu:' not in output:
            return False

    if old_probe_configs_dict['agent_options'][0]['burst_advisor_peak'] != 'msec':
        command = "10\n" # Toggle the burst_advisor_peak setting
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            return False
        if 'Agent Options Menu:' not in output:
            return False

    if old_probe_configs_dict['agent_options'][0]['nGeniusONE Managed'] != 'on':
        command = "14\n" # Toggle the Infinistream nGeniusONE Managed setting
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            return False
        if 'Agent Options Menu:' not in output:
            return False

    if old_probe_configs_dict['agent_options'][0]['Health Monitoring'] != 'on':
        command = "16\n" # Toggle the Infinistream Health Monitoringsetting
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            return False
        if 'Agent Options Menu:' not in output:
            return False

    if old_probe_configs_dict['agent_options'][0]['Eth0 GRE Monitoring'] != 'off':
        command = "19\n" # Toggle the Infinistream Eth0 GRE Monitoring setting
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            return False
        if 'Agent Options Menu:' not in output:
            return False

    command = "99\n" # Return to the main menu
    output = execute_single_command_on_remote(command, rem_con, logger)
    if output == False:
        return False
    if 'Probe IP V4 address' not in output: # We did not enter the localconsole menu correctly.
        return False

    return True


def set_probe_configs(old_probe_configs_dict, interface_list, rem_con, logger):
    """
    Sends a series of commands to the remote console to set certain configurations to match what are
    considered best practice settings for a POC. The old_probe_configs_dict is used to see if the settings
    match the desired poc settings. If there is a delta, the probe configuration is modified until all
    the desired settings match what is in the probe. Depending on what needs to be set, there may be one
    or more agent reset operations.
    :rem_con: An instance of the remote console shell session to the probe.
    :old_probe_configs_dict: A dictionary of the current probe settings used to look for deltas to the
    desired poc settings.
    :return: False if any command fails, True if all settings are successfully modified to match the
    desired poc settings.
    """

    print('[INFO] Checking current config against the desired POC config settings...')
    logger.info('[INFO] Checking current config against the desired POC config settings...')

    command = "localconsole\n"
    output = execute_single_command_on_remote(command, rem_con, logger)
    if output == False:
        return False
    if 'Probe IP V4 address' not in output: # We did not enter the localconsole menu correctly.
        return False

    command = "11\n" # Enter the command line mode in localconsole.
    output = execute_single_command_on_remote(command, rem_con, logger)
    if output == False:
        return False
    if 'Enter "quit" to exit command-line mode' not in output: # We did not enter command line mode.
        return False
    print('\rSetting basic probe modes...', end="")
    set_status = set_probe_options_non_interface_specific(old_probe_configs_dict, rem_con, logger)
    if set_status == False: # A set operation has failed. Return False.
        return False

    config_attributes_list = ['power_alarm_util', 'power_alarm_resp', 'admin_shutdown', 'Data w/o Control Tcm',
                            'jumboframe_support', 'interface_speed', 'mib2_ifspeed', 'vifn_enable',
                            'vifn_discovery', 'vifn_mode', 'reverse_ports', 'HTTP Mode', 'M3UA Table',
                            'enable xDR', 'Tunnel Parsing', 'interface type', 'auxiliary interfaces', 'Data w/o Control',
                            'Interface Mode', 'Configure Tunnel Termination']
    print('\rSetting interface options configs...', end="")
    set_status = set_probe_options_per_interface(config_attributes_list, old_probe_configs_dict, interface_list, rem_con, logger)
    if set_status == False: # A set operation has failed. Return False.
        return False

    config_attributes_list = ['kti_peak_type', 'kti_peak_interval', 'ksi_mtu_size', 'uc_conv',
                            'server_table', 'disc_table', 'vital_table', 'tcp_monitor', 'conv',
                            'conv ports', 'conv qos', 'la_burst', 'la_type', 'host_activity',
                            'htt', 'ksi 1min', 'ksi client_ip', 'subscriber', '1-min', '15-sec',
                            'url_disc_table']
    print('\rSetting ASI configs...', end="")
    set_status = set_probe_options_interface_specific(config_attributes_list, old_probe_configs_dict, interface_list, rem_con, logger)
    if set_status == False: # A set operation has failed. Return False.
        return False

    config_attributes_list = ['watchdog', 'auto_reboot', 'timestamp_ns', 'burst_advisor_peak',
                            'Infinistream Console Support', 'Traffic Violations', 'nGeniusONE Managed',
                            'Health Monitoring', 'Eth0 GRE Monitoring', 'Network Analyzer Support']
    print('\rSetting probe agent options...', end="")
    set_status = set_probe_agent_options(config_attributes_list, old_probe_configs_dict, rem_con, logger)
    if set_status == False: # A set operation has failed. Return False.
        return False

    config_attributes_list = ['Response Time Monitor', 'NL and AL Host', 'NL and AL Conversation',
                            'SBA Priority']
    print('\rSetting probe software options...', end="")
    set_status = set_probe_software_options(config_attributes_list, old_probe_configs_dict, rem_con, logger)
    if set_status == False: # A set operation has failed. Return False.
        return False

    config_attributes_list = ['Pattern Matching', 'CORBA', 'Conversation Port Discovery',
                            'Skype Pattern Matching', 'Extended FIS', 'Voice and Video Quality']
    print('\rSetting probe protocol options...', end="")
    set_status = set_probe_protocol_options(config_attributes_list, old_probe_configs_dict, rem_con, logger)
    if set_status == False: # A set operation has failed. Return False.
        return False

    config_attributes_list = ['http web_classify', 'http db_type', 'http proxy_server_uri_search', 'http hsts',
                            'http my_nw_url_discovery', 'http parse_xcap', 'http parse_stir', 'http ssl_quic_subscr_info',
                            'http use_xff', 'http use_xff_multiple_clients', 'http use_client_ip_field',
                            'http use_x_true_client_ip', 'http use_x_real_ip_field']
    print('\rSetting probe http options...', end="")
    set_status = set_probe_http_options(config_attributes_list, old_probe_configs_dict, rem_con, logger)
    if set_status == False: # A set operation has failed. Return False.
        return False

    command = "12\n" # Reset the agent
    output = execute_single_command_on_remote(command, rem_con, logger)
    if output == False:
        return False
    if 'WARNING : agent will be reset, confirm [n]' not in output: # The expected response did not come back.
        return False

    reset_agent_command = 'y\n' # Respond to the confirmation prompt with a 'y'.
    reset_status = do_agent_reset(reset_agent_command, rem_con, logger)
    if output == False:
        return False

    return True

def gather_probe_configs(logger, rem_con):
    """
    Sends a series of commands to the remote console and gathers the responses for processing.
    The responses will be used to fill in the attributes for the old_probe_configs_dict.
    :rem_con: An instance of the remote console shell session to the probe.
    :return: False if any command fails, The filled in old_probe_configs_dict and the interface_list if all commands pass.
    """

    print('[INFO] Gathering current probe configurations...')
    logger.info('[INFO] Gathering current probe configurations...')

    #try:
    # Initialize an empty dictionary to hold our probe config params.
    old_probe_configs_dict = {'interface_options': [{}], 'agent_configs': [{}], 'agent_options': [{}], 'software_options': [{}],
                            'protocol_options': [{}], 'http': [{}], 'asi': [{}], 'interface_specific': [{}],
                            'non_interface_specific': [{}]}

    command = "localconsole\n"
    output = execute_single_command_on_remote(command, rem_con, logger)
    if output == False:
        print('Exiting...')
        sys.exit()
    output = ""
    command = "7\n" # We need to know what interfaces exist on this probe.
    print('\rGetting Interfaces...', end="")
    output = execute_single_command_on_remote(command, rem_con, logger) # Send option 7 to the localconsole menu.
    if output == False:
        print('Exiting...')
        sys.exit()
    interface_list = [] # Initialize an empty list to put our available monitor interfaces into.
    interface_configs = output.splitlines()
    for interface_config in interface_configs:
        interface_config_split = interface_config.split()
        interface_config_new = " ".join(interface_config_split)
        if '[99] Go Back to Main Menu' in interface_config_new: # We are at the end of the page. Break.
            break
        if '-ETHERNET' in interface_config_new: # Add the interface number to the list of monitor interfaces.
            interface_list.append(interface_config_new[1:3].strip())

    command = "99\n" # Return to the main localconsole menu page.
    output = execute_single_command_on_remote(command, rem_con, logger)
    if output == False:
        print('Exiting...')
        sys.exit()

    command = "11\n" # Enter the command line mode in localconsole.
    output = execute_single_command_on_remote(command, rem_con, logger)
    if output == False:
        print('Exiting...')
        sys.exit()

    # Difficult not to hard code these lists of attribute names as the names are not consistent in...
    # the probe itself as to underscores or spaces or how many words are in the attribute name.
    config_attributes_list = ['power_alarm_util', 'power_alarm_resp', 'admin_shutdown', 'Data w/o Control Tcm',
                            'jumboframe_support', 'interface_speed', 'mib2_ifspeed', 'vifn_enable',
                            'vifn_discovery', 'vifn_mode', 'reverse_ports', 'HTTP Mode', 'M3UA Table',
                            'enable xDR', 'Tunnel Parsing', 'interface type', 'auxiliary interfaces', 'Data w/o Control',
                            'Interface Mode', 'Configure Tunnel Termination']
    index_counter = 4 # The starting index of the first valid element in formatted_interface_configs.
    options_type = 'interface_options'
    print("\r                                             ", end='') # Clear the progress print line before we return.
    print('\rGetting Interface Options...', end="")
    # Get the whole list of interface options settings for each monitor interface and add them to the old_probe_configs_dict.
    old_probe_configs_dict = get_probe_options_per_interface(config_attributes_list, interface_list, index_counter, rem_con, old_probe_configs_dict, options_type, logger)

    config_attributes_list = ['model_number', 'software_version', 'link time', 'memory size', 'nvram_version',
                            'nvram size', 'agent_location', 'agent_contact', 'agent_name', 'read_community',
                            'write_community', 'Probe Communication Mode', 'IP V4 address', 'MAC Address',
                            'config_server', 'serial_number', 'nsprobe_type', 'kernel']
    index_counter = 2 # The starting index of the first valid element in formatted_interface_configs.
    options_type = 'agent_configs'
    print("\r                                             ", end='') # Clear the progress print line before we return.
    print('\rGetting Agent Configs...', end="")
    # Get the whole list of probe agent configs settings and add them to the old_probe_configs_dict.
    old_probe_configs_dict = get_probe_options(config_attributes_list, index_counter, rem_con, old_probe_configs_dict, options_type, logger)

    config_attributes_list = ['watchdog', 'auto_reboot', 'timestamp_ns', 'burst_advisor_peak',
                            'Infinistream Console Support', 'Traffic Violations', 'nGeniusONE Managed',
                            'Health Monitoring', 'Eth0 GRE Monitoring', 'Network Analyzer Support']
    index_counter = 4 # The starting index of the first valid element in formatted_interface_configs.
    options_type = 'agent_options'
    print("\r                                             ", end='') # Clear the progress print line before we return.
    print('\rGetting Agent Options...', end="")
    # Get the whole list of probe agent options settings and add them to the old_probe_configs_dict.
    old_probe_configs_dict = get_probe_options(config_attributes_list, index_counter, rem_con, old_probe_configs_dict, options_type, logger)

    config_attributes_list = ['Response Time Monitor', 'NL and AL Host', 'NL and AL Conversation',
                            'SBA Priority']
    index_counter = 2 # The starting index of the first valid element in formatted_interface_configs.
    options_type = 'software_options'
    print("\r                                             ", end='') # Clear the progress print line before we return.
    print('\rGetting Software Options...', end="")
    # Get the whole list of probe software options settings and add them to the old_probe_configs_dict.
    old_probe_configs_dict = get_probe_options(config_attributes_list, index_counter, rem_con, old_probe_configs_dict, options_type, logger)

    config_attributes_list = ['Pattern Matching', 'CORBA', 'Conversation Port Discovery',
                            'Skype Pattern Matching', 'Extended FIS', 'Voice and Video Quality']
    index_counter = 2 # The starting index of the first valid element in formatted_interface_configs.
    options_type = 'protocol_options'
    print("\r                                             ", end='') # Clear the progress print line before we return.
    print('\rGetting Protocol Options...', end="")
    # Get the whole list of protocol options settings and add them to the old_probe_configs_dict.
    old_probe_configs_dict = get_probe_options(config_attributes_list, index_counter, rem_con, old_probe_configs_dict, options_type, logger)

    config_attributes_list = ['http web_classify', 'http db_type', 'http proxy_server_uri_search', 'http hsts',
                            'http my_nw_url_discovery', 'http parse_xcap', 'http parse_stir', 'http ssl_quic_subscr_info',
                            'http use_xff', 'http use_xff_multiple_clients', 'http use_client_ip_field',
                            'http use_x_true_client_ip', 'http use_x_real_ip_field']
    index_counter = 2 # The starting index of the first valid element in formatted_interface_configs.
    options_type = 'http'
    print("\r                                             ", end='') # Clear the progress print line before we return.
    print('\rGetting HTTP...', end="")
    # Get the whole list of probe http settings and add them to the old_probe_configs_dict.
    old_probe_configs_dict = get_probe_options(config_attributes_list, index_counter, rem_con, old_probe_configs_dict, options_type, logger)

    config_attributes_list = ['kti_peak_type', 'kti_peak_interval', 'ksi_mtu_size', 'uc_conv',
                            'server_table', 'disc_table', 'vital_table', 'tcp_monitor', 'conv',
                            'conv ports', 'conv qos', 'la_burst', 'la_type', 'host_activity',
                            'htt', 'ksi 1min', 'ksi client_ip', 'subscriber', '1-min', '15-sec',
                            'url_disc_table']
    index_counter = 3 # The starting index of the first valid element in the formatted configs returned by the probe.
    options_type = 'asi'
    print("\r                                             ", end='') # Clear the progress print line before we return.
    print('\rGetting ASI...', end="")
    # Get the whole list of probe asi settings per interface and add them to the old_probe_configs_dict.
    old_probe_configs_dict = get_probe_options_per_interface(config_attributes_list, interface_list, index_counter, rem_con, old_probe_configs_dict, options_type, logger)

    config_attributes_list = ['skt_vlan_enable', 'span_duplicate', 'ssl_sni']
    index_counter = 2 # The starting index of the first valid element in the formatted configs returned by the probe.
    options_type = 'interface_specific'
    print("\r                                             ", end='') # Clear the progress print line before we return.
    print('\rGetting Interface Specific Options...', end="")
    # Get the whole list of probe interface specific settings and add them to the old_probe_configs_dict.
    old_probe_configs_dict = get_probe_options_interface_specific(config_attributes_list, interface_list, index_counter, rem_con, old_probe_configs_dict, options_type, logger)

    config_attributes_list = ['config_download', 'probe_mode', 'vq payload', 'asi_mode']
    index_counter = 2 # The starting index of the first valid element in the formatted configs returned by the probe.
    options_type = 'non_interface_specific'
    print("\r                                             ", end='') # Clear the progress print line before we return.
    print('\rGetting Non-Interface Specific Options...', end="")
    # Get each probe non-interface specific settings and add them to the old_probe_configs_dict.
    old_probe_configs_dict = get_probe_options_non_interface_specific(config_attributes_list, index_counter, rem_con, old_probe_configs_dict, options_type, logger)

    config_attributes_list = ['community_type']
    index_counter = 3 # The starting index of the first valid element in the formatted configs returned by the probe.
    options_type = 'interface_specific'
    print("\r                                             ", end='') # Clear the progress print line before we return.
    print('\rGetting Community Type...', end="")
    # Get each probe interface specific settings for each interface one-by-one and add them to the old_probe_configs_dict.
    old_probe_configs_dict = get_probe_options_single_command_multi_interface(config_attributes_list, interface_list, index_counter, rem_con, old_probe_configs_dict, options_type, logger)

    command = "quit\n"
    output = execute_single_command_on_remote(command, rem_con, logger)
    if output == False:
        print('Exiting...')
        sys.exit()

    command = "exit\n"
    output = execute_single_command_on_remote(command, rem_con, logger)
    if output == False:
        print('Exiting...')
        sys.exit()
    print("\r                                             ", end='') # Clear the progress print line before we return.
    return old_probe_configs_dict, interface_list

def write_config_to_json(config_filename, old_probe_configs_dict, logger):
    """
    Serialize the old_probe_configs_dict and write it out to a json file so we have a backup of the original config.
    :config_filename: The name of the json file that we want to save the probe configs to.
    :old_probe_configs_dict: The probe config dictionary that contains all the probe config settings.
    :return: False if any command fails, True if the config is successfully written to the json file.
    """

    # Backup the current probe configs by writing the old_probe_configs_dict to a json file.
    try:
        with open(config_filename,"w") as f:
            json.dump(old_probe_configs_dict, f)
            print(f'\r[INFO] Backing up the probe config to JSON file: {config_filename}')
            logger.info(f'[INFO] Backup the probe config to JSON file: {config_filename}')
    except IOError as e: # Handle file I/O errors.
        print(f'[ERROR] Unable to backup the probe config to the JSON config file: {config_filename}')
        logger.error(f'[ERROR] Unable to backup the probe config to the JSON config file: {config_filename}')
        print("I/O error({0}): {1}".format(e.errno, e.strerror))
        logger.error(f'[ERROR] I/O error: {e.errno}:  {e.strerror}.')
        return False
    except: # Handle other exceptions such as attribute errors.
        print(f'[ERROR] Unable to backup the probe config to the JSON config file: {config_filename}')
        logger.error(f'[ERROR] Unable to backup the probe config to the JSON config file: {config_filename}')
        print(f'Unexpected error: {sys.exc_info()[0]}')
        logger.error(f'[ERROR] Unexpected error: {sys.exc_info()[0]}.')
        return False
    return True

def read_config_from_json(config_filename, logger):
    # The contents of the json config file are read into config_data, converted to a python dictionay object and returned
    try:
        with open(config_filename) as f:
            # decoding the JSON data to a python dictionary object
            config_data = json.load(f)
            print(f'[INFO] Reading config data from JSON file: {config_filename}')
            logger.info(f'[INFO] Reading config data from JSON file: {config_filename}')
            return config_data
    except IOError as e:
        print(f'[ERROR] Unable to read the JSON config file: {config_filename}')
        logger.error(f'[ERROR] Unable to read the JSON config file: {config_filename}')
        print("I/O error({0}): {1}".format(e.errno, e.strerror))
        logger.error(f'[ERROR] I/O error: {e.errno}:  {e.strerror}.')
        return False
    except: #handle other exceptions such as attribute errors
        print(f'[ERROR] Unable to read the JSON config file:: {config_filename}')
        logger.error(f'[ERROR] Unable to read the JSON config file: {config_filename}')
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

    log_filename = 'isng_vstream_poc_config.log' #The name of the log file we will write to.
    golden_probe_config_filename = 'golden_probe_config.json'

    # Hardcoding the filenames for encrypted credentials and the key file needed to decrypt the credentials.
    cred_filename = 'ProbeCredFile.ini'
    probekey_file = 'probekey.key'
    # Create a logger instance and write the date_time to a log file.
    logger = create_logging_function(log_filename)
    if logger == False: # Creating the logger instance has failed. Exit.
        print('Exiting...')
        sys.exit()

    # Get the user's credentials from a file and decrypt them.
    user_creds = get_decrypted_credentials(cred_filename, probekey_file, logger)
    if user_creds == False: # Creating the user_creds instance has failed. Exit.
        print('Exiting...')
        sys.exit()

    # Open an SSH session to the probe.
    client = open_ssh_session(user_creds, logger)
    if client == False: # Opening the SSH session to the probe has failed. Exit.
        print('Exiting...')
        sys.exit()

    # Open a remote shell console session over the SSH connection and become the root user.
    rem_con = init_probe_console(logger, client)
    if rem_con == False: # Establishing the remote console session has failed. Exit.
        print('Exiting...')
        sys.exit()

    # Run the localconsole menu on the remote probe and gather it's current settings.
    old_probe_configs_dict, interface_list = gather_probe_configs(logger, rem_con)
    if old_probe_configs_dict == False:
        print('Closing the connection...')
        close_status = close_ssh_session(user_creds, client, rem_con, logger)
        print('Exiting...')
        sys.exit()

    # Create the backup config filename as 'probe IP' + 'probe_config_backup_' + a date-time string.
    now = datetime.now()
    date_time = now.strftime("%Y_%m_%d_%H%M%S")
    probe_ipv4 = str(old_probe_configs_dict['agent_configs'][0]['IP V4 address']) # Get the IP addr of the probe.
    probe_ipv4 = probe_ipv4.replace('.', '_') # Replace dots with underscores so we have a valid filename.
    config_filename = probe_ipv4 + '_' 'probe_config_backup_' + str(date_time) + '.json'
    # Backup the finished configs dictionary to a json file.
    write_status = write_config_to_json(config_filename, old_probe_configs_dict, logger)
    if write_status == False: # Writing the probe config to a json file has failed. Exit.
        print('Closing the connection...')
        close_status = close_ssh_session(user_creds, client, rem_con, logger)
        print('Exiting...')
        sys.exit()

    # Open the golden config file to use for setting the probe to the desired configuration.
    # Read it in as a python dictionary that we can parse.
    #new_probe_configs_dict = read_config_from_json(golden_probe_config_filename, logger)
    #if new_probe_configs_dict == False: # The read operation failed. Bail out.
        #print('Closing the connection...')
        #close_status = close_ssh_session(user_creds, client, rem_con, logger)
        #print('Exiting...')
        #sys.exit()

    #print('\nThe new probe configuration will be: ')
    #pprint.pprint(new_probe_configs_dict)

    set_status = set_probe_configs(old_probe_configs_dict, interface_list, rem_con, logger)
    if set_status == False: # Closing the SSH session to the probe has failed. Exit.
        print('Closing the connection...')
        close_status = close_ssh_session(user_creds, client, rem_con, logger)
        print('Exiting...')
        sys.exit()

    # Close the SSH session to the probe.
    close_status = close_ssh_session(user_creds, client, rem_con, logger)
    if close_status == False: # Closing the SSH session to the probe has failed. Exit.
        print('Exiting...')
        sys.exit()
    else:
        # We are done. Exit anyway.
        sys.exit()

if __name__ == "__main__":
    main()
