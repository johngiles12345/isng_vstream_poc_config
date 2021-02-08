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
from datetime import datetime
import logging
from cryptography.fernet import Fernet
import paramiko
import pprint
import re
import string
import json
import argparse
import requests

class ProbeCredentials:
    """
        A class to hold probe connection and user credentials and pass into other functions.
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
        usessshpemfile : bool
            Use a keyfile or not for the SSH connection.
        probesshpemfile : str
            The filename (include the path) of the SSH key file.
        pkey : str
            The key contents of the probesshpemfile.
        time_of_exp : str
            The number of seconds before the encrypted password expires.
        """
    def __init__(self):
        self.probehostname = []
        self.probeport = ''
        self.probeusername = ''
        self.probepassword = ''
        self.probesshpemfile = ""
        self.usessshpemfile = False
        self.pkey = ''
        self.expiry_time = -1

class nGeniusONECredentials():
    """
    This class creates a credentials object that holds all the attributes needed to connect to
    connect to a NetScout nGeniusONE appliance or virtual appliance and authenticate.
    :return: An instance of this class with all parameters initialized.
    Attributes
    ----------
    ng1hostname : str
        The hostname of the ng1 server.
    ng1port : str
        The port to use for the HTTP-HTTPS connection.
    ng1username : str
        The ng1 username for the connection.
    ng1password : str
        The encrypted ng1 password if using a password.
    ng1password_pl: str
        The unencrypted password for the connection.
    use_token : bool
        Use a token rather than a password for the connection.
    ng1token : str
        The encrypted token if using a token.
    ng1token_pl: str
        The decrypted ng1 token if using a token.
    ng1key : str
        The key contents of the private ng1key_file.
    expiry_time : str
        The number of seconds before the encrypted password or token expires.
    """

    def __init__(self):
        self.ng1hostname = ''
        self.ng1port = ''
        self.ng1username = ''
        self.ng1password = ''
        self.ng1password_pl = ''
        self.use_token = False
        self.ng1token = ''
        self.ng1token_pl = ''
        self.ng1key_file = ''
        self.pkey = ''
        self.expiry_time = ''

class ApiSession:
    """
        A class to hold the parameters needed to exchange API data over a persistent API session.
        ...
        Attributes
        ----------
        ng1_host : str
            A combination of the web protocol (HTTP or HTTPS) + nG1 Hostname (DNS or IP addr) + the
             protocol port (80, 8080, 443, 8443).
        headers : str
            The HTTP header info. We use this to tell the nG1 API that we would like it to return data
             in the JSON format.
        cookies : str
            The HTTP session cookie that nG1 returns upon establishing the initial API session. This
             cookie will be used with every subsequent API call until we are finished. This tells the
             nG1 to autheticate each API call without establishing a brand new API session. This is much
             faster than creating and destroying an API session for each and every API we make. When we
             are all done, we will gracefully close the API session and release it from nG1.
        credentials : str
            The combination of username:password if using a password, if using a token, this is set to 'Null'.
        """
    def __init__(self):
        self.ng1host = ''
        self.header = ''
        self.cookies = ''
        self.credentials = ''

def flags_and_arguments(prog_version, logger):
    """Allows the user to add optional flags to the launch command.
    Adding to --get flag will tell the program to only collect configurations and output to a JSON file.
     when using the --get flag, the program will end without doing any set commands to the probe.
    :program_version: Pass in the program version so the user can type --version.
    Return status = True if there are no errors, False if there are errors encountered.
    Return is_set_config_true = False if the user specified the --get optional flag.
    Return is_set_config_true = True if the user did not specify the --get optional flag.
    """
    try:
        # Define the program description
        text = 'This program is used to get probe configurations and back them up. Also it can set probe configurations.'
        # Initiate the parser with a description
        parser = argparse.ArgumentParser(description=text)
        parser.add_argument('--set', action="store_true", help='in addition to getting probe configurations, also set the probe configurations', dest='set', default=False)
        parser.add_argument('--version', action="store_true", help="show program version and exit", dest='version', default=False)
        #parser.add_argument('--config', dest='config_type', required=True, action="store", choices=['sites', 'client_comm', 'interfaces', 'apps'],
                    #help="specify which nGeniusONE configuration you want; sites, client_comm, interfaces or apps")
        # Parse the arguments and create a result.
        args = parser.parse_args()
        if args.version == True: # They typed either "-V" or "--version" flags.
            print(f'Program version is: {prog_version}')
            sys.exit()
        if args.set == True: # They typed the "--set" flag.
            is_set_config_true = True # In addition to getting the probe configs and backing them up, I need to
            # also set the probe configurations based on a golden config file.
        else:
            is_set_config_true = False # I only need to do the get probe configs and backup operations
        status = True

        return status, is_set_config_true
    except Exception: # An error has occurred, log the error and return a status of False.
        logger.exception(f'[ERROR] An exception occurred while attempting to parse the program launch arguments')
        status = False
        is_set_config_true = False

        return status, is_set_config_true

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

def create_logging_function():
    """Creates the logging function and specifies a log file to write to that is date-time stamped.
    Use this option to log to stdout and stderr using systemd (import os):
    logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
    :return: The logger instance if successfully completed, and the logging filename. Return False if not successful.
    """
    now = datetime.now()
    date_time = now.strftime("%Y_%m_%d_%H%M%S") # Used for timestamping filenames.

    log_filename = 'probe_config_' + date_time + '.log' #The name of the log file we will write to.

    try:
        # Call the basicConfig module and pass in the log file filename.
        logging.basicConfig(filename=log_filename, format='%(asctime)s %(message)s', filemode='a+')
        # Call the logging class and create a logger object.
        logger = logging.getLogger()
        # Set the logging level to the lowest setting so that all logging messages get logged.
        logger.setLevel(logging.INFO) # Allowable options include DEBUG, INFO, WARNING, ERROR, and CRITICAL.
        # Write the current date and time to the log file to at least show when the program was executed.
        logger.info(f"*** Start of logs {date_time} ***")
        return logger, log_filename
    except Exception:
        print(f"[ERROR] An exception occurred while attempting to the create log file function for: {log_filename}")
        return False

def get_ng1_decrypted_credentials(ng1_cred_filename, ng1key_file, logger):
    """Read in the encrypted user or user-token credentials from a local CredFile.ini file.
    Decrypt the credentials and place all the user credentials attributes into a creds instance.
    :ng1_cred_filename: A string that is the name of the ng1_cred_filename to read in.
    :ng1key_file: A string that is the name of the ng1's key file to read in.
    :return: If successful, return the creds as a class instance that contains all the params needed to
     connect to the ng1 server via HTTP or HTTPS and authenticate the user.
    :logger: An instance of the logger class so we can write error messages if they occur.
    Return False if any error occurrs.
    """
    # Create an ng1_creds instance to hold our user credentials.
    ng1_creds = nGeniusONECredentials()
    # Retrieve the decrypted credentials that we will use to open a session to the ng1 server.
    try:
        try: # Open the keyfile containing the key needed to decrypt the password.
            with open(ng1key_file, 'r') as ng1key_in:
                ng1key = ng1key_in.read().encode() # Read the key as a string.
                fng1 = Fernet(ng1key) # Create an instance of the Fernet class to hold the key info.
        except IOError as e: # Handle file I/O errors.
            print(f"\n[ERROR] Fatal error: Unable to open ng1key file: {ng1key_file}")
            print('Did you run the cred_script_nG1.py first?')
            logger.critical(f"[ERROR] Fatal error: Unable to open ng1key file: {ng1key_file}")
            logger.error(f'[ERROR] I/O error({e.errno}):  {e.strerror}.')
        except Exception as e:
            logger.exception(f"[ERROR] Fatal error: Unable to open ng1key_file: {ng1key_file}")
            logger.exception(f"Exception error is:\n{e}")
            return False
        with open(ng1_cred_filename, 'r') as cred_in:
            lines = cred_in.readlines()
            ng1_creds.ng1token = lines[4].partition('=')[2].rstrip("\n")
            #Check to see if we are expected to use an API Token or Username:Password
            # print(f' ng1_creds.ng1token is: {ng1_creds.ng1token}')
            if len(ng1_creds.ng1token) > 1: # Yes use a Token rather than a password.
                ng1_creds.use_token = True
                ng1_creds.ng1token_pl = fng1.decrypt(ng1_creds.ng1token.encode()).decode() # Use the key to decrypt.
                ng1_creds.ng1username = lines[2].partition('=')[2].rstrip("\n")
            else:
                ng1_creds.use_token = False # No, do not use a Token, but rather use a password.
                ng1_creds.ng1username = lines[2].partition('=')[2].rstrip("\n")
                ng1_creds.ng1password = lines[3].partition('=')[2].rstrip("\n")
                ng1_creds.ng1password_pl = fng1.decrypt(ng1_creds.ng1password.encode()).decode() # Use the key to decrypt.
            ng1_creds.ng1hostname = lines[1].partition('=')[2].rstrip("\n")
            ng1_creds.ng1Port = lines[5].partition('=')[2].rstrip("\n")
    except IOError as e: # Handle file I/O errors.
        logger.error(f"[ERROR] Fatal error: Unable to open ng1_cred_filename: {ng1_cred_filename}")
        logger.error(f'[ERROR] I/O error: {e}')
        return False
    except Exception as e: # Handle other unexpected errors.
        logger.exception(f"[ERROR] Fatal error: Unable to open ng1_cred_filename: {ng1_cred_filename}")
        logger.exception(f"[ERROR] Exception error is:\n{e}")
        return False

    return ng1_creds # The function was successful.

def determine_ng1_api_params(ng1_creds, logger):
    """Based on the values in the ng1_creds instance, determine what all the nG1 API connection and authentication parameters are.
    :ng1_creds: A class instance that holds all our nG1 connection and user authentication credentials values.
    :logger: An instance of the logger class so we can write error messages if they occur.
    :return: If successful, return the nG1 API parameters for ng1_host, headers, cookies and credentials.
    Return False if any error occurrs.
    """
    # You can use an authentication token named NSSESSIONID obtained from the User Management module in nGeniusONE (open the user and click Generate New Key).
    # This token can be passed to nG1 as a cookie so that we can autheticate.
    # If we are using the token rather than credentials, we will set credentials to 'Null'.
    # If we are using the username:password rather than a token, we will set cookies to 'Null'.
    # Initialize the return parameters just in case we have an error and need to return False.

    # Create an ApiSession instance to hold our API Session parameters. Use these params for all subsequent API calls.
    session = ApiSession()

    try:
        if ng1_creds.use_token == True: # The user had selected token rather than username:password.
            session.credentials = 'Null' # Set username:password to 'Null'. We won't be using these.
            session.cookies = {'NSSESSIONID': ng1_creds.ng1token_pl} # In this case we will use the token read from the CredFile.ini file.
        # Otherwise set the credentials to username:password and use that instead of an API token to authenticate to nG1.
        else: # The user had selected username:password rather than a token.
            session.cookies = 'Null' # Set cookies to 'Null'. We won't be using a token. We will use username:password instead.
            session.credentials = ng1_creds.ng1username + ':' + ng1_creds.ng1password_pl # Combines the username and the decrypted password.

        # set the URL web protocol to match what was read out of the CredFile.ini file for ng1Port.
        if ng1_creds.ng1Port == '80' or ng1_creds.ng1Port == '8080':
            web_protocol = 'http://'
        elif ng1_creds.ng1Port == '443' or ng1_creds.ng1Port == '8443':
            web_protocol = 'https://'
        else: # Not a standard port, so I don't know if I should use HTTP or HTTPS.
            print(f'[CRITICAL] nG1 destination port {ng1_creds.ng1Port} is not equal to 80, 8080, 443 or 8443')
            logger.critical(f'[CRITICAL] nG1 destination port {ng1_creds.ng1Port} is not equal to 80, 8080, 443 or 8443')
            status = False
            return status, session # As we are returning multiple params, we will status to set True or False.
        # Build up the base URL to use for all nG1 API calls.
        session.ng1_host = web_protocol + ng1_creds.ng1hostname + ':' + ng1_creds.ng1Port

        # Hardcoding the HTTP header to use in all the nG1 API calls.
        # Specifies the JSON data type as the format of the data we want returned by the nG1 API.
        session.headers = {
            'Cache-Control': "no-cache",
            'Accept': "application/json",
            'Content-Type': "application/json"
        }
    except Exception as e:
        logger.exception(f"[ERROR] Fatal error: Unable to create log file function for: {log_filename}")
        logger.exception(f"[ERROR] Exception error is:\n{e}")
        status = False
        return status, session # As we are returning multiple params, we will status to set True or False.

    status = True # Success
    return status, session # As we are returning multiple params, we will status to set True or False.

def open_session(session, logger):
    """Open an HTTP or HTTPS API session to the nG1. Reuse that session for all commands until finished.
    :session: An instance of the ApiSession class that holds all our API session params.
    :logger: An instance of the logger class to write to in case of an error.
    :return: True if successful. Return False if there are any errors or exceptions.
    """
    uri = "/ng1api/rest-sessions" # The uri to use for nG1 API initial connection.
    url = session.ng1_host + uri

    # Perform the HTTP or HTTPS API call to open the session with nG1 and return a session cookie.
    try:
        if session.credentials == 'Null': # Use a token rather than username:password.
            # Null credentials tells us to use the token. We will use this post and pass in the cookies as the token.
            post = requests.request("POST", url, headers=session.headers, verify=False, cookies=session.cookies)
        elif session.cookies == 'Null': # Use a username:password credentials combo instead of a token.
            #split the credentials string into two parts; username and the unencrypted password.
            ng1username = session.credentials.split(':')[0]
            ng1password_pl = session.credentials.split(':')[1]
            # Null cookies tells us to use the credentials string. We will use this post and pass in the credentials string.
            post = requests.request("POST", url, headers=session.headers, verify=False, auth=(ng1username, ng1password_pl))
        else:
            # print(f'[CRITICAL] opening session to URL: {url} failed')
            logger.critical(f'[CRITICAL] opening session to URL: {url} failed.')
            # print('Unable to determine authentication by credentials or token')
            logger.critical('[CRITICAL] Unable to determine authentication by credentials or token.')
            return False
        if post.status_code == 200: # The nG1 API call was successful.
            print(f'[INFO] Opened Session to URL: {url} Successfully')
            logger.info(f'[INFO] Opened Session to URL: {url} Successfully')
            # Utilize the returned cookie for future authentication. Keep this session open for all nG1 API calls.
            session.cookies = post.cookies # Set the session.cookies param to equal the Web RequestsCookieJar value.
            return True # Success!
        else: # We reached the nG1, but the request has failed. A different HTTP code other than 200 was returned.
            logger.critical(f'[CRITICAL] opening session to URL: {url} failed. Response Code: {post.status_code}. Response Body: {post.text}.')
            return False
    except Exception as e: # This means we likely did not reach the nG1 at all. Check your VPN or internet connection.
        logger.critical(f'[CRITICAL] Opening the nG1 API session has failed')
        logger.critical(f'[CRITICAL] Cannot reach URL: {url}')
        logger.critical(f'[CRITICAL] Check the VPN or internet connection')
        logger.exception(f"[ERROR] Exception error is:\n{e}")
        return False

def close_session(session, logger):
    """Close the HTTP or HTTPS API session to the nG1.
    :session: An instance of the ApiSession class that holds all our API session params.
    :logger: An instance of the logger class to write to in case of an error.
    :return: If successful, return True. Return False if there are any errors or exceptions.
    """
    try:
        uri = "/ng1api/rest-sessions/close"
        url = session.ng1_host + uri
        # perform the HTTPS API call
        close = requests.request("POST", url, headers=session.headers, verify=False, cookies=session.cookies)

        if close.status_code == 200: # The nG1 API call was successful.
            print('[INFO] Closed nG1 API Session Successfully')
            logger.info('[INFO] Closed nG1 API Session Successfully')
            return True # Success! We closed the API session.
        else: # The nG1 API call failed.
            logger.error(f'[ERROR] closing session failed. Response Code: {close.status_code}. Response Body: {close.text}.')
            return False
    except Exception as e:
        # This means we likely did not reach the nG1 at all. Check your VPN or internet connection.
        logger.error(f'[CRITICAL] Closing the nG1 API session has failed')
        logger.exception(f"Exception error is:\n{e}")
        print('[CRITICAL] Closing the nG1 API session has failed')
        print('We did not reach the nG1. Check your VPN or internect connection')
        return False

def get_probe_decrypted_credentials(probe_cred_filename, probekey_file, logger):
    """Read in the encrypted user or user-token credentials from a local CredFile.ini file.
    Decrypt the credentials and place all the user credentials attributes into a probe_creds instance.
    :param probe_cred_filename: A string that is the name of the probe_cred_filename to read in.
    :param probekey_file: A string that is the name of the probe's key file to read in.
    :logger: An instance of the logger class that we can use to write errors and exceptions to a local log file.
    :return: If successful, return the probe_creds as a class instance that contains all the params needed to
    log into the probe via SSH. Return False if any error occurrs.
    """
    # Create a probe_creds instance to hold our user credentials.
    probe_creds = ProbeCredentials()
    # Retrieve the decrypted credentials that we will use to open a session to the probe.
    try:
        with open(probe_cred_filename, 'r') as cred_in:
            lines = cred_in.readlines()
            # print(f'\ncred_in readlines is: {lines}')
            pem_file_or_password = lines[3].partition('=')[0].rstrip("\n")
            # print(f'pem_file_or_password is: {pem_file_or_password}')
            #Check to see if we are expected to use an SSH key file or a password.
            if pem_file_or_password == 'probesshpemfile': # Yes use an SSH key file rather than a password.
                probe_creds.usessshpemfile = True
                probe_creds.probesshpemfile = lines[3].partition('=')[2].rstrip("\n")
                probe_creds.probeusername = lines[2].partition('=')[2].rstrip("\n")
                try:
                    probe_creds.pkey = paramiko.RSAKey.from_private_key_file(probe_creds.probesshpemfile)
                    logger.info(f'[INFO] Found SSH .pem key: {probe_creds.probesshpemfile}')
                except SSHException as error:
                    logger.critical(f'[CRITICAL] An SSHException has occurred {error}')
                    return False
            else: # no don't use an SSH key file but rather a password.
                try: # Open the keyfile containing the key needed to decrypt the password.
                    with open(probekey_file, 'r') as probekey_in:
                        probekey = probekey_in.read().encode()
                        fprobe = Fernet(probekey)
                except Exception:
                    logger.exception(f"[ERROR] An exception occurred while attempting to open probekey_file: {probekey_file}")
                    return False
                probe_creds.usessshpemfile = False
                probe_creds.probeusername = lines[2].partition('=')[2].rstrip("\n")
                probe_creds.probepassword = lines[3].partition('=')[2].rstrip("\n")
                probe_creds.probepassword_pl = fprobe.decrypt(probe_creds.probepassword.encode()).decode()
            probe_creds.probehostname = lines[1].partition('=')[2].rstrip("\n")
            probe_creds.probeport = lines[4].partition('=')[2].rstrip("\n")
    except IOError as e: # Handle file I/O errors.
        print(f"[ERROR] Unable to open probe_cred_filename: {probe_cred_filename}")
        logger.error(f"[ERROR] Unable to open probe_cred_filename: {probe_cred_filename}")
        print(f'[ERROR] I/O error: {e}')
        logger.error(f'[ERROR] I/O error: {e}')
        return False
    except Exception: # Handle other unexpected errors.
        logger.exception(f"[ERROR] An exception occurred while attempting to open probe_cred_filename: {probe_cred_filename}")
        return False

    return probe_creds # The function was successful.

def open_ssh_session(probe_creds, hostname, logger):
    """
    Opens an SSH session to the probe using the paramiko module.
    :probe_creds: A class instance that contains all the necessary SSH connection parameters.
    :The hostname or IP Address of the Infinistream or vStream probe.
    :logger: An instance of the logger class that we can use to write errors and exceptions to a local log file.
    :return: The SSH client instance if successful, False if unsuccessful.
    """
    try:
        port = probe_creds.probeport
        username = probe_creds.probeusername
        if probe_creds.usessshpemfile == False: # Use a password for the SSH connection
            key_filename = None
            pkey = None
            password = probe_creds.probepassword_pl
        else: # Use an SSH .pem keyfile for the SSH connection rather than a password.
            password = None
            key_filename = probe_creds.probesshpemfile
            pkey = probe_creds.pkey
        timeout = 20 # Number of seconds to wait before timing out
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # *** Below is the full list of connection params you can use.
        # client.connect(hostname=hostname, port=port, username=username, password=password, pkey=pkey,
        # key_filename=key_filename, timeout=timeout, allow_agent=True, look_for_keys=True,
        # compress=False, sock=None, gss_auth=False, gss_kex=False, gss_deleg_creds=True,
        # gss_host=None, banner_timeout=None, auth_timeout=None, gss_trust_dns=True, passphrase=None,
        # disabled_algorithms=None)
        print(f'[INFO] Attempting SSH connection to hostname: {hostname} with username: {username} on port: {port}')
        client.connect(hostname=hostname, username=username, password=password, pkey=pkey, timeout=timeout, port=port)
        print(f'[INFO] Open SSH connection to: {hostname} Successful')
        logger.info(f'[INFO] Open SSH connection to: {hostname} Successful')
        #client.connect(hostname,username,pkey=none,key_filename='id_rsa',look_for_keys=True)
        return client
    except Exception:
        logger.exception(f"[ERROR] An exception occurred while attempting to open SSH connection to: {hostname}")
        return False

def execute_single_command_on_remote(command, rem_con, logger):
    """
    Sends a single console command to the probe and returns the result.
    :command: A string that contains the command with an new line char at the end to simulate
    hitting the enter key.
    :rem_con: A class instance of invoke_shell that opens a remote console shell over SSH.
    :logger: An instance of the logger class that we can use to write errors and exceptions to a local log file.
    :return: The output string that was returned from the console as a result of the command.
    """
    #print(f'[INFO] Executing command: {command}')
    logger.info(f'[INFO] Executing command: {command}')
    try:
        #while not rem_con.send_ready(): # Wait for send ready status before sending a command.
            #time.sleep(0.5)
        rem_con.send(command) # Send the command string to the remote console shell.
        #while not rem_con.recv_ready(): # Wait for the first byte to come into the buffer before starting the sleep timer.
            #time.sleep(0.5)
        time.sleep(1)
        output = rem_con.recv(2048) # Pull down the receive buffer from the remote console to a limit of 2048 bytes.
        output = output.decode("utf-8") # Output comes back as a file-like binary object. Decode to a string.
    except Exception:
        logger.exception(f"[ERROR] An exception occurred while attempting to execute the single command: {command} over the SSH shell")
        return False
    return output

def init_probe_console(logger, client):
    """
    Sends commands to the SSH client to establish a console object and set the user to su.
    :client: The SSH client instance established with the probe.
    :logger: An instance of the logger class that we can use to write errors and exceptions to a local log file.
    :return: rem_con, A class instance of invoke_shell that opens a remote console shell over SSH.
    """
    try:
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
            logger.error("[ERROR] SSH command invoke_shell has failed. 'Last login' missing from output")
            return False
    except Exception:
        logger.exception(f"[ERROR] An exception occurred while attempting to execute SSH command invoke_shell")
        return False

    command = "sudo su -\n"
    output = execute_single_command_on_remote(command, rem_con, logger)
    if "su:" in output or "sudo:" in output: # The sudo command has failed.
        logger.error(f'[ERROR] Init_probe_console, Console command: {command} failed')
        return False
    elif output == False:
        logger.error(f'[ERROR] Init_probe_console, Console command: {command} failed')
        return False

    return rem_con

def get_probe_options(config_attributes_list, rem_con, old_probe_configs_dict, options_type, logger):
    """
    Query the probe for the current config parameters of a set of related options.
    The list of options returned by the probe will be used to fill in the attributes for the old_probe_configs_dict.
    :config_attributes_list: A list of attribute names to be entered into the old_probe_configs_dict.
    :interface_list: A list of probe monitor interface numbers that are available.
    :rem_con: An instance of the remote console shell session to the probe.
    :old_probe_configs_dict: A dictionary of all the probe configurations.
    :options_type: The name of the probe options that we want to fetch from the probe.
    :logger: An instance of the logger class that we can use to write errors and exceptions to a local log file.
    :return: The filled in old_probe_configs_dict if all commands pass and status = True.
    Return old_probe_configs_dict and status = False if any errors occur.
    """
    try:
        #formatted_configs = [] # Initialize an empty list to hold the formatted configs prior to adding them to the dict.
        if options_type == 'agent_configs':
            command = "get agent\n"
        elif options_type == 'health_mib_info':
            command = "get health_mib info\n"
        else:
            command = "get " + options_type + "\n"
        output = execute_single_command_on_remote(command, rem_con, logger)
        #print(f"\nraw output is: \n{output}")
        if output == False:
            logger.error(f'[ERROR] get_probe_options, Console command: {command} failed')
            status = False
            return old_probe_configs_dict, status
        formatted_options_configs, status = get_formatted_options_configs(output, logger)
        if status == False:
            logger.error(f'[ERROR] get_probe_options, get_formatted_options_configs failed')
            return old_probe_configs_dict, status
        for config_attribute in config_attributes_list:
            old_probe_configs_dict, status = process_output_non_interface(old_probe_configs_dict, options_type, config_attribute, formatted_options_configs, logger)
            if status == False:
                logger.error(f'[ERROR] get_probe_options, process_output_non_interface failed')
                return old_probe_configs_dict, status
    except Exception:
        logger.exception(f"[ERROR] An exception occurred while atempting the get {options_type} command")
        status = False
        return old_probe_configs_dict, status

    return old_probe_configs_dict, status

def get_probe_config_interface_specific(config_attributes_list, interface_list, rem_con, old_probe_configs_dict, options_type, logger):
    """
    For each monitor interface, send a command the probe to get the specific settings passed in as config_attributes_list.
    The setting for each config attribute will be used to fill in the attributes for the old_probe_configs_dict.
    :config_attributes_list: A list of attribute names to be entered into the old_probe_configs_dict.
    :interface_list: A list of probe monitor interface numbers that are available.
    :rem_con: An instance of the remote console shell session to the probe.
    :old_probe_configs_dict: A dictionary of all the probe configurations.
    :options_type: In this case, interface_specific to indicate that we need send the query with the
     interface number included in the command.
    :logger: An instance of the logger class that we can use to write errors and exceptions to a local log file.
    :return: The filled in old_probe_configs_dict and status = True if all commands pass.
    Return the old_probe_configs_dict and status = False if any errors occur.
    """
    try:
        for interface in interface_list:
            old_probe_configs_dict[options_type][0]['interface '+ interface] = [{}]
            # This is what makes this function different from the others is that we have to execute a command for every...
            # config item in the config_attributes_list and for every interface, one by one.
        for config_attribute in config_attributes_list:
            for interface in interface_list:

                if config_attribute == 'sip_db':
                    command = "get " + config_attribute + " " + interface + "\n"
                    output1 = execute_single_command_on_remote(command, rem_con, logger)
                    time.sleep(2)
                    command = "y" + "\n"
                    output2 = execute_single_command_on_remote(command, rem_con, logger)
                    output = output1 + output2
                elif config_attribute == 'h248_cfg': # Special case where the command includes a space char.
                    command = "get " + 'h248 cfg' + " " + interface + "\n"
                    output = execute_single_command_on_remote(command, rem_con, logger)
                else:
                    command = "get " + config_attribute + " " + interface + "\n"
                    output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] get_probe_options_interface_specific, Console command: {command} failed')
                    status = False
                    return old_probe_configs_dict, status
                # one by one rather than passing the whole config attributes list to process_output_per_interface.
                formatted_options_configs, status = get_formatted_options_configs(output, logger)
                if status == False:
                    logger.error(f'[ERROR] get_probe_options_interface_specific, get_formatted_options_configs failed')
                    return old_probe_configs_dict, status
                old_probe_configs_dict, status = process_output_per_interface(config_attribute, old_probe_configs_dict, options_type, formatted_options_configs, interface, logger)
                if status == False:
                    logger.error(f'[ERROR] get_probe_options_interface_specific, process_output_per_interface failed')
                    return old_probe_configs_dict, status
    except Exception:
        logger.exception(f"[ERROR] An exception occurred in get_probe_options_interface_specific, Get config attribute for an interface")
        status = False
        return old_probe_configs_dict, status
    status = True
    return old_probe_configs_dict, status

def process_output_non_interface(old_probe_configs_dict, options_type, config_attribute, formatted_options_configs, logger):
    """
    After retrieving the output from a get command to the probe, the data supplied requires some formatting...
     so we can create searchable lists that hold the configuration item and its current configuration status.
     :old_probe_configs_dict: A dictionary of all the probe configurations that we will add to.
     :options_type: The name of the probe options that we want to fetch from the probe.
     :config_attribute: A string. The config_attribute to search for within the formatted_options_configs list.
     :formatted_options_config: A formatted and filtered list of all the config settings returned by the probe output.
    :logger: An instance of the logger class that we can use to write errors and exceptions to a local log file.
    :return: old_probe_configs_dict, status. status = True if successful, False if there were any errors.
    """
    #print(f'non interface specific items formatted_options_configs is: {formatted_options_configs}')
    try:
        # The probe data returned for any command may or may not include the config_attribute.
        # In many cases we need to modify the config_attribute string so we can validate the data...
        # returned by the probe.
        if config_attribute == 'config_download':
            formatted_config_attribute = 'config_download :'
        elif config_attribute == 'probe_mode':
            formatted_config_attribute = 'Probe Mode :'
        elif config_attribute == 'vq_payload':
            formatted_config_attribute = 'vq payload:'
        elif config_attribute == 'vq_dtmf_events':
            formatted_config_attribute = 'vq dtmf_events:'
        elif config_attribute == 'asi_mode':
            formatted_config_attribute = 'asi_mode is currently set to'
        elif config_attribute == 'capture_slice_size':
            formatted_config_attribute = 'Change capture slice size :'
        elif config_attribute == 'data_capture':
            formatted_config_attribute = 'Toggle data capture :'
        elif config_attribute == 'geo_probe':
            formatted_config_attribute = 'geo_probe is'
        elif config_attribute == 'qos_mode':
            formatted_config_attribute = 'qos mode'
        elif options_type == 'health_mib_info':
            formatted_config_attribute = config_attribute + ' :'
        elif config_attribute == 'trap_port':
            formatted_config_attribute = 'Trap port 1:'
        elif config_attribute == 'ipfrag_table_size':
            formatted_config_attribute = 'IP Fragment Table size:'
        elif config_attribute == 'tns_skt_count':
            formatted_config_attribute = 'No of Simultaneous Sockets Supported Per Mibmgr Handler ='
        elif config_attribute == 'ts_resolution':
            formatted_config_attribute = 'Hi-res timestamp -'
        elif config_attribute == 'citrix_discover_apps':
            formatted_config_attribute = 'Citrix application discovery is'
        elif config_attribute == 'citrix_server_push':
            formatted_config_attribute = 'Citrix server push is'
        elif config_attribute == 'citrix_wildcard_support':
            formatted_config_attribute = 'Citrix wildcard support is'
        elif config_attribute == 'citrix_channel_monitoring':
            formatted_config_attribute = 'Citrix channel support is'
        elif config_attribute == 'krb_maxname':
            formatted_config_attribute = 'Kerberos max Name Entries'
        elif config_attribute == 'krb_ntr':
            formatted_config_attribute = 'Kerberos NameTable Recording'
        elif config_attribute == 'rtp_heur':
            formatted_config_attribute = 'high_priority'
        elif config_attribute == 'max_hset_download':
            formatted_config_attribute = 'max_hset_download ='
        elif config_attribute == 'auto_scroll':
            formatted_config_attribute = 'auto scroll is'

        elif config_attribute == 'ipreassembly': # Special case where multiple values are returned, and all interfaces all at once.
            for formatted_options_config in formatted_options_configs: # loop through the list and see if the config_attribute is there.
                interface_num = '' # Initialize interface_num just in case we can't find it.
                if 'Interface ' in formatted_options_config:
                    interface = formatted_options_config[26:28].strip('-') # Account for both one and two digit interface numbers.
                    interface.strip(' ')
                    continue
                else:
                    ipreassembly_setting = formatted_options_config.split(' = ')[0]
                    ipreassembly_value = formatted_options_config.split(' = ')[1]
                    if len(ipreassembly_value) > 0: # I found a value after the equals sign.
                        old_probe_configs_dict['interface_specific'][0]['interface '+ interface][0][ipreassembly_setting] = ipreassembly_value
                        continue
            status = True
            return old_probe_configs_dict, status
        elif config_attribute == 'ipsec':
            # The output returned for this includes multiple values, but we only 3 of them. Just add the values to the dict.
            if len(formatted_options_configs) == 1:
                old_probe_configs_dict[options_type][0][config_attribute] = formatted_options_configs[0] # Account for pre-ISNG vintage probes
            if len(formatted_options_configs) == 3:
                old_probe_configs_dict[options_type][0]['ipsec_esp_sequence_processing'] = formatted_options_configs[0].partition('ipsec: esp sequence processing ')[2][:-2]
                old_probe_configs_dict[options_type][0]['ipsec_esp_list_size'] = formatted_options_configs[1].partition('esp list size is configured : ')[2]
                ipsec_reassembly_stamping_setting = formatted_options_configs[2].split()[-1] # The last configuration has its own name and setting
                old_probe_configs_dict[options_type][0]['ipsec_reassembly_stamping'] = ipsec_reassembly_stamping_setting[1:] # Add it to the dict.
            status = True
            return old_probe_configs_dict, status
        elif config_attribute == 'npn_alarms':
            # The output returned for this includes 3 key:value pairs per line and 7 lines returned by the probe.
            for formatted_options_config in formatted_options_configs: # loop through the list and see if the config_attribute is there.
                if 'npn_alarms set to' in formatted_options_config:
                    old_probe_configs_dict[options_type][0][config_attribute] = formatted_options_config.partition('npn_alarms set to')[2]
                    break # This is the last setting returned from the command, so break out of the loop if found.
                npn_alarms_split = formatted_options_config.split()
                old_probe_configs_dict[options_type][0][npn_alarms_split[1]] = npn_alarms_split[2]
                old_probe_configs_dict[options_type][0][npn_alarms_split[4]] = npn_alarms_split[5]
                old_probe_configs_dict[options_type][0][npn_alarms_split[7]] = npn_alarms_split[8]
            status = True
            return old_probe_configs_dict, status
        elif config_attribute == 'app_table_size':
            # The output returned for this only includes the value. Just add the value to the dict.
            old_probe_configs_dict[options_type][0][config_attribute] = formatted_options_configs[0]
            status = True
            return old_probe_configs_dict, status
        elif config_attribute == 'h248_protocols':
            for formatted_options_config in formatted_options_configs: # loop through the list and see if the config_attribute is there.
                if 'H248-' in formatted_options_config: # Some basic validity checking to make sure we have the right values.
                    # The output returned for this only includes the value. Just add the value to the dict.
                    h248_protocols_split = formatted_options_config.split(maxsplit=1) # Split out the first word.
                    h248_protocols_setting = h248_protocols_split[0] # Get the first word of the formatted_options_config to get the setting
                    h248_protocols_value = h248_protocols_split[1] # The rest of the words represent the setting value
                    old_probe_configs_dict[options_type][0][h248_protocols_setting] = h248_protocols_value
            status = True
            return old_probe_configs_dict, status
        elif config_attribute == 'max_capture_size':
            # The output returned for this only includes the value. Just add the value to the dict.
            old_probe_configs_dict[options_type][0][config_attribute] = formatted_options_configs[0]
            status = True
            return old_probe_configs_dict, status
        elif config_attribute == 'h323_options':
            # The output returned for this only includes the value. Just add the value to the dict.
            old_probe_configs_dict[options_type][0][config_attribute + ' max calls'] = formatted_options_configs[0].split()[-1]
            status = True
            return old_probe_configs_dict, status
        elif config_attribute == 'max_dhcp':
            # The output returned for this only includes the value. Just add the value to the dict.
            old_probe_configs_dict[options_type][0][config_attribute] = formatted_options_configs[0]
            status = True
            return old_probe_configs_dict, status
        elif config_attribute == 'max_ipv6':
            # The output returned for this only includes the value. Just add the value to the dict.
            old_probe_configs_dict[options_type][0][config_attribute] = formatted_options_configs[0]
            status = True
            return old_probe_configs_dict, status
        elif config_attribute == 'ip_options':
            # The output returned for this only includes the value. Just add the value to the dict.
            old_probe_configs_dict[options_type][0][config_attribute] = formatted_options_configs[0]
            status = True
            return old_probe_configs_dict, status
        elif config_attribute == 'vlan_disc_type':
            # The output returned for this only includes the value. Just add the value to the dict.
            old_probe_configs_dict[options_type][0][config_attribute] = formatted_options_configs[0]
            status = True
            return old_probe_configs_dict, status
        else:
            formatted_config_attribute = config_attribute # The config_attribute string is within the data returned by the probe as-is.
        # Depending on the config of the probe, the list of attributes can change.
        for formatted_options_config in formatted_options_configs: # loop through the list and see if the config_attribute is there.
            #formatted_options_config_list = formatted_options_config.partition(formatted_config_attribute + ' ')
            #print(f"\nformatted_options_config_list after split is: {formatted_options_config_list}")
            #print(f'compare left formatted_config_attribute is: {formatted_config_attribute}')
            #print(f'compare right formatted_options_config is: {formatted_options_config}')
            if formatted_config_attribute in formatted_options_config:
                index = formatted_options_configs.index(formatted_options_config) # Find the index of the formatted_options_configs
                # print(f'I found {formatted_config_attribute} at index position {index}')
                old_probe_configs_dict[options_type][0][config_attribute] = formatted_options_configs[index].partition(formatted_config_attribute + ' ')[2]
                break # I found the formatted_config_attribute, break out of this search loop.
            else:
                #print(f'I did not find the index for this {formatted_config_attribute}')
                continue # I did  find the formatted_config_attribute in this loop, get the next formatted_config_attribute.
        status = True
        return old_probe_configs_dict, status
    except Exception:
        logger.exception(f"[ERROR] An exception occurred in process_output_non_interface")
        status = False
        return old_probe_configs_dict, status

def get_formatted_options_configs(output, logger):
    """
    After retrieving the output from a get command to the probe, the data supplied requires some formatting...
     so we can create searchable lists that hold the configuration item and its current configuration status.
    :output: The raw output returned by the probe that requires formatting.
    :logger: An instance of the logger class that we can use to write errors and exceptions to a local log file.
    :return: If successful, return the formatted_options_configs and status = True. Return empty formatted_options_configs
     list and status = False if there are any exceptions.
    """
    try:
        formatted_options_configs = [] # Initialize an empty list to hold the formatted options configs.
        options_configs = output.splitlines()
        for options_config in options_configs:
            #print(f'\nLooking for bogus options_config items: {options_config}')
            if 'get ' in options_config:
                continue
            elif options_config == '':
                continue
            elif '%' in options_config:
                continue
            elif 'Ifn  Type (current)' in options_config:
                continue
            elif 'Press Enter to Continue? [y/n]:' in options_config:
                continue
            elif 'options =' in options_config:
                continue
            elif 'ext_options =' in options_config:
                continue
            elif '[2] Change user_password' in options_config:
                continue
            elif '[5] Clear All passwords' in options_config:
                continue
            elif '[99] Go Back to Main Menu' in options_config:
                continue
            elif 'Secure Access Menu:' in options_config:
                continue
            elif 'Selection:' in options_config:
                continue
            elif '** ' in options_config:
                continue
            elif 'Select Interface :' in options_config:
                continue
            elif 'New Interface' in options_config:
                continue
            elif 'Ifn  value' in options_config:
                continue
            elif 'ifn ip_hdr CRC Inner_VLAN Outer_VLAN Generic' in options_config:
                continue
            elif 'Table size allocation' in options_config:
                continue
            elif 'Ifn Percentage' in options_config:
                continue
            elif 'Change admin_password' in options_config:
                continue
            elif  'Selection#:' in options_config:
                continue
            elif 'IFN  asi_mode' in options_config:
                continue
            elif 'ifn  custom_dpi' in options_config:
                continue
            elif 'Ifn   State' in options_config:
                continue
            elif 'Ifn  Type (current)' in options_config:
                continue
            elif 'Configured values' in options_config:
                continue
            elif 'IFN  table' in options_config:
                continue
            elif 'size   interval' in options_config:
                continue
            elif 'GM Null ciphering for the ifn' in options_config:
                continue
            elif 'Value that will be used after probe reset' in options_config:
                continue
            elif 'Health MIB Information!' in options_config:
                continue
            elif 'Platform Model' in options_config:
                continue
            elif 'Please note that this size' in options_config:
                continue
            elif 'it applies to both ipv4 and ipv6' in options_config:
                continue
            elif 'Meaning if you have 8 parsers' in options_config:
                continue
            elif '8/16 times the configured size' in options_config:
                continue
            elif 'Configured values (in thousands)' in options_config:
                continue
            elif 'IFN sessions' in options_config:
                continue
            elif 'IFN gtp_gen_con_opt' in options_config:
                continue
            elif 'current_value' in options_config:
                continue
            elif 'protocol  ppid' in options_config:
                continue
            elif 'Health MIB is initialized successfully.' in options_config:
                continue
            elif options_config == '------------------------':
                continue
            elif 'H248 curIFN' in options_config:
                continue
            elif 'NPN Alarm Table Types' in options_config:
                continue
            else:
                options_config_split = options_config.split()
                options_config_new = " ".join(options_config_split)
                formatted_options_configs.append(options_config_new)
    except Exception:
        logger.exception(f"[ERROR] An exception occurred in get_formatted_options_configs")
        status = False
        return formatted_options_configs, status
    status = True
    #print(f'\noptions_configs is: {options_configs}')
    #print(f'\nformatted_options_configs are: {formatted_options_configs}')
    return formatted_options_configs, status

def process_output_per_interface(config_attribute, old_probe_configs_dict, options_type, formatted_options_configs, interface, logger):
    """
    After retrieving the output from a get command to the probe, the data supplied requires some formatting...
     so we can create searchable lists that hold the configuration item and its current configuration status.
    :config_attribute: A string. The config_attribute to search for within the formatted_options_configs list.
    :old_probe_configs_dict: A dictionary of all the probe configurations that we will add to.
    :options_type: The name of the probe options that we want to fetch from the probe.
    :formatted_options_config: A formatted and filtered list of all the config settings returned by the probe output.
    :interface: An integer. The probe interface number. Settings can be different for each interface so we need
     to loop through each one.
    :logger: An instance of the logger class that we can use to write errors and exceptions to a local log file.
    :return: old_probe_configs_dict, status. status = True if successful, False if there were any errors.
    """
    index_found = False # I ran into a case where this is not set within the for loop. Initializing.
    try:
        #print(f'which config_attribute are we at: {config_attribute}')
        if config_attribute == 'skt_vlan_enable':
            formatted_config_attribute = 'skt_vlan_enable is'
        elif config_attribute == 'span_duplicate':
            formatted_config_attribute = interface
        elif config_attribute == 'ssl_sni':
            formatted_config_attribute = 'ssl_sni is'
        elif config_attribute == 'encap_type':
            formatted_config_attribute = 'enabled on ' + interface
        elif config_attribute == 'community_type':
            formatted_config_attribute = interface
        elif config_attribute == 'custom_dpi':
            formatted_config_attribute = interface
        elif config_attribute == 'time_sync':
            formatted_config_attribute = 'time_sync -'
        elif config_attribute == 'skt':
            formatted_config_attribute = interface + ' '
        elif config_attribute == 'match_uri_only_mode':
            formatted_config_attribute = interface
        elif config_attribute == 'ssl_cert':
            formatted_config_attribute = 'ssl_cert is'
        elif config_attribute == 'ssl_decrypt':
            formatted_config_attribute = 'SSL decryption is'
        elif config_attribute == 'ssl_session_ageout':
            formatted_config_attribute = 'SSL session ageout for IFN ' + interface + ' ='
        elif config_attribute == 'ssl_session_cnt':
            formatted_config_attribute = 'Max. SSL session count for IFN ' + interface + ' ='
        elif config_attribute == 'table_size_allocation':
            formatted_config_attribute = interface + ' '
        elif config_attribute == 'ipv6_mode':
            formatted_config_attribute = interface
        elif config_attribute == 'xdr':
            formatted_config_attribute = interface
        elif config_attribute == 'rtp_ast':
            formatted_config_attribute = interface
        else:
            formatted_config_attribute = config_attribute
        # Loop through each each config setting returned by the probe for this config_attribute.
        for formatted_options_config in formatted_options_configs: # loop through the list and see if the config_attribute is there.
            if '------------' in formatted_options_config: # Filter out lines like this.
                continue
            # Next several lines are to avoid a false positive partial match. See the comment 'Skip the partial match'.
            if config_attribute == 'Data w/o Control' and 'Data w/o Control Tcm' in formatted_options_config:
                continue # Skip the partial match.
            if config_attribute == 'disc_table' and 'url_disc_table' in formatted_options_config:
                continue # Skip the partial match.
            if config_attribute == 'conv' and 'conv ports' in formatted_options_config:
                continue # Skip the partial match.
            if config_attribute == 'conv' and 'conv qos' in formatted_options_config:
                continue # Skip the partial match.
            if config_attribute == 'conv' and 'uc_conv' in formatted_options_config:
                continue # Skip the partial match.
            if config_attribute == 'skt': # Special case where we might match the interface number to one of the values.
                if formatted_options_config.startswith(formatted_config_attribute): # The interface number plus a space will come first.
                    old_probe_configs_dict[options_type][0]['interface '+ interface][0][config_attribute] = formatted_options_config.partition(formatted_config_attribute)[2]
                    continue # I found the config_attribute, go to the next formatted_options_config item returned by the probe.
            elif config_attribute == 'site_outer': # Special case where the return is only the value on or off
                if 'on' or 'off' in formatted_options_config: # The interface number plus a space will come first.
                    old_probe_configs_dict[options_type][0]['interface '+ interface][0][config_attribute] = formatted_options_config
                    continue # go to the next formatted_options_config item returned by the probe.
            elif config_attribute == 'sip_db': # Special case where the return includes both the setting and value
                if '=' in formatted_options_config: # Basic validity check
                    sip_db_setting = formatted_options_config.partition(' = ')[0]
                    sip_db_value = formatted_options_config.partition(' = ')[2]
                    old_probe_configs_dict['sip_db'][0]['interface '+ interface][0]['sip_db ' + sip_db_setting] = sip_db_value
                    continue # go to the next formatted_options_config item returned by the probe.
            elif config_attribute == 'frag_reassembly': # Special case where the return includes both the setting and value
                if len(formatted_options_config) < 1: # special case for interfaces belonging to an AGGREGATE interface.
                    old_probe_configs_dict['frag_reassembly'][0]['interface '+ interface][0]['frag_reassembly'] = 'N/A for ifns part of an AGGREGATE interface'
                    break
                if '=' in formatted_options_config: # Basic validity check
                    frag_reassembly_setting = formatted_options_config.partition(' = ')[0]
                    frag_reassembly_value = formatted_options_config.partition(' = ')[2]
                    old_probe_configs_dict['frag_reassembly'][0]['interface '+ interface][0]['frag_reassembly ' + frag_reassembly_setting] = frag_reassembly_value
                    continue # go to the next formatted_options_config item returned by the probe.
            elif config_attribute == 'h248_cfg': # Special case where the return includes both the setting and value
                if '=' in formatted_options_config: # Basic validity check
                    # print(f' For H248 the formatted_options_config prior to partition and strip is: {formatted_options_config}')
                    h248_cfg_setting = formatted_options_config.partition(' = ')[0].strip('-') # Strip out dashes at the beginning and end of strings.
                    if '-' in h248_cfg_setting:
                        for char in h248_cfg_setting: # Strip out dashes in the middle of the string.
                            if char == '-':
                                h248_cfg_setting = h248_cfg_setting.replace(char,"")
                            if char == '  ':
                                h248_cfg_setting = h248_cfg_setting.replace(char," ") # Replace double spaces with a single space.
                    # print(f'\nH248 setting after strip is: {h248_cfg_setting}')
                    h248_cfg_value = formatted_options_config.partition(' = ')[2]
                    old_probe_configs_dict['h248_cfg'][0]['interface '+ interface][0]['h248_cfg ' + h248_cfg_setting] = h248_cfg_value
                    continue # go to the next formatted_options_config item returned by the probe.
            elif config_attribute == 'max_etherpktsize': # Special case where the return is only the value on or off
                old_probe_configs_dict[options_type][0]['interface '+ interface][0][config_attribute] = formatted_options_config
                continue # I found the config_attribute, go to the next formatted_options_config item returned by the probe.
            elif config_attribute == 'ipsec_opts': # Special case where non of the values include the 'ipsec_opts' key.
                ipsec_opts_setting = formatted_options_config.split(' = ')[0]
                ipsec_opts_value = formatted_options_config.split(' = ')[1]
                if len(ipsec_opts_value) > 1: # I found a value after the equals sign.
                    old_probe_configs_dict[options_type][0]['interface '+ interface][0][ipsec_opts_setting] = ipsec_opts_value
                    # The ipsec_opts keys returned do not contain any portion of 'ipsec_opts'.
                    # So we will process them as key:value pairs and just write them to the dictionary.
                    # Skip the index search portion of this function.
                    continue # go to the next formatted_options_config item returned by the probe.
            elif config_attribute == 'ssl_health': # Special case where the value contains the name of the setting.
                ssl_health_setting = formatted_options_config.split('ssl_health: ')
                ssl_health_setting = ssl_health_setting[1].split()[0] # Get the first word of the value and add it to the setting name.
                if ssl_health_setting == 'enabled': # The first setting does not include the actual setting label.
                    ssl_health_setting = 'ssl_health'
                    ssl_health_value_string = formatted_options_config.split('ssl_health: ')[1]
                else:
                    ssl_health_setting = 'ssl_health ' + ssl_health_setting # Add the config_attribute to the setting name.
                    ssl_health_value = formatted_options_config.split('ssl_health: ')[1] #get the whole value portion of the string again.
                    ssl_health_value_list = ssl_health_value.split(' ') # split it into a list.
                    ssl_health_value_list.pop(0) # Remove the first word which is now part of the ssl_health_setting string.
                    ssl_health_value_string = " ".join(ssl_health_value_list) # Put all the remaining words back together into a string.
                if len(ssl_health_value_string) > 1: # Checking to make sure I don't have an empty string.
                    # Add it to the dictionay.
                    old_probe_configs_dict[options_type][0]['interface '+ interface][0][ssl_health_setting] = ssl_health_value_string
                    # Skip the index search portion of this function.
                    continue # go to the next formatted_options_config item returned by the probe.
            elif config_attribute == 'xdr':
                if interface + ' Enabled' in formatted_options_config or interface + ' Disabled' in formatted_options_config:
                    old_probe_configs_dict[options_type][0]['interface '+ interface][0]['gtp_gen_con_opt'] = formatted_options_config.partition(formatted_config_attribute + ' ')[2]
                    # Skip the index search portion of this function. Special case where an extra surprise attribute is returned.
                elif interface + ' ' in formatted_options_config:
                    old_probe_configs_dict[options_type][0]['interface '+ interface][0]['xdr'] = formatted_options_config.partition(formatted_config_attribute + ' ')[2]
                    # Skip the index search portion of this function. Special case where an extra surprise attribute is returned.
                    continue
            else:
                if formatted_config_attribute in formatted_options_config:
                    index = formatted_options_configs.index(formatted_options_config) # Find the index of the formatted_options_configs
                    # print(f'I found {config_attribute} at index position {index}')
                    if config_attribute == 'encap_type':
                        old_probe_configs_dict[options_type][0]['interface '+ interface][0][config_attribute] = formatted_options_configs[index]
                    else:
                        old_probe_configs_dict[options_type][0]['interface '+ interface][0][config_attribute] = formatted_options_configs[index].partition(formatted_config_attribute + ' ')[2]
                    continue
        status = True
        return old_probe_configs_dict, status
    except Exception:
        logger.exception(f"[ERROR] An exception occurred in process_output_per_interface")
        status = False
        return old_probe_configs_dict, status

def get_probe_options_per_interface(config_attributes_list, interface_list, rem_con, old_probe_configs_dict, options_type, logger):
    """
    For each monitor interface, send a command the probe to get the whole options list.
    The list of options returned by the probe will be used to fill in the attributes for the old_probe_configs_dict.
    :config_attributes_list: A list of attribute names to be entered into the old_probe_configs_dict.
    :interface_list: A list of probe monitor interface numbers that are available.
    :rem_con: An instance of the remote console shell session to the probe.
    :old_probe_configs_dict: A dictionary of all the probe configurations that we will add to.
    :options_type: The name of the probe options that we want to fetch from the probe.
    :logger: An instance of the logger class that we can use to write errors and exceptions to a local log file.
    :return: The filled in old_probe_configs_dict and status = True if all commands pass.
    Returen the old_probe_configs_dict and status = False if any errors occur.
    """
    loop_counter = 0 # Used to determine if we need to do get asi or just responding to yes prompt with enter.
    try:
        for interface in interface_list:
            # Create an empty dictionary to hold the configs for each interface.
            old_probe_configs_dict[options_type][0]['interface '+ interface] = [{}]
        # loop_counter = 0 # If options_type is asi, the first time through the interface loop, we...
        # need to do a 'get asi'. From then on, we just hit enter to advance to the next asi interface.
        for interface in interface_list:
            #print(f'\noptions_type is: {options_type}')
            if options_type != 'asi': # Get asi does not use set curr_interface, you must hit enter to advance.
                command = "set curr_interface " + interface +" \n"
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] get_probe_options_per_interface, Console command: {command} failed')
                    status = False
                    return old_probe_configs_dict, status
                command = "get " + options_type + "\n"
                output = execute_single_command_on_remote(command, rem_con, logger)
            elif options_type == 'asi':
                if loop_counter == 0: # This is the first interface, do a 'get asi' command.
                    command = "get asi" + "\n"
                else:
                    command = "\n" # Send the yes response to get asi on the next interface.
                output = execute_single_command_on_remote(command, rem_con, logger)
            #print(f"\nraw output is: \n{output}")
            if output == False:
                logger.error(f'[ERROR] get_probe_options_per_interface, Console command: {command} failed')
                status = False
                return old_probe_configs_dict, status
            formatted_options_configs, status = get_formatted_options_configs(output, logger)
            if status == False:
                logger.error(f'[ERROR] get_probe_options_per_interface, get_formatted_options_configs failed')
                status = False
                return old_probe_configs_dict, status
            for config_attribute in config_attributes_list:
                old_probe_configs_dict, status = process_output_per_interface(config_attribute, old_probe_configs_dict, options_type, formatted_options_configs, interface, logger)
                if status == False:
                    logger.error(f'[ERROR] get_probe_options_per_interface, process_output_per_interface failed')
                    status = False
                    return old_probe_configs_dict, status
                loop_counter += 1 # Used to determine if we need to do get asi or just responding to yes prompt with enter.
        if options_type == 'asi': # The final menu page prints out the V4 and V6 community masks.
            command = "\n" # Send the yes <enter> response to 'get asi' to end the menu and return to the command line prompt.
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] get_probe_options_per_interface, Console command: {command} failed')
                status = False
                return old_probe_configs_dict, status
            command = "\n" # Send the yes <enter> response to 'get asi' to end the menu and return to the command line prompt.
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] get_probe_options_per_interface, Console command: {command} failed')
                status = False
                return old_probe_configs_dict, status
    except Exception:
        logger.exception(f"[ERROR] An exception occurred in get_probe_options_per_interface, Getting probe options for an interface")
        status = False
        return old_probe_configs_dict, status
    status = True
    return old_probe_configs_dict, status

def get_probe_options_non_interface_specific(config_attributes_list, rem_con, old_probe_configs_dict, options_type, logger):
    """
    For each config attribute, send a command the probe to get the specific probe-wide non-interface specific settings.
    The setting for each config attribute will be used to fill in the attributes for the old_probe_configs_dict.
    :config_attributes_list: A list of attribute names to be entered into the old_probe_configs_dict.
    :rem_con: An instance of the remote console shell session to the probe.
    :old_probe_configs_dict: A dictionary of all the probe configurations.
    :options_type: In this case, interface_non_specific to indicate that we need send one command for each config attribute.
    :logger: An instance of the logger class that we can use to write errors and exceptions to a local log file.
    :return: The filled in old_probe_configs_dict and status = True if all commands pass.
    Return the old_probe_configs_dict and status = False if any errors occur.
    """
    try:
        for config_attribute in config_attributes_list:
            if config_attribute == 'citrix_discover_apps': # special case where citrix commands include a space char.
                command = "get " + 'citrix discover_apps' + "\n"
            elif config_attribute == 'citrix_server_push':
                command = "get " + 'citrix server_push' + "\n"
            elif config_attribute == 'citrix_wildcard_support':
                command = "get " + 'citrix wildcard_support' + "\n"
            elif config_attribute == 'citrix_channel_monitoring':
                command = "get " + 'citrix channel_monitoring' + "\n"
            elif config_attribute == 'h248_protocols':
                command = "get " + 'h248 protocols' + "\n"
            elif config_attribute == 'vq_dtmf_events':
                command = "get " + 'vq dtmf_events' + "\n"
            elif config_attribute == 'vq_payload':
                command = "get " + 'vq payload' + "\n"
            elif config_attribute == 'krb_maxname':
                command = "get " + 'krb maxname' + "\n"
            elif config_attribute == 'krb_ntr':
                command = "get " + 'krb ntr' + "\n"
            else:
                command = "get " + config_attribute + "\n"
            output = execute_single_command_on_remote(command, rem_con, logger) # Run the command.
            if output == False:
                logger.error(f'[ERROR] get_probe_options_non_interface_specific, Console command: {command} failed')
                status = False
                return old_probe_configs_dict, status
            formatted_options_configs, status = get_formatted_options_configs(output, logger)
            if status == False:
                logger.error(f'[ERROR] get_probe_options_non_interface_specific, get_formatted_options_configs failed')
                return old_probe_configs_dict, status
            old_probe_configs_dict, status = process_output_non_interface(old_probe_configs_dict, options_type, config_attribute, formatted_options_configs, logger)
            if status == False:
                logger.error(f'[ERROR] get_probe_options_non_interface_specific, process_output_non_interface failed')
                return old_probe_configs_dict, status
    except Exception:
        logger.exception(f"[ERROR] An exception occurred in get_probe_options_non_interface_specific, Getting probe options")
        status = False
        return old_probe_configs_dict, status
    status = True
    return old_probe_configs_dict, status

def get_probe_options_single_command_multi_interface(config_attributes_list, interface_list, rem_con, old_probe_configs_dict, options_type, logger):
    """
    This is another example of how get <setting> returns a wildly different format from other get commands.
    In this case a single get command returns a list of each setting for each interface.
    The list of options returned by the probe will be used to fill in the attributes for the old_probe_configs_dict.
    :config_attributes_list: A list of attribute names to be entered into the old_probe_configs_dict.
    :interface_list: A list of probe monitor interface numbers that are available.
    :rem_con: An instance of the remote console shell session to the probe.
    :old_probe_configs_dict: A dictionary of all the probe configurations.
    :options_type: The name of the probe options that we want to fetch from the probe.
    :logger: An instance of the logger class that we can use to write errors and exceptions to a local log file.
    :return: The filled in old_probe_configs_dict and status = True if all commands pass.
    Return the old_probe_configs_dict and status = False if any errors occur.
    """
    try:
        for config_attribute in config_attributes_list:
            command = "get " + config_attribute + "\n" # One command returns a list of interface settings to parse through.
            #print(f'\ncommand is: {command}')
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] get_probe_options_single_command_multi_interface, Console command: {command} failed')
                status = False
                return old_probe_configs_dict, status
            formatted_options_configs, status = get_formatted_options_configs(output, logger)
            if status == False:
                logger.error(f'[ERROR] get_probe_options_per_interface, get_formatted_options_configs failed')
                return old_probe_configs_dict, status
            #print(f'\nformatted_options_configs is: {formatted_options_configs}')
            # one by one rather than passing the whole config attributes list to process_output_per_interface.
            for interface in interface_list: # In this case, loop through each line returned for each interface.
                old_probe_configs_dict, status = process_output_per_interface(config_attribute, old_probe_configs_dict, options_type, formatted_options_configs, interface, logger)
                if status == False:
                    logger.error(f'[ERROR] get_probe_options_per_interface, process_output_per_interface failed')
                    return old_probe_configs_dict, status
    except Exception:
        logger.exception(f"[ERROR] An exception occurred in get_probe_options_single_command_multi_interface, Get config attribute for multi-interface")
        status = False
        return old_probe_configs_dict, status
    status = True
    return old_probe_configs_dict, status

def get_probe_security_options(config_attributes_list, options_type, rem_con, old_probe_configs_dict, logger):
    """
    There is no 'get security_options' cli command, so we must get these setting directly from the menu.
    The list of options returned by the probe will be used to fill in the attributes for the old_probe_configs_dict.
    :config_attributes_list: A list of attribute names to be entered into the old_probe_configs_dict.
    :options_type: The options category to enter into the localconsole menu (security_options in this case).
    :rem_con: An instance of the remote console shell session to the probe.
    :old_probe_configs_dict: A dictionary of all the probe configurations.
    :logger: An instance of the logger class that we can use to write errors and exceptions to a local log file.
    :return: The filled in old_probe_configs_dict and status = True if all commands pass.
    Return the old_probe_configs_dict and status = False if any errors occur.
    """
    try:
        command = "quit\n" # Get out of the command line and back to the main menu
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            logger.error(f'[ERROR] get_probe_security_options, Console command: {command} failed')
            status = False
            return old_probe_configs_dict, status
        if 'Probe IP V4 address' not in output:
            logger.error(f'[ERROR] get_probe_security_options, Console command: {command} has Unexpected output: {output}')
            status = False
            return old_probe_configs_dict, status

        command = "13\n" # Get into the security options menu
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            logger.error(f'[ERROR] get_probe_security_options, Console command: {command} failed')
            status = False
            return old_probe_configs_dict, status
        if 'Secure Access Menu:' not in output:
            logger.error(f'[ERROR] get_probe_security_options, Console command: {command} has Unexpected output: {output}')
            status = False
            return old_probe_configs_dict, status

        formatted_options_configs, status = get_formatted_options_configs(output, logger)
        if status == False:
            logger.error(f'[ERROR] get_probe_options, get_formatted_options_configs failed')
            return old_probe_configs_dict, status
        for config_attribute in config_attributes_list:
            old_probe_configs_dict, status = process_output_non_interface(old_probe_configs_dict, options_type, config_attribute, formatted_options_configs, logger)
            if status == False:
                logger.error(f'[ERROR] get_probe_options, process_output_non_interface failed')
                return old_probe_configs_dict, status
    except Exception:
        logger.exception(f"[ERROR] An exception occurred in get_probe_security_options, Getting the Security Options menu")
        status = False
        return old_probe_configs_dict, status

    status = True
    return old_probe_configs_dict, status

def get_probe_interface_list(old_probe_configs_dict, options_type, rem_con, logger):
    """
    Get the list of probe interfaces via the localconsole menu option 7.
    Validate the output info returned and put the interface number into a list that we can use to loop on later.
    Add the interface number and description to the old_probe_configs_dict.
    :old_probe_configs_dict: A dictionary of all the probe configurations.
    :options_type: The options category to enter into the localconsole menu (security_options in this case).
    :rem_con: An instance of the remote console shell session to the probe.
    :logger: An instance of the logger class that we can use to write errors and exceptions to a local log file.
    :return: The list of interface numbers and status = True if all commands pass.
    Return and empty interface list and status = False if any errors occur.
    """
    interface_list = [] # Initialize an empty list to put our available monitor interfaces into.
    try:
        command = "localconsole\n"
        output = execute_single_command_on_remote(command, rem_con, logger)
        if 'Interface number :' not in output: # There may be a session already open on this probe...
        # or the probe services are not running.
            print(f'\n[CRITICAL] Attempt to run the localconsole script failed, the menu was not presented')
            print(f'There may be another console session already open? Please close them.')
            print(f'Otherwise the probe processes may not be running - check with ./PS')
            logger.critical("[CRITICAL] get_probe_interface_list - 'localconsole' command failed")
            status = False
            return old_probe_configs_dict, interface_list, status
        if output == False:
            logger.critical("[CRITICAL] get_probe_interface_list - command 'localconsole' failed")
            status = False
            return old_probe_configs_dict, interface_list, status
        command = "7\n" # We need to know what interfaces exist on this probe. Enter interface options menu.
        #print('Getting Interfaces...', end="")
        output = execute_single_command_on_remote(command, rem_con, logger) # Send option 7 to the localconsole menu.
        if output == False:
            logger.error("[ERROR] get_probe_interface_list - option '7' command failed")
            status = False
            return old_probe_configs_dict, interface_list, status

        formatted_options_configs, status = get_formatted_options_configs(output, logger)
        if status == False:
            logger.error(f'[ERROR] get_probe_interface_list, get_formatted_options_configs failed')
            return old_probe_configs_dict, interface_list, status
        #print(f'\nformatted_options_configs is: {formatted_options_configs}')
        for formatted_option in formatted_options_configs:
            # Add the interface number to the list of monitor interfaces.
            if formatted_option == '7': # This is the command itself, ignore it.
                continue
            elif '[FDX]' in formatted_option: # Validate output data.
                interface_num = formatted_option[1:3].strip()
                interface_list.append(interface_num) # Get the interface number.
                # Add inf # and description to dictionary as a key:value pair.
                # Note that if you don't convert to integer, the sort order by default is wrong.
                old_probe_configs_dict[options_type][0][int(interface_num)] = formatted_option[4:]
            elif '[HDX]' in formatted_option: # Validate output data.
                interface_num = formatted_option[1:3].strip()
                interface_list.append(interface_num) # Get the interface number.
                old_probe_configs_dict[options_type][0][int(interface_num)] = formatted_option[4:]
            elif '[MDX]' in formatted_option: # Validate output data.
                interface_num = formatted_option[1:3].strip()
                interface_list.append(interface_num) # Get the interface number.
                old_probe_configs_dict[options_type][0][int(interface_num)] = formatted_option[4:]
            elif 'AGGREGATE IFN' in formatted_option: # Validate output data.
                interface_num = formatted_option[1:3].strip()
                interface_list.append(interface_num) # Get the interface number.
                old_probe_configs_dict[options_type][0][int(interface_num)] = formatted_option[4:]
            elif '[PFS_FDX]' in formatted_option: # Validate output data.
                interface_num = formatted_option[1:3].strip()
                interface_list.append(interface_num) # Get the interface number.
                old_probe_configs_dict[options_type][0][int(interface_num)] = formatted_option[4:]
            elif '[PFS_HDX]' in formatted_option: # Validate output data.
                interface_num = formatted_option[1:3].strip()
                interface_list.append(interface_num) # Get the interface number.
                old_probe_configs_dict[options_type][0][int(interface_num)] = formatted_option[4:]
            else:
                print(f'[ERROR] There is an interface mode type that I do not recognize: {formatted_option}')
                logger.error(f'[ERROR] There is an interface mode type that I do not recognize: {formatted_option}')
                status = False
                return old_probe_configs_dict, interface_list, status

        command = "99\n" # Return to the main localconsole menu page.
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            logger.error("[ERROR] get_probe_interface_list - command '99' return to main menu failed")
            status = False
            return old_probe_configs_dict, interface_list, status

        command = "11\n" # Enter the command line mode in localconsole.
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            logger.error("[ERROR] get_probe_interface_list - command '11' return to main menu failed")
            status = False
            return old_probe_configs_dict, interface_list, status
        status = True
        return old_probe_configs_dict, interface_list, status
    except Exception:
        logger.exception(f"[ERROR] An exception occurred in get_probe_interface_list")
        status = False
        return old_probe_configs_dict, interface_list, status

def do_agent_reset(command, rem_con, logger):
    """
    Sends to the remote console either a 'y' yes to respond to a reset agent confirmation message from
    the localconsole menu, or a 'do reset' command if not responding to a reset agent prompt from localconsole.
    :command: Either 'y\n' if responding to a prompt or 'do reset\n' if not responding to a prompt.
    :rem_con: An instance of the remote console shell session to the probe.
    :logger: An instance of the logger class that we can use to write errors and exceptions to a local log file.
    :return: False if any command fails, True if the agent resets and we get the localconsole menu back.
    """
    try:
        spinner = spinning_cursor() # Initialize a spinner object for long wait times.

        if command == "y\n": # We are responding to a prompt, check for the expected output
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] do_agent_reset, Console command: {command} failed')
                return False
            if 'Rebooting after 5 secs' not in output:
                logger.error(f'[ERROR] do_agent_reset, Console command: {command} has Unexpected output: {output}')
                return False
        if command == 'do reset\n': # You have to enter a confirmation after sending a 'do reset' command.
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] do_agent_reset, Console command: {command} failed')
                return False
            if 'WARNING : agent will be reset, confirm' not in output:
                logger.error(f'[ERROR] do_agent_reset, Console command: {command} has Unexpected output: {output}')
                return False
            command = "y\n"
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] do_agent_reset, Console command: {command} failed')
                return False
            if 'Rebooting after 5 secs' not in output:
                logger.error(f'[ERROR] do_agent_reset, Console command: {command} has Unexpected output: {output}')
                return False
        timer = 60 # We will wait 60 seconds for the probe agent to reset.
        display_spinner(spinner, timer)

        while True:
            #print('\nWe are trying to get back into localconsole following an agent reset')
            command = "localconsole\n" # Following an agent reset, you have to launch localconsole again.
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] do_agent_reset, Console command: {command} failed')
                return False
            elif 'Error connecting to server:: Connection refused' in output:
                timer = 30 # We will wait 30 seconds for the localconsole to become available.
                display_spinner(spinner, timer) # Wait a little longer and try again.
                print('Done') # Erase the last spinner character and return the cursor to home.
                continue
            elif 'History file:' in output and 'Error connecting to server:: Connection refused' not in output:
                break # We successfully entered the localconsole menu. Break.
            else:
                logger.error(f'[ERROR] do_agent_reset, Console command: {command} has Unexpected output: {output}')
                return False

        while True:
            #print('\nWe are trying to get back into localconsole command line mode following an agent reset')
            command = "11\n" # Enter the command line mode in localconsole.
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] do_agent_reset, Console command: {command} failed')
                return False
            elif 'Enter "quit" to exit command-line mode' in output: # We successfully entered command line mode. Break.
                break
            elif 'Please wait while the agent is coming up' in output:
                command = "\n" # Press enter to continue.
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] do_agent_reset, Console command: {command} failed')
                    return False
                timer = 60 # We will wait 30 seconds for the probe agent to finish its reset.
                display_spinner(spinner, timer) # Wait a little longer and try again.
                print('Done') # Erase the last spinner character and return the cursor to home.
                continue # Wait a little longer and try again.
            else:
                logger.error(f'[ERROR] do_agent_reset, Console command: {command} has Unexpected output: {output}')
                return False
    except Exception:
        logger.exception(f"[ERROR] do_agent_reset, An exception occurred while attempting to reset the agent")
        return False

    return True

def set_probe_other_interface_specific(old_probe_configs_dict, interface_list, rem_con, logger):
    """
    For each monitor interface, set the probe config parameters to match the desired POC settings.
    :old_probe_configs_dict: A dictionary of all the probe configurations.
    :interface_list: A list of probe monitor interface numbers that are available.
    :rem_con: An instance of the remote console shell session to the probe.
    :logger: An instance of the logger class that we can use to write errors and exceptions to a local log file.
    :return: False if any command fails, True if all commands pass.
    """
    try:
        # We should already be in the command line entry mode within the localconsole menu.
        for interface in interface_list:
            if old_probe_configs_dict['interface_specific'][0]['interface ' + str(interface)][0]['skt_vlan_enable'] != 'on':
                command = 'set skt_vlan_enable ' + interface + ' on' + "\n"
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_other_interface_specific, Console command: {command} failed')
                    return False
                # 'MICRO_SEGMENT is enabled on interface' may be returned. We won't be able to set skt_vlan_enable in this case.
                if '%' not in output: # The response to the set skt_vlan_enable command is not the expected '%'.
                    logger.error(f'[ERROR] set_probe_other_interface_specific, Console command: {command} has Unexpected output: {output}')
                    return False

            if old_probe_configs_dict['interface_specific'][0]['interface ' + str(interface)][0]['span_duplicate'] != 'on':
                command = 'set span_duplicate ' + interface + ' on' + "\n"
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_other_interface_specific, Console command: {command} failed')
                    return False
                if '%' not in output: # The response to the set span_duplicate command is not the expected '%'.
                    logger.error(f'[ERROR] set_probe_other_interface_specific, Console command: {command} has Unexpected output: {output}')
                    return False

            if old_probe_configs_dict['interface_specific'][0]['interface ' + str(interface)][0]['ssl_sni'] != 'on':
                command = 'set ssl_sni ' + interface + ' on' + "\n"
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_other_interface_specific, Console command: {command} failed')
                    return False
                if '%' not in output: # The response to the set ssl_sni command is not the expected '%'.
                    logger.error(f'[ERROR] set_probe_other_interface_specific, Console command: {command} has Unexpected output: {output}')
                    return False

            if old_probe_configs_dict['interface_specific'][0]['interface ' + str(interface)][0]['community_type'] != 'ip_address':
                command = 'set community_type ' + interface + ' ip_address' + "\n"
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_other_interface_specific, Console command: {command} failed')
                    return False
                if '%' not in output: # The response to the set community_type command is not the expected '%'.
                    logger.error(f'[ERROR] set_probe_other_interface_specific, Console command: {command} has Unexpected output: {output}')
                    return False
    except Exception:
        logger.exception(f"[ERROR] set_probe_other_interface_specific, An exception has occurred in set probe other")
        return False
    # We need to stay in the command line mode for the next action.
    return True

def set_probe_asi_interface_specific(old_probe_configs_dict, interface_list, rem_con, logger):
    """
    For each monitor interface, set the asi config parameters to match the desired POC settings.
    :old_probe_configs_dict: A dictionary of all the probe configurations.
    :interface_list: A list of probe monitor interface numbers that are available.
    :rem_con: An instance of the remote console shell session to the probe.
    :logger: An instance of the logger class that we can use to write errors and exceptions to a local log file.
    :return: False if any command fails, True if all commands pass.
    """
    try:
        # We should already be in the command line entry mode within the localconsole menu.
        for interface in interface_list:
            if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['kti_peak_type'] != 'octet':
                command = 'set asi ' + interface + ' kti_peak_type octet' + "\n"
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} failed')
                    return False
                if '%' not in output: # The response to the set asi command is not the expected '%'.
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} has Unexpected output: {output}')
                    return False

            if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['kti_peak_interval'] != '100000':
                command = 'set asi ' + interface + ' kti_peak_interval 100000' + "\n"
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} failed')
                    return False
                if '%' not in output: # The response to the set asi command is not the expected '%'.
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} has Unexpected output: {output}')
                    return False

            if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['ksi_mtu_size'] != '1518':
                command = 'set asi ' + interface + ' ksi_mtu_size 1518' + "\n"
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} failed')
                    return False
                if '%' not in output: # The response to the set asi command is not the expected '%'.
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} has Unexpected output: {output}')
                    return False

            if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['uc_conv'] != 'on':
                command = 'set asi ' + interface + ' uc_conv on' + "\n"
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} failed')
                    return False
                if '%' not in output: # The response to the set asi command is not the expected '%'.
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} has Unexpected output: {output}')
                    return False

            # If client IP mode is on, then currently you are not allowed to have server_table on.
            if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['server_table'] != 'off':
                command = 'set asi ' + interface + ' server_table off' + "\n"
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} failed')
                    return False
                if '%' not in output: # The response to the set asi command is not the expected '%'.
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} has Unexpected output: {output}')
                    return False

            if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['disc_table'] != 'on':
                command = 'set asi ' + interface + ' disc_table on' + "\n"
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} failed')
                    return False
                if '%' not in output: # The response to the set asi command is not the expected '%'.
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} has Unexpected output: {output}')
                    return False

            if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['vital_table'] != 'on':
                command = 'set asi ' + interface + ' vital_table on' + "\n"
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} failed')
                    return False
                if '%' not in output: # The response to the set asi command is not the expected '%'.
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} has Unexpected output: {output}')
                    return False

            if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['tcp_monitor'] != 'on':
                command = 'set asi ' + interface + ' tcp_monitor on' + "\n"
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} failed')
                    return False
                if '%' not in output: # The response to the set asi command is not the expected '%'.
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} has Unexpected output: {output}')
                    return False

            if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['conv'] != 'off':
                command = 'set asi ' + interface + ' conv off' + "\n"
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} failed')
                    return False
                if '%' not in output: # The response to the set asi command is not the expected '%'.
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} has Unexpected output: {output}')
                    return False

            if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['conv ports'] != 'off':
                command = 'set asi ' + interface + ' conv ports off' + "\n"
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} failed')
                    return False
                if '%' not in output: # The response to the set asi command is not the expected '%'.
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} has Unexpected output: {output}')
                    return False

            if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['conv qos'] != 'off':
                command = 'set asi ' + interface + ' conv qos off' + "\n"
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} failed')
                    return False
                if '%' not in output: # The response to the set asi command is not the expected '%'.
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} has Unexpected output: {output}')
                    return False

            if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['la_type'] != 'site':
                command = 'set asi ' + interface + ' la_burst site' + "\n"
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} failed')
                    return False
                if '%' not in output: # The response to the set asi command is not the expected '%'.
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} has Unexpected output: {output}')
                    return False

            if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['host_activity'] != 'off':
                command = 'set asi ' + interface + ' host_activity off' + "\n"
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} failed')
                    return False
                if '%' not in output: # The response to the set asi command is not the expected '%'.
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} has Unexpected output: {output}')
                    return False

            if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['htt'] != 'off':
                command = 'set asi ' + interface + ' htt off' + "\n"
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} failed')
                    return False
                if '%' not in output: # The response to the set asi command is not the expected '%'.
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} has Unexpected output: {output}')
                    return False

            if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['ksi 1min'] != 'on':
                command = 'set asi ' + interface + ' ksi 1min on' + "\n"
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} failed')
                    return False
                if '%' not in output: # The response to the set asi command is not the expected '%'.
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} has Unexpected output: {output}')
                    return False

            if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['ksi client_ip'] != 'on':
                command = 'set asi ' + interface + ' ksi client_ip on' + "\n"
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} failed')
                    return False
                if 'KSI client_ip is only allowed on ISNG Devices' in output:
                    print('Error')
                    print('Unable to set KSI client IP mode as this probe is not an ISNG Device')
                    print(f"The probe model is: {old_probe_configs_dict['agent_configs'][0]['model_number']}")
                    logger.critical(f'[CRITICAL] set_probe_asi_interface_specific, Unable to set KSI client IP mode as this probe is not an ISNG Device')
                    logger.critical(f"[CRITICAL] set_probe_asi_interface_specific, The probe model is: {old_probe_configs_dict['agent_configs'][0]['model_number']}")
                    return False
                if 'WARNING: client_ip on will disable ASI_CONV and HOST_ACTIVITY' not in output: # The response to the set asi command is not the expected '%'.
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} has Unexpected output: {output}')
                    return False

            if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['subscriber'] != 'off':
                command = 'set asi ' + interface + ' subscriber off' + "\n"
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} failed')
                    return False
                if '%' not in output: # The response to the set asi command is not the expected '%'.
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} has Unexpected output: {output}')
                    return False

            if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['1-min'] != 'on':
                command = 'set asi ' + interface + ' 1-min on' + "\n"
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} failed')
                    return False
                if '%' not in output: # The response to the set asi command is not the expected '%'.
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} has Unexpected output: {output}')
                    return False

            if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['15-sec'] != 'on':
                command = 'set asi ' + interface + ' 15-sec on' + "\n"
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} failed')
                    return False
                if '%' not in output: # The response to the set asi command is not the expected '%'.
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} has Unexpected output: {output}')
                    return False

            if old_probe_configs_dict['asi'][0]['interface ' + str(interface)][0]['url_disc_table'] != 'on':
                command = 'set asi ' + interface + ' url_disc_table on' + "\n"
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} failed')
                    return False
                if '%' not in output: # The response to the set asi command is not the expected '%'.
                    logger.error(f'[ERROR] set_probe_asi_interface_specific, Console command: {command} has Unexpected output: {output}')
                    return False
    except Exception:
        logger.exception(f"[ERROR] set_probe_asi_interface_specific, An exception has occurred while setting ASI probe configurations")
        return False
    return True

def set_probe_options_per_interface(old_probe_configs_dict, interface_list, rem_con, logger):
    """
    For each monitor interface, set the interface options config parameters to match the desired POC settings.
    :old_probe_configs_dict: A dictionary of all the probe configurations.
    :interface_list: A list of probe monitor interface numbers that are available.
    :rem_con: An instance of the remote console shell session to the probe.
    :logger: An instance of the logger class that we can use to write errors and exceptions to a local log file.
    :return: False if any command fails, True if all commands pass.
    """

    enterprise_set_flag = 0 # If you change to enterprise mode, you have to reset the agent again.
    try:
        command = "quit\n" # Exit the command line menu to the main menu
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} failed')
            return False
        if 'Probe IP V4 address' not in output: # We did not enter the localconsole menu correctly.
            logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} has Unexpected output: {output}')
            return False

        command = "7\n" # We need to get to the list of interfaces menu.
        output = execute_single_command_on_remote(command, rem_con, logger) # Send option 7 to the localconsole menu.
        if output == False:
            logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} failed')
            return False
        if 'Select Interface :' not in output: # We did not enter the interface menu correctly.
            logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} has Unexpected output: {output}')
            return False

        for interface in interface_list:
            #print(f'interface is: {interface}')
            command = str(interface + '\n') # Select the interface to configure by sending the interface number.
            output = execute_single_command_on_remote(command, rem_con, logger) # Send option 7 to the localconsole menu.
            if output == False:
                logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} failed')
                return False
            if 'Interface Options Menu:' not in output: # We did not enter the interface options menu correctly.
                logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} has Unexpected output: {output}')
                return False

            if old_probe_configs_dict['interface_options'][0]['interface ' + str(interface)][0]['power_alarm_util'] != 'off':
                command = "2\n" # Toggle the power_alarm_util setting.
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} failed')
                    return False
                if 'Interface Options Menu:' not in output:
                    logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} has Unexpected output: {output}')
                    return False

            if old_probe_configs_dict['interface_options'][0]['interface ' + str(interface)][0]['power_alarm_resp'] != 'off':
                command = "3\n" # Toggle the power_alarm_resp setting.
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} failed')
                    return False
                if 'Interface Options Menu:' not in output:
                    logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} has Unexpected output: {output}')
                    return False

            if old_probe_configs_dict['interface_options'][0]['interface ' + str(interface)][0]['admin_shutdown'] != 'off':
                command = "5\n" # Toggle the admin_shutdown setting.
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} failed')
                    return False
                if 'Interface Options Menu:' not in output:
                    logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} has Unexpected output: {output}')
                    return False

            if old_probe_configs_dict['interface_options'][0]['interface ' + str(interface)][0]['Data w/o Control Tcm'] != 'off':
                command = "10\n" # Toggle the Data w/o Control Tcm setting.
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} failed')
                    return False
                if 'Interface Options Menu:' not in output:
                    logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} has Unexpected output: {output}')
                    return False

            if old_probe_configs_dict['interface_options'][0]['interface ' + str(interface)][0]['vifn_enable'] != 'on':
                command = "34\n" # Toggle the vifn_enable setting.
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} failed')
                    return False
                if 'Interface Options Menu:' not in output:
                    logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} has Unexpected output: {output}')
                    return False

            if old_probe_configs_dict['interface_options'][0]['interface ' + str(interface)][0]['vifn_mode'] != 'vlan-site-qos':
                command = "36\n" # Enter the vifn_mode menu.
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} failed')
                    return False
                if 'Select vifn_mode:' not in output:
                    logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} has Unexpected output: {output}')
                    return False
                command = "38\n" # Enter the vlan-site-qos as the vifn_mode.
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} failed')
                    return False
                if 'Interface Options Menu:' not in output: # localconsole returns us to the interface options menu.
                    logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} has Unexpected output: {output}')
                    return False

            if old_probe_configs_dict['interface_options'][0]['interface ' + str(interface)][0]['HTTP Mode'] != 'Monitor URL Only':
                command = "45\n" # Enter the HTTP Mode menu.
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} failed')
                    return False
                if 'Select HTTP Mode:' not in output:
                    logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} has Unexpected output: {output}')
                    return False
                command = "1\n" # Select Monitor URL Only.
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} failed')
                    return False
                if 'Interface Options Menu:' not in output:
                    logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} has Unexpected output: {output}')
                    return False

            if old_probe_configs_dict['interface_options'][0]['interface ' + str(interface)][0]['M3UA Table'] != 'off':
                command = "52\n" # Toggle the M3UA Table setting.
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} failed')
                    return False
                if 'Interface Options Menu:' not in output:
                    logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} has Unexpected output: {output}')
                    return False

            if old_probe_configs_dict['interface_options'][0]['interface ' + str(interface)][0]['enable xDR'] != 'on':
                command = "53\n" # Toggle the enable xDR setting.
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} failed')
                    return False
                if 'Interface Options Menu:' not in output:
                    logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} has Unexpected output: {output}')
                    return False

            if old_probe_configs_dict['interface_options'][0]['interface ' + str(interface)][0]['Tunnel Parsing'] != 'off':
                command = "54\n" # Toggle the Tunnel Parsing setting.
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} failed')
                    return False
                if 'Interface Options Menu:' not in output:
                    logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} has Unexpected output: {output}')
                    return False

            if old_probe_configs_dict['interface_options'][0]['interface ' + str(interface)][0]['interface type'] != 'Enterprise':
                command = "55\n" # Enter the interface type menu.
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} failed')
                    return False
                if 'Select interface type:' not in output:
                    logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} has Unexpected output: {output}')
                    return False
                command = "1\n" # Select Enterprise type.
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} failed')
                    return False
                if 'Interface Options Menu:' not in output:
                    logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} has Unexpected output: {output}')
                    return False
                enterprise_set_flag = 1 # If you change to enterprise mode, you have to reset the agent again.

            if old_probe_configs_dict['interface_options'][0]['interface ' + str(interface)][0]['Data w/o Control'] != 'off':
                command = "54\n" # Toggle the Data w/o Control setting.
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} failed')
                    return False
                if 'Interface Options Menu:' not in output:
                    logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} has Unexpected output: {output}')
                    return False
            command = "99\n" # We need to get back to the list of interfaces menu.
            output = execute_single_command_on_remote(command, rem_con, logger) # Send option 7 to the localconsole menu.
            if output == False:
                logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} failed')
                return False
            if 'Select Interface :' not in output: # We did not enter the interface list menu correctly.
                logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} has Unexpected output: {output}')
                return False

        command = "99\n" # Exit the interfaces list menu back up to the main menu
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} failed')
            return False
        if 'Probe IP V4 address' not in output: # We did not enter the localconsole menu correctly.
            logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} has Unexpected output: {output}')
            return False

        command = "11\n" # Enter the command line mode in localconsole.
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} failed')
            return False
        if 'Enter "quit" to exit command-line mode' not in output: # We did not enter command line mode.
            logger.error(f'[ERROR] set_probe_options_per_interface, Console command: {command} has Unexpected output: {output}')
            return False

        if enterprise_set_flag == 1: # A change of interface type to enterprise mode occurred. We need to reset agent.
            reset_agent_command = 'do reset\n' # Respond to the confirmation prompt with a 'y'.
            print(f"\nOne or more modifications to interface type 'Enterprise' requires a probe agent reset again, please wait...", end='')
            logger.info(f"\nOne or more modifications to interface type 'Enterprise' requires an additional probe agent reset")
            reset_status = do_agent_reset(reset_agent_command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] Unable to reset agent following a change of interface type to Enterprise')
                return False
    except Exception:
        logger.exception("Fatal error in set_probe_options_per_interface:")
        return False

    return True

def set_probe_options_non_interface_specific(old_probe_configs_dict, rem_con, logger):
    """
    Set the major, probe-wide non-interface specific settings. Do agent resets as needed.
    :old_probe_configs_dict: A dictionary of all the probe configurations.
    :rem_con: An instance of the remote console shell session to the probe.
    :logger: An instance of the logger class that we can use to write errors and exceptions to a local log file.
    :return: False if any command fails, True if all commands pass.
    """
    try:
        reset_agent_command = ''
        if old_probe_configs_dict['non_interface_specific'][0]['vq_payload'] == 'on, but not enough resources available':
            command = "set vq payload off\n"
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_options_non_interface_specific, Console command: {command} failed')
                return False
        elif old_probe_configs_dict['non_interface_specific'][0]['vq_payload'] != 'on':
            command = "set vq payload on\n"
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_options_non_interface_specific, Console command: {command} failed')
                return False
            if 'vq payload will be updated on next reset' not in output or '%' not in output:
                logger.error(f'[ERROR] set_probe_options_non_interface_specific, Console command: {command} has Unexpected output: {output}')
                return False
            reset_agent_command = 'do reset\n' # Not a prompt to reset agent, so we will do it after table size allocation.

        if old_probe_configs_dict['non_interface_specific'][0]['config_download'] != 'off':
            command = "set config_download off\n"
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_options_non_interface_specific, Console command: {command} failed')
                return False

        if old_probe_configs_dict['non_interface_specific'][0]['vq_dtmf_events'] != 'on':
            command = "set vq dtmf_events on\n"
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_options_non_interface_specific, Console command: {command} failed')
                return False

        if old_probe_configs_dict['non_interface_specific'][0]['asi_mode'] != 'asi':
            command = "set asi_mode ASI\n"
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_options_non_interface_specific, Console command: {command} failed')
                return False
            if "Please rerun 'set table_size_allocation commit' to ensure correct table sizes" not in output:
                logger.error(f'[ERROR] set_probe_options_non_interface_specific, Console command: {command} has Unexpected output: {output}')
                return False
            reset_agent_command = 'do reset\n' # Need to reallocate interface table sizes before reset.

        if old_probe_configs_dict['non_interface_specific'][0]['probe_mode'] != 'half-duplex':
            command = "set probe_mode hdx\n"
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_options_non_interface_specific, Console command: {command} failed')
                return False
            if 'Warning: This will delete all existing flows and reboot the probe!!' not in output:
                logger.error(f'[ERROR] set_probe_options_non_interface_specific, Console command: {command} has Unexpected output: {output}')
                return False
            command = "y\n"
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_options_non_interface_specific, Console command: {command} failed')
                return False
            if "Error: For vASI probe_mode must be 'hdx'!" in output: # Cannot set vStream to FDX probe_mode.
                    logger.error(f'[ERROR] set_probe_options_non_interface_specific, Console command: {command} failed')
                    logger.error(f"[ERROR] set_probe_options_non_interface_specific, Error message: For vASI probe_mode must be 'hdx'!")
                    return False
            if 'WARNING : agent will be reset, confirm [n]' not in output:
                logger.error(f'[ERROR] set_probe_options_non_interface_specific, Console command: {command} has Unexpected output: {output}')
                return False

            reset_agent_command = 'y\n' # In this case you are prompted to reset the agent before coninuing.

        if reset_agent_command != '': # Skip the reset if none of the major settings needs to be modified.
            print(f'\nResetting the probe agent following major probe mode set operations, please wait...', end='')
            reset_status = do_agent_reset(reset_agent_command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_options_non_interface_specific, Console command: {command} failed')
                return False
            else:
                print('Done')

        command = "set tsa auto\n"
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            logger.error(f'[ERROR] set_probe_options_non_interface_specific, Console command: {command} failed')
            return False
        if "A commit and reset will be required before this setting takes effect" not in output:
            logger.error(f'[ERROR] set_probe_options_non_interface_specific, Console command: {command} has Unexpected output: {output}')
            return False
        command = "set tsa commit\n"
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            logger.error(f'[ERROR] set_probe_options_non_interface_specific, Console command: {command} failed')
            return False
        if "Committed new table sizes" not in output:
            logger.error(f'[ERROR] set_probe_options_non_interface_specific, Console command: {command} has Unexpected output: {output}')
            return False
        reset_agent_command = 'y\n' # In this case you are prompted to reset the agent before coninuing.
        print(f'\nResetting the probe agent following table size allocation commit, please wait...', end='')
        reset_status = do_agent_reset(reset_agent_command, rem_con, logger)
        if output == False:
            logger.error(f'[ERROR] set_probe_options_non_interface_specific, Console command: {command} failed')
            return False
        else:
            print('Done')
    except Exception:
        logger.exception(f"[ERROR] set_probe_options_non_interface_specific, An exception has occurred while setting probe options non interface specific")
        return False

    return True

def set_probe_software_options(old_probe_configs_dict, rem_con, logger):
    """
    Set the probe software options settings.
    :old_probe_configs_dict: A dictionary of all the probe configurations.
    :rem_con: An instance of the remote console shell session to the probe.
    :logger: An instance of the logger class that we can use to write errors and exceptions to a local log file.
    :return: False if any command fails, True if all commands pass.
    """
    try:
        command = "8\n" # We need to get into the agent options menu.
        output = execute_single_command_on_remote(command, rem_con, logger) # Send option 8 to the localconsole menu.
        if output == False:
            logger.error(f'[ERROR] set_probe_software_options, Console command: {command} failed')
            return False
        if 'Software Options Menu:' not in output: # We did not enter the interface menu correctly.
            logger.error(f'[ERROR] set_probe_software_options, Console command: {command} has Unexpected output: {output}')
            return False

        if old_probe_configs_dict['software_options'][0]['Response Time Monitor'] != 'on':
            command = "2\n" # Toggle the Response Time Monitor setting
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_software_options, Console command: {command} failed')
                return False
            if 'Software Options Menu:' not in output:
                logger.error(f'[ERROR] set_probe_software_options, Console command: {command} has Unexpected output: {output}')
                return False

        if old_probe_configs_dict['software_options'][0]['NL and AL Host'] != 'off':
            command = "3\n" # Toggle the NL and AL Host setting as this in not applicable to ASI mode
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_software_options, Console command: {command} failed')
                return False
            if 'Software Options Menu:' not in output:
                logger.error(f'[ERROR] set_probe_software_options, Console command: {command} has Unexpected output: {output}')
                return False

        if old_probe_configs_dict['software_options'][0]['NL and AL Conversation'] != 'off':
            command = "4\n" # Toggle the NL and AL Conversation setting s this in not applicable to ASI mode
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_software_options, Console command: {command} failed')
                return False
            if 'Software Options Menu:' not in output:
                logger.error(f'[ERROR] set_probe_software_options, Console command: {command} has Unexpected output: {output}')
                return False

        if old_probe_configs_dict['software_options'][0]['SBA Priority'] != 'on':
            command = "13\n" # Toggle the NL and AL Conversation setting
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_software_options, Console command: {command} failed')
                return False
            if 'Software Options Menu:' not in output:
                logger.error(f'[ERROR] set_probe_software_options, Console command: {command} has Unexpected output: {output}')
                return False

        command = "99\n" # Return to the main menu
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            logger.error(f'[ERROR] set_probe_software_options, Console command: {command} failed')
            return False
        if 'Probe IP V4 address' not in output: # We did not enter the localconsole menu correctly.
            logger.error(f'[ERROR] set_probe_software_options, Console command: {command} has Unexpected output: {output}')
            return False
    except Exception:
        logger.exception(f"[ERROR] set_probe_software_options, An exception has occurred while setting probe software options")
        return False

    return True

def set_probe_protocol_options(old_probe_configs_dict, rem_con, logger):
    """
    Set the probe protocol options settings.
    :old_probe_configs_dict: A dictionary of all the probe configurations.
    :rem_con: An instance of the remote console shell session to the probe.
    :logger: An instance of the logger class that we can use to write errors and exceptions to a local log file.
    :return: False if any command fails, True if all commands pass.
    """
    try:
        command = "15\n" # We need to get into the protocol options menu.
        output = execute_single_command_on_remote(command, rem_con, logger) # Send option 15 to the localconsole menu.
        if output == False:
            logger.error(f'[ERROR] set_probe_protocol_options, Console command: {command} failed')
            return False
        if 'Protocol Options Menu:' not in output: # We did not enter the interface menu correctly.
            logger.error(f'[ERROR] set_probe_protocol_options, Console command: {command} has Unexpected output: {output}')
            return False

        if old_probe_configs_dict['protocol_options'][0]['Pattern Matching'] != 'off':
            command = "2\n" # Toggle the Pattern Matching setting
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_protocol_options, Console command: {command} failed')
                return False
            if 'Protocol Options Menu:' not in output:
                logger.error(f'[ERROR] set_probe_protocol_options, Console command: {command} has Unexpected output: {output}')
                return False

        if old_probe_configs_dict['protocol_options'][0]['CORBA'] != 'off':
            command = "3\n" # Toggle the CORBA setting
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_protocol_options, Console command: {command} failed')
                return False
            if 'Protocol Options Menu:' not in output:
                logger.error(f'[ERROR] set_probe_protocol_options, Console command: {command} has Unexpected output: {output}')
                return False

        if old_probe_configs_dict['protocol_options'][0]['Conversation Port Discovery'] != 'on':
            command = "5\n" # Toggle the Conversation Port Discovery setting
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_protocol_options, Console command: {command} failed')
                return False
            if 'Protocol Options Menu:' not in output:
                logger.error(f'[ERROR] set_probe_protocol_options, Console command: {command} has Unexpected output: {output}')
                return False

        if old_probe_configs_dict['protocol_options'][0]['Skype Pattern Matching'] != 'off':
            command = "8\n" # Toggle the Conversation Port Discovery setting
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_protocol_options, Console command: {command} failed')
                return False
            if 'Protocol Options Menu:' not in output:
                logger.error(f'[ERROR] set_probe_protocol_options, Console command: {command} has Unexpected output: {output}')
                return False

        if old_probe_configs_dict['protocol_options'][0]['Extended FIS'] != 'off':
            command = "14\n" # Toggle the Extended FIS setting
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_protocol_options, Console command: {command} failed')
                return False
            if 'Protocol Options Menu:' not in output:
                logger.error(f'[ERROR] set_probe_protocol_options, Console command: {command} has Unexpected output: {output}')
                return False

        if old_probe_configs_dict['protocol_options'][0]['Voice and Video Quality'] != 'on':
            command = "15\n" # Toggle the Extended FIS setting
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_protocol_options, Console command: {command} failed')
                return False
            if 'Protocol Options Menu:' not in output:
                logger.error(f'[ERROR] set_probe_protocol_options, Console command: {command} has Unexpected output: {output}')
                return False

        command = "99\n" # Return to the main menu
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            logger.error(f'[ERROR] set_probe_protocol_options, Console command: {command} failed')
            return False
        if 'Probe IP V4 address' not in output: # We did not enter the localconsole menu correctly.
            logger.error(f'[ERROR] set_probe_protocol_options, Console command: {command} has Unexpected output: {output}')
            return False
    except Exception:
        logger.exception(f"[ERROR] set_probe_protocol_options, An exception has occurred while setting probe protocol options")
        return False
    return True

def set_probe_http_options(old_probe_configs_dict, rem_con, logger):
    """
    Set the probe protocol options settings.
    :old_probe_configs_dict: A dictionary of all the probe configurations.
    :rem_con: An instance of the remote console shell session to the probe.
    :logger: An instance of the logger class that we can use to write errors and exceptions to a local log file.
    :return: False if any command fails, True if all commands pass.
    """
    try:
        command = "11\n" # Enter the command line mode in localconsole.
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            logger.error(f'[ERROR] set_probe_http_options, Console command: {command} failed')
            return False
        if 'Enter "quit" to exit command-line mode' not in output: # We did not enter command line mode.
            logger.error(f'[ERROR] set_probe_http_options, Console command: {command} has Unexpected output: {output}')
            return False

        if old_probe_configs_dict['http'][0]['http web_classify'] != 'off':
            command = "set http web_classify off\n" # Change the http web_classify setting
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_http_options, Console command: {command} failed')
                return False
            if '%' not in output: # I am expecting the command line prompt to be returned.
                logger.error(f'[ERROR] set_probe_http_options, Console command: {command} has Unexpected output: {output}')
                return False

        if old_probe_configs_dict['http'][0]['http db_type'] != 'full':
            command = "set http db_type full\n" # Change the http db_type setting
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_http_options, Console command: {command} failed')
                return False
            if '%' not in output: # I am expecting the command line prompt to be returned.
                logger.error(f'[ERROR] set_probe_http_options, Console command: {command} has Unexpected output: {output}')
                return False

        if old_probe_configs_dict['http'][0]['http proxy_server_uri_search'] != 'off':
            command = "set http proxy_server_uri_search off\n" # Change the http proxy_server_uri_search setting
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_http_options, Console command: {command} failed')
                return False
            if '%' not in output: # I am expecting the command line prompt to be returned.
                logger.error(f'[ERROR] set_probe_http_options, Console command: {command} has Unexpected output: {output}')
                return False

        if old_probe_configs_dict['http'][0]['http hsts'] != 'off':
            command = "set http hsts off\n" # Change the http hsts setting
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_http_options, Console command: {command} failed')
                return False
            if '%' not in output: # I am expecting the command line prompt to be returned.
                logger.error(f'[ERROR] set_probe_http_options, Console command: {command} has Unexpected output: {output}')
                return False

        if old_probe_configs_dict['http'][0]['http my_nw_url_discovery'] != 'on':
            command = "set http my_nw_url_discovery on\n" # Change the http my_nw_url_discovery setting
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_http_options, Console command: {command} failed')
                return False
            if '%' not in output: # I am expecting the command line prompt to be returned.
                logger.error(f'[ERROR] set_probe_http_options, Console command: {command} has Unexpected output: {output}')
                return False

        if old_probe_configs_dict['http'][0]['http parse_xcap'] != 'off':
            command = "set http parse_xcap off\n" # Change the http parse_xcap setting
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_http_options, Console command: {command} failed')
                return False
            if '%' not in output: # I am expecting the command line prompt to be returned.
                logger.error(f'[ERROR] set_probe_http_options, Console command: {command} has Unexpected output: {output}')
                return False

        if old_probe_configs_dict['http'][0]['http parse_stir'] != 'off':
            command = "set http parse_stir off\n" # Change the http parse_stir setting
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_http_options, Console command: {command} failed')
                return False
            if '%' not in output: # I am expecting the command line prompt to be returned.
                logger.error(f'[ERROR] set_probe_http_options, Console command: {command} has Unexpected output: {output}')
                return False

        if old_probe_configs_dict['http'][0]['http ssl_quic_subscr_info'] != 'off':
            command = "set http ssl_quic_subscr_info off\n" # Change the http ssl_quic_subscr_info setting
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_http_options, Console command: {command} failed')
                return False
            if '%' not in output: # I am expecting the command line prompt to be returned.
                logger.error(f'[ERROR] set_probe_http_options, Console command: {command} has Unexpected output: {output}')
                return False

        if old_probe_configs_dict['http'][0]['http use_xff'] != 'off':
            command = "set http use_xff off\n" # Change the http use_xff setting
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_http_options, Console command: {command} failed')
                return False
            if '%' not in output: # I am expecting the command line prompt to be returned.
                logger.error(f'[ERROR] set_probe_http_options, Console command: {command} has Unexpected output: {output}')
                return False

        if old_probe_configs_dict['http'][0]['http use_xff_multiple_clients'] != 'off':
            command = "set http use_xff_multiple_clients off\n" # Change the http use_xff_multiple_clients setting
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_http_options, Console command: {command} failed')
                return False
            if '%' not in output: # I am expecting the command line prompt to be returned.
                logger.error(f'[ERROR] set_probe_http_options, Console command: {command} has Unexpected output: {output}')
                return False

        if old_probe_configs_dict['http'][0]['http use_client_ip_field'] != 'off':
            command = "set http use_client_ip_field off\n" # Change the http use_client_ip_field setting
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_http_options, Console command: {command} failed')
                return False
            if '%' not in output: # I am expecting the command line prompt to be returned.
                logger.error(f'[ERROR] set_probe_http_options, Console command: {command} has Unexpected output: {output}')
                return False

        if old_probe_configs_dict['http'][0]['http use_x_true_client_ip'] != 'off':
            command = "set http use_x_true_client_ip off\n" # Change the http use_x_true_client_ip setting
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_http_options, Console command: {command} failed')
                return False
            if '%' not in output: # I am expecting the command line prompt to be returned.
                logger.error(f'[ERROR] set_probe_http_options, Console command: {command} has Unexpected output: {output}')
                return False

        if old_probe_configs_dict['http'][0]['http use_x_real_ip_field'] != 'off':
            command = "set http use_x_real_ip_field off\n" # Change the http use_x_real_ip_field setting
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_http_options, Console command: {command} failed')
                return False
            if '%' not in output: # I am expecting the command line prompt to be returned.
                logger.error(f'[ERROR] set_probe_http_options, Console command: {command} has Unexpected output: {output}')
                return False
        # Stay in the command line mode for the next function.
    except Exception:
        logger.exception(f"[ERROR] set_probe_http_options, An exception has occurred while setting probe http options")
        return False

    return True

def set_probe_security_options(old_probe_configs_dict, rem_con, logger):
    """
    Set the probe security options settings.
    :old_probe_configs_dict: A dictionary of all the probe configurations.
    :rem_con: An instance of the remote console shell session to the probe.
    :logger: An instance of the logger class that we can use to write errors and exceptions to a local log file.
    :return: False if any command fails, True if all commands pass.
    """
    try:
        command = "quit\n" # We need to exit the command line.
        output = execute_single_command_on_remote(command, rem_con, logger) # Send option 15 to the localconsole menu.
        #print(output)
        if output == False:
            logger.error(f'[ERROR] set_probe_security_options, Console command: {command} failed')
            return False
        if 'Probe IP V4 address' not in output: # We did not enter the interface menu correctly.
            logger.error(f'[ERROR] set_probe_security_options, Console command: {command} has Unexpected output: {output}')
            return False

        command = "13\n" # We need to get into the security options menu.
        output = execute_single_command_on_remote(command, rem_con, logger) # Send option 15 to the localconsole menu.
        #print(output)
        if output == False:
            logger.error(f'[ERROR] set_probe_security_options, Console command: {command} failed')
            return False
        if 'Secure Access Menu:' not in output: # We did not enter the interface menu correctly.
            logger.error(f'[ERROR] set_probe_security_options, Console command: {command} has Unexpected output: {output}')
            return False

        if old_probe_configs_dict['security_options'][0]['capture_slice_size'] != '10240':
            command = "3\n" # Modify the capture slice size to match 10240.
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_security_options, Console command: {command} failed')
                return False
            if 'Enter new slice size :' not in output:
                logger.error(f'[ERROR] set_probe_security_options, Console command: {command} has Unexpected output: {output}')
                return False
            command = "10240\n" # Toggle the Pattern Matching setting
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_security_options, Console command: {command} failed')
                return False
            if 'Secure Access Menu:' not in output:
                logger.error(f'[ERROR] set_probe_security_options, Console command: {command} has Unexpected output: {output}')
                return False

        if old_probe_configs_dict['security_options'][0]['data_capture'] != 'on':
            command = "4\n" # Toggle the data capture setting
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_security_options, Console command: {command} failed')
                return False
            if 'Secure Access Menu:' not in output:
                logger.error(f'[ERROR] set_probe_security_options, Console command: {command} has Unexpected output: {output}')
                return False

        command = "99\n" # Return to the main menu
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            logger.error(f'[ERROR] set_probe_security_options, Console command: {command} failed')
            return False
        if 'Probe IP V4 address' not in output: # We did not enter the localconsole menu correctly.
            logger.error(f'[ERROR] set_probe_security_options, Console command: {command} has Unexpected output: {output}')
            return False
    except Exception:
        logger.exception(f"[ERROR] set_probe_security_options, An exception has occurred while setting probe security options")
        return False
    return True

def set_probe_agent_options(old_probe_configs_dict, rem_con, logger):
    """
    Set the probe agent (not related to interfaces) specific settings.
    :old_probe_configs_dict: A dictionary of all the probe configurations.
    :rem_con: An instance of the remote console shell session to the probe.
    :logger: An instance of the logger class that we can use to write errors and exceptions to a local log file.
    :return: False if any command fails, True if all commands pass.
    """
    try:
        command = "quit\n" # Exit the command line menu to the main menu
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            logger.error(f'[ERROR] set_probe_agent_options, Console command: {command} failed')
            return False
        if 'Probe IP V4 address' not in output: # We did not enter the localconsole menu correctly.
            logger.error(f'[ERROR] set_probe_agent_options, Console command: {command} has Unexpected output: {output}')
            return False

        command = "9\n" # We need to get into the agent options menu.
        output = execute_single_command_on_remote(command, rem_con, logger) # Send option 7 to the localconsole menu.
        if output == False:
            logger.error(f'[ERROR] set_probe_agent_options, Console command: {command} failed')
            return False
        if 'Agent Options Menu:' not in output: # We did not enter the interface menu correctly.
            logger.error(f'[ERROR] set_probe_agent_options, Console command: {command} has Unexpected output: {output}')
            return False

        if old_probe_configs_dict['agent_options'][0]['watchdog'] != 'on':
            command = "1\n" # Toggle the watchdog setting
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_agent_options, Console command: {command} failed')
                return False
            if 'Agent Options Menu:' not in output:
                logger.error(f'[ERROR] set_probe_agent_options, Console command: {command} has Unexpected output: {output}')
                return False

        if old_probe_configs_dict['agent_options'][0]['auto_reboot'] != 'on':
            command = "6\n" # Toggle the auto_reboot setting
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_agent_options, Console command: {command} failed')
                return False
            if 'Agent Options Menu:' not in output:
                logger.error(f'[ERROR] set_probe_agent_options, Console command: {command} has Unexpected output: {output}')
                return False

        if old_probe_configs_dict['agent_options'][0]['burst_advisor_peak'] != 'msec':
            command = "10\n" # Toggle the burst_advisor_peak setting
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_agent_options, Console command: {command} failed')
                return False
            if 'Agent Options Menu:' not in output:
                logger.error(f'[ERROR] set_probe_agent_options, Console command: {command} has Unexpected output: {output}')
                return False

        # vStreams do not have the next setting, so skip it if it if the model number is vStream.
        if old_probe_configs_dict['agent_configs'][0]['model_number'] != 'vSTREAM':
            if old_probe_configs_dict['agent_options'][0]['Infinistream Console Support'] != 'on':
                command = "11\n" # Toggle the Infinistream Eth0 GRE Monitoring setting
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_agent_options, Console command: {command} failed')
                    return False
                if 'Agent Options Menu:' not in output:
                    logger.error(f'[ERROR] set_probe_agent_options, Console command: {command} has Unexpected output: {output}')
                    return False

        if old_probe_configs_dict['agent_options'][0]['nGeniusONE Managed'] != 'on':
            command = "14\n" # Toggle the Infinistream nGeniusONE Managed setting
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_agent_options, Console command: {command} failed')
                return False
            if 'Agent Options Menu:' not in output:
                logger.error(f'[ERROR] set_probe_agent_options, Console command: {command} has Unexpected output: {output}')
                return False

        if old_probe_configs_dict['agent_options'][0]['Health Monitoring'] != 'on':
            command = "16\n" # Toggle the Infinistream Health Monitoringsetting
            output = execute_single_command_on_remote(command, rem_con, logger)
            if output == False:
                logger.error(f'[ERROR] set_probe_agent_options, Console command: {command} failed')
                return False
            if 'Agent Options Menu:' not in output:
                logger.error(f'[ERROR] set_probe_agent_options, Console command: {command} has Unexpected output: {output}')
                return False

        # vStreams do not have the next setting, so skip it if it if the model number is vStream.
        if old_probe_configs_dict['agent_configs'][0]['model_number'] != 'vSTREAM':
            if old_probe_configs_dict['agent_options'][0]['Eth0 GRE Monitoring'] != 'off':
                command = "19\n" # Toggle the Infinistream Eth0 GRE Monitoring setting
                output = execute_single_command_on_remote(command, rem_con, logger)
                if output == False:
                    logger.error(f'[ERROR] set_probe_agent_options, Console command: {command} failed')
                    return False
                if 'Agent Options Menu:' not in output:
                    logger.error(f'[ERROR] set_probe_agent_options, Console command: {command} has Unexpected output: {output}')
                    return False

        command = "99\n" # Return to the main menu
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            logger.error(f'[ERROR] set_probe_agent_options, Console command: {command} failed')
            return False
        if 'Probe IP V4 address' not in output: # We did not enter the localconsole menu correctly.
            logger.error(f'[ERROR] set_probe_agent_options, Console command: {command} has Unexpected output: {output}')
            return False
    except Exception:
        logger.exception(f"[ERROR] set_probe_agent_options, An exception occurred while setting the probe agent options")
        return False
    return True


def set_probe_configs(old_probe_configs_dict, interface_list, rem_con, logger):
    """
    Sends a series of commands to the remote console to set certain configurations to match what are
    considered best practice settings for a POC. The old_probe_configs_dict is used to see if the settings
    match the desired poc settings. If there is a delta, the probe configuration is modified until all
    the desired settings match what is in the probe. Depending on what needs to be set, there may be one
    or more agent reset operations.
    :old_probe_configs_dict: A dictionary of the current probe settings used to look for deltas to the
    desired poc settings.
    :rem_con: An instance of the remote console shell session to the probe.
    :logger: An instance of the logger class that we can use to write errors and exceptions to a local log file.
    :return: False if any command fails, True if all settings are successfully modified to match the
    desired poc settings.
    """
    try:
        print("\nSetting the probe configs to match 'POC-Ready' settings")
        logger.info('[INFO] Initiating set_probe_configs to modify the probe settings to POC-ready')

        command = "localconsole\n"
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            logger.error(f'[ERROR] set_probe_configs, Console command: {command} failed')
            return False
        if 'Probe IP V4 address' not in output: # We did not enter the localconsole menu correctly.
            logger.error(f'[ERROR] set_probe_configs, Console command: {command} has Unexpected output: {output}')
            return False

        command = "11\n" # Enter the command line mode in localconsole.
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            logger.error(f'[ERROR] set_probe_configs, Console command: {command} failed')
            return False
        if 'Enter "quit" to exit command-line mode' not in output: # We did not enter command line mode.
            logger.error(f'[ERROR] set_probe_configs, Console command: {command} has Unexpected output: {output}')
            return False
        print('\rSetting basic probe modes, the agent will be reset', end="")
        set_status = set_probe_options_non_interface_specific(old_probe_configs_dict, rem_con, logger)
        if set_status == False: # A set operation has failed. Return False.
            return False

        print('\rSetting interface options...', end="")
        set_status = set_probe_options_per_interface(old_probe_configs_dict, interface_list, rem_con, logger)
        if set_status == False: # A set operation has failed. Return False.
            return False
        else:
            print('Done')

        print('\rSetting ASI configs...', end="")
        set_status = set_probe_asi_interface_specific(old_probe_configs_dict, interface_list, rem_con, logger)
        if set_status == False: # A set operation has failed. Return False.
            return False
        else:
            print('Done')

        print('\rSetting probe agent options...', end="")
        set_status = set_probe_agent_options(old_probe_configs_dict, rem_con, logger)
        if set_status == False: # A set operation has failed. Return False.
            return False
        else:
            print('Done')

        print('\rSetting probe software options...', end="")
        set_status = set_probe_software_options(old_probe_configs_dict, rem_con, logger)
        if set_status == False: # A set operation has failed. Return False.
            return False
        else:
            print('Done')

        print('\rSetting probe protocol options...', end="")
        set_status = set_probe_protocol_options(old_probe_configs_dict, rem_con, logger)
        if set_status == False: # A set operation has failed. Return False.
            return False
        else:
            print('Done')

        print('\rSetting probe http options...', end="")
        set_status = set_probe_http_options(old_probe_configs_dict, rem_con, logger)
        if set_status == False: # A set operation has failed. Return False.
            return False
        else:
            print('Done')

        print('\rSetting other interface specific configs...', end="")
        set_status = set_probe_other_interface_specific(old_probe_configs_dict, interface_list, rem_con, logger)
        if set_status == False: # A set operation has failed. Return False.
            return False
        else:
            print('Done')

        print('\rSetting probe security options...', end="")
        set_status = set_probe_security_options(old_probe_configs_dict, rem_con, logger)
        if set_status == False: # A set operation has failed. Return False.
            return False
        else:
            print('Done')

        command = "12\n" # Reset the agent
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            logger.error(f'[ERROR] set_probe_configs, Console command: {command} failed')
            return False
        if 'WARNING : agent will be reset, confirm [n]' not in output: # The expected response did not come back.
            logger.error(f'[ERROR] set_probe_configs, Console command: {command} has Unexpected output: {output}')
            return False

        reset_agent_command = 'y\n' # Respond to the confirmation prompt with a 'y'.
        print(f'\nAll set operations complete...Resetting the probe agent, please wait...', end='')
        reset_status = do_agent_reset(reset_agent_command, rem_con, logger)
        if output == False:
            logger.error(f'[ERROR] set_probe_configs, Console command: {command} failed')
            return False
        else:
            print('Done')
    except Exception:
        logger.exception(f"[ERROR] set_probe_configs, An exception occurred while setting the probe configs")
        return False

    return True

def gather_probe_configs(logger, rem_con):
    """
    Sends a series of commands to the remote console and gathers the responses for processing.
    The responses will be used to fill in the attributes for the old_probe_configs_dict.
    :rem_con: An instance of the remote console shell session to the probe.
    :logger: An instance of the logger class that we can use to write errors and exceptions to a local log file.
    :return: The filled in old_probe_configs_dict, the interface_list and status = True if all commands pass.
    Return the old_probe_configs_dict, the interface list and status = False if any errors occur.
    """

    print('[INFO] Gathering current probe configurations for backup')
    logger.info('[INFO] Gathering current probe configurations...')

    try:
        # Initialize an empty dictionary to hold our probe config params.
        old_probe_configs_dict = {'interface_list': [{}], 'interface_options': [{}], 'agent_configs': [{}],
                                'health_mib_info': [{}], 'agent_options': [{}], 'software_options': [{}],
                                'protocol_options': [{}], 'http': [{}], 'asi': [{}], 'interface_specific': [{}],
                                'non_interface_specific': [{}], 'security_options': [{}], 'ipsec_opts': [{}],
                                'ssl_health': [{}], 'frag_reassembly':[{}], 'h248_cfg':[{}], 'sip_db':[{}],
                                'npn_alarms':[{}]}

        options_type = 'interface_list'
        print('\rGetting Interface List...', end="")
        # Get the list of monitor interfaces, add them to the old_probe_configs_dict and return a numerical list of interface numbers.
        old_probe_configs_dict, interface_list, status = get_probe_interface_list(old_probe_configs_dict, options_type, rem_con, logger)
        #print(f'\ninterface_list is: {interface_list}')
        #print(f'options_type is {options_type}')
        #print(f'old_probe_configs_dict is: \n{old_probe_configs_dict}')
        #exit()
        if status == False:
            logger.error("[ERROR] Gather probe configs, Getting Probe Interface List failed")
            return old_probe_configs_dict, interface_list, status
        else:
            print('Done')
        # Difficult not to hard code these lists of attribute names as the names are not consistent in...
        # the probe itself as to underscores or spaces or how many words are in the attribute name.
        config_attributes_list = ['power_alarm_util', 'power_alarm_resp', 'admin_shutdown', 'Data w/o Control Tcm',
                                'jumboframe_support', 'interface_speed', 'mib2_ifspeed', 'vifn_enable',
                                'vifn_discovery', 'vifn_mode', 'reverse_ports', 'HTTP Mode', 'M3UA Table',
                                'enable xDR', 'Tunnel Parsing', 'interface type', 'auxiliary interfaces', 'Data w/o Control',
                                'Interface Mode', 'Configure Tunnel Termination']
        options_type = 'interface_options'
        print('\rGetting Interface Options...', end="")
        # Get the whole list of interface options settings for each monitor interface and add them to the old_probe_configs_dict.
        old_probe_configs_dict, status = get_probe_options_per_interface(config_attributes_list, interface_list, rem_con, old_probe_configs_dict, options_type, logger)
        if status == False:
            logger.error("[ERROR] Gather probe configs, Getting Interface Options failed")
            return old_probe_configs_dict, interface_list, status
        else:
            print('Done')

        config_attributes_list = ['model_number', 'software_version', 'link time', 'memory size', 'nvram_version',
                                'nvram size', 'agent_location', 'agent_contact', 'agent_name', 'read_community',
                                'write_community', 'Probe Communication Mode', 'IP V4 address', 'MAC Address',
                                'config_server', 'serial_number', 'nsprobe_type', 'kernel']
        options_type = 'agent_configs'
        print('\rGetting Agent Configs...', end="")
        # Get the whole list of probe agent configs settings and add them to the old_probe_configs_dict.
        old_probe_configs_dict, status = get_probe_options(config_attributes_list, rem_con, old_probe_configs_dict, options_type, logger)
        if status == False:
            logger.error("[ERROR] Gather probe configs, Getting Agent Configs failed")
            return old_probe_configs_dict, interface_list, status
        else:
            print('Done')

        # vStreams do not have the next setting, so skip it if it if the model number is vStream.
        if old_probe_configs_dict['agent_configs'][0]['model_number'] != 'vSTREAM':
            config_attributes_list = ['Total number of Chassis', 'Total number of Controller', 'Total number of Raid Array',
            'Total number of Disks', 'Total number of Power Supplies', 'Total number of monitoring Ifns',
            'Total number of mgmt Ifns', 'Total number of Fans', 'Total number of Temperature status',
            'Total number of Voltage status', 'Total number of NTP Servers', 'Total number of IPMI']
            options_type = 'health_mib_info'
            print('\rGetting Health MIB Info...', end="")
            # Get the whole list of probe agent configs settings and add them to the old_probe_configs_dict.
            old_probe_configs_dict, status = get_probe_options(config_attributes_list, rem_con, old_probe_configs_dict, options_type, logger)
            if status == False:
                logger.error("[ERROR] Gather probe configs, Getting Health MIB Info failed")
                return old_probe_configs_dict, interface_list, status
            else:
                print('Done')
        else:
            old_probe_configs_dict['health_mib_info'][0]['N/A'] = ''

        config_attributes_list = ['watchdog', 'auto_reboot', 'timestamp_ns', 'burst_advisor_peak',
                                'Infinistream Console Support', 'Traffic Violations', 'nGeniusONE Managed',
                                'Health Monitoring', 'Eth0 GRE Monitoring', 'Network Analyzer Support']
        options_type = 'agent_options'
        print('\rGetting Agent Options...', end="")
        # Get the whole list of probe agent options settings and add them to the old_probe_configs_dict.
        old_probe_configs_dict, status = get_probe_options(config_attributes_list, rem_con, old_probe_configs_dict, options_type, logger)
        if status == False:
            logger.error("[ERROR] Gather probe configs, getting Agent Options failed")
            return old_probe_configs_dict, interface_list, status
        else:
            print('Done')

        config_attributes_list = ['Response Time Monitor', 'NL and AL Host', 'NL and AL Conversation',
                                'SBA Priority']
        options_type = 'software_options'
        print('\rGetting Software Options...', end="")
        # Get the whole list of probe software options settings and add them to the old_probe_configs_dict.
        old_probe_configs_dict, status = get_probe_options(config_attributes_list, rem_con, old_probe_configs_dict, options_type, logger)
        if status == False:
            logger.error("[ERROR] Gather probe configs, Getting Software Options failed")
            return old_probe_configs_dict, interface_list, status
        else:
            print('Done')

        config_attributes_list = ['Pattern Matching', 'CORBA', 'Conversation Port Discovery',
                                'Skype Pattern Matching', 'Extended FIS', 'Voice and Video Quality']
        options_type = 'protocol_options'
        print('\rGetting Protocol Options...', end="")
        # Get the whole list of protocol options settings and add them to the old_probe_configs_dict.
        old_probe_configs_dict, status = get_probe_options(config_attributes_list, rem_con, old_probe_configs_dict, options_type, logger)
        if status == False:
            logger.error("[ERROR] Gather probe configs, Getting Protocol Options failed")
            return old_probe_configs_dict, interface_list, status
        else:
            print('Done')

        config_attributes_list = ['http web_classify', 'http db_type', 'http proxy_server_uri_search', 'http hsts',
                                'http my_nw_url_discovery', 'http parse_xcap', 'http parse_stir', 'http ssl_quic_subscr_info',
                                'http use_xff', 'http use_xff_multiple_clients', 'http use_client_ip_field',
                                'http use_x_true_client_ip', 'http use_x_real_ip_field']
        options_type = 'http'
        print('\rGetting HTTP Config...', end="")
        # Get the whole list of probe http settings and add them to the old_probe_configs_dict.
        old_probe_configs_dict, status = get_probe_options(config_attributes_list, rem_con, old_probe_configs_dict, options_type, logger)
        if status == False:
            logger.error("[ERROR] Gather probe configs, Getting HTTP Config failed")
            return old_probe_configs_dict, interface_list, status
        else:
            print('Done')

        config_attributes_list = ['kti_peak_type', 'kti_peak_interval', 'ksi_mtu_size', 'uc_conv',
                                'server_table', 'disc_table', 'vital_table', 'tcp_monitor', 'conv',
                                'conv ports', 'conv qos', 'la_burst', 'la_type', 'host_activity',
                                'htt', 'ksi 1min', 'ksi client_ip', 'subscriber', '1-min', '15-sec',
                                'url_disc_table']
        options_type = 'asi'
        print('\rGetting ASI Config...', end="")
        # Get the whole list of probe asi settings per interface and add them to the old_probe_configs_dict.
        old_probe_configs_dict, status = get_probe_options_per_interface(config_attributes_list, interface_list, rem_con, old_probe_configs_dict, options_type, logger)
        if status == False:
            logger.error("[ERROR] Gather probe configs, Getting ASI Config failed")
            return old_probe_configs_dict, interface_list, status
        else:
            print('Done')

        config_attributes_list = ['frag_reassembly']
        options_type = 'frag_reassembly'
        print('\rGetting Frag Reassembly Config...', end="")
        old_probe_configs_dict, status = get_probe_config_interface_specific(config_attributes_list, interface_list, rem_con, old_probe_configs_dict, options_type, logger)
        if status == False:
            logger.error("[ERROR] Gather probe configs, Getting Frag Reassembly Config failed")
            return old_probe_configs_dict, interface_list, status
        else:
            print('Done')

        config_attributes_list = ['h248_cfg']
        options_type = 'h248_cfg'
        print('\rGetting H.248 Config...', end="")
        old_probe_configs_dict, status = get_probe_config_interface_specific(config_attributes_list, interface_list, rem_con, old_probe_configs_dict, options_type, logger)
        if status == False:
            logger.error("[ERROR] Gather probe configs, Getting H.248 Config failed")
            return old_probe_configs_dict, interface_list, status
        else:
            print('Done')

        config_attributes_list = ['ipsec_opts']
        options_type = 'ipsec_opts'
        print('\rGetting IPsec Options...', end="")
        old_probe_configs_dict, status = get_probe_config_interface_specific(config_attributes_list, interface_list, rem_con, old_probe_configs_dict, options_type, logger)
        if status == False:
            logger.error("[ERROR] Gather probe configs, Getting IPsec Options failed")
            return old_probe_configs_dict, interface_list, status
        else:
            print('Done')

        config_attributes_list = ['ssl_health']
        options_type = 'ssl_health'
        print('\rGetting SSL Health Configs...', end="")
        old_probe_configs_dict, status = get_probe_config_interface_specific(config_attributes_list, interface_list, rem_con, old_probe_configs_dict, options_type, logger)
        if status == False:
            logger.error("[ERROR] Gather probe configs, Getting SSL Health Configs failed")
            return old_probe_configs_dict, interface_list, status
        else:
            print('Done')

        config_attributes_list = ['sip_db']
        options_type = 'sip_db'
        print('\rGetting SIP Database Configs...', end="")
        old_probe_configs_dict, status = get_probe_config_interface_specific(config_attributes_list, interface_list, rem_con, old_probe_configs_dict, options_type, logger)
        if status == False:
            logger.error("[ERROR] Gather probe configs, Getting SIP Database Configs failed")
            return old_probe_configs_dict, interface_list, status
        else:
            print('Done')

        config_attributes_list = ['npn_alarms']
        options_type = 'npn_alarms'
        print('\rGetting NPN Alarm Configs...', end="")
        old_probe_configs_dict, status = get_probe_options_non_interface_specific(config_attributes_list, rem_con, old_probe_configs_dict, options_type, logger)
        if status == False:
            logger.error("[ERROR] Gather probe configs, Getting NPN Alarm Configs failed")
            return old_probe_configs_dict, interface_list, status
        else:
            print('Done')

        config_attributes_list = ['skt_vlan_enable', 'span_duplicate', 'ssl_sni', 'encap_type', 'time_sync',
        'ssl_cert', 'ssl_decrypt', 'ssl_session_ageout', 'ssl_session_cnt', 'site_outer', 'max_etherpktsize',
        'rtp_ast']
        options_type = 'interface_specific'
        print('\rGetting Interface Specific Configs...', end="")
        # Get the whole list of probe interface specific settings and add them to the old_probe_configs_dict.
        old_probe_configs_dict, status = get_probe_config_interface_specific(config_attributes_list, interface_list, rem_con, old_probe_configs_dict, options_type, logger)
        if status == False:
            logger.error("[ERROR] Gather probe configs, Getting Interface Specific Configs failed")
            return old_probe_configs_dict, interface_list, status
        else:
            print('Done')

        config_attributes_list = ['config_download', 'probe_mode', 'vq_payload', 'vq_dtmf_events', 'asi_mode',
         'app_table_size', 'ip_options', 'ipfrag_table_size', 'geo_probe', 'vlan_disc_type', 'ipsec', 'qos_mode', 'trap_port',
         'max_capture_size', 'max_dhcp', 'max_ipv6', 'site_conversation', 'site_mac', 'vlan_disc_type',
         'qos_groups', 'ipother_qos', 'ipreassembly', 'virt_pkt_dist', 'ts_resolution', 'tns_skt_count',
         'citrix_discover_apps', 'citrix_server_push', 'citrix_wildcard_support', 'citrix_channel_monitoring',
          'krb_maxname', 'krb_ntr', 'rtp_heur', 'h248_protocols', 'h323_options', 'max_hset_download', 'auto_scroll']
        options_type = 'non_interface_specific'
        print('\rGetting Non-Interface Specific Configs...', end="")
        # Get each probe non-interface specific settings and add them to the old_probe_configs_dict.
        old_probe_configs_dict, status = get_probe_options_non_interface_specific(config_attributes_list, rem_con, old_probe_configs_dict, options_type, logger)
        if status == False:
            logger.error("[ERROR] Gather probe configs, Getting Non-Interface Specific Configs failed")
            return old_probe_configs_dict, interface_list, status
        else:
            print('Done')

        config_attributes_list = ['community_type', 'custom_dpi', 'skt', 'match_uri_only_mode', 'table_size_allocation', 'ipv6_mode', 'xdr']
        options_type = 'interface_specific'
        print('\rGetting Community Type...', end="")
        old_probe_configs_dict, status = get_probe_options_single_command_multi_interface(config_attributes_list, interface_list, rem_con, old_probe_configs_dict, options_type, logger)
        if status == False:
            logger.error("[ERROR] Gather probe configs, Getting Getting Community Type failed")
            return old_probe_configs_dict, interface_list, status
        else:
            print('Done')

        config_attributes_list = ['capture_slice_size', 'data_capture']
        options_type = 'security_options'
        print('\rGetting Security Options...', end="")
        # Get each probe interface specific settings for each interface one-by-one and add them to the old_probe_configs_dict.
        old_probe_configs_dict, status = get_probe_security_options(config_attributes_list, options_type, rem_con, old_probe_configs_dict, logger)
        if status == False:
            logger.error("[ERROR] Gather probe configs, Getting Security Options failed")
            return old_probe_configs_dict, interface_list, status
        else:
            print('Done')

        command = "exit\n"
        output = execute_single_command_on_remote(command, rem_con, logger)
        if output == False:
            logger.error("[ERROR] Gather probe configs, exit command failed")
            status = False
            return old_probe_configs_dict, interface_list, status
    except Exception:
        logger.exception(f"[ERROR] Gather probe configs, An exception has occurred while gathering the probe configs")
        status = False
        return old_probe_configs_dict, interface_list, status

    status = True
    return old_probe_configs_dict, interface_list, status

def write_config_to_json(config_filename, old_probe_configs_dict, logger):
    """
    Serialize the old_probe_configs_dict and write it out to a json file so we have a backup of the original config.
    :config_filename: The name of the json file that we want to save the probe configs to.
    :old_probe_configs_dict: The probe config dictionary that contains all the probe config settings.
    :logger: An instance of the logger class that we can use to write errors and exceptions to a local log file.
    :return: False if any command fails, True if the config is successfully written to the json file.
    """

    # Backup the current probe configs by writing the old_probe_configs_dict to a json file.
    try:
        with open(config_filename,"w") as f:
            json.dump(old_probe_configs_dict, f, indent=4, sort_keys=True)
            print(f'\n[INFO] Backing up the probe config to file: {config_filename}')
            logger.info(f'[INFO] Backup the probe config to file: {config_filename}')
    except IOError as e: # Handle file I/O errors.
        print(f'[ERROR] Unable to backup the probe config to the JSON config file: {config_filename}')
        logger.error(f'[ERROR] Unable to backup the probe config to the JSON config file: {config_filename}')
        print("I/O error({0}): {1}".format(e.errno, e.strerror))
        logger.error(f'[ERROR] I/O error: {e.errno}:  {e.strerror}.')
        return False
    except Exception:
        logger.exception(f"[ERROR] An exception occurred when attempting to backup the probe config to the JSON config file: {config_filename}")
        return False
    return True

def read_config_from_json(config_filename, logger):
    # The contents of the json config file are read into config_data, converted to a python dictionay object and returned
    try:
        with open(config_filename) as f:
            # decoding the JSON data to a python dictionary object
            config_data = json.load(f)
            print(f'Reading config data from JSON file: {config_filename}...Done')
            logger.info(f'[INFO] Reading config data from JSON file: {config_filename}')
            return config_data
    except IOError as e:
        print(f'[ERROR] Unable to read the JSON config file: {config_filename}')
        logger.error(f'[ERROR] Unable to read the JSON config file: {config_filename}')
        print("I/O error({0}): {1}".format(e.errno, e.strerror))
        logger.error(f'[ERROR] I/O error: {e.errno}:  {e.strerror}.')
        return False
    except Exception:
        logger.exception(f"[ERROR] An exception occurred when attempting to read the JSON config file: {config_filename}")
        return False

def close_ssh_session(probe_creds, hostname, client, rem_con, logger):
    """
    Close the remote console shell session to the probe.
    Close an SSH session to the probe using paramiko.
    :probe_creds: A class instance that contains all the necessary connection parameters.
    :client: The SSH client instance.
    :rem_con: The remote console shell session instance.
    :logger: An instance of the logger class that we can use to write errors and exceptions to a local log file.
    :return: True if successful, False if unsuccessful.
    """
    try:
        rem_con.close()
        client.close()
        print(f'[INFO] SSH connection to: {hostname} successfully closed.')
        logger.info(f'[INFO] SSH connection to: {hostname} successfully closed.')
        return True
    except Exception:
        logger.exception(f"[ERROR] An exception occurred while attempting to close the SSH connection to: {hostname}")
        return False

def get_probe_targets_from_ng1(session, config_type, logger):
    """Use the nG1 API to get the configuration in the system for the config_type passed in.
    :config_type: The type of config data to get (devices, other for future expansion)
    :session: An instance of the ApiSession class that holds all our API session params.
    :logger: An instance of the logger class to write to in case of an error.
    :return: If successful, return the devices data in JSON format and status = True
    Return an empty dictionary and status = False if there are any errors or exceptions.
    """
    if config_type == 'devices':
        uri = "/ng1api/ncm/devices/"
    else:
        print(f'[ERROR] Invalid config_type: {config_type}')
        logger.error(f'[ERROR] Invalid config_type: {config_type}')
        status = False
        devices_data = {}
        return devices_data, status
    url = session.ng1_host + uri
    try:
        # perform the HTTPS API call to get the sites information
        get = requests.get(url, headers=session.headers, verify=False, cookies=session.cookies)

        if get.status_code == 200:
            # success
            print(f'[INFO] get {config_type} nG1 API request Successful')
            logger.info(f'[INFO] get {config_type} nG1 API request Successful')
            # return the json object that contains the site information
            status = True
            devices_data = get.json()
            return devices_data, status
        else:
            logger.error(f'[ERROR] get {config_type} nG1 API request failed. Response Code: {get.status_code}. Response Body: {get.text}.')
            devices_data = {}
            status = False
            return devices_data, status
    except Exception as e: # Handle other unexpected errors.
        logger.exception(f'[ERROR] get {config_type} nG1 API request failed')
        logger.exception(f'[ERROR] URL sent is: {url}')
        logger.exception(f"[ERROR] Exception error is:\n{e}")
        devices_data = {}
        status = False
        return devices_data, status

def get_ip_addresses_on_all_devices(session, logger, devices_data):
    """Use the nG1 API to get the host IP address for every active device (Infinistream or vStream) in the system.
    This will loop through the list of active devices and pull in the IP address for each device.
    :session: An instance of the ApiSession class that holds all our API session params.
    :devices_data: A json formatted dictionary of all the devices in the system attached to nG1.
    :logger: An instance of the logger object to write to in case of an error.
    :return: If successful, return the finished probe_targe_list.
    Return False if there are any errors or exceptions.
    """
    # Initialize a dictionary to hold all the valid, active devices and thier active interface info.
    probe_target_list = []
    try:
        # Interate over the devices in devices_list and only include active infinistreams or vStreams.
        for device in devices_data['deviceConfigurations']:
            device_name = device['deviceName']
            device_ip_address = device['deviceIPAddress']
            device_status = device['status']
            device_type = device['deviceType']
            if device_status == 'Active': # Only include active devices.
                if device_type == 'InfiniStream' or device_type == 'vSTREAM': # Only include Infinstreams or vStreams.
                    # This is a qualified probe, add it to the target list.
                    probe_target_list.append(device_ip_address)
                else:
                    print(f'[INFO] Device: {device_name} type is: {device_type}. Skipping...')
                    logger.info(f'[INFO] Device: {device_name} type is: {device_type}. Skipping...')
            else:
                print(f'[INFO] Device: {device_name} status is: {device_status}. Skipping...')
                logger.info(f'[INFO] Device: {device_name} status is: {device_status}. Skipping...')
    except Exception as e:
        logger.exception('[ERROR] get_ip_addresses_on_all_devices has failed')
        logger.exception(f"[ERROR] Exception error is:\n{e}")
        status = False
        return probe_target_list, status
    status = True
    return probe_target_list, status # Success! Return the finished probe list to the calling function.

def main():
    #golden_probe_config_filename = 'golden_probe_config.json'
    # Create a logger instance and write the date_time to a log file.
    logger, log_filename = create_logging_function()
    if logger == False: # Creating the logger instance has failed. Exit.
        print("\n[CRITICAL] Main, Creating the logger instance has failed")
        print('Exiting...')
        sys.exit()

    prog_version = '0.2'
    status, is_set_config_true = flags_and_arguments(prog_version, logger)
    if status == False: # Parsing the user entered flags or arguments has failed Exit.
        logger.critical("[CRITICAL] Main, Parsing the user entered flags or arguments has failed")
        print("\n[CRITICAL] Main, Parsing the user entered flags or arguments has failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit()

    # Hardcoding the filenames for encrypted credentials and the key file needed to decrypt the credentials.
    probe_cred_filename = 'ProbeCredFile.ini'
    ng1_cred_filename = 'CredFile.ini'
    os_type = sys.platform
    if os_type == 'linux':
        probekey_file = '.probekey.key' # hide the probekey file if Linux.
    else:
        probekey_file = 'probekey.key' # don't hide it if Windows.

    # Get the user's credentials from a file and decrypt them.
    probe_creds = get_probe_decrypted_credentials(probe_cred_filename, probekey_file, logger)
    if probe_creds == False: # Creating the probe_creds instance has failed. Exit.
        logger.critical(f"[CRITICAL] Main, Getting the login credentials from file: {probe_cred_filename} failed")
        print(f"\n[CRITICAL] Main, Getting the probe login credentials from file: {probe_cred_filename} failed")
        print(f'Check the log file: {log_filename}. Exiting...')
        sys.exit()

    probe_target_list = probe_creds.probehostname.strip('][').split(', ') # Convert string to a list.

    if 'ng1' in probe_target_list[0]: # The user requested to get the probe targets from an ng1.
        # Disable the warnings for ignoring Self-Signed Certificates
        requests.packages.urllib3.disable_warnings()
        os_type = sys.platform
        if os_type == 'linux':
            ng1key_file = '.ng1key.key' # hide the probekey file if Linux.
        else:
            ng1key_file = 'ng1key.key' # don't hide it if Windows.
        # Get the user's credentials from a file and decrypt them.
        ng1_creds = get_ng1_decrypted_credentials(ng1_cred_filename, ng1key_file, logger)
        if ng1_creds == False: # Creating the creds instance has failed. Exit.
            logger.critical(f"[CRITICAL] Main, Getting the ng1 login credentials from file: {ng1_cred_filename} failed")
            print(f"\n[CRITICAL] Main, Getting the ng1 login credentials from file: {ng1_cred_filename} failed")
            print(f'Check the log file: {log_filename}. Exiting...')
            sys.exit()

        # Based on what is in the ng1_creds, determine all the parameters needed to make an nG1 API connection.
        status, session = determine_ng1_api_params(ng1_creds, logger)
        if status == False: # Determining the nG1 API parameters has failed. Exit.
            logger.critical(f"[CRITICAL] Main, determining the nG1 API parameters has failed")
            print(f"\n[CRITICAL] Main, determining the nG1 API parameters has failed")
            print(f'Check the log file: {log_filename}. Exiting...')
            sys.exit()

        # Open an API session to nG1 and keep it open for all subsequent calls.
        status = open_session(session, logger)
        if status == False: # Opening the HTTP-HTTPS nG1 API session has failed. Exit.
            logger.critical(f"[CRITICAL] Main, opening the HTTP-HTTPS nG1 API session has failed")
            print(f"\n[CRITICAL] Main, opening the HTTP-HTTPS nG1 API session has failed")
            print(f'Check the log file: {log_filename}. Exiting...')
            sys.exit()

        # Get active infinistrem / vStream info from the nG1 API. Returned as a python object (a json formatted dictionary).
        config_type = 'devices'
        devices_data, status = get_probe_targets_from_ng1(session, config_type, logger)
        if status == False: # Getting the config data from the nG1 API has failed. Exit.
            logger.critical(f"[CRITICAL] Main, getting the {config_type} data from the nG1 API has failed")
            print(f"\n[CRITICAL] Main, getting the {config_type} data from the nG1 API has failed")
            close_session(session, logger)
            print(f'Check the log file: {log_filename}. Exiting...')
            sys.exit()

        probe_target_list, status = get_ip_addresses_on_all_devices(session, logger, devices_data)
        # Create a printable version of the probe target list for display to the user.
        if status == False: # Getting the config data from the nG1 API has failed. Exit.
            logger.critical(f"[CRITICAL] Main, getting the {config_type} data from the nG1 API has failed")
            print(f"\n[CRITICAL] Main, getting the {config_type} data from the nG1 API has failed")
            close_session(session, logger)
            print(f'Check the log file: {log_filename}. Exiting...')
            sys.exit()
        elif probe_target_list == []: # There were no active infinistreams or vstreams attached to the ng1.
            logger.critical(f"[CRITICAL] Main, nGeniusONE reports no active Infinistreams or vStreams attached")
            print(f"\n[CRITICAL] Main, nGeniusONE reports no active Infinistreams or vStreams attached")
            print('Unable to proceed without any probe targets')
            close_session(session, logger)
            print(f'Check the log file: {log_filename}. Exiting...')
            sys.exit()

        # We are all finished, close the nG1 API session.
        if close_session(session, logger) == False: # Failed to close the API session.
            logger.critical(f"[CRITICAL] Main, close_session has failed")
            print(f"\n[CRITICAL] Main, Unable to close the nG1 API session")
            print(f'Check the log file: {log_filename}. Exiting...')
            sys.exit()

    else: #The user either selected a probe targets file or manually entered the target info.
        # Get the target list of all the probes we need to read from and potentially write to.
        probe_target_list = probe_creds.probehostname.strip('][').split(', ') # Convert string to a list.

    number_of_hosts = len(probe_target_list)
    printable_target_list = [] # Initialize an empty list for character stripping.
    for target in probe_target_list:
        target = target.strip("''") # Strip off the quotes around each hostname - IP address.
        printable_target_list.append(target)
    print(f'probe_target_list is: {printable_target_list}')
    print(f'number_of_hosts is: {number_of_hosts}')
    host_count = 0
    for hostname in printable_target_list:
        #hostname = hostname.strip("''") # Strip off the quotes around each hostname - IP address.
        host_count += 1
        if number_of_hosts > 1:
            print(f'\nWorking on probe {host_count} of {number_of_hosts}...')
            print('---------------------------------------------------------')
        # Open an SSH session to the probe.
        client = open_ssh_session(probe_creds, hostname, logger)
        if client == False: # Opening the SSH session to the probe has failed. Exit.
            logger.critical("[CRITICAL] Main, Opening the SSH connection failed")
            print("\n[CRITICAL] Main, Opening the SSH connection failed")
            print(f'Check the log file: {log_filename}. Exiting...')
            sys.exit()

        # Open a remote shell console session over the SSH connection and become the root user.
        rem_con = init_probe_console(logger, client)
        if rem_con == False: # Establishing the remote console session has failed. Exit.
            logger.critical("[CRITICAL] Main, Opening the remote console session failed")
            print("\n[CRITICAL] Main, Opening the remote console session failed")
            print(f'Check the log file: {log_filename}. Exiting...')
            sys.exit()

        # Run the localconsole menu on the remote probe and gather it's current settings.
        try:
            old_probe_configs_dict, interface_list, status = gather_probe_configs(logger, rem_con)
            if status == False:
                logger.critical("[CRITICAL] Main, Gathering the current probe configs has failed")
                print("\n[CRITICAL] Main, Gathering the current probe configs has failed")
                print('Closing the connection...')
                close_status = close_ssh_session(probe_creds, hostname, client, rem_con, logger)
                if close_status == False: # Connection close has failed.
                    logger.critical("[CRITICAL] Main, Closing the SSH connection failed")
                print(f'Check the log file: {log_filename}. Exiting...')
                sys.exit()
        except Exception: # You can get a traceback exception here if you already have a putty console session open to the probe.
            logger.critical('[CRITICAL] Main, An exception occurred while trying to gather probe configs')
            print('[CRITICAL] Main, An exception occurred while trying to gather probe configs')
            print(f'Check the log file: {log_filename}. Exiting...')
            sys.exit()

        # Create the backup config filename as 'probe IP' + 'probe_config_backup_' + a date-time string.
        now = datetime.now()
        date_time = now.strftime("%Y_%m_%d_%H%M%S")
        #probe_ipv4 = str(old_probe_configs_dict['agent_configs'][0]['IP V4 address']) # Get the IP addr of the probe.
        probe_ipv4 = hostname.replace('.', '_') # Replace dots with underscores so we have a valid filename.
        config_filename = probe_ipv4 + '_' 'probe_config_backup_' + str(date_time) + '.json'
        # Backup the finished configs dictionary to a json file.
        write_status = write_config_to_json(config_filename, old_probe_configs_dict, logger)
        if write_status == False: # Writing the probe config to a json file has failed. Exit.
            logger.critical("[CRITICAL] Main, Backing up current config to file has failed")
            print("\n[CRITICAL] Main, Backing up current config to file has failed")
            close_status = close_ssh_session(probe_creds, hostname, client, rem_con, logger) # Write failure, close the SSH connection
            if close_status == False: # Connection close has failed.
                logger.critical("[CRITICAL] Main, Closing the SSH connection failed")
            print(f'Check the log file: {log_filename}. Exiting...')
            sys.exit()

        if is_set_config_true == True: # The user specified the --set flag
            # NOTE: All set operations are stubbed out in this version. This version only gets configs.

            # Open the golden config file to use for setting the probe to the desired configuration.
            # Read it in as a python dictionary that we can parse.
            #new_probe_configs_dict = read_config_from_json(golden_probe_config_filename, logger)
            #if new_probe_configs_dict == False: # The read operation failed. Bail out.
                #print('Closing the connection...')
                #close_status = close_ssh_session(probe_creds, hostname, client, rem_con, logger)
                #print('Exiting...')
                #sys.exit()

            #set_status = set_probe_configs(old_probe_configs_dict, interface_list, rem_con, logger)
            #if set_status == False: # Closing the SSH session to the probe has failed. Exit.
                #logger.critical("[CRITICAL] Main, Setting the probe configs failed")
                #print("\n[CRITICAL] Main, Setting the probe configs failed")
                #close_status = close_ssh_session(probe_creds, hostname, client, rem_con, logger)
                #if close_status == False: # Connection close has failed.
                    #logger.critical("[CRITICAL] Main, Closing the SSH connection failed")
                #print(f'Check the log file: {log_filename}. Exiting...')
                #sys.exit()
            #else: # Success.
                #print('\n[INFO] All probe configurations were successfully applied')
                #logger.info("[INFO] All probe configurations were successfully applied")
            print('\n[INFO] All probe configurations were successfully backed up')
            print('[INFO] No modifications were made to the probe configurations')
            logger.info("[INFO] All probe configurations were successfully backed up")
            logger.info("[INFO] No modifications were made to the probe configurations")
        else: # The user specified the --get flag. We will not make any modifications.
            print('\n[INFO] All probe configurations were successfully backed up')
            print('[INFO] No modifications were made to the probe configurations')
            logger.info("[INFO] All probe configurations were successfully backed up")
            logger.info("[INFO] No modifications were made to the probe configurations")
        # Close the SSH session to the probe.
        close_status = close_ssh_session(probe_creds, hostname, client, rem_con, logger)
        if close_status == False: # Connection close has failed.
            logger.critical("[CRITICAL] Main, Closing the SSH connection failed")
            print("\n[CRITICAL] Main, Closing the SSH connection failed")
            print(f'Check the log file: {log_filename}. Exiting...')
            sys.exit()
        else:
            # We are done with this probe. IF this is the last one, exit out..
            if host_count == number_of_hosts:
                print('[INFO] Program execution finished')
                logger.info("[INFO] Program execution is finished")
                sys.exit()

if __name__ == "__main__":
    main()
