from cryptography.fernet import Fernet
import ctypes
import time
import os
import sys
import getpass
import stdiomask
import argparse

"""
This program provides a user interactive menu to allow the entry of both connection criteria and authentication
credentials for Netscout Infinistream / vStream probes in order to produce a ProbeCredFile.ini file.
The ProbeCredFile.ini can then be used by other programs to make the connections to netScout ISNGs or vStreams
and authenticate without requiring any human interaction. The user can specify the one or more probe targets manually,
specify a text file to read the target list from, or input nG1 probe_creds to gather the target list from the nG1 API.
Any passwords or tokens entered by the user will be stored in encrypted form in the ProbeCredFile.ini file.
A decryption key is produced by the program and placed in the local directory.
This key file will be used by any other program that uses the ProbeCredFile.ini file to determine targets and credentials.
"""


class ProbeCredentials():
    """
    This class creates a credentials object that holds all the attributes needed to connect to
    a NetScout Infinistream or vStream probe and authenticate.
    :return: An instance of this class with all parameters initialized.
    """
    def __init__(self):
        self.probehostname = []
        self.probeport = ""
        self.probeusername = ""
        self.probesshpemfile = ""
        self.usessshpemfile = False
        self.probepassword = ""
        self.probekey_file = "probekey.key"
        self.probekey = ""
        self.expiry_time = -1

class nGeniusONECredentials():
    """
    This class creates a credentials object that holds all the attributes needed to connect to
    a NetScout nGeniusONE appliance or virtual appliance and authenticate.
    :return: An instance of this class with all parameters initialized.
    """
    def __init__(self):
        self.ng1hostname = ""
        self.ng1port = ""
        self.ng1username = ""
        self.ng1password = ""
        self.use_ng1_token = False
        self.ng1token = ""
        self.ng1key_file = "ng1key.key"
        self.ng1key = ""
        self.expiry_time = -1

def flags_and_arguments(prog_version):
    """Provides the program version and for future expansion using flags or arguments.
    :program_version: Pass in the program version so the user can type --version.
    :return: status = True if successful. Return status = False if any errors occur.
    """
    try:
        # Define the program description
        text = 'This program is used to input connection and credentials parameters for one or more NetScout Infinistreams or vStreams probes.'
        # Initiate the parser with a description
        parser = argparse.ArgumentParser(description=text)
        parser.add_argument('--targets', action="store_true", help='read in the list of probe IP addresses from probe_targets.txt', dest='targets', default=False)
        parser.add_argument('--version', action="store_true", help="show program version and exit", dest='version', default=False)
        # Parse the arguments and create a result.
        args = parser.parse_args()
        #config_type = args.config_type
        if args.version == True: # They typed either "-V" or "--version" flags.
            print(f'Program version is: {prog_version}')
            sys.exit()
        status = True
        return status
    except Exception as e: # Handle unexpected errors.
        print(f'[ERROR] Parsing the program launch arguments has failed')
        print(f'[ERROR] An exception occurred: {e}')
        status = False
        return status

def create_ng1_creds(ng1_creds, ng1_cred_filename):
    """
    This function encrypts the password or token and then stores the key in a key file.
    It also stores the encrypted password or token into a credentials file, with all other target information.
    :ng1_creds: An instance of the Credentials class that holds all of the nG1 API connection and authentication parameters.
    :ng1_cred_filename: A string that is the name of the local credentials file. CredFile.ini is the default.
    :return: True if successful, False if unsuccessful.
    """
    try:
        os_type = sys.platform
        if os_type == 'linux':
            ng1_creds.ng1key_file = '.ng1key.key' # Prepend a dot to the filename to hide it in Linux.
        elif os_type == 'win32' or os_type == 'win64':
                ng1_creds.ng1key_file = 'ng1key.key' # Default key filename if Windows.
        else:
            ng1_creds.ng1key_file = 'ng1key.key' # Default key filename.

        # If there exists an older key file, This will remove it.
        if os.path.exists(ng1_creds.ng1key_file):
            os.remove(ng1_creds.ng1key_file)
        if ng1_creds.ng1token == '': # The user entered a password.
            # The user entered a password, so we will store the key needed to decrypt that password.
            # Open the ng1key.key file and place the key in it.
            ng1_creds.ng1key = Fernet.generate_key()
            fng1 = Fernet(ng1_creds.ng1key)
            ng1_creds.ng1password = fng1.encrypt(ng1_creds.ng1password.encode()).decode()
            del fng1
            with open(ng1_creds.ng1key_file, 'w') as key_in:
                key_in.write(ng1_creds.ng1key.decode())
                # Hiding the key file. The below code learns OS and tries to hide key file accordingly.
                if os_type == 'win32' or os_type == 'win64':
                    ctypes.windll.kernel32.SetFileAttributesW(ng1_creds.ng1key_file, 2)
                else:
                    pass
        else: # The user entered a token.
            # The user entered a token, so we will store the key needed to decrypt that token.
            # Open the ng1key.key file and place the key in it.
            ng1_creds.ng1key = Fernet.generate_key()
            fng1 = Fernet(ng1_creds.ng1key)
            ng1_creds.ng1token = fng1.encrypt(ng1_creds.ng1token.encode()).decode()
            del fng1
            with open(ng1_creds.ng1key_file, 'w') as key_in:
                key_in.write(ng1_creds.ng1key.decode())
                # Hiding the key file. The below code learns OS and tries to hide key file accordingly.
                if os_type == 'win32' or os_type == 'win64':
                    ctypes.windll.kernel32.SetFileAttributesW(ng1_creds.ng1key_file, 2)
                else:
                    pass
        with open(ng1_cred_filename, 'w') as file_in: # Write the nG1 connection and user authentication parameters to the CredFile.ini file.
            file_in.write(f"# nGeniusONE Credentials file:\nng1hostname={ng1_creds.ng1hostname}\nng1username={ng1_creds.ng1username}\nng1password={ng1_creds.ng1password}\nng1token={ng1_creds.ng1token}\nng1port={ng1_creds.ng1port}\nexpirytime={ng1_creds.expiry_time}")
    except IOError as e:
        print('[ERROR] Unable to write file')
        print(f'I/O error: {e}')
        return False
    except PermissionError as e:
        os.remove(ng1_creds.key_file)
        print('[ERROR] Unable to write to file')
        print(f'Permissions error: {e}')
        return False
    except Exception as e: #handle other exceptions such as attribute errors
        print('[ERROR] Unable to write to file')
        print(f'Unexpected error: {e}')
        return False

    return True

def create_probe_creds(probe_creds, probe_cred_filename):
    """
    This function encrypts the password (if used) and it create a key file that can be used later for decryption.
    It writes the decryption key to the key file and attempts to hide the key file depending on the OS.
    It also stores the encrypted password (if used) into the ProbeCredFile.ini file, with all other target information.
    :probe_creds: An instance of the Credentials class that holds all of the probe connection and authentication parameters.
    :probe_cred_filename: A string that is the name of the local credentials file. ProbeCredFile.ini is the default.
    :return: True if successful, False if unsuccessful.
    """
    try:
        if probe_creds.usessshpemfile == False: # We are using a password. We need to encrypt it.
            os_type = sys.platform
            if os_type == 'linux':
                probe_creds.probekey_file = '.probekey.key' # Prepend a dot to the filename to hide it in Linux.
            elif os_type == 'win32' or os_type == 'win64':
                    probe_creds.probekey_file = 'probekey.key' # Default key filename if Windows.
            else:
                probe_creds.probekey_file = 'probekey.key' # Default key filename if OS cannot be determined.

            # If there exists an older key file, This will remove it.
            if os.path.exists(probe_creds.probekey_file):
                os.remove(probe_creds.probekey_file)
            # We will store the key needed to decrypt the user entered password.
            # Open the probekey.key file and place the key in it.
            probe_creds.probekey = Fernet.generate_key()
            fprobe = Fernet(probe_creds.probekey)
            probe_creds.probepassword = fprobe.encrypt(probe_creds.probepassword.encode()).decode()
            del fprobe
            with open(probe_creds.probekey_file, 'w') as key_in:
                key_in.write(probe_creds.probekey.decode())
                # Hiding the key file. The below code learns OS and tries to hide key file accordingly.
                if os_type == 'win32' or os_type == 'win64':
                    ctypes.windll.kernel32.SetFileAttributesW(probe_creds.probekey_file, 2)
            with open(probe_cred_filename, 'w') as file_in: # Write the probe connection and user authentication parameters to the ProbeCredFile.ini file.
                file_in.write(f"# Infinistrem-vStream Credentials file:\nprobehostname={probe_creds.probehostname}\nprobeusername={probe_creds.probeusername}\nprobepassword={probe_creds.probepassword}\nprobeport={probe_creds.probeport}\nexpirytime={probe_creds.expiry_time}")
        else: # We are using a .pem file rather than a password for vStreams.
            with open(probe_cred_filename, 'w') as file_in: # Write the probe connection and user authentication parameters to the ProbeCredFile.ini file.
                file_in.write(f"# Infinistrem-vStream Credentials file:\nprobehostname={probe_creds.probehostname}\nprobeusername={probe_creds.probeusername}\nprobesshpemfile={probe_creds.probesshpemfile}\nprobeport={probe_creds.probeport}\nexpirytime={probe_creds.expiry_time}")
    except IOError as e: # Handle file I/O errors.
        print('[ERROR] Unable to write file')
        print(f'I/O error: {e}')
        return False
    except PermissionError as e:
        os.remove(probe_creds.key_file)
        print('[ERROR] Unable to write to file')
        print(f'Permissions error: {e}')
        return False
    except Exception as e: # Handle unexpected errors.
        print('[ERROR] Unable to write to file')
        print(f'Unexpected error({e})')
        return False

    return True

def yes_or_no(question):
    reply = ""
    while reply != 'y' or reply != 'n':
        reply = str(input(question+' (y/n): ')).lower().strip()
        if reply[:1] == 'y':
            return True
        if reply[:1] == 'n':
            return False
        else:
            print("The answer is invalid, please enter y or n")
            continue

def user_entry_menu(probe_creds, ng1_creds, ng1_cred_filename):
    """
    This function prompts the user to input the probe connection and user credentials parameters.
    The user can manually enter one or more target probe IPs, but only one set of credentials.
    The user can alternatively specify a list of probe targets from a list or enter nG1 probe_creds to pull
    the probe list down from the nG1 API.
    The params that are entered become parameters of the probe_creds instance.
    :probe_creds: An instance of the Credentials class to place all the entered parameters into.
    :ng1_creds: An instance of the Credentials class that holds all of the nG1 API connection and authentication parameters.
    :ng1_cred_filename: A string that is the name of the local credentials file. CredFile.ini is the default.
    :return: True if successful, False if unsuccessful.
    """
    try:
        # Accepting probe connection criteria and user credentials via user menu manual input.
        print("\nInput the required Infinstream/vStream connection info or type 'exit' at any time to bail out")
        print('---------------------------------------------------------------------------------------------')

        while True:
            menu_selection = [1, 2, 3]
            print('\nPlease select the source of the probe target list')
            print('[1] Manual entry')
            print('[2] Text file')
            print('[3] nGeniusONE API')
            target_source = input('Selection: ')
            if target_source.lower() == 'exit':
                return False
            else:
                if target_source.isnumeric():
                    target_source = int(target_source)
                else:
                    print('Invalid entry, please enter 1, 2 or 3')
                    continue # They made an invalid selection.
            if target_source not in menu_selection :
                print('Invalid entry, please enter 1, 2 or 3')
                continue # They made an invalid selection.
            else:
                break # They made a valid selection.
        if target_source == 1: # Manual input of IPs.
            print('You selected option 1, manual entry of one or more probe targets')
            loop_counter = 0
            while True:
                if loop_counter == 0:
                    probehostname = input("Enter the probe Hostname or IP Address: ")
                else:
                    probehostname = input("Enter an additional probe Hostname or IP Address (or <enter> if no more targets to enter): ")
                if probehostname.lower() == 'exit':
                    return False
                elif probehostname == '':
                    print('All target Hostname/IP Address entries complete\n')
                    break
                else:
                    probe_creds.probehostname.append(probehostname)
                loop_counter += 1
        elif target_source == 2: # Specify a text filename for the probe target list.
            while True:
                print('You selected option 2, read in a text file that lists one or more probe targets')
                print("\nPlease enter the text file name or <enter> for default 'probe_targets.txt'")
                probe_targets_filename = input('Filename with .txt extension: ')
                if probe_targets_filename == '': # The just hit enter to go with the default filename.
                    probe_targets_filename = 'probe_targets.txt'
                    break
                elif ".txt" not in probe_targets_filename:
                    print('filename must have a .txt extension, please try again')
                    continue
                elif probe_targets_filename.lower() == 'exit':
                    return False
                else:
                    break
            target_list, status = read_probe_targets_file(probe_targets_filename)
            if status == False:
                print('[ERROR] The read_probe_targets_file function has failed')
                return False
            else:
                print('Target Hostname/IP Address list was acquired from the probe targets text file')
                print(f'Target list is: {target_list}\n')
                target_list = target_list.strip('][').split(', ') # Convert string representation of a list to a real list.
                probe_creds.probehostname = target_list
        elif target_source == 3: # The user wants us to query the nG1 to produce a list of active probes.
            probe_creds.probehostname.append('ng1') # Set the probe hostname to ng1 so that the main program knows what to target.
            status = ng1_user_entry_menu(ng1_creds)
            if status == False:
                print('[ERROR] The ng1_user_entry_menu function has failed or user exited')
                return False
            status = create_ng1_creds(ng1_creds, ng1_cred_filename)
            if status == False:
                print('[ERROR] The create_ng1_creds function has failed')
                return False
            print(f'nGeniusONE connection and credentials successfully written to: {ng1_cred_filename}')
            print('Continuing with common probe parameters entry...')
        probeport = input("\nEnter probe connection port or <enter> for default SSH port '22': ")
        if probeport == '': # Use the default setting.
            probe_creds.probeport = 22
        elif probeport.lower() == 'exit':
            return False
        else:
            probe_creds.probeport = int(probeport)
        probeusername = input("Enter probe Username or <enter> for default 'root': ")
        if probeusername == '': # Use the default setting.
            probe_creds.probeusername = 'root'
        elif probeusername.lower() == 'exit':
            return False
        else:
            probe_creds.probeusername = probeusername
          # Give the user the option to use a .pem key file or a username:password pair.
          # For vStreams on AWS, you must supply a .pem key file.
          # We will assume the same key file is used on all the target vStream IPs they enter.
        if yes_or_no("Use an SSH .pem key file?") == True:
            probe_creds.probesshpemfile = input("Enter probe SSH key filename: ")
            if probe_creds.probesshpemfile.lower() == 'exit':
                return False
            probe_creds.usessshpemfile = True
        else: # The user said no, so they want to enter a password.
            while True:
                # Do not echo the user entered password characters to the terminal.
                probepassword = stdiomask.getpass(prompt="Enter probe Password: ")
                confirm = stdiomask.getpass("Confirm probe Password: ") # They need to type it in again.
                if probepassword == confirm: # The two password entries match.
                    probe_creds.probepassword = probepassword
                    break
                elif probepassword.lower() == 'exit':
                    return False
                else: # The two password entries do not match, ask them to try again.
                    print("Passwords do not match")
                    print('Try again')
                    continue
            probe_creds.usessshpemfile = False

        expiry_time = input("Enter the probe expiry time for key file in minutes or <enter> for default 'never expire': ")
        if expiry_time == '': # Use the default setting.
            probe_creds.expiry_time = -1
        elif expiry_time.lower() == 'exit':
            return False
        else:
            probe_creds.expiry_time = int(expiry_time)
    except Exception as e: # Handle unexpected errors.
        print('[ERROR] The probe entry menu has failed')
        print(f'Unexpected error({e})')
        return False

    return True

def ng1_user_entry_menu(ng1_creds):
    """
    This function prompts the user to input the nG1 connection and user credentials parameters.
    The params that are entered become parameters of the creds instance.
    :creds: An instance of the Credentials class to place all the entered parameters into.
    :return: True if successful, False if unsuccessful.
    """
    try:
        # Accepting nG1 connection criteria and user credentials via user menu manual input.
        print('You selected option 3, use nGeniusONE API as the target source')
        print("\nInput the required nGeniusONE connection info or type 'exit' at any time to bail out")
        print('---------------------------------------------------------------------------------------------')
        while True:
            ng1hostname = input("Enter the nG1 Hostname or IP Address: ")
            if ng1hostname.lower() == 'exit':
                return False
            elif ng1hostname == '': #The user hit enter without entering anything
                print('Not a valid hostname or IP address, try again')
                continue
            else:
                ng1_creds.ng1hostname = ng1hostname
                break
        ng1port = input("Enter nG1 connection port or <enter> for default '443': ")
        if ng1port == '': # Use the default setting.
            ng1_creds.ng1port = 443
        elif ng1port.lower() == 'exit':
            return False
        else:
            ng1_creds.ng1port = int(ng1port)
        ng1username = input("Enter nG1 Username or <enter> for default 'administrator': ")
        if ng1username == '': # Use the default setting.
            ng1_creds.ng1username = 'administrator'
        elif ng1username.lower() == 'exit':
            return False
        else:
            ng1_creds.ng1username = ng1username
        # Give the user the option to use an API Token or a username:password pair.
        if yes_or_no("Use Token instead of Password?") == True:
            ng1token = input("Enter nG1 User Token: ")
            if ng1token.lower() == 'exit':
                return False
            else: # They said yes, set the creds parameter.
                ng1_creds.ng1token = ng1token
                ng1_creds.ng1password = ''
                ng1_creds.use_ng1_token = True
        else: # They said no, so we will ask them to enter a password.
            while True:
                # Do not echo the user entered password characters to the terminal.
                ng1password = stdiomask.getpass(prompt="Enter nG1 Password: ")
                confirm = stdiomask.getpass("Confirm nG1 Password: ") # They need to type it in again.
                if ng1password == confirm: # The two password entries match.
                    ng1_creds.ng1password = ng1password
                    ng1_creds.ng1token = ''
                    ng1_creds.use_ng1_token = False
                    break
                elif ng1password.lower() == 'exit':
                    return False
                else: # The two password entries do not match, ask them to try again.
                    print("Passwords do not match")
                    print('Try again')
                    continue
        expiry_time = input("Enter the ng1 expiry time for key file in minutes or <enter> for default 'never expire': ")
        if expiry_time == '': # Use the default setting.
            ng1_creds.expiry_time = -1
        elif expiry_time.lower() == 'exit':
            return False
        else:
            ng1_creds.expiry_time = int(expiry_time)
    except Exception as e: # Handle any and all exceptions.
        print('[ERROR] The ng1 entry menu has failed')
        print(f'Unexpected error: {e}')
        return False

    return True


def read_probe_targets_file(probe_targets_filename):
    """Read in the list of probe IP addresses from the probe_targets text file.
    :probe_targets_filename: A string that is the name of the probe targets text file to read in.
    :return: If successful, return the list of probe target IP addresses and status = true.
    Return an empty target_list and status = False if any errors occur.
    """
    target_list = []
    # Open the probe_targets text file and read in the probe IP list.
    try: # Open the probe_targets_filename.
        with open(probe_targets_filename, 'r') as targets_in:
            lines = targets_in.readlines()
            target_list = lines[0].rstrip("\n")
            # Do some basic verification that the text read in is in the form of a list.
            if '[' not in target_list or ']' not in target_list or ',' not in target_list or target_list == '':
                print(f'\n[ERROR]The contents of the target list file: {probe_targets_filename} are invalid')
                print('The text should be in list format')
                print('Example: [1.1.1.1, 2.2.2.2, 3.3.3.3]')
                status = False
                return target_list, status
            else:
                print(f'successfully read file: {probe_targets_filename}')
    except IOError as e: # Handle file I/O errors.
        print(f"\n[ERROR] Unable to open or read the contents the targets file: {probe_targets_filename}")
        print(f'[ERROR] I/O error: {e}')
        status = False
        return target_list, status
    except Exception as e: # Handle unexpected errors.
        print(f"\n[ERROR] Unable to open or read the contents of the targets file: {probe_targets_filename}")
        print(f"Exception error is:\n{e}")
        status = False
        return target_list, status
    status = True
    return target_list, status # The function was successful.

def main():
    prog_version = '0.2'
    # Create an instance of the Credentials class to store all the probe connection paramaters and authentication parameters.
    probe_creds = ProbeCredentials()
    ng1_creds = nGeniusONECredentials()
    # So that other scripts can use this connection info without any menu, we must hardcode the probe and nG1 credentials filenames.
    probe_cred_filename = 'ProbeCredFile.ini'
    ng1_cred_filename = 'CredFile.ini'
    # Hardcoding the probe targets default filename to read in from the local directory if the user sets the --targets flag.
    probe_targets_filename = 'probe_target.txt'

    status = flags_and_arguments(prog_version)
    if status == False: # Parsing the user entered flags or arguments has failed Exit.
        print("\n[CRITICAL] Main, Parsing the user entered flags or arguments has failed")
        print('\nExiting the script...')
        sys.exit()

    # Prompt the user to input the probe connection and user authentication parameters.
    if user_entry_menu(probe_creds, ng1_creds, ng1_cred_filename) == False: #The credentials params entry menu has failed:
        print('[CRITICAL] Main: The user_entry_menu has failed')
        print('\nExiting the script...')
        sys.exit()

    # Create the credentials file.
    if create_probe_creds(probe_creds, probe_cred_filename) == False: # The create credentials file function has failed.
        print('[CRITICAL] Main: create_probe_creds function has failed')
        print('\nExiting the script...')
        sys.exit()
    else: # The credentials file was created successfully.
        print(f"\nThe probe credentials file {probe_cred_filename} was created at {time.ctime()}")
        print('\nProgram execution has completed successfully')

if __name__ == "__main__":
    main()
