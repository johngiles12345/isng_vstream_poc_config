from cryptography.fernet import Fernet
import ctypes
import time
import os
import sys
import getpass
import stdiomask
import argparse

"""
This program provides a user interactive menu to allow users to enter both connection criteria and authentication
credentials to produce a ProbeCredFile.ini file. The ProbeCredFile.ini can then be used by other programs to make the
connections to netScout ISNGs or vStreams and authenticate without requiring any human interaction.
An optional flag --targets can be used to tell the program that there is more than one probe to input
 paramaters for. The --targets flag tells the program to specifically look for a probe_targets.txt file
 that has a list of IP addresses, one for each ISNG/vStream they want to process. Otherwise by default,
 the program will ask the user if they just want to enter them one by one. Also, any passwords or tokens
 entered by the user will be stored in encrypted form in the ProbeCredFile.ini file. A decryption key is produced
 by the program and placed in the local directory. This key file will be used by any other program that
 uses the ProbeCredFile.ini file to determine targets and credentials.
"""


class Credentials():
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

def flags_and_arguments(prog_version):
    """Allows the user to an optional argument of --targets to tell the program to use a text file to
    read in the list of probe IP address rather than having them enter each one manually.
    Adding to --targets flag will indicate that there is a file called probe_targets.txt in the local directory
    and to read that in.
    If the --targets flag is not specified by the user, the program allow the user to enter probe IP addressses
    one by one manually.
    :program_version: Pass in the program version so the user can type --version.
    :return: is_target_true and status = True if successful. Return is_target_true and status = False if any errors occur.
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
        if args.targets == True: # They typed the "--targets" flag.
            is_targets_true = True # I need to read in the probe_targets.txt file.
        else:
            is_targets_true = False # I will allow the user to input the IP addresses manually.
        status = True

        return status, is_targets_true
    except Exception as e: # Handle unexpected errors.
        print(f'[ERROR] Parsing the program launch arguments has failed')
        print(f'[ERROR] An exception occurred: {e}')
        status = False
        is_targets_true = False
        return status, is_targets_true

def create_cred(creds, cred_filename):
    """
    This function encrypts the password (if used) and it create a key file that can be used later for decryption.
    It writes the decryption key to the key file and attempts to hide the key file depending on the OS.
    It also stores the encrypted password (if used) into the ProbeCredFile.ini file, with all other target information.
    :creds: An instance of the Credentials class that holds all of the probe connection and authentication parameters.
    :cred_filename: A string that is the name of the local credentials file. ProbeCredFile.ini is the default.
    :return: True if successful, False if unsuccessful.
    """
    try:
        if creds.usessshpemfile == False: # We are using a password. We need to encrypt it.
            os_type = sys.platform
            if os_type == 'linux':
                creds.probekey_file = '.probekey.key' # Prepend a dot to the filename to hide it in Linux.
            elif os_type == 'win32' or os_type == 'win64':
                    creds.probekey_file = 'probekey.key' # Default key filename if Windows.
            else:
                creds.probekey_file = 'probekey.key' # Default key filename if OS cannot be determined.

            # If there exists an older key file, This will remove it.
            if os.path.exists(creds.probekey_file):
                os.remove(creds.probekey_file)
            # We will store the key needed to decrypt the user entered password.
            # Open the probekey.key file and place the key in it.
            creds.probekey = Fernet.generate_key()
            fprobe = Fernet(creds.probekey)
            creds.probepassword = fprobe.encrypt(creds.probepassword.encode()).decode()
            del fprobe
            with open(creds.probekey_file, 'w') as key_in:
                key_in.write(creds.probekey.decode())
                # Hiding the key file. The below code learns OS and tries to hide key file accordingly.
                if os_type == 'win32' or os_type == 'win64':
                    ctypes.windll.kernel32.SetFileAttributesW(creds.probekey_file, 2)
                else:
                    pass
            with open(cred_filename, 'w') as file_in: # Write the probe connection and user authentication parameters to the ProbeCredFile.ini file.
                file_in.write(f"# Infinistrem-vStream Credentials file:\nprobehostname={creds.probehostname}\nprobeusername={creds.probeusername}\nprobepassword={creds.probepassword}\nprobeport={creds.probeport}\nexpirytime={creds.expiry_time}")
        else: # We are using a .pem file rather than a password for vStreams.
            with open(cred_filename, 'w') as file_in: # Write the probe connection and user authentication parameters to the ProbeCredFile.ini file.
                file_in.write(f"# Infinistrem-vStream Credentials file:\nprobehostname={creds.probehostname}\nprobeusername={creds.probeusername}\nprobesshpemfile={creds.probesshpemfile}\nprobeport={creds.probeport}\nexpirytime={creds.expiry_time}")
    except IOError as e: # Handle file I/O errors.
        print('[ERROR] Unable to write file')
        print(f'I/O error({e.errno}): {e.strerror}')
        return False
    except PermissionError as e:
        os.remove(creds.key_file)
        print('[ERROR] Unable to write to file')
        print(f'Permissions error({e.errno}): {e.strerror}')
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

def user_entry_menu(creds, is_targets_true, target_list):
    """
    This function prompts the user to input the probe connection and user credentials parameters.
    The user can enter one or more target probe IPs, but only one set of credentials
    The params that are entered become parameters of the creds instance.
    :creds: An instance of the Credentials class to place all the entered parameters into.
    :is_target_true: A boolean to tell the menu if we already have the probe target list or if we
     need the user to input it/them manually.
    :target_list: The list of IPs/hostnames of the probes read in from the probe_targets_filename.
    :return: True if successful, False if unsuccessful.
    """
    try:
        # Accepting probe connection criteria and user credentials via user menu manual input.
        print("\nInput the required Infinstream/vStream connection info or type 'exit' at any time to bail out")
        print('---------------------------------------------------------------------------------------------')
        if is_targets_true == False: # The user did not use the --targets flag, thus we need manual input of IPs.
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
                    creds.probehostname.append(probehostname)
                loop_counter += 1
        else:
            print('Target Hostname/IP Address list was acquired from the probe_target.txt file')
            print(f'Target list is: {target_list}\n')
            target_list = target_list.strip('][').split(', ') # Convert string representation of a list to a real list.
            creds.probehostname = target_list
        probeport = input("Enter probe connection port or <enter> for default SSH port '22': ")
        if probeport == '': # Use the default setting.
            creds.probeport = 22
        elif probeport.lower() == 'exit':
            return False
        else:
            creds.probeport = int(probeport)
        probeusername = input("Enter probe Username or <enter> for default 'root': ")
        if probeusername == '': # Use the default setting.
            creds.probeusername = 'root'
        elif probeusername.lower() == 'exit':
            return False
        else:
            creds.probeusername = probeusername
          # Give the user the option to use a .pem key file or a username:password pair.
          # For vStreams on AWS, you must supply a .pem key file.
          # We will assume the same key file is used on all the target vStream IPs they enter.
        if yes_or_no("Use an SSH .pem key file?") == True:
            creds.probesshpemfile = input("Enter probe SSH key filename: ")
            if creds.probesshpemfile.lower() == 'exit':
                return False
            creds.usessshpemfile = True
        else: # The user said no, so they want to enter a password.
            while True:
                # Do not echo the user entered password characters to the terminal.
                probepassword = stdiomask.getpass(prompt="Enter probe Password: ")
                confirm = stdiomask.getpass("Confirm probe Password: ") # They need to type it in again.
                if probepassword == confirm: # The two password entries match.
                    creds.probepassword = probepassword
                    break
                elif probepassword.lower() == 'exit':
                    return False
                else: # The two password entries do not match, ask them to try again.
                    print("Passwords do not match")
                    print('Try again')
                    continue
            creds.usessshpemfile = False

        expiry_time = input("Enter the expiry time for key file in minutes or <enter> for default 'never expire': ")
        if expiry_time == '': # Use the default setting.
            creds.expiry_time = -1
        elif expiry_time.lower() == 'exit':
            return False
        else:
            creds.expiry_time = int(expiry_time)
    except Exception as e: # Handle unexpected errors.
        print('[ERROR] The entry menu has failed')
        print(f'Unexpected error({e})')
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
        print(f'[ERROR] I/O error({e.errno}):  {e.strerror}.')
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
    prog_version = '0.1'
    # Create an instance of the Credentials class to store all the probe connection paramaters and authentication parameters.
    creds = Credentials()
    # So that other scripts can use this connection info without any menu, we must hardcode the cred_filename.
    cred_filename = 'ProbeCredFile.ini'
    # Hardcoding the probe targets filename to read in from the local directory if the user sets the --targets flag.
    probe_targets_filename = 'probe_target.txt'

    status, is_targets_true = flags_and_arguments(prog_version)
    if status == False: # Parsing the user entered flags or arguments has failed Exit.
        print("\n[CRITICAL] Main, Parsing the user entered flags or arguments has failed")
        print('Exiting...')
        sys.exit()

    if is_targets_true == True:
        target_list, status = read_probe_targets_file(probe_targets_filename)
        if status == False:
            print('[CRITICAL] Main: Reading the probe_target.txt file has failed')
            print('\nExiting the script...')
            sys.exit()
    else:
        target_list = [] # The user did not set the --targets flag, thus we need manual entry of IPs.

    # Prompt the user to input the probe connection and user authentication parameters.
    if user_entry_menu(creds, is_targets_true, target_list) == False: #The credentials params entry menu has failed:
        print('[CRITICAL] Main: The user_entry_menu has failed')
        print('\nExiting the script...')
        sys.exit()

    # Create the credentials file.
    if create_cred(creds, cred_filename) == False: # The create credentials file function has failed.
        print('[CRITICAL] Main: create_cred has failed')
        print('\nExiting the script...')
        sys.exit()
    else: # The credentials file was created successfully.
        print(f"\nThe credentials file {cred_filename} was created at {time.ctime()}")
        print('\nProgram execution has completed successfully')

if __name__ == "__main__":
    main()
