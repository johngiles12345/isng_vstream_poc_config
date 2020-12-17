from cryptography.fernet import Fernet
import ctypes
import time
import os
import sys
import string
import getpass
import stdiomask

class Credentials():
    """
    This class creates a credentials object that is holds all the attributes needed to connect to
    a NetScout Infinistream or vStream probe.It stores the encrypted password in a credentials file,
    with all other target information. It also creates a private key to use when decrypting the passord.
    :param cred_filename: A string that is the name of the local credentials file.
    :return: True if successful, False if unsuccessful.
    """
    def __init__(self):
        self.__probehostname = ""
        self.__probeport = 22
        self.__probeusername = ""
        self.__probepassword = ""
        self.__use_ssh_keyfile = False
        self.__probe_ssh_keyfile = ""
        self.__probekey_file = 'probekey.key'
        self.__probekey = ""
        self.__time_of_exp = -1

    @property
    def probehostname(self):
        return self.__probehostname
    @probehostname.setter
    def probehostname(self, probehostname):
        self.__probehostname = probehostname

    @property
    def probeport(self):
        return self.__probeport
    @probeport.setter
    def probeport(self, probeport):
        self.__probeport = probeport

    @property
    def probeusername(self):
        return self.__probeusername
    @probeusername.setter
    def probeusername(self, probeusername):
        self.__probeusername = probeusername

    @property
    def probepassword(self):
        return self.__probepassword
    @probepassword.setter
    def probepassword(self, probepassword):
        self.__probekey = Fernet.generate_key()
        fprobe = Fernet(self.__probekey)
        self.__probepassword = fprobe.encrypt(probepassword.encode()).decode()
        del fprobe

    @property
    def use_ssh_keyfile(self):
        return self.__use_ssh_keyfile
    @use_ssh_keyfile.setter
    def use_ssh_keyfile(self, use_ssh_keyfile):
        self.__use_ssh_keyfile = use_ssh_keyfile

    @property
    def probe_ssh_keyfile(self):
        return self.__probe_ssh_keyfile
    @probe_ssh_keyfile.setter
    def probe_ssh_keyfile(self, probe_ssh_keyfile):
        self.__probe_ssh_keyfile = probe_ssh_keyfile

    @property
    def probekey_file(self):
        return self.__probekey_file
    @probekey_file.setter
    def probekey_file(self, probekey_file):
        self.__probekey_file = probekey_file

    @property
    def probekey(self):
        return self.__probekey
    @probekey.setter
    def probekey(self, probekey):
        self.__probekey = probekey

    @property
    def expiry_time(self):
        return self.__time_of_exp
    @expiry_time.setter
    def expiry_time(self, exp_time):
        if (exp_time >= 2):
            self.__time_of_exp = exp_time

    def create_cred(self, cred_filename):
        """
        This function encrypts the password then stores the key in a key file.
        It also stores the encrypted password in a credentials file, with all other target information.
        :param cred_filename: A string that is the name of the local credentials file.
        :return: True if successful, False if unsuccessful.
        """
        try:
            with open(cred_filename, 'w') as file_in:
                file_in.write("#Probe Credentials file:\nExpiry={}\nprobe_ssh_keyfile={}\nprobeusername={}\nprobepassword={}\nprobehostname={}\nprobeport={}\n"
                            .format(self.__time_of_exp, self.__probe_ssh_keyfile, self.__probeusername, self.__probepassword, self.__probehostname, self.__probeport))
                # If there exists an older key file, This will remove it.
                if os.path.exists(self.__probekey_file):
                    os.remove(self.__probekey_file)
        except IOError as e:
            print(f'[ERROR] Unable to open credentials file: {cred_filename}')
            print(f"I/O error({e.errno}): {e.strerror}")
            return False
        except: #handle other exceptions such as attribute errors
            print(f'[ERROR] Unable to open credentials file: {cred_filename}')
            print(f'Unexpected error: {sys.exc_info()[0]}')
            return False

        if self.__probe_ssh_keyfile == '': # The user did not select to enter an SSH .pem keyfile filename.
            # The user entered a password, so we will store the key needed to decrypt that password.
            # Open the key.key file and place the key in it.
            try:
                os_type = sys.platform
                if os_type == 'linux':
                    self.__probekey_file = '.' + self.__probekey_file
                else:
                    pass
                with open(self.__probekey_file, 'w') as key_in:
                        key_in.write(self.__probekey.decode())
                        # Hiding the key file. The below code learns OS and tries to hide key file accordingly.
                        #if os_type == 'win32' or os_type == 'win64':
                            #ctypes.windll.kernel32.SetFileAttributesW(self.__probekey_file, 2)
                        #else:
                            #pass
            except IOError as e:
                print(f'[ERROR] Unable to write to key file: {self.__probekey_file}')
                print(f"I/O error({e.errno}): {e.strerror}")
                return False
            except PermissionError:
                os.remove(self.__key_file)
                print(f'[ERROR] Unable to write to key file: {self.__probekey_file}')
                print("A permissions error has occurred")
                return False
            except: #handle other exceptions such as attribute errors
                print(f'[ERROR] Unable to write to key file: {self.__probekey_file}')
                print(f'Unexpected error: {sys.exc_info()[0]}')
                return False

        self.__probehostname = ""
        self.__probeport = 22
        self.__probeusername = ""
        self.__probepassword = ""
        self.__use_ssh_keyfile = False
        self.__probe_ssh_keyfile = ""
        self.__probekey_file = 'probekey.key'
        self.__probekey = ""
        self.__time_of_exp = -1

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

def user_entry_menu(creds):
    """
    This function prompts the user to input the credentials parameters.
    The params that are entered become parameters of the creds instance.
    :param creds: An instance of the Credentials class.
    :return: True if successful, False if unsuccessful.
    """
    # Accepting credentials via user menu input.
    print("\nInput the required probe SSH connection info or type 'exit' to bail out")
    creds.probehostname = input("Enter probe hostname/IP: ")
    if creds.probehostname.lower() == 'exit':
        return False
    probeport = input("Enter SSH port or <enter> for 22: ")
    if probeport == '':
        creds.probeport = 22
    elif probeport.lower() == 'exit':
        return False
    else:
        creds.probeport = int(probeport)
    creds.probeusername = input("Enter probe Username or <enter> for 'root': ")
    if creds.probeusername == '':
        creds.probeusername = 'root'
    elif creds.probeusername.lower() == 'exit':
        return False
    # Give the user the option to use an API Token or a username:password pair
    if yes_or_no("Use an SSH .pem key file?") == True:
        creds.probe_ssh_keyfile = input("Enter probe SSH key filename: ")
        if creds.probe_ssh_keyfile.lower() == 'exit':
            return False
    else:
        while True:
            # Do not echo the user entered password characters to the terminal.
            probepassword = stdiomask.getpass(prompt="Enter probe Password: ")
            confirm = stdiomask.getpass("Confirm probe password: ")
            if probepassword == confirm:
                creds.probepassword = probepassword
                break
            elif probepassword.lower() == 'exit':
                return False
            else:
                print("Passwords do not match")
                print('Try again')
                continue

    expiry_time = input("Enter the expiry time for key file in minutes or <enter> for 'never expire': ")
    if expiry_time == '':
        creds.expiry_time = -1
    elif expiry_time.lower() == 'exit':
        return False
    else:
        creds.expiry_time = int(expiry_time)

    return True

def main():

    # Creating an object for Credentials class
    creds = Credentials()
    cred_filename = 'ProbeCredFile.ini'

    # Prompt the user to input the SSH connection parameters needed for the connection.
    if user_entry_menu(creds) == False: #The params entry menu has failed:
        print('\nExiting the script...')
        exit()

    # Create the credentials file.
    if creds.create_cred(cred_filename) == False: # The create credentials file function has failed.
        print('\nExiting the script...')
        exit()
    else: # The credentials file was created successfully.
        print(f"The credentials file {cred_filename} was created successfully at {time.ctime()}")

if __name__ == "__main__":
    main()
