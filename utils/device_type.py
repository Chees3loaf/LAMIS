import logging
import time
import paramiko
import re
from scripts.Nokia_SAR import Script as Sar
from scripts.Nokia_IXR import Script as Ixr
from scripts.Nokia_1830 import Script as Pss

# Configure logging with a debug flag
debug_mode = True  # Toggle this for verbose logging
logging.basicConfig(level=logging.DEBUG if debug_mode else logging.INFO)

class DeviceIdentifier:
    def __init__(self):
        self.credentials = ('admin', 'admin')  # Same credentials for both attempts
        
    def _attempt_ssh_login(self, ip, use_cli, queue, command):
        """
        Attempts SSH login, optionally using 'cli' before entering credentials.
        """
        username, password = self.credentials
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            logging.debug(f"Attempting SSH connection to {ip} with username: {username} (use_cli={use_cli})")

            ssh_client.connect(ip, username=username, password=password, look_for_keys=False, allow_agent=False, timeout=10)
            session = ssh_client.invoke_shell()
            time.sleep(1)  # Allow session to initialize

            if use_cli:
                logging.info(f"Sending 'cli' command before logging in to {ip}.")
                session.send("cli\n")
                time.sleep(1)

            # Send login credentials
            logging.debug(f"Logging in as {username} on {ip} (use_cli={use_cli})")
            session.send(f"{username}\n")
            time.sleep(1)
            session.send(f"{password}\n")
            time.sleep(1)

            # Execute the appropriate status command
            logging.info(f"Executing SSH command on {ip}: {command}")
            session.send(command + '\n')
            time.sleep(2)

            output = self._read_ssh_output(session)
            ssh_client.close()
            logging.debug(f"SSH connection to {ip} closed.")

            # If "Access Denied" appears, return failure to trigger fallback
            if "Access Denied" in output:
                logging.error(f"Access Denied for {ip} (use_cli={use_cli}).")
                return False, None

            if output:
                queue.put(f"Received response from {ip} via SSH:\n{output}\n")
                logging.debug(f"Raw output from SSH:\n{output}")
                return True, self.parse_device_info(output)

            logging.warning(f"No output received from {ip} after executing command.")
        
        except paramiko.AuthenticationException:
            logging.error(f"Authentication failed for {ip} (use_cli={use_cli}).")
        except paramiko.SSHException as ssh_ex:
            logging.error(f"SSH error occurred for {ip} (use_cli={use_cli}): {ssh_ex}")
        except Exception as e:
            logging.error(f"Unexpected error during SSH session with {ip} (use_cli={use_cli}): {e}", exc_info=True)
        
        return False, None


    
    def _read_ssh_output(self, session, timeout=10):
        """
        Reads output from an SSH session with a timeout.
        """
        output = ""
        timeout_counter = 0

        while timeout_counter < timeout:
            if session.recv_ready():
                chunk = session.recv(1024).decode('utf-8')
                if not chunk.strip():
                    break
                output += chunk
            else:
                timeout_counter += 1
                time.sleep(1)  # Wait for more data

        return output.strip()
    
    def identify_device(self, ip, queue):
        """
        Identifies the device type and name based on command output.
        If 'Access Denied' occurs, it retries using 'cli' before login with a different command.
        """
        logging.info(f"Starting device identification for {ip} via SSH.")

        # First attempt using initial status command
        success, device_info = self._attempt_ssh_login(ip, use_cli=False, queue=queue, command="show system information | match (Name.+) post-lines 1 expression")
        
        if success:
            return device_info

        logging.warning(f"Primary SSH login failed for {ip}. Retrying using 'cli' before login.")

        # Explicitly force the retry with 'cli'
        logging.debug(f"Retrying SSH login for {ip} with 'cli'.")
        
        success, device_info = self._attempt_ssh_login(ip, use_cli=True, queue=queue, command="show general system-identification")

        if success:
            return device_info

        logging.error(f"Failed to authenticate on {ip}, even after using 'cli'.")
        return None, None



    @staticmethod
    def parse_device_info(output):
        """
        Extracts both 'Type' and 'Name' from the command output.
        """
        try:
            logging.debug(f"Raw device output before parsing:\n{output}")

            type_match = re.search(r"Type\s*:\s*([^\n]+)", output)
            name_match = re.search(r"Name\s*:\s*([^\n]+)", output)
            product_match = re.search(r"Product\s*:\s*([^\n]+)", output)

            device_type = type_match.group(1).strip() if type_match else None
            device_name = name_match.group(1).strip() if name_match else None
            product_line = product_match.group(1).strip() if product_match else None

            if not device_type or not device_name:
                logging.warning(f"Incomplete device info extracted: Type='{device_type}', Name='{device_name}', Product='{product_line}'")

            return device_type, device_name, product_line
        except Exception as e:
            logging.error(f"Error parsing device info: {e}", exc_info=True)
            
            return None, None



class ScriptSelector:
    DEVICE_SCRIPT_MAPPING = {
        '7705 sar-8 v2': Sar,
        '7250 ixr-r6': Ixr,
        '7250 ixr-r6d': Ixr,
        '1830': Pss,
    }

    def select_script(self, device_type, connection_type='ssh'):
        """
        Select a script class based on device type and connection type.
        """
        normalized_device_type = device_type.strip().lower() if device_type else 'unknown'
        script_class = self.DEVICE_SCRIPT_MAPPING.get(normalized_device_type)

        if script_class:
            logging.debug(f"Script class for device type '{device_type}': {script_class.__name__}")
            return script_class
        else:
            logging.error(f"No script found for device type: '{device_type}'")
            return None
