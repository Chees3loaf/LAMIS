import logging
import paramiko
import re
from scripts.Nokia_SAR import Script as Sar
from scripts.Nokia_IXR import Script as Ixr
from scripts.Nokia_1830 import Script as Pss

# Configure logging with a debug flag
debug_mode = False  # Toggle this for verbose logging
logging.basicConfig(level=logging.DEBUG if debug_mode else logging.INFO)

class DeviceIdentifier:
    def identify_device(self, ip, queue):
        """
        Identifies the device type and name based on command output.
        """
        username, password = 'admin', 'admin'
        logging.debug(f"Attempting to identify device at {ip} with SSH.")
        
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(ip, username=username, password=password, look_for_keys=False, allow_agent=False, timeout=10)

            session = ssh_client.invoke_shell()
            command = "show chassis | match (Type) pre-lines 1 expression"
            logging.debug(f"Executing SSH command on {ip}: {command}")
            session.send(command + '\n')
            
            output = ""
            while session.recv_ready():
                output += session.recv(1024).decode('utf-8')
            
            ssh_client.close()
            
            if output:
                queue.put(f"Received response from {ip} via SSH: {output}\n")
                logging.debug(f"Raw output from SSH: {output}")
                return self.parse_device_info(output)
        except Exception as e:
            logging.warning(f"SSH connection failed for {ip}: {e}")
        
        return None, None

    @staticmethod
    def parse_device_info(output):
        """
        Extracts both 'Type' and 'Name' from the command output.
        """
        try:
            type_match = re.search(r"Type\s+:\s+(.+)", output)
            name_match = re.search(r"Name\s+:\s+(.+)", output)

            device_type = type_match.group(1).strip() if type_match else None
            device_name = name_match.group(1).strip() if name_match else None

            if not device_type or not device_name:
                logging.warning(f"Incomplete device info found in output: {output}")

            return device_type, device_name
        except Exception as e:
            logging.error(f"Error parsing device info: {e}")
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
